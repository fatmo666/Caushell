//! Native UnZip modes and argv ownership; inputs are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;
fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}
#[test]
fn stdout_modes_have_real_data_and_no_member_writes() {
    for options in ["-p", "-c", "-pq", "-cv", "-lp", "-pc", "-q -p"] {
        for destination in ["", " -d /opt/out", " -d/opt/out"] {
            let command = format!("unzip {options} archive.zip{destination}");
            let b = resolve(&command);
            assert_eq!(b.form_id.as_str(), "stdout_archive", "{command}");
            assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
            assert!(
                !b.effects.iter().any(|e| matches!(
                    e.kind,
                    EffectKind::WritePath | EffectKind::MetadataMutation
                )),
                "{command}: {b:#?}"
            );
            assert_eq!(
                b.stream_contract.unwrap().stdout_mode,
                StreamOutputMode::Data
            );
            assert_eq!(
                b.stream_contract.unwrap().stdout_dependency,
                caushell_types::StreamDataDependency::Inputs
            );
        }
    }
}
#[test]
fn inspection_modes_ignore_extraction_directory_and_overwrite_flags() {
    for (options, form) in [
        ("-t", "test_archive"),
        ("-tv", "test_archive"),
        ("-l", "list_archive"),
        ("-v", "list_archive"),
        ("-z", "list_archive"),
        ("-zT", "list_archive"),
        ("-Z", "zipinfo"),
    ] {
        let b = resolve(&format!("unzip {options} -o archive.zip -d /opt/out"));
        assert_eq!(b.form_id.as_str(), form);
        assert_eq!(b.effects.len(), 1);
        assert_eq!(b.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(values(&b, "output_directory"), ["/opt/out"]);
        assert!(values(&b, "extraction_directory").is_empty());
        assert_eq!(
            b.stream_contract.unwrap().stdout_mode,
            StreamOutputMode::Opaque
        );
    }
}
#[test]
fn trailing_mode_lookalikes_remain_member_selectors() {
    for member in [
        "-p",
        "-c",
        "-t",
        "-l",
        "-v",
        "-T",
        "-h",
        "-Z",
        "-pd/opt/out",
        "-xp",
    ] {
        let b = resolve(&format!("unzip archive.zip {member} -d /opt/out"));
        assert_eq!(b.form_id.as_str(), "extract_archive");
        assert_eq!(values(&b, "archive_file"), ["archive.zip"]);
        assert_eq!(values(&b, "member_filters"), [member]);
        assert_eq!(values(&b, "output_directory"), ["/opt/out"]);
        assert_eq!(values(&b, "extraction_directory"), ["/opt/out"]);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
    let b = resolve("unzip -p archive.zip -x private -t -d/opt/out");
    assert_eq!(b.form_id.as_str(), "stdout_archive");
    assert_eq!(values(&b, "member_filters"), ["private", "-t"]);
}
#[test]
fn timestamp_is_archive_metadata_not_extracted_members() {
    for flags in ["-T", "-Tp", "-Tt", "-Tl"] {
        let b = resolve(&format!("unzip {flags} /opt/archive.zip -d /opt/unused"));
        assert_eq!(b.form_id.as_str(), "archive_timestamp");
        assert_eq!(
            b.effects
                .iter()
                .filter(|e| e.kind == EffectKind::MetadataMutation)
                .count(),
            1
        );
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
}
