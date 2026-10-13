use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(r: &ResolvedInvocationArtifact, slot: &str) -> Vec<String> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.values.iter())
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}
fn unresolved(command: &str) -> bool {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound.operation_semantics_unresolved,
        ResolveInvocationArtifactResult::SelectionError { .. } => true,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn rg_owns_patterns_option_values_and_input_paths() {
    for command in [
        "rg LAB public",
        "rg -e LAB public",
        "rg --regexp=LAB public",
        "rg -e LAB -e OTHER public",
        "rg public -e LAB",
        "rg -g '*.rs' -n -e LAB public",
        "rg -A2 -B 3 -C4 -m1 -e LAB public",
        "rg -- --help public",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert_eq!(values(&r, "input_paths"), ["public"], "{command}");
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath
                    && e.path_access == Some(PathAccessKind::ContentOpen))
        );
    }
    let r = resolved("rg -f cache/patterns public");
    assert!(!r.bound.operation_semantics_unresolved);
    assert_eq!(values(&r, "pattern_files"), ["cache/patterns"]);
    assert_eq!(values(&r, "input_paths"), ["public"]);
}

#[test]
fn rg_stdin_markers_are_consumed_not_bound_as_paths() {
    for command in [
        "rg LAB -",
        "rg -e LAB -",
        "rg LAB public -",
        "rg -e LAB - public",
        "rg LAB",
        "rg -e LAB",
        "rg -f - public",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
        assert!(!values(&r, "input_paths").iter().any(|s| s == "-"));
        assert!(!values(&r, "pattern_files").iter().any(|s| s == "-"));
    }
    let r = resolved("rg -- - ./-");
    assert_eq!(values(&r, "pattern"), ["-"]);
    assert_eq!(values(&r, "input_paths"), ["./-"]);
}

#[test]
fn rg_quiet_information_and_listing_do_not_emit_input_contents() {
    for command in [
        "rg -q LAB .env",
        "rg -qe LAB .env",
        "rg --help PUBLIC .env",
        "rg --version PUBLIC .env",
        "rg --help --pre /opt/shared/helper -f /opt/shared/patterns public",
        "rg --files .env",
        "rg --generate man",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
        if r.bound.form_id.as_str() == "information" {
            assert!(
                r.bound.effects.is_empty(),
                "{command}: {:?}",
                r.bound.effects
            );
        }
    }
    for command in ["rg --stats -q LAB .env", "rg --json -q LAB .env"] {
        assert_ne!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdout_dependency,
            StreamDataDependency::Independent
        );
    }
    assert!(unresolved("rg --unknown-mode LAB .env"));
    assert!(unresolved(
        "rg --hostname-bin /opt/shared/helper LAB public"
    ));
}

#[test]
fn mv_information_owns_operands_without_mutations() {
    for command in [
        "mv --help public /opt/shared/out",
        "mv --version public /opt/shared/out",
        "mv --help -t /opt/shared public",
        "mv --help --backup=numbered -S .bak public /opt/shared/out",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(
            r.bound.effects.is_empty(),
            "{command}: {:?}",
            r.bound.effects
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
}

#[test]
fn mv_native_arguments_retain_actual_mutations_and_stream_boundary() {
    for command in [
        "mv -v public cache/out",
        "mv public cache/out -f",
        "mv -t cache public other",
        "mv -T public cache/out",
        "mv --backup=numbered public cache/out",
        "mv -b -S .bak public cache/out",
        "mv -bS.bak public cache/out",
        "mv --update=none public cache/out",
        "mv -- --help cache/out",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::MovePath)
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
        assert!(
            !values(&r, "source_paths")
                .iter()
                .any(|s| s == ".bak" || s == "none")
        );
    }
    assert!(unresolved("mv --exchange public cache/out"));
}
