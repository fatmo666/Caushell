use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn result(command: &str) -> ResolveInvocationArtifactResult {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    )
}
fn resolved(command: &str) -> ResolvedInvocationArtifact {
    match result(command) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(r: &ResolvedInvocationArtifact, slot: &str) -> Vec<String> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{other:#?}"),
        })
        .collect()
}

#[test]
fn named_text_inputs_ignore_stdin_while_content_reads_remain_explicit() {
    for tool in [
        "base32",
        "base64",
        "rev",
        "expand",
        "unexpand",
        "tac",
        "nl",
        "pr -t",
        "ptx",
        "sha1sum",
        "sha224sum",
        "sha384sum",
        "sha512sum",
        "b2sum",
        "sum",
    ] {
        let command = format!("{tool} /dev/fd/3");
        let r = resolved(&command);
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
                    && e.path_access == Some(PathAccessKind::ContentOpen)),
            "{command}"
        );
        let command = format!("{tool}");
        assert_eq!(
            resolved(&command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
        if tool != "rev" {
            let command = format!("{tool} -");
            let r = resolved(&command);
            assert_eq!(
                r.proven_stream_contract().unwrap().stdin_mode,
                StreamInputMode::DataOptional,
                "{command}"
            );
            assert!(
                !r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::ReadPath),
                "{command}"
            );
        }
    }
    for tool in [
        "expand",
        "unexpand",
        "tac",
        "pr -t",
        "ptx",
        "sha1sum",
        "sha224sum",
        "sha384sum",
        "sha512sum",
        "b2sum",
        "sum",
    ] {
        let command = format!("{tool} public -");
        assert_eq!(
            resolved(&command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
    }
}

#[test]
fn rev_dash_is_a_real_input_path_not_a_stdin_sentinel() {
    for command in ["rev -", "rev -- -", "rev public -"] {
        let r = resolved(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
        assert!(
            values(&r, "input_paths").iter().any(|p| p == "-"),
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
}

#[test]
fn ptx_traditional_output_never_changes_the_input_argument_role() {
    for flag in ["-G", "--traditional"] {
        for (input, stdin) in [
            ("public", StreamInputMode::Ignored),
            ("-", StreamInputMode::DataOptional),
            ("''", StreamInputMode::DataOptional),
        ] {
            for output in ["/opt/shared/out", "cache/out", "-", "/dev/stdout"] {
                let command = format!("ptx {flag} {input} {output}");
                let r = resolved(&command);
                assert_eq!(values(&r, "output_path"), [output], "{command}");
                assert_eq!(
                    values(&r, "input_paths"),
                    if input == "public" {
                        vec!["public".to_owned()]
                    } else {
                        vec![]
                    },
                    "{command}"
                );
                let c = r.proven_stream_contract().unwrap();
                assert_eq!(c.stdin_mode, stdin, "{command}");
                assert_eq!(
                    c.stdout_dependency,
                    StreamDataDependency::Independent,
                    "{command}"
                );
                assert!(
                    r.bound
                        .effects
                        .iter()
                        .any(|e| e.kind == EffectKind::WritePath
                            && e.path_access == Some(PathAccessKind::ContentOpen)),
                    "{command}"
                );
            }
        }
        for input in ["", " -", " ''"] {
            let command = format!("ptx {flag}{input}");
            let r = resolved(&command);
            assert_eq!(
                r.proven_stream_contract().unwrap().stdin_mode,
                StreamInputMode::DataOptional
            );
            assert_eq!(
                r.proven_stream_contract().unwrap().stdout_dependency,
                StreamDataDependency::Inputs
            );
            assert!(
                !r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::WritePath)
            );
        }
    }
    let r = resolved("ptx public-a public-b");
    assert_eq!(values(&r, "input_paths"), ["public-a", "public-b"]);
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn ptx_auxiliary_input_and_format_values_have_different_semantics() {
    for command in [
        "ptx -S .env -W PATTERN public",
        "ptx --sentence-regexp=.env --word-regexp=PATTERN public",
        "ptx -F .env -M TITLE public",
    ] {
        let r = resolved(command);
        assert_eq!(values(&r, "input_paths"), ["public"], "{command}");
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    for flag in [
        "-b",
        "--break-file",
        "-i",
        "--ignore-file",
        "-o",
        "--only-file",
    ] {
        let command = format!("ptx {flag} /dev/fd/3 public");
        let r = resolved(&command);
        assert_eq!(values(&r, "auxiliary_files"), ["/dev/fd/3"]);
        assert_eq!(values(&r, "input_paths"), ["public"]);
        assert!(r.bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath && e.path_access == Some(PathAccessKind::ContentOpen) && matches!(&e.target, EffectTarget::Slot(slot) if slot.as_str() == "auxiliary_files")));
        let command = format!("ptx {flag} - public");
        let r = resolved(&command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
        assert!(values(&r, "auxiliary_files").is_empty());
    }
}

#[test]
fn pr_optional_values_do_not_take_the_next_input_file() {
    for command in [
        "pr -h .env public",
        "pr -h.env public",
        "pr --header=.env public",
        "pr -D .env public",
        "pr --date-format=.env public",
        "pr -s public",
        "pr --separator public",
        "pr -S public",
        "pr -n public",
        "pr -e public",
        "pr --columns=2 public",
        "pr -s.env public",
        "pr --sep-string=.env public",
    ] {
        let r = resolved(command);
        assert_eq!(values(&r, "input_paths"), ["public"], "{command}");
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    let r = resolved("b2sum -l 128 public");
    assert_eq!(values(&r, "input_paths"), ["public"]);
    let r = resolved("tac -s .env public");
    assert_eq!(values(&r, "input_paths"), ["public"]);
}

#[test]
fn base_decode_keeps_the_transform_kind_with_native_input_modes() {
    for tool in ["base32", "base64"] {
        for input in ["public", "-", ""] {
            let command = format!("{tool} -di -w0 {input}");
            let r = resolved(&command);
            assert_eq!(
                r.proven_stream_contract().unwrap().stdin_mode,
                if input == "public" {
                    StreamInputMode::Ignored
                } else {
                    StreamInputMode::DataOptional
                },
                "{command}"
            );
            assert!(
                r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::TransformData
                        && e.extensions.get("transform.kind").and_then(|v| v.as_str())
                            == Some("decode"))
            );
        }
    }
}

#[test]
fn incomplete_shapes_never_prove_input_ignored_or_output_empty() {
    for command in [
        "base32 \"$input\"",
        "base64 a b",
        "nl a -",
        "rev \"$input\"",
        "pr -h \"$title\" public",
        "ptx -G - \"$output\"",
        "ptx -G public output extra",
        "ptx -S",
        "ptx --unknown public",
    ] {
        match result(command) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                assert!(r.proven_stream_contract().is_none(), "{command}: {r:#?}")
            }
            ResolveInvocationArtifactResult::SelectionError { .. } => {}
            other => panic!("{command}: {other:#?}"),
        }
    }
}

#[test]
fn checksum_format_flags_preserve_inputs_but_unmodeled_list_expansion_stays_opaque() {
    for tool in ["sha1sum", "sha224sum", "sha384sum", "sha512sum", "b2sum"] {
        for flags in ["-b", "-t", "--tag", "-z"] {
            let command = format!("{tool} {flags} public");
            let r = resolved(&command);
            assert_eq!(values(&r, "input_paths"), ["public"]);
            assert_eq!(
                r.proven_stream_contract().unwrap().stdin_mode,
                StreamInputMode::Ignored
            );
        }
        let command = format!("{tool} -c checksums");
        match result(&command) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                assert!(r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
                assert!(r.proven_stream_contract().is_none());
            }
            ResolveInvocationArtifactResult::SelectionError { .. } => {}
            other => panic!("{command}: {other:#?}"),
        }
    }
}
