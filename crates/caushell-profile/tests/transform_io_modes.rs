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
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{other:#?}"),
        })
        .collect()
}

#[test]
fn transforms_consume_stdin_only_when_the_native_input_mode_does() {
    for tool in [
        "fold",
        "fmt",
        "od -An -t x1",
        "iconv -f UTF-8 -t UTF-8",
        "shuf",
        "md5sum",
        "sha256sum",
        "cksum",
    ] {
        for (input, expected) in [
            ("", StreamInputMode::DataOptional),
            (" -", StreamInputMode::DataOptional),
            (" public", StreamInputMode::Ignored),
        ] {
            let command = format!("{tool}{input}");
            let r = resolved(&command);
            assert_eq!(
                r.proven_stream_contract().unwrap().stdin_mode,
                expected,
                "{command}"
            );
            assert!(
                !r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::ReadPath
                        && e.path_access != Some(PathAccessKind::ContentOpen)),
                "{command}"
            );
        }
    }
    for tool in [
        "fold",
        "fmt",
        "od -An -t x1",
        "iconv -f UTF-8 -t UTF-8",
        "md5sum",
        "sha256sum",
        "cksum",
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
    let r = resolved("strings /dev/fd/3");
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath
                && e.path_access == Some(PathAccessKind::ContentOpen))
    );
}

#[test]
fn xxd_sentinels_never_shift_the_fixed_input_and_output_roles() {
    for flags in [
        "",
        "-p ",
        "-r -p ",
        "-ps ",
        "-cols 8 ",
        "-c8 ",
        "-c 8 -g 1 -l 64 ",
        "-s 0 ",
        "-seek 0 ",
    ] {
        for (input, stdin) in [
            ("-", StreamInputMode::DataOptional),
            ("public", StreamInputMode::Ignored),
        ] {
            let command = format!("xxd {flags}{input} /opt/shared/out");
            let r = resolved(&command);
            assert_eq!(values(&r, "output_path"), ["/opt/shared/out"], "{command}");
            assert_eq!(
                values(&r, "input_path"),
                if input == "-" {
                    vec![]
                } else {
                    vec!["public".to_owned()]
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
}

#[test]
fn xxd_explicit_stdout_has_no_fictitious_dash_file() {
    for command in [
        "xxd",
        "xxd -",
        "xxd - -",
        "xxd public -",
        "xxd -r -p - -",
        "xxd -r -p public -",
    ] {
        let r = resolved(command);
        assert!(values(&r, "output_path").is_empty(), "{command}");
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
    }
    // Once the infile is seen, a following dash-prefixed name is the outfile.
    let r = resolved("xxd public -cache");
    assert_eq!(values(&r, "output_path"), ["-cache"]);
}

#[test]
fn iconv_and_shuf_preserve_their_different_output_dash_contracts() {
    for command in [
        "iconv -o - public",
        "iconv --output=- public",
        "iconv -o - -",
    ] {
        let r = resolved(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
    }
    let r = resolved("shuf -o - public");
    assert_eq!(values(&r, "output_path"), ["-"]);
    assert_eq!(
        r.proven_stream_contract().unwrap().stdout_dependency,
        StreamDataDependency::Independent
    );
}

#[test]
fn file_output_is_independent_but_keeps_a_content_write() {
    for command in [
        "iconv -o cache/out .env",
        "iconv -o cache/out -",
        "shuf -o cache/out .env",
        "shuf -o cache/out -",
        "xxd .env cache/out",
        "xxd - cache/out",
    ] {
        let r = resolved(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
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

#[test]
fn shuf_generation_binds_values_not_paths_or_stdin() {
    for command in [
        "shuf -e .env",
        "shuf --echo -- .env -",
        "shuf -i 1-3",
        "shuf --input-range=1-3",
        "shuf -n 2 -e PUBLIC",
        "shuf -n2 -i1-3",
    ] {
        let r = resolved(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Inputs,
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
    let r = resolved("shuf -e .env PUBLIC");
    assert_eq!(values(&r, "arguments"), [".env", "PUBLIC"]);
    for command in ["shuf -e .env -o cache/out", "shuf -i 1-3 -o cache/out"] {
        let r = resolved(command);
        assert_eq!(values(&r, "output_path"), ["cache/out"]);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
    let r = resolved("shuf -e PUBLIC --random-source=/dev/fd/3");
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath
                && e.path_access == Some(PathAccessKind::ContentOpen))
    );
}

#[test]
fn incomplete_transforms_cannot_prove_ignored_input_or_empty_stdout() {
    for command in [
        "fold \"$unknown\"",
        "iconv -o \"$output\" public",
        "shuf \"$input\"",
        "shuf -i 1-3 extra",
        "xxd - \"$output\"",
        "xxd public output extra",
    ] {
        static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match resolve_invocation_artifact_with_bindings(
            REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        ) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                assert!(r.proven_stream_contract().is_none(), "{command}: {r:#?}")
            }
            ResolveInvocationArtifactResult::SelectionError { .. } => {}
            other => panic!("{command}: {other:#?}"),
        }
    }
}
