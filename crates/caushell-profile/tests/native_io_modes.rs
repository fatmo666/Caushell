use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn file_tools_declare_no_implicit_content_stdout_or_stdin() {
    for command in [
        "cp .env cache/copy",
        "cp -t cache .env",
        "install .env cache/copy",
        "touch -r .env cache/stamp",
    ] {
        let r = resolved(command);
        let c = r.proven_stream_contract().unwrap();
        assert_eq!(c.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert_eq!(
            c.stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
    let reference = resolved("touch -r .env cache/stamp");
    assert!(
        !reference
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        reference
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TargetPath)
    );
    assert!(
        resolved("install -s --strip-program=cat -T .env cache/copy")
            .proven_stream_contract()
            .is_none()
    );
}

#[test]
fn dd_declares_all_four_native_io_combinations() {
    for (command, stdin, stdout) in [
        (
            "dd status=none",
            StreamInputMode::DataOptional,
            StreamDataDependency::Inputs,
        ),
        (
            "dd if=.env status=none",
            StreamInputMode::Ignored,
            StreamDataDependency::Inputs,
        ),
        (
            "dd of=cache/copy status=none",
            StreamInputMode::DataOptional,
            StreamDataDependency::Independent,
        ),
        (
            "dd if=.env of=cache/copy status=none",
            StreamInputMode::Ignored,
            StreamDataDependency::Independent,
        ),
    ] {
        let c = resolved(command).proven_stream_contract().unwrap();
        assert_eq!(
            (c.stdin_mode, c.stdout_dependency),
            (stdin, stdout),
            "{command}"
        );
    }
    assert!(
        resolved("dd of=\"$target\"")
            .proven_stream_contract()
            .is_none()
    );
}

#[test]
fn jq_null_input_does_not_prove_arbitrary_filters_input_free() {
    for command in [
        "jq -nR inputs",
        "jq -nR input",
        "jq -n 'reduce inputs as $x (0; .+1)'",
        "jq -nf filter.jq",
    ] {
        assert_ne!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    for command in [
        "jq . public.json",
        "jq -R . public",
        "jq -nR inputs public",
        "jq -f filter.jq public",
    ] {
        assert_eq!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    for command in ["jq . public -", "jq -nR inputs public -"] {
        assert_ne!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    for command in [
        "jq -n '\"PUBLIC\"'",
        "jq -n '\"inputs\"'",
        "jq -n true",
        "jq -n 123",
    ] {
        assert_eq!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    assert_ne!(
        resolved(r#"jq -nR '"prefix\(inputs)"'"#)
            .proven_stream_contract()
            .unwrap()
            .stdin_mode,
        StreamInputMode::Ignored
    );
}

#[test]
fn sed_quiet_output_requires_a_complete_decoded_program() {
    for command in [
        "sed -n 's/x/y/' .env",
        "sed -n -e 'h' -e 'd' .env",
        "sed -n '' .env",
        "sed -n 's/p/p/' .env",
    ] {
        assert_eq!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
    for script in ["p", "P", "s/x/y/p", "l", "=", "a PUBLIC", "r .env", "F"] {
        let command = format!("sed -n '{script}' .env");
        assert_ne!(
            resolved(&command)
                .proven_stream_contract()
                .unwrap()
                .stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
    assert_ne!(
        resolved("sed -n 'unknown' .env")
            .proven_stream_contract()
            .unwrap()
            .stdout_dependency,
        StreamDataDependency::Independent
    );
    assert!(
        resolved("sed -n \"$script\" .env")
            .proven_stream_contract()
            .is_none()
    );
    assert!(!resolved("sed -n 's/x/y/' .env").bound.effects.is_empty());
}

#[test]
fn payload_output_proof_is_opt_in_and_never_uses_a_partial_decode() {
    let source = include_str!("../profiles/sed.yaml");
    for invalid in [
        source.replace(
            "stdout_emissions: script_stdout",
            "stdout_emissions: script_reads",
        ),
        source.replace("stdout_emissions: script_stdout", ""),
    ] {
        assert!(load_command_profile_from_str(&invalid).is_err());
    }
    let profile = load_command_profile_from_str(
        &source
            .replace(
                "canonical_name: sed",
                "canonical_name: arbitrary-transformer",
            )
            .replace("max_operations: 4096", "max_operations: 1"),
    )
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for (command, expected) in [
        (
            "arbitrary-transformer -n 'h' .env",
            StreamDataDependency::Independent,
        ),
        (
            "arbitrary-transformer -n 'h;p' .env",
            StreamDataDependency::Inputs,
        ),
        (
            "arbitrary-transformer -n -e h -e p .env",
            StreamDataDependency::Inputs,
        ),
    ] {
        let p = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(r) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &p.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}")
        };
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            expected,
            "{command}"
        );
    }
}
