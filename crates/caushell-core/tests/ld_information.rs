//! Static checks of linker information queries. Submitted shell text never executes.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("ld-information"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn single_information_argument_is_resolved_with_or_without_a_pipeline() {
    for command in [
        r"ld --verbose | grep SEARCH_DIR | tr -s ' ;' \\012",
        "/usr/bin/ld --version",
        "ld -v",
        "ld -V",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effect| {
                    effect.normalized_command_name == "ld"
                        && effect.form_id == "information_only"
                        && !effect.operation_semantics_unresolved
                })
        );
    }
}

#[test]
fn information_only_ignores_stdin_and_has_no_named_input_or_output() {
    let parsed = parse_command("ld --verbose", ShellKind::Bash).unwrap();
    let artifacts = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = artifacts else {
        panic!("expected information-only resolution: {artifacts:#?}");
    };
    let streams = result.proven_stream_contract().unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(streams.stdout_dependency, StreamDataDependency::Independent);
    assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
    assert!(result.bound.effects.is_empty());
}

#[test]
fn an_information_flag_cannot_mask_linking_or_a_separate_shell_effect() {
    for command in [
        "ld --verbose object.o",
        "ld --verbose --library=example",
        "ld --verbose --output=product",
        "ld --verbose --script=example.ld",
        "ld --version --plugin=example.so",
        "ld --verbose @options",
        "ld --verbose -- -",
        "ld --verbose \"$unknown\"",
        "ld \"$unknown\"",
        "ld --verbose >/outside/output",
        "ld --verbose | sh",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}
