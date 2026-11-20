//! Static launchctl classification. No submitted command is executed.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("launchctl-list"),
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
fn list_without_arguments_inspects_service_state() {
    for command in [
        "launchctl list",
        "/bin/launchctl list | grep fixture",
        "launchctl 'list'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let service = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "launchctl")
            .expect("the service query should be represented explicitly");
        assert_eq!(service.form_id, "list_jobs");
        assert_eq!(
            service.state_operations,
            [StateOperation {
                domain: StateOperationDomain::ServiceManager,
                operation: StateOperationKind::Inspect,
                resource: None,
            }]
        );
    }
}

#[test]
fn job_list_has_no_file_effects_or_stdin_payload() {
    let parsed = parse_command("launchctl list", ShellKind::Bash).unwrap();
    let artifacts = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = artifacts else {
        panic!("expected service-list resolution: {artifacts:#?}");
    };
    let streams = result.proven_stream_contract().unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::Ignored);
    assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
    assert!(
        result
            .bound
            .effects
            .iter()
            .all(|effect| effect.kind == EffectKind::StateOperation)
    );
}

#[test]
fn other_subcommands_and_separate_shell_effects_stay_guarded() {
    for command in [
        "launchctl",
        "launchctl list com.example.fixture",
        "launchctl list -x",
        "launchctl list --",
        "launchctl list \"$unknown\"",
        "launchctl \"$unknown\"",
        "launchctl bootstrap gui/501 fixture.plist",
        "launchctl kickstart gui/501/com.example.fixture",
        "launchctl list >/outside/output",
        "launchctl list | sh",
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
