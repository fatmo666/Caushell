//! Static checks for Subversion status and implicit state.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("svn-status-config"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn status_models_configuration_initialization() {
    let result = check("svn status ./fixture");
    assert_eq!(result.decision, Decision::NeedApproval);
    let status = result
        .decision_trace
        .execution_semantics
        .iter()
        .find(|entry| entry.normalized_command_name == "svn")
        .expect("recognized Subversion status");
    assert_eq!(status.form_id, "local_status");
    assert!(
        result
            .decision_trace
            .path_targets
            .iter()
            .any(|target| target.operation == PathTargetOperation::Write),
        "{:?}",
        result.reasons
    );
}

#[test]
fn remote_or_mutating_subcommands_keep_approval() {
    for command in [
        "svn status --show-updates ./fixture",
        "svn status \"$unobserved\"",
        "svn update ./fixture",
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
