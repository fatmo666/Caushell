//! Judge-only tests. No command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("uuidgen-generation"),
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
fn explicit_random_only_uses_standard_output() {
    for command in ["uuidgen -r", "uuidgen --random", "uuidgen -r | wc -c"] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|entry| {
                    entry.normalized_command_name == "uuidgen"
                        && entry.form_id == "explicit_random"
                        && !entry.operation_semantics_unresolved
                        && !entry.executes_payload
                }),
            "{command}"
        );
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .all(|target| !target.operation.is_mutation())
        );
    }
}

#[test]
fn default_mode_preserves_the_unresolved_clock_fallback() {
    for command in ["uuidgen", "find . -maxdepth 0 -exec uuidgen \\;"] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|entry| {
                    entry.normalized_command_name == "uuidgen"
                        && entry.form_id == "default_generation"
                        && entry.operation_semantics_unresolved
                }),
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn mixed_modes_unknown_arguments_and_redirections_remain_guarded() {
    for command in [
        "uuidgen -t",
        "uuidgen -r -t",
        "uuidgen -rt",
        "uuidgen --random=on",
        "uuidgen -r -o ./ids",
        "uuidgen -r ./ids",
        "uuidgen -r --",
        "uuidgen -r -r",
        "uuidgen -r \"$ARG\"",
        "uuidgen \"$ARG\"",
        "uuidgen -r > /opt/round-fixture/ids",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}
