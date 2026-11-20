//! Static checks for UUID-to-device lookup and its configuration.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("blkid-uuid-config"),
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
fn uuid_lookup_retains_pending_cache_writes() {
    for command in [
        "blkid -U 00000000-0000-4000-8000-000000000123",
        "blkid --uuid 00000000-0000-4000-8000-000000000123",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let lookup = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "blkid")
            .expect("recognized blkid UUID lookup");
        assert_eq!(lookup.form_id, "lookup_uuid");
        assert!(lookup.operation_semantics_unresolved);
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
}

#[test]
fn unsupported_and_unproved_modes_keep_approval() {
    for command in [
        "blkid -U",
        "blkid -U \"$unobserved\"",
        "blkid --garbage-collect",
        "blkid -U 00000000-0000-4000-8000-000000000123 --garbage-collect",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
    }
}
