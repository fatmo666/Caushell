//! Static policy checks. No directory service call is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("dscl-local-list"),
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
fn explicit_local_record_names_are_host_identity_inspection() {
    for command in [
        "dscl . list /Groups",
        "dscl . -list /Users",
        "/usr/bin/dscl . -list /Groups",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let semantics = &result.decision_trace.execution_semantics[0];
        assert_eq!(semantics.form_id, "list_local_account_names");
        assert_eq!(semantics.state_operations.len(), 1);
        assert_eq!(
            semantics.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            semantics.state_operations[0].operation,
            StateOperationKind::Inspect
        );
        assert!(!semantics.executes_payload);
    }
}

#[test]
fn other_directory_routes_and_operations_still_require_approval() {
    for command in [
        "dscl",
        "dscl .",
        "dscl . -list",
        "dscl . -list /Users GeneratedUID",
        "dscl . -list /Users \"\"",
        "dscl . -list /Config",
        "dscl . -list /Users --",
        "dscl .. -list /Users",
        "dscl remote.example.test -list /Users",
        "dscl -f ./fixture-db localonly -list /Users",
        "dscl . -read /Users/example",
        "dscl . -create /Users/example",
        "dscl . -delete /Groups/example",
        "dscl . \"$operation\" /Groups",
        "dscl . -list \"$category\"",
        "dscl . -list /Users > /opt/shared/list.txt",
        "dscl . -list /Users | sh",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}
