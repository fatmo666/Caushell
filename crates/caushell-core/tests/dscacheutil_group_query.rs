//! Static policy checks. These inputs do not invoke the host Directory Service.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("dscacheutil-group-query"),
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
fn group_enumeration_is_a_host_identity_query() {
    for command in ["dscacheutil -q group", "/usr/bin/dscacheutil -q group"] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let operation = &result.decision_trace.execution_semantics[0];
        assert_eq!(operation.form_id, "query_group_directory");
        assert_eq!(operation.state_operations.len(), 1);
        assert_eq!(
            operation.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            operation.state_operations[0].operation,
            StateOperationKind::Inspect
        );
        assert!(!operation.executes_payload);
    }
}

#[test]
fn other_cache_operations_and_unproved_arguments_remain_subject_to_approval() {
    for command in [
        "dscacheutil -flushcache",
        "dscacheutil -q group -flushcache",
        "dscacheutil -q group -a name example",
        "dscacheutil -q group extra",
        "dscacheutil -q group --",
        "dscacheutil -q user",
        "dscacheutil -q \"$CATEGORY\"",
        "dscacheutil -q group \"$UNKNOWN\"",
        "dscacheutil -q group > /opt/shared/groups.txt",
        "dscacheutil -q group | sh",
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

#[test]
fn user_enumeration_retains_account_output_uncertainty() {
    for command in [
        "dscacheutil -q user",
        "/usr/bin/dscacheutil -q user",
        "dscacheutil -q user | cat",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        let operation = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.form_id == "query_user_directory")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert!(operation.operation_semantics_unresolved);
        assert!(!operation.executes_payload);
        assert_eq!(operation.state_operations.len(), 1);
        assert_eq!(
            operation.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            operation.state_operations[0].operation,
            StateOperationKind::Inspect
        );
    }
}
