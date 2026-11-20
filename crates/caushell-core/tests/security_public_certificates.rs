//! Static policy checks. No system security commands are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("security-public-certificates"),
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
fn public_certificate_query_is_host_identity_inspection() {
    for command in [
        "security find-certificate -a -p",
        "/usr/bin/security find-certificate -p -a > ./certificates.pem",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let operation = &result.decision_trace.execution_semantics[0];
        assert_eq!(operation.form_id, "list_public_certificates_pem");
        assert_eq!(
            operation.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            operation.state_operations[0].operation,
            StateOperationKind::Inspect
        );
        assert!(!operation.executes_payload);
        if command.contains('>') {
            assert!(result.decision_trace.path_targets.iter().any(|fact| {
                fact.operation == PathTargetOperation::Write
                    && fact.lexical.concrete_path() == Some("/bench/workspace/certificates.pem")
            }));
        }
    }
}

#[test]
fn other_keychain_operations_and_shell_effects_remain_guarded() {
    for command in [
        "security",
        "security -i",
        "security find-generic-password",
        "security import fixture.pem",
        "security export",
        "security -a find-certificate -p",
        "security find-certificate -a -p fixture.keychain",
        "security find-certificate -a -p --",
        "security find-certificate -a -p \"$unknown\"",
        "security find-certificate -a -p > /opt/shared/certificates.pem",
        "security find-certificate -a -p | sh",
        "sudo security find-certificate -a -p",
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
fn global_account_policy_query_is_host_identity_inspection() {
    for command in [
        "pwpolicy getaccountpolicies",
        "/usr/bin/pwpolicy -getaccountpolicies > ./policy-info.txt",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let operation = &result.decision_trace.execution_semantics[0];
        assert_eq!(operation.form_id, "inspect_global_account_policies");
        assert_eq!(
            operation.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            operation.state_operations[0].operation,
            StateOperationKind::Inspect
        );
        assert!(!operation.executes_payload);
        if command.contains('>') {
            assert!(result.decision_trace.path_targets.iter().any(|fact| {
                fact.operation == PathTargetOperation::Write
                    && fact.lexical.concrete_path() == Some("/bench/workspace/policy-info.txt")
            }));
        }
    }
}

#[test]
fn account_policy_mutations_unknown_arguments_and_shell_effects_remain_guarded() {
    for command in [
        "pwpolicy setaccountpolicies ./fixture.plist",
        "pwpolicy clearaccountpolicies",
        "pwpolicy -u fixture-user getaccountpolicies",
        "pwpolicy -n /Local/Default getaccountpolicies",
        "pwpolicy getaccountpolicies ./fixture.plist",
        "pwpolicy getaccountpolicies ''",
        "pwpolicy getaccountpolicies \"$extra\"",
        "pwpolicy getaccountpolicies --",
        "pwpolicy \"$operation\"",
        "pwpolicy -getaccountpolicies > /outside/policy-info.txt",
        "pwpolicy getaccountpolicies | sh",
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
