//! Static native service-entry contracts. Submitted commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("service-control-entries"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/user".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn has_operation(response: &CheckResponse, name: &str, kind: StateOperationKind) -> bool {
    response.decision_trace.execution_semantics.iter().any(|f| {
        f.normalized_command_name == name
            && f.state_operations
                .iter()
                .any(|op| op.domain == StateOperationDomain::ServiceManager && op.operation == kind)
    })
}

#[test]
fn postfix_control_is_a_state_operation_in_every_supported_shell_composition() {
    for command in [
        "postfix start",
        "/usr/sbin/postfix start-fg",
        "postfix stop",
        "postfix abort",
        "postfix reload",
        "postfix flush",
        "postfix -v -c /workspace/config start",
        "MAIL_CONFIG=/tmp/config postfix start",
        "env postfix start",
        "time postfix start 2>&1 | tail -2",
        "postfix start 2>&1; postfix status 2>&1",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            has_operation(&response, "postfix", StateOperationKind::Control),
            "{command}"
        );
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::StateControl),
            "{command}"
        );
    }
}

#[test]
fn postfix_maintenance_is_not_misclassified_as_read_only_checking() {
    for command in [
        "postfix check",
        "postfix set-permissions",
        "postfix set-permissions mail_owner=postfix",
        "postfix upgrade-configuration",
        "postfix logrotate",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            has_operation(&response, "postfix", StateOperationKind::Mutate),
            "{command}"
        );
    }
}

#[test]
fn status_is_inspection_but_unknown_configured_helpers_do_not_gain_authority() {
    let response = ShellQueryCore::new().check(request("postfix status"));
    assert!(has_operation(
        &response,
        "postfix",
        StateOperationKind::Inspect
    ));
    assert!(!has_operation(
        &response,
        "postfix",
        StateOperationKind::Control
    ));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(has_operation(
        &response,
        "postfix",
        StateOperationKind::Opaque
    ));
    // Existing modeled inspection is not converted into service control.
    let response = ShellQueryCore::new().check(request("service example status"));
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    assert!(has_operation(
        &response,
        "service",
        StateOperationKind::Inspect
    ));
}

#[test]
fn local_configuration_and_unknown_native_syntax_cannot_authorize_services() {
    for command in [
        "postfix -c /workspace/config start",
        "postfix -c /tmp/config reload",
        "postfix --unknown start",
        "postfix start --unknown",
        "postfix status start",
        "postfix tls deploy-server-cert",
        "postfix -c",
        "postfix $ACTION",
        "postfix",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        for evidence in &response.decision_trace.evidence {
            if let EvidenceKind::ResourceAuthorization(proof) = &evidence.kind {
                assert!(!proof.authorized, "{command}: {proof:#?}");
            }
        }
    }
}

#[test]
fn partial_service_analysis_does_not_erase_independent_or_explicit_denies() {
    for command in [
        "postfix --unknown start; rm -rf /",
        "postfix start; rm -rf /",
        "postfix -c \"$(rm -rf /)\" start",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::Deny,
            "{command}"
        );
    }
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .rules
        .insert(RuleId::StateControl, RulePolicyEntry::new(RuleAction::Deny));
    for command in ["postfix start", "postfix start --unknown"] {
        let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            response.decision,
            Decision::Deny,
            "{command}: {:?}",
            response.reasons
        );
    }
}
