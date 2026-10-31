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

#[test]
fn adjacent_manager_entries_share_the_service_state_contract() {
    for (command, name) in [
        ("postmulti -p start", "postfix"),
        ("postmulti -a -p reload", "postfix"),
        ("postmulti -i example -p stop", "postfix"),
        ("postmulti -g group -p flush", "postfix"),
        ("mailman start", "mailman"),
        ("mailman stop", "mailman"),
        ("mailman restart", "mailman"),
        ("mailman --run-as-root start", "mailman"),
        ("mailman -C /workspace/mailman.cfg restart", "mailman"),
        (
            "mailman --config=/tmp/mailman.cfg --run-as-root stop",
            "mailman",
        ),
        ("service example start --help", "service"),
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            has_operation(&response, name, StateOperationKind::Control),
            "{command}: {:?}",
            response.reasons
        );
    }
    for command in [
        "postmulti -e init",
        "postmulti -I postfix-test -e create",
        "postmulti -i example -e disable",
        "mailman info",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response.decision_trace.execution_semantics.iter().any(|f| f
                .state_operations
                .iter()
                .any(|op| op.domain == StateOperationDomain::ServiceManager
                    && op.operation == StateOperationKind::Mutate)),
            "{command}"
        );
    }
}

#[test]
fn configured_queries_are_inspection_with_separate_unresolved_initialization() {
    for (command, name) in [("postmulti -l", "postmulti"), ("mailman status", "mailman")] {
        let response = ShellQueryCore::new().check(request(command));
        assert!(has_operation(&response, name, StateOperationKind::Inspect));
        assert!(!has_operation(&response, name, StateOperationKind::Control));
        assert!(has_operation(&response, name, StateOperationKind::Opaque));
        assert_eq!(response.decision, Decision::NeedApproval);
    }
    for command in [
        "postmulti -p -x start",
        "postmulti -e",
        "postmulti -x",
        "postmulti -p",
        "postmulti --unknown",
        "postmulti -i /workspace/instance -p start",
        "mailman -C",
        "mailman --unknown start",
        "mailman shell",
        "mailman start --unknown",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn explicit_child_denies_and_partial_control_denies_survive_manager_wrappers() {
    for command in [
        "postmulti -x rm -rf /",
        "postmulti -i example -x sh -c 'rm -rf /'",
        "postmulti -x sh -c 'rm -rf /' --help",
        "mailman --unknown start; rm -rf /",
        "mailman -C \"$(rm -rf /)\" start",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Deny,
            "{command}: {:?}",
            response.reasons
        );
    }
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .rules
        .insert(RuleId::StateControl, RulePolicyEntry::new(RuleAction::Deny));
    for command in [
        "postmulti -p start",
        "postmulti -p start --unknown",
        "mailman start",
        "mailman start --unknown",
        "service example start --help",
    ] {
        let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            response.decision,
            Decision::Deny,
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn manager_context_and_instance_names_are_not_caller_facts_or_deletion_grants() {
    let command =
        "queue_directory=/workspace postmulti -x sh -c 'printf x > \"$queue_directory/out\"'";
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(!response.decision_trace.path_targets.iter().any(|p|
        p.operation == PathTargetOperation::Write && matches!(&p.resolution,
            SemanticResolution::Resolved { value: PathResolution::Concrete { path } } if path == "/workspace/out")));
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Write
                && matches!(&p.resolution, SemanticResolution::Unresolved { .. }))
    );
    let mut policy = PolicyConfig::default();
    policy.rule_policy.families.insert(
        RuleFamily::StateSafety,
        FamilyPolicy {
            action: RuleAction::Observe,
            trust_sets: vec![],
        },
    );
    let response = ShellQueryCore::with_policy(policy)
        .check(request("postmulti -i /workspace/instance -e destroy"));
    assert_eq!(
        response.decision,
        Decision::NeedApproval,
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::FileDeletion)
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Delete
                && !matches!(&p.resolution, SemanticResolution::Resolved { .. }))
    );
}
