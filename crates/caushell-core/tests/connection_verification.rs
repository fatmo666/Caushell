//! Static request checks; no curl/wget commands or network traffic are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("connection-verification"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str, expected: Decision, verification: bool) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    assert_eq!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.state_operations.iter().any(|op| op.domain
                == StateOperationDomain::ConnectionVerification
                && op.operation == StateOperationKind::Control)),
        verification,
        "{command}: {r:#?}"
    );
    assert_eq!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::StateControl),
        verification,
        "{command}: {r:#?}"
    );
    r
}

#[test]
fn disabled_verification_is_a_typed_state_control_not_a_file_write() {
    for command in [
        "curl -k https://ipinfo.io/",
        "curl --insecure https://example.test/",
        "curl -skL https://example.test/",
        "curl --no-insecure -sk https://example.test/",
        "curl --insecure --url https://example.test/ -o ./response",
        "curl --proxy-insecure https://example.test/",
        "curl --doh-insecure https://example.test/",
        "curl --proxy-insecure --no-insecure https://example.test/",
        "curl -k --no-proxy-insecure https://example.test/",
        "wget --no-hsts --no-check-certificate https://example.test/file",
        "wget --no-hsts --check-certificate=off https://example.test/file",
        "wget --no-hsts --check-certificate=NO https://example.test/file",
        "wget --no-hsts --check-certificate=0 https://example.test/file",
        "wget --no-hsts --check-certificate=quiet https://example.test/file",
        "wget --no-hsts '--check-certificate=off' https://example.test/file",
        "wget --no-hsts --check-certificate=\"off\" https://example.test/file",
        "wget --no-hsts --check-certificate --no-check-certificate https://example.test/file",
        "wget --no-hsts --spider --no-check-certificate https://example.test/",
    ] {
        let r = check(command, Decision::NeedApproval, true);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn restoration_is_ordered_and_independent_for_direct_proxy_and_doh_connections() {
    for command in [
        "curl https://example.test/",
        "curl -sk --no-insecure https://example.test/",
        "curl --insecure --no-insecure https://example.test/",
        "curl --proxy-insecure --no-proxy-insecure https://example.test/",
        "curl --doh-insecure --no-doh-insecure https://example.test/",
        "curl -k --proxy-insecure --no-insecure --no-proxy-insecure https://example.test/",
        "wget --no-hsts https://example.test/file",
        "wget --no-hsts --no-check-certificate --check-certificate https://example.test/file",
        "wget --no-hsts --check-certificate=off --check-certificate=on https://example.test/file",
        "wget --no-hsts --check-certificate=off --check-certificate=YES https://example.test/file",
        "wget --no-hsts --check-certificate=0 --check-certificate=1 https://example.test/file",
        "wget --no-hsts --check-certificate=off '--check-certificate=on' https://example.test/file",
    ] {
        check(command, Decision::Allow, false);
    }
}

#[test]
fn help_and_option_shaped_operands_do_not_disable_verification() {
    for command in [
        "curl --help -k",
        "curl -k --version",
        "curl -k --manual",
        "curl --engine list -k",
        "curl --engine list --proxy-insecure",
        "wget --help --no-check-certificate",
        "wget --no-check-certificate --version",
        "curl -o --insecure https://example.test/",
        "curl -A --insecure https://example.test/",
        "curl -- https://example.test/--insecure",
        "wget --no-hsts -O --no-check-certificate https://example.test/",
    ] {
        check(command, Decision::Allow, false);
    }
    for command in [
        "curl -k -A --no-insecure https://example.test/",
        "curl -k -- https://example.test/--no-insecure",
        "wget --no-hsts --no-check-certificate -O --check-certificate https://example.test/",
    ] {
        check(command, Decision::NeedApproval, true);
    }
}

#[test]
fn wrappers_nested_payloads_and_resolved_variables_retain_verification_effects() {
    for command in [
        "env curl -k https://example.test/",
        "bash -c 'curl -k https://example.test/'",
        "timeout 2 curl -k https://example.test/",
        "f() { curl -k https://example.test/; }; f",
        "flag=--insecure; curl \"$flag\" https://example.test/",
        "echo \"$(curl -k https://example.test/)\"",
    ] {
        check(command, Decision::NeedApproval, true);
    }
    check(
        "flag=--no-insecure; curl -k \"$flag\" https://example.test/",
        Decision::Allow,
        false,
    );
    for command in [
        "wget --no-hsts --check-certificate=\"$SETTING\" https://example.test/",
        "curl --insecure --next --no-insecure https://example.test/",
    ] {
        assert_ne!(
            ShellQueryCore::new().check(request(command, 1)).decision,
            Decision::Allow,
            "{command}"
        );
    }
}

#[test]
fn existing_state_policy_overrides_work_and_old_actions_do_not_contaminate_new_ones() {
    for (action, decision) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::StateControl, RulePolicyEntry::new(action));
        let mut core = ShellQueryCore::with_policy(policy);
        let r = core.check(request("curl -k https://example.test/", 1));
        assert_eq!(r.decision, decision, "{r:#?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::StateControl)
        );
        let r = core.check(request("curl https://example.test/", 2));
        assert_eq!(r.decision, Decision::Allow, "{r:#?}");
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::StateControl)
        );
    }
}

#[test]
fn restoring_verification_does_not_waive_other_risks() {
    for (command, rule) in [
        (
            "curl -k --no-insecure https://example.test/ -o /opt/file",
            RuleId::OutsideWorkspaceMutation,
        ),
        (
            "curl -k --no-insecure -d DATA https://example.test/",
            RuleId::NetworkUpload,
        ),
        (
            "wget --no-hsts --no-check-certificate --check-certificate -O /opt/file https://example.test/file",
            RuleId::OutsideWorkspaceMutation,
        ),
    ] {
        let r = check(command, Decision::NeedApproval, false);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == rule),
            "{command}: {r:#?}"
        );
    }
}
