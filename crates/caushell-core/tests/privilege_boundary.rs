//! Static command proposals only: none of these shell strings is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("privilege-boundary"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn finding(r: &CheckResponse) -> bool {
    r.decision_trace
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::PrivilegeBoundary)
}

#[test]
fn identity_changes_approve_independently_of_child_risk_or_target_location() {
    for c in [
        "sudo id",
        "sudo cat /etc/shadow",
        "sudo chmod 600 ./file",
        "sudo chmod 600 /tmp/file",
        "sudo -u nobody id",
        "sudo -u \"$TARGET_USER\" id",
        "sudo \"$COMMAND\"",
        "doas id",
        "doas -u nobody id",
        "doas -s",
        "su -c 'id' root",
        "su nobody",
        "runuser -u nobody -- id",
        "runcon unconfined_u:unconfined_r:unconfined_t:s0 id",
        "sg wheel -c 'id'",
        "pkexec --keep-cwd id",
        "ksu -q -e id",
    ] {
        let r = ShellQueryCore::new().check(request(c));
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
        assert!(finding(&r), "{c}: {r:#?}");
    }
}

#[test]
fn nested_and_conditional_invocations_keep_the_same_privilege_boundary() {
    for c in [
        "env sudo id",
        "sh -c 'sudo id'",
        "f(){ sudo id; }; f",
        r"find . -exec sudo id \;",
        "printf 'item\\0' | xargs -0 sudo id",
        "true && sudo id",
        "sudo -l; sudo id",
    ] {
        let r = ShellQueryCore::new().check(request(c));
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
        assert!(finding(&r), "{c}: {r:#?}");
    }
}

#[test]
fn queries_data_and_known_suppressed_children_do_not_trigger_privilege_approval() {
    for c in [
        "sudo -l",
        "sudo --list",
        "sudo -l id",
        "id",
        "cat ./file",
        "chmod 600 ./file",
        "printf '%s' sudo",
        "echo 'sudo chmod 600 ./file'",
        "printf '' | xargs -r sudo id",
    ] {
        let r = ShellQueryCore::new().check(request(c));
        assert_eq!(r.decision, Decision::Allow, "{c}: {r:#?}");
        assert!(!finding(&r), "{c}: {r:#?}");
    }
}

#[test]
fn policy_actions_preserve_findings_and_do_not_override_other_rules() {
    for (value, decision) in [
        ("allow", Decision::Allow),
        ("need_approval", Decision::NeedApproval),
        ("deny", Decision::Deny),
    ] {
        let policy = caushell_config::load_config_from_str(&format!(
            "version: 1\npolicy:\n  rules:\n    privilege_boundary: {value}\n"
        ))
        .unwrap()
        .policy;
        let r = ShellQueryCore::with_policy(policy).check(request("sudo id"));
        assert_eq!(r.decision, decision);
        assert!(finding(&r));
    }
    let policy =
        caushell_config::load_config_from_str("policy:\n  rules:\n    privilege_boundary: allow\n")
            .unwrap()
            .policy;
    let r = ShellQueryCore::with_policy(policy.clone()).check(request("sudo rm ./file"));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::FileDeletion)
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("sudo rm -rf /"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn host_family_override_and_rule_precedence_use_existing_configuration() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.families.insert(
        RuleFamily::HostSafety,
        FamilyPolicy::new(RuleAction::Observe),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("sudo id"))
            .decision,
        Decision::Allow
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("sudo rm -rf /"))
            .decision,
        Decision::Deny
    );
    policy.rule_policy.rules.insert(
        RuleId::PrivilegeBoundary,
        RulePolicyEntry::new(RuleAction::NeedApproval),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("sudo id"))
            .decision,
        Decision::NeedApproval
    );
}

#[test]
fn prior_privilege_effects_do_not_contaminate_later_requests() {
    let mut core = ShellQueryCore::with_policy(
        caushell_config::load_config_from_str("policy:\n  rules:\n    privilege_boundary: allow\n")
            .unwrap()
            .policy,
    );
    assert!(finding(&core.check(request("sudo id"))));
    let mut next = request("echo ordinary");
    next.sequence_no = CommandSequenceNo::new(2);
    let r = core.check(next);
    assert_eq!(r.decision, Decision::Allow);
    assert!(!finding(&r));
}
