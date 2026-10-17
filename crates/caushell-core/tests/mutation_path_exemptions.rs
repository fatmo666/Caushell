//! Static guard requests only; none of these shell actions are executed.
use caushell_config::load_config_from_str;
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RuleId, RulePolicyEntry,
    RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("mutation-exemptions"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn expect(command: &str, decision: Decision) {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
}

#[test]
fn ordinary_writes_and_metadata_use_default_temporary_roots() {
    for command in [
        "mkdir -p /tmp/package",
        "touch /tmp/output",
        "cp input /tmp/output",
        "cp --parents src/prog.js images/icon.jpg /tmp/package",
        "printf data > /tmp/output",
        "printf data | tee /private/tmp/output",
        "> /private/tmp/output",
        "cat <> /tmp/output",
        "chmod 600 /tmp/output",
        "chmod u+rw,g-w /tmp/output",
        "chmod u-s /tmp/output",
        "chown alice:staff /tmp/output",
        "chgrp staff /private/tmp/output",
        "chmod -R 600 /tmp/output",
        "chown -R alice:staff /tmp/output",
        "chgrp -R staff /private/tmp/output",
        "mktemp /tmp/cache.XXXXXX",
        "curl -o /tmp/download https://example.test/file",
        "csplit -f /tmp/part input '/x/'",
        "cd /tmp; touch output",
        "find /tmp -type f -exec chmod 600 {} +",
        "TMPDIR=/tmp/cache mktemp -d",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn deletion_move_source_and_generic_attributes_are_not_exempt() {
    for command in [
        "rm /tmp/output",
        "rmdir /private/tmp/output",
        "mv /tmp/output ./output",
        "find /tmp -type f -delete",
        "chattr +i /tmp/output",
        "chattr -i /tmp/output",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect("rm -rf /", Decision::Deny);
}

#[test]
fn unknown_targets_and_path_boundaries_do_not_acquire_exemption() {
    for command in [
        "touch /tmp-other/output",
        "touch /private/tmp-other/output",
        "touch /tmp/../etc/output",
        "touch /private/tmp/../../etc/output",
        "touch /tmp/output /opt/output",
        "touch \"$TMPDIR/output\"",
        "mktemp -d",
        "cd \"$UNKNOWN\"; touch output",
        "chmod \"$MODE\" /tmp/output",
        "TMPDIR=/opt/cache mktemp -d",
        "TMPDIR=\"$UNKNOWN\" mktemp -d",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn special_and_reference_permission_modes_use_default_temporary_roots() {
    for command in [
        "chmod 4755 /tmp/output",
        "chmod 6755 /tmp/output",
        "chmod 2775 /private/tmp/output",
        "chmod u+s /private/tmp/output",
        "chmod g+s /tmp/output",
        "chmod --reference=input /tmp/output",
        "chmod --reference=input ./output",
        "find /tmp -type d -exec chmod 2775 {} +",
        "find /tmp -type f -print0 | xargs -0 chmod u+s",
        "bash -c 'chmod 4755 /private/tmp/output'",
        "cp -p input /tmp/output",
        "cp --preserve=mode input /private/tmp/output",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        "chmod 4755 /tmp-other/output",
        "chmod u+s /tmp/../etc/output",
        "chmod 2775 /opt/output",
        "chmod --reference=input /opt/output",
        "chmod 4755 /tmp/output /opt/output",
        "chmod u+s \"$UNKNOWN\"",
        "chattr +i /private/tmp/output",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn permission_metadata_is_explicit_and_ordinary_metadata_keeps_its_old_scope() {
    for (operation, special) in [
        ("ordinary_metadata", Decision::NeedApproval),
        ("permission_metadata", Decision::Allow),
    ] {
        let policy = load_config_from_str(&format!(
            "version: 1\nmutation_path_exemptions:\n  - root: /opt/scratch\n    operations: [{operation}]\n"
        )).unwrap().policy;
        for (command, expected) in [
            ("chmod 600 /opt/scratch/output", Decision::Allow),
            ("chown alice:staff /opt/scratch/output", Decision::Allow),
            ("chmod 4755 /opt/scratch/output", special),
            ("chmod --reference=input /opt/scratch/output", special),
            ("touch /opt/scratch/output", Decision::NeedApproval),
            ("chattr +i /opt/scratch/output", Decision::NeedApproval),
            ("rm /opt/scratch/output", Decision::NeedApproval),
            ("chmod 4755 /tmp/output", Decision::NeedApproval),
        ] {
            let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
            assert_eq!(
                response.decision, expected,
                "{operation}: {command}: {response:#?}"
            );
        }
    }
}

#[test]
fn config_can_disable_replace_and_limit_operations() {
    let disabled = load_config_from_str("version: 1\nmutation_path_exemptions: []\n")
        .unwrap()
        .policy;
    assert_eq!(
        ShellQueryCore::with_policy(disabled)
            .check(request("touch /tmp/output"))
            .decision,
        Decision::NeedApproval
    );
    let write_only = load_config_from_str(
        "version: 1\nmutation_path_exemptions:\n  - root: /opt/scratch\n    operations: [write]\n",
    )
    .unwrap()
    .policy;
    for (command, decision) in [
        ("touch /opt/scratch/output", Decision::Allow),
        ("chmod 600 /opt/scratch/output", Decision::NeedApproval),
        ("touch /tmp/output", Decision::NeedApproval),
        ("rm /opt/scratch/output", Decision::NeedApproval),
    ] {
        assert_eq!(
            ShellQueryCore::with_policy(write_only.clone())
                .check(request(command))
                .decision,
            decision,
            "{command}"
        );
    }
    let metadata_only = load_config_from_str("version: 1\nmutation_path_exemptions:\n  - root: /opt/scratch\n    operations: [ordinary_metadata]\n").unwrap().policy;
    assert_eq!(
        ShellQueryCore::with_policy(metadata_only.clone())
            .check(request("chmod 600 /opt/scratch/output"))
            .decision,
        Decision::Allow
    );
    assert_eq!(
        ShellQueryCore::with_policy(metadata_only)
            .check(request("touch /opt/scratch/output"))
            .decision,
        Decision::NeedApproval
    );
}

#[test]
fn other_risk_rules_still_apply_to_temporary_paths() {
    let mut policy = PolicyConfig::default();
    for rule in [
        RuleId::OutsideWorkspaceScriptSource,
        RuleId::OutsideWorkspaceStartupConfig,
    ] {
        policy
            .rule_policy
            .rules
            .insert(rule, RulePolicyEntry::new(RuleAction::NeedApproval));
    }
    for command in [
        "bash /tmp/script.sh; rm /tmp/data",
        "BASH_ENV=/tmp/startup bash -c 'true'",
        "kill -TERM 1234; touch /tmp/output",
    ] {
        let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id != RuleId::OutsideWorkspaceMutation)
        );
    }
}

#[test]
fn temporary_exemption_is_not_a_workspace_or_global_trust_override() {
    let mut r = request("pwd");
    r.shell_state_before = ShellStateSnapshot::new("/tmp");
    let response = ShellQueryCore::new().check(r);
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CwdOutsideWorkspaceRoot)
    );
    let policy = PolicyConfig::default();
    assert!(policy.path_trust_sets.is_empty());
}
