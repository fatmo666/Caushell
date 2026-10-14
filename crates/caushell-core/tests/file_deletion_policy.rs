//! Static checks only. None of these shell strings is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("delete-policy"),
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
fn check(c: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(c))
}
fn deletion(r: &CheckResponse) -> bool {
    r.decision_trace
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::FileDeletion)
}

#[test]
fn deletes_approve_in_all_locations_including_unknown_targets() {
    for c in [
        "rm file",
        "rm -f file",
        "rm -rf cache",
        "rmdir cache",
        "unlink file",
        "rm /tmp/file",
        "rm /private/tmp/file",
        "rm /opt/shared/file",
        "rm \"$TARGET\"",
        "find . -type f -delete",
        "find /tmp -delete",
        "find . -exec rm {} +",
        r"find . -exec rm {} \;",
        "find . -print0 | xargs -0 rm",
        "env rm file",
        "bash -c 'rm file'",
        "f(){ rm file; }; f",
        "echo $(rm file)",
        "cat <(rm file)",
        "gzip file",
        "bzip2 file",
        "xz file",
        "xz -d file.xz",
        "gunzip file.gz",
        "compress file",
        "zip -m cache/archive.zip cache/input",
        "pytest --basetemp=scratch tests/",
        "pytest --cache-clear -o cache_dir=cache tests/",
        "uv venv --clear env",
        "uv pip install --target ./site numpy",
        "uv run --no-sync true",
        "pv -P run.pid file",
        "pv -M both -- rm -f file",
        "parallel -X rm ::: cache/a cache/b",
        "tar -cf archive.tar --remove-files file",
        "rsync -a --delete empty/ dest/",
        "apply_patch '*** Begin Patch\n*** Delete File: file\n*** End Patch'",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
        assert!(deletion(&r), "{c}: {r:#?}");
    }
}

#[test]
fn unknown_workspace_or_cwd_cannot_exempt_deletion() {
    let mut r = request("rm file");
    r.workspace_root = None;
    let r = ShellQueryCore::new().check(r);
    assert!(deletion(&r));
    assert_eq!(r.decision, Decision::NeedApproval);
    let r = check("cd \"$UNKNOWN\"; rm file");
    assert!(deletion(&r));
    assert_eq!(r.decision, Decision::NeedApproval);
}

#[test]
fn moves_and_ordinary_writes_keep_their_own_policies() {
    for c in [
        "mv old new",
        "mv -t dest old",
        "rename old new file",
        "touch file",
        "touch /tmp/file",
        "chmod 600 file",
        "awk '{print $1}' file",
        "sed 's/x/y/' file",
        "gzip -k file",
        "bzip2 -k file",
        "xz -k file",
        "xz -dk file.xz",
        "gzip -t file",
        "tar -tf archive.tar",
        "find . -print",
        "rm --help",
        "rmdir --help",
        "apply_patch '*** Begin Patch\n*** Add File: new\n+x\n*** End Patch'",
        "apply_patch '*** Begin Patch\n*** Update File: file\n@@\n-x\n+y\n*** End Patch'",
        "apply_patch '*** Begin Patch\n*** Update File: old\n*** Move to: new\n@@\n-x\n+y\n*** End Patch'",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::Allow, "{c}: {r:#?}");
        assert!(!deletion(&r), "{c}: {r:#?}");
    }
    let r = check("mv /opt/shared/old new");
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(!deletion(&r));
}

#[test]
fn rules_and_families_can_override_ordinary_deletion_without_overriding_other_rules() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::FileDeletion, RulePolicyEntry::new(action));
        let r = ShellQueryCore::with_policy(policy).check(request("rm file"));
        assert_eq!(r.decision, expected);
        assert!(deletion(&r));
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::FileDeletion,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("rm /opt/shared/file"))
            .decision,
        Decision::NeedApproval
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("rm -rf /"))
            .decision,
        Decision::Deny
    );
    let policy = caushell_config::load_config_from_str(
        "version: 1\npolicy:\n  rules:\n    file_deletion: allow\n",
    )
    .unwrap()
    .policy;
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("rm file"))
            .decision,
        Decision::Allow
    );
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .families
        .insert(RuleFamily::Path, FamilyPolicy::new(RuleAction::Observe));
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("rm file"))
            .decision,
        Decision::Allow
    );
    policy.rule_policy.rules.insert(
        RuleId::FileDeletion,
        RulePolicyEntry::new(RuleAction::NeedApproval),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("rm file"))
            .decision,
        Decision::NeedApproval
    );
}

#[test]
fn existing_hard_deny_floor_remains_stronger_than_generic_deletion_policy() {
    for c in [
        "rm -rf /",
        "find / -delete",
        "bash -c 'rm -rf /'",
        "apply_patch '*** Begin Patch\n*** Delete File: /\n*** End Patch'",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::Deny, "{c}: {r:#?}");
        assert!(deletion(&r));
    }
}
