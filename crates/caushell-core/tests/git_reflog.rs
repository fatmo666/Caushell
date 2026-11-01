//! End-to-end static guard checks; submitted Git and shell text is never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("git-reflog"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
#[test]
fn bounded_reflog_queries_use_existing_read_authority() {
    for source in [
        "git --no-pager reflog --date=iso | head -30",
        "git -P reflog show --date relative -30 HEAD",
        "git reflog list",
        "git reflog exists refs/heads/arbitrary",
    ] {
        let result = ShellQueryCore::new().check(request(source));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{source}: {:?}",
            result.reasons
        );
    }
}
#[test]
fn pager_and_unmodeled_native_options_still_ask() {
    for source in [
        "git reflog --date=iso | head -30",
        "git --no-pager --paginate reflog",
        "git --no-pager reflog --output=/outside/log",
        "git --no-pager reflog --ext-diff",
        "git --no-pager reflog HEAD --output=/outside/log",
        "git --no-pager reflog --date=\"$UNKNOWN\"",
        "git --no-pager reflog; rm /workspace/file",
    ] {
        let result = ShellQueryCore::new().check(request(source));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{source}: {:?}",
            result.reasons
        );
    }
}
#[test]
fn mutating_reflog_modes_keep_deletion_even_when_analysis_is_incomplete() {
    for source in [
        "git --no-pager reflog delete HEAD@{0}",
        "git --no-pager reflog drop refs/heads/arbitrary",
        "git --no-pager reflog expire --expire=now --all",
        "git --no-pager reflog delete --dry-run HEAD@{0}",
        "git --no-pager reflog delete --unknown HEAD@{0}",
    ] {
        let result = ShellQueryCore::new().check(request(source));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{source}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::FileDeletion)
        );
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::FileDeletion, RulePolicyEntry::new(RuleAction::Deny));
        assert_eq!(
            ShellQueryCore::with_policy(policy)
                .check(request(source))
                .decision,
            Decision::Deny
        );
    }
    assert_eq!(
        ShellQueryCore::new()
            .check(request(
                "git --no-pager reflog write refs/heads/topic deadbeef cafebabe message"
            ))
            .decision,
        Decision::NeedApproval
    );
}
#[test]
fn supported_queries_never_hide_sibling_or_substitution_deny() {
    for source in [
        "git --no-pager reflog --date=iso; rm -rf /",
        "git --no-pager reflog --date=\"$(rm -rf /)\"",
        "git --no-pager reflog delete HEAD@{0}; rm -rf /",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(source)).decision,
            Decision::Deny,
            "{source}"
        );
    }
}
