//! No shell commands are executed by these state/authorization tests.
use caushell_core::{SessionState, ShellQueryCore};
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("approval-test"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "state-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
    }
}

fn approval(receipt: &CheckReceipt, approved: bool) -> ApprovalRequest {
    ApprovalRequest {
        check_id: receipt.check_id.clone(),
        state_revision: receipt.state_revision,
        approved,
        authority: ApprovalAuthority::SimulatedUser,
    }
}

fn target(core: &ShellQueryCore) -> Option<SessionVariableValue> {
    core.session_snapshot(&SessionId::new("approval-test"), 0)
        .and_then(|s| {
            s.summary
                .variable_binding("TARGET")
                .map(|b| b.value.clone())
        })
}

#[test]
fn ask_is_not_applied_until_explicit_approval_and_is_applied_once() {
    let mut core = ShellQueryCore::new();
    let outcome = core
        .try_check_with_outcome(request(
            1,
            "export TARGET=/bench/outside/a; touch \"$TARGET\"",
        ))
        .unwrap();
    assert_eq!(outcome.response.decision, Decision::NeedApproval);
    assert!(target(&core).is_none());
    let receipt = outcome.check_receipt.unwrap();
    let message = approval(&receipt, true);
    let (first, changed) = core.authorize(&message).unwrap();
    assert!(changed && first.approved);
    assert_eq!(
        target(&core),
        Some(SessionVariableValue::exact_scalar("/bench/outside/a"))
    );
    let (repeated, changed) = core.authorize(&message).unwrap();
    assert!(!changed);
    assert_eq!(first, repeated);
    assert!(core.authorize(&approval(&receipt, false)).is_err());
    assert_eq!(outcome.response.decision, Decision::NeedApproval);
}

#[test]
fn rejected_stale_foreign_and_policy_changed_approvals_do_not_apply() {
    for case in ["rejected", "stale", "foreign", "policy"] {
        let mut core = ShellQueryCore::new();
        let outcome = core
            .try_check_with_outcome(request(1, "TARGET=/bench/outside/a; touch \"$TARGET\""))
            .unwrap();
        let mut message = approval(&outcome.check_receipt.unwrap(), case != "rejected");
        match case {
            "stale" => {
                core.check(request(2, "pwd"));
            }
            "foreign" => {
                message.check_id.session_id = SessionId::new("other");
            }
            "policy" => {
                let mut p = PolicyConfig::default();
                p.runtime_taint.max_hops += 1;
                core.replace_policy(p);
            }
            _ => {}
        }
        let result = core.authorize(&message);
        if case == "rejected" {
            assert!(!result.unwrap().0.approved);
        } else {
            assert!(result.is_err());
        }
        assert!(target(&core).is_none(), "{case}");
    }
}

#[test]
fn pending_and_resolved_authorization_survive_snapshot_restore() {
    let mut core = ShellQueryCore::new();
    let receipt = core
        .try_check_with_outcome(request(1, "TARGET=/bench/outside/a; touch \"$TARGET\""))
        .unwrap()
        .check_receipt
        .unwrap();
    for resolved in [false, true] {
        let mut restored = ShellQueryCore::new();
        if resolved {
            core.authorize(&approval(&receipt, true)).unwrap();
        }
        let snapshot = core
            .session_snapshot(&SessionId::new("approval-test"), 4)
            .unwrap();
        restored.insert_session_state(
            snapshot.session_id.clone(),
            SessionState::from_snapshot(snapshot).unwrap(),
        );
        let (_, changed) = restored.authorize(&approval(&receipt, true)).unwrap();
        assert_eq!(changed, !resolved);
        assert!(target(&restored).is_some());
    }
}

#[test]
fn judge_only_and_deny_do_not_offer_authorizable_effects() {
    let mut core = ShellQueryCore::new();
    for (sequence, command) in [
        (1, "TARGET=/bench/workspace/a"),
        (2, "TARGET=/bench/outside/a; touch \"$TARGET\""),
    ] {
        let outcome = core
            .try_check_with_intent(request(sequence, command), CheckIntent::JudgeOnly)
            .unwrap();
        assert!(outcome.check_receipt.is_none());
        assert!(target(&core).is_none());
    }
    let outcome = core.try_check_with_outcome(request(3, "rm -rf /")).unwrap();
    assert_eq!(outcome.response.decision, Decision::Deny);
    assert!(outcome.check_receipt.is_none());
}
