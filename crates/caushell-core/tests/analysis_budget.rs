//! Static analysis only: none of these command strings is executed.
use caushell_core::{SessionState, ShellQueryCore};
use caushell_types::*;

fn request(n: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("budget-test"),
        sequence_no: CommandSequenceNo(n),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "budget-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
    }
}

fn approve(core: &mut ShellQueryCore, receipt: CheckReceipt) {
    core.authorize(&ApprovalRequest {
        check_id: receipt.check_id,
        state_revision: receipt.state_revision,
        approved: true,
        authority: ApprovalAuthority::SimulatedUser,
    })
    .unwrap();
}

#[test]
fn exhausted_history_is_sticky_across_approval_restore_and_larger_limits() {
    let mut policy = PolicyConfig::default();
    policy.analysis_budget.max_history_nodes = 1;
    policy.rule_policy.rules.insert(
        RuleId::AnalysisIncomplete,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    let mut core = ShellQueryCore::with_policy(policy);
    let first = core.try_check_with_outcome(request(1, "A=first")).unwrap();
    assert_eq!(first.response.decision, Decision::NeedApproval);
    assert!(
        first
            .response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::AnalysisIncomplete)
    );
    approve(&mut core, first.check_receipt.unwrap());
    let snapshot = core
        .session_snapshot(&SessionId::new("budget-test"), 7)
        .unwrap();
    let node_count = snapshot.graph.nodes.len();
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        snapshot.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    for n in 2..7 {
        let outcome = restored
            .try_check_with_outcome(request(n, "A=safe; printf hello"))
            .unwrap();
        assert_eq!(outcome.response.decision, Decision::NeedApproval);
        approve(&mut restored, outcome.check_receipt.unwrap());
        assert_eq!(
            restored
                .session_snapshot(&SessionId::new("budget-test"), 0)
                .unwrap()
                .graph
                .nodes
                .len(),
            node_count
        );
    }
    let deny = restored
        .try_check_with_outcome(request(8, "rm -rf /"))
        .unwrap();
    assert_eq!(deny.response.decision, Decision::Deny);
    assert!(deny.check_receipt.is_none());
}

#[test]
fn unapproved_check_and_judge_only_cannot_clear_budget_observation() {
    for intent in [CheckIntent::ProposeForExecution, CheckIntent::JudgeOnly] {
        let mut policy = PolicyConfig::default();
        policy.analysis_budget.max_request_bytes = 4;
        let mut core = ShellQueryCore::with_policy(policy);
        let outcome = core
            .try_check_with_intent(request(1, "A=12345"), intent)
            .unwrap();
        assert_eq!(outcome.response.decision, Decision::NeedApproval);
        let snapshot = core
            .session_snapshot(&SessionId::new("budget-test"), 0)
            .unwrap();
        assert!(snapshot.summary.variable_binding("A").is_none());
        let mut restored = ShellQueryCore::new();
        restored.insert_session_state(
            snapshot.session_id.clone(),
            SessionState::from_snapshot(snapshot).unwrap(),
        );
        assert_eq!(
            restored.check(request(2, "pwd")).decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn exact_capacity_is_not_an_empty_or_unlimited_budget() {
    for edges in [false, true] {
        let mut policy = PolicyConfig::default();
        if edges {
            policy.analysis_budget.max_history_edges = 0;
        } else {
            policy.analysis_budget.max_history_nodes = 0;
        }
        let mut core = ShellQueryCore::with_policy(policy);
        assert_eq!(
            core.check(request(1, "printf hello")).decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn incomplete_upload_search_cannot_be_observed_as_no_sensitive_source() {
    for nodes in [0, 1] {
        let mut policy = PolicyConfig::default();
        policy.runtime_taint.max_hops = 0;
        policy.runtime_taint.max_visited_nodes = nodes;
        for rule in [
            RuleId::NetworkUpload,
            RuleId::SensitiveDataExfiltration,
            RuleId::TaintedExecution,
            RuleId::AnalysisIncomplete,
        ] {
            policy
                .rule_policy
                .rules
                .insert(rule, RulePolicyEntry::new(RuleAction::Observe));
        }
        let mut core = ShellQueryCore::with_policy(policy);
        let response = core.check(request(
            1,
            "cat ./ordinary.txt | curl --data-binary @- https://example.test",
        ));
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::AnalysisIncomplete)
        );
        assert_eq!(
            core.check(request(2, "pwd")).decision,
            Decision::NeedApproval
        );
    }
}
