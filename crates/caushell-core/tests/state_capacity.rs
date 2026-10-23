use caushell_core::{SessionState, ShellQueryCore};
use caushell_graph::{GraphNode, GraphRead, NodeId, NodeKind, SessionGraph};
use caushell_query::StateCandidateQuery;
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("capacity"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "capacity-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
    }
}

fn variable(name: &str, value: &str, sequence: u64) -> StateCandidateFact {
    StateCandidateFact {
        object: SafetyObject {
            scope: SafetyScope::Shell,
            kind: SafetyStateKind::Variable,
            name: name.into(),
        },
        value: SafetyStateValue::Variable {
            value: SessionVariableValue::exact_scalar(value),
            exported: false,
        },
        sequence_no: CommandSequenceNo(sequence),
        source_end: 1,
    }
}

fn seed(names: impl IntoIterator<Item = String>) -> SessionState {
    let mut state = SessionState::new();
    for name in names {
        state.graph_mut().add_node(GraphNode::new(
            NodeId::new(format!("seed:{name}")),
            NodeKind::StateCandidate {
                fact: variable(&name, "safe", 1),
            },
        ));
        state
            .summary_mut()
            .set_exact_scalar_variable(&name, "safe", false, CommandSequenceNo(1));
    }
    state
}

#[test]
fn task_and_16384_background_objects_share_the_declared_capacity() {
    let state =
        seed(std::iter::once("TASK".into()).chain((0..16_384).map(|i| format!("cache{i:05}"))));
    let mut core = ShellQueryCore::new();
    core.insert_session_state(SessionId::new("capacity"), state);
    let response = core.check(request(2, "NEXT=safe; printf '%s' \"$TASK\""));
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    let usage = response.decision_trace.analysis_usage.unwrap();
    assert_eq!(usage.state_objects, 16_386);
    assert_eq!(usage.state_candidate_facts, 16_386);
    assert!(usage.incomplete_budgets.is_empty());
    assert_eq!(usage.limits.max_state_objects, 32_768);
    let snapshot = core
        .session_snapshot(&SessionId::new("capacity"), 0)
        .unwrap();
    let graph = SessionGraph::from_snapshot(snapshot.graph).unwrap();
    assert_eq!(graph.state_candidate_count(), usage.state_candidate_facts);
    assert_eq!(graph.state_object_count(), usage.state_objects);
    assert_eq!(graph.state_history_bytes(), usage.state_history_bytes);
}

#[test]
fn exact_object_limit_is_sticky_and_usage_does_not_claim_a_complete_history() {
    let mut policy = PolicyConfig::default();
    policy.analysis_budget.max_state_objects = 3;
    let mut core = ShellQueryCore::with_policy(policy);
    core.insert_session_state(SessionId::new("capacity"), seed(["A".into(), "B".into()]));
    let outcome = core.check_with_outcome(request(2, "C=safe"));
    assert_eq!(outcome.response.decision, Decision::NeedApproval);
    let usage = outcome.response.decision_trace.analysis_usage.unwrap();
    assert_eq!(usage.state_objects, 3);
    assert!(
        usage
            .incomplete_budgets
            .contains(&AnalysisBudgetKind::StateObjects)
    );
    let receipt = outcome.check_receipt.unwrap();
    core.authorize(&ApprovalRequest {
        check_id: receipt.check_id,
        state_revision: receipt.state_revision,
        approved: true,
        authority: ApprovalAuthority::SimulatedUser,
    })
    .unwrap();
    let snapshot = core
        .session_snapshot(&SessionId::new("capacity"), 0)
        .unwrap();
    assert!(snapshot.summary.variable_binding("C").is_none());
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        snapshot.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    let response = restored.check(request(3, "printf safe"));
    assert_eq!(response.decision, Decision::NeedApproval);
    let usage = response.decision_trace.analysis_usage.unwrap();
    assert_eq!(usage.state_objects, 2);
    assert!(
        usage
            .incomplete_budgets
            .contains(&AnalysisBudgetKind::StateObjects)
    );
}

#[test]
fn entry_dedup_retains_actual_writes_risky_candidates_and_order_after_restore() {
    let mut core = ShellQueryCore::new();
    for (i, command) in [
        "DEST=/outside/first",
        "DEST=/bench/workspace/safe",
        "DEST=/bench/workspace/safe",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            core.check(request(i as u64 + 1, command)).decision,
            Decision::Allow
        );
    }
    let snapshot = core
        .session_snapshot(&SessionId::new("capacity"), 0)
        .unwrap();
    let graph = SessionGraph::from_snapshot(snapshot.graph).unwrap();
    let object = variable("DEST", "", 1).object;
    let facts: Vec<_> = graph
        .state_candidate_nodes(&object)
        .map(|node| match &node.kind {
            NodeKind::StateCandidate { fact } => fact,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(facts.len(), 3);
    assert!(facts.iter().all(|fact| fact.source_end > 0));
    assert_eq!(
        facts
            .iter()
            .map(|fact| fact.sequence_no.0)
            .collect::<std::collections::BTreeSet<_>>(),
        [1, 2, 3].into_iter().collect()
    );
    let values = StateCandidateQuery {
        object: &object,
        before_sequence: CommandSequenceNo(4),
        before_source_start: 0,
        limits: &AnalysisBudgetPolicy::default(),
    }
    .execute(&graph);
    assert!(values.is_complete());
    assert_eq!(values.candidates.len(), 2);
    assert!(
        values
            .candidates
            .iter()
            .any(|c| c.value == variable("DEST", "/outside/first", 1).value)
    );
    assert_eq!(
        core.check(request(4, "touch \"$DEST\"")).decision,
        Decision::Allow
    );
    assert_eq!(
        core.check(request(5, "touch /outside/first")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn judge_only_usage_projects_new_state_without_committing_it() {
    let mut core = ShellQueryCore::new();
    core.insert_session_state(SessionId::new("capacity"), seed(["A".into()]));
    let response = core
        .try_check_with_intent(request(2, "B=safe"), CheckIntent::JudgeOnly)
        .unwrap()
        .response;
    assert_eq!(
        response
            .decision_trace
            .analysis_usage
            .unwrap()
            .state_objects,
        2
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("capacity"), 0)
        .unwrap();
    assert!(snapshot.summary.variable_binding("B").is_none());
    assert_eq!(
        SessionGraph::from_snapshot(snapshot.graph)
            .unwrap()
            .state_object_count(),
        1
    );
}
