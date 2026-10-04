//! Generic Profile opt-in exercised through the existing pipeline, not Yum branches.
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, OutsideWorkspaceMutationGuardPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass, ResolvePolicyPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn run(
    command: &str,
    opt_in: bool,
    action: Option<RuleAction>,
) -> (RunnerContext, Vec<ExecutionSemantics>) {
    let profile = load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: opaque-fixture}}
opaque_on_unresolved: {opt_in}
forms:
  - id: write
    selector: {{kind: has_positional_at_matching, index: 0, matcher: {{kind: literal, value: write}}}}
    parameters:
      - {{name: operation, semantic: {{kind: plain_value}}, binding: {{kind: positional_at, index: 0}}, cardinality: required_one}}
      - {{name: output, semantic: {{kind: path, role: write}}, binding: {{kind: next_positional}}, cardinality: required_one}}
    effects: [{{kind: write_path, target: {{kind: slot, name: output}}}}]
"#)).unwrap();
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::from_profiles(vec![profile]).unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_request_analysis_pass(ResolvePolicyPass);
    runner.register_session_analysis_pass(OutsideWorkspaceMutationGuardPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let request = CheckRequest {
        session_id: SessionId::new("opaque-fixture"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    let mut policy = PolicyConfig::default();
    if let Some(action) = action {
        policy
            .rule_policy
            .resolve_gap
            .defaults
            .insert(ResolveGapKind::OpaqueInvocation, action);
    }
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::with_policy(request, policy);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let stage = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let semantics = stage
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect();
    // The generic fact must survive graph snapshot/restore, not just decisions.
    let mut staged_graph = SessionGraph::new();
    for node in stage.graph().nodes() {
        staged_graph.add_node(node.clone());
    }
    for edge in stage.graph().edges() {
        staged_graph.add_edge(edge.clone()).unwrap();
    }
    let restored = SessionGraph::from_snapshot(staged_graph.to_snapshot()).unwrap();
    let restored_semantics: Vec<_> = restored
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(semantics, restored_semantics);
    (ctx, semantics)
}

#[test]
fn profile_opt_in_marks_selection_failure_and_binding_residuals() {
    for c in [
        "opaque-fixture unknown",
        "opaque-fixture write output --future",
        "opaque-fixture write",
    ] {
        let (ctx, semantics) = run(c, true, None);
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval), "{c}");
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError)
        );
        assert_eq!(semantics.len(), 1, "{c}");
        assert!(semantics[0].operation_semantics_unresolved, "{c}");
    }
}

#[test]
fn known_form_and_unopted_profiles_keep_the_old_admission_behavior() {
    for (c, opt_in) in [
        ("opaque-fixture write output", true),
        ("opaque-fixture unknown", false),
        ("opaque-fixture write output --future", false),
    ] {
        let (ctx, semantics) = run(c, opt_in, None);
        assert_eq!(ctx.final_decision, Some(Decision::Allow), "{c}");
        assert!(semantics.iter().all(|s| !s.operation_semantics_unresolved));
    }
}

#[test]
fn opaque_invocation_action_remains_configurable_and_graph_fact_remains_true() {
    for c in [
        "opaque-fixture unknown",
        "opaque-fixture write output --future",
    ] {
        for (action, expected) in [
            (RuleAction::Observe, Decision::Allow),
            (RuleAction::Deny, Decision::Deny),
        ] {
            let (ctx, semantics) = run(c, true, Some(action));
            assert_eq!(ctx.final_decision, Some(expected), "{c}");
            assert!(semantics[0].operation_semantics_unresolved);
        }
    }
}

#[test]
fn observing_uncertainty_does_not_remove_known_external_write_effects() {
    let (ctx, semantics) = run(
        "opaque-fixture write /etc/output --future",
        true,
        Some(RuleAction::Observe),
    );
    assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    assert!(
        ctx.decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    assert!(semantics[0].operation_semantics_unresolved);
}
