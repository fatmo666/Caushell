//! Command-agnostic coverage of retained effects and graph roles.
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractPathFactsPass,
    OutsideWorkspaceMutationGuardPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: semantic-tool}
forms:
  - id: run
    selector: {kind: has_flag, flag: '--run'}
modifiers:
  - id: run
    matcher: {kind: any_flag, flags: ['--run']}
  - id: output
    matcher: {kind: any_flag, flags: ['--output']}
    parameters:
      - {name: output, semantic: {kind: path, role: read, purpose: generic_operand}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
    effects: [{kind: write_path, target: {kind: slot, name: output}}]
"#;

fn run(profile: &str, command: &str, expected: Decision) -> Vec<ResolvedPathRole> {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(profile).unwrap()])
            .unwrap();
    let mut state = ShellStateSnapshot::new("/workspace");
    state.observability.variables = ShellStateKnowledge::Complete;
    let req = CheckRequest {
        session_id: SessionId::new("partial-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: None,
        workspace_root: Some("/workspace".into()),
    };
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_analysis_pass(OutsideWorkspaceMutationGuardPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(req);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    assert_eq!(
        ctx.final_decision,
        Some(expected),
        "{command}: {:?}",
        ctx.findings
    );
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    ctx.pending_mutations()
        .iter()
        .filter_map(|m| match m {
            PendingMutation::AddPathFact { node_id, role, .. } => {
                assert!(matches!(
                    staged.graph().get_node(node_id).unwrap().kind,
                    NodeKind::PathFact { .. }
                ));
                Some(*role)
            }
            _ => None,
        })
        .collect()
}

#[test]
fn failed_selection_does_not_drop_known_mutation_effects() {
    run(
        PROFILE,
        "semantic-tool --output /etc/a",
        Decision::NeedApproval,
    );
    run(PROFILE, "semantic-tool --output file", Decision::Allow);
}

#[test]
fn read_parameters_can_also_have_a_declared_write_role() {
    for command in [
        "semantic-tool --run --output file",
        "semantic-tool --output file",
    ] {
        let roles = run(PROFILE, command, Decision::Allow);
        assert!(roles.contains(&ResolvedPathRole::Read));
        assert!(roles.contains(&ResolvedPathRole::Write));
    }
}

#[test]
fn opaque_argument_expansion_survives_form_failure_without_language_guessing() {
    let p = PROFILE.replace(
        "forms:",
        "argument_files:\n  - {prefix: '@', possible_effects: [read_path, write_path]}\nforms:",
    );
    run(&p, "semantic-tool @args.txt", Decision::NeedApproval);
}
