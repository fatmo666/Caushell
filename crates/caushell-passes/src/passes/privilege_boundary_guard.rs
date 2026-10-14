use caushell_profile::{BoundInvocation, EffectKind};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::RuleId;

use crate::support::{
    bound_invocation, decision_for_rule_action, graph_backed_execution_resolve_records,
};

/// Enforces the declared execution-identity/privilege boundary independently
/// of the child's filesystem targets or otherwise read-only behavior.
pub struct PrivilegeBoundaryGuardPass;

fn has_candidate(bound: &BoundInvocation) -> bool {
    bound
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::PrivilegeModifier)
}

impl SessionAnalysisPass for PrivilegeBoundaryGuardPass {
    fn name(&self) -> &'static str {
        "privilege_boundary_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        // No graph query, path resolution or identity lookup on the common
        // path. Use the same existing bound effects as the enforcement below.
        if !ctx
            .execution_unit_resolve_records()
            .iter()
            .any(|record| bound_invocation(&record.result).is_some_and(has_candidate))
        {
            return;
        }

        let reasons: Vec<_> = graph_backed_execution_resolve_records(ctx).into_iter().filter_map(|record| {
            let bound = bound_invocation(record.result()).filter(|bound| has_candidate(bound))?;
            Some(format!("{} ({}) declares an execution-identity or privilege change; crossing this boundary requires approval", bound.command_name.as_str(), bound.form_id.as_str()))
        }).collect();
        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::PrivilegeBoundary);
        for reason in reasons {
            ctx.add_finding(RuleId::PrivilegeBoundary, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::PrivilegeBoundary, decision, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DecisionAssemblyPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::PassRunner;
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RulePolicyEntry,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
        ShellStateSnapshot,
    };

    fn run(command: &str, action: RuleAction) -> RunnerContext {
        let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-identity-tool}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: query
    selector: {kind: has_modifier, modifier: inspect}
  - id: change_identity
    selector: {kind: not, item: {kind: has_modifier, modifier: inspect}}
    effects: [{kind: privilege_modifier, target: {kind: none}}]
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
modifiers: [{id: inspect, matcher: {kind: any_flag, flags: [--inspect]}}]
"#).unwrap();
        let request = CheckRequest {
            session_id: SessionId::new("privilege-test"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static-test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        };
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::PrivilegeBoundary, RulePolicyEntry::new(action));
        let mut ctx = RunnerContext::with_policy(request, policy);
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        runner.register_session_analysis_pass(PrivilegeBoundaryGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn consumes_declarations_without_command_names_or_extra_action_metadata() {
        for (action, expected) in [
            (RuleAction::Observe, Decision::Allow),
            (RuleAction::NeedApproval, Decision::NeedApproval),
            (RuleAction::Deny, Decision::Deny),
        ] {
            let ctx = run("arbitrary-identity-tool", action);
            assert_eq!(ctx.final_decision, Some(expected));
            assert_eq!(
                ctx.findings
                    .iter()
                    .filter(|f| f.rule_id == RuleId::PrivilegeBoundary)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn skips_queries_and_unknown_tool_without_privilege_effects() {
        for command in ["arbitrary-identity-tool --inspect", "unknown-tool"] {
            let ctx = run(command, RuleAction::NeedApproval);
            assert_eq!(ctx.final_decision, Some(Decision::Allow));
            assert!(ctx.findings.is_empty(), "{command}");
        }
    }

    #[test]
    fn retains_declared_effects_on_partial_bound_invocations() {
        let ctx = run(
            "arbitrary-identity-tool \"$UNKNOWN\"",
            RuleAction::NeedApproval,
        );
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(
            ctx.findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivilegeBoundary)
        );
    }

    #[test]
    fn unprojected_records_cannot_trigger_enforcement() {
        let resolved = run("arbitrary-identity-tool", RuleAction::NeedApproval);
        let mut ctx = RunnerContext::new(resolved.request().clone());
        ctx.set_execution_unit_resolve_records(resolved.execution_unit_resolve_records().to_vec());
        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        PrivilegeBoundaryGuardPass.run(
            SessionView::new(&graph, &summary),
            SessionView::new(&graph, &summary),
            &mut ctx,
        );
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }
}
