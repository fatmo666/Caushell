use std::collections::BTreeSet;

use caushell_profile::{BoundInvocation, EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{DatabaseOperationKind, RuleId};

use crate::support::{decision_for_rule_action, graph_backed_execution_resolve_records};

/// Consumes declared database semantics, never tool names, keys or server state.
pub struct DatabaseOperationGuardPass;

impl SessionAnalysisPass for DatabaseOperationGuardPass {
    fn name(&self) -> &'static str {
        "database_operation_guard"
    }

    fn run(&self, _session: SessionView<'_>, _staged: SessionView<'_>, ctx: &mut RunnerContext) {
        // Reuse this request's already-resolved invocations. Unrelated commands
        // return before building the canonical-source set or allocating findings.
        if !ctx.execution_unit_resolve_records().iter().any(|record| {
            database_bound(&record.result).is_some_and(|(_, bound)| {
                bound.effects.iter().any(|effect| {
                    effect.kind == EffectKind::DatabaseOperation
                        && effect
                            .database_operation
                            .is_some_and(|operation| operation != DatabaseOperationKind::Read)
                })
            })
        }) {
            return;
        }

        let mut seen = BTreeSet::new();
        let mut proposals = Vec::new();
        for record in graph_backed_execution_resolve_records(ctx) {
            let Some((name, bound)) = database_bound(record.result()) else {
                continue;
            };
            for operation in bound
                .effects
                .iter()
                .filter(|effect| effect.kind == EffectKind::DatabaseOperation)
                .filter_map(|effect| effect.database_operation)
            {
                let Some(rule) = rule_for(operation) else {
                    continue;
                };
                if !seen.insert((record.source_node_id().clone(), operation)) {
                    continue;
                }
                proposals.push((rule, format!("database {operation:?} operation declared for {name} ({}) at {}; filesystem workspace membership does not establish database ownership", bound.form_id.as_str(), record.source_node_id().0)));
            }
        }

        for (rule, reason) in proposals {
            ctx.add_finding(rule, reason.clone());
            if let Some(decision) =
                decision_for_rule_action(ctx.policy().rule_policy.action_for(rule))
            {
                ctx.propose_decision(self.name(), rule, decision, reason);
            }
        }
    }
}

fn database_bound(result: &ResolveInvocationArtifactResult) -> Option<(&str, &BoundInvocation)> {
    match result {
        ResolveInvocationArtifactResult::Resolved(resolved) => {
            Some((&resolved.normalized_command_name, &resolved.bound))
        }
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            partial_bound: Some(bound),
            ..
        } => Some((normalized_command_name, bound)),
        _ => None,
    }
}

fn rule_for(operation: DatabaseOperationKind) -> Option<RuleId> {
    match operation {
        DatabaseOperationKind::Read => None,
        DatabaseOperationKind::Write => Some(RuleId::DatabaseStateMutation),
        DatabaseOperationKind::Administration => Some(RuleId::DatabaseAdministration),
        DatabaseOperationKind::Opaque => Some(RuleId::DatabaseOpaqueExecution),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DecisionAssemblyPass, ExtractExecutionSemanticsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::PassRunner;
    use caushell_types::*;

    fn run(operation: Option<&str>, failure: bool) -> RunnerContext {
        let effect = operation.map(|op| format!("effects: [{{kind: database_operation, database_operation: {op}, target: {{kind: none}}}}, {{kind: database_operation, database_operation: {op}, target: {{kind: none}}}}]")).unwrap_or_default();
        let declaration = if failure {
            "option_scope: leading_options\nselection_failure_effects: [{kind: database_operation, database_operation: opaque, target: {kind: none}}]"
        } else {
            ""
        };
        let profile = load_command_profile_from_str(&format!("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-state-client}}\n{declaration}\nforms:\n  - id: run\n    selector: {{kind: all, items: []}}\n    {effect}\n")).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_analysis_pass(DatabaseOperationGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        let request = CheckRequest {
            session_id: SessionId::new("generic-db-guard"),
            sequence_no: CommandSequenceNo::new(1),
            command: if failure {
                "arbitrary-state-client --unknown"
            } else {
                "arbitrary-state-client"
            }
            .into(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
            home: None,
            workspace_root: Some("/tmp/project".into()),
        };
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }
    #[test]
    fn unrelated_and_query_invocations_skip_without_findings() {
        for operation in [None, Some("read")] {
            let ctx = run(operation, false);
            assert_eq!(ctx.final_decision, Some(Decision::Allow));
            assert!(ctx.findings.is_empty());
            assert!(ctx.decision_proposals.is_empty());
        }
    }
    #[test]
    fn generic_declared_classes_enforce_and_duplicate_effects_do_not_duplicate_decisions() {
        for (operation, rule) in [
            ("write", RuleId::DatabaseStateMutation),
            ("administration", RuleId::DatabaseAdministration),
            ("opaque", RuleId::DatabaseOpaqueExecution),
        ] {
            let ctx = run(Some(operation), false);
            assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
            assert_eq!(ctx.decision_proposals.len(), 1);
            assert_eq!(ctx.decision_proposals[0].rule_id, rule);
        }
    }
    #[test]
    fn declared_partial_invocations_enforce_without_a_redis_name_branch() {
        let ctx = run(None, true);
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::DatabaseOpaqueExecution
        );
    }
}
