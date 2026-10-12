use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{RuleId, StateOperationKind};

use crate::support::decision_for_rule_action;

/// Enforces declared external state classes, never names, live state or guessed
/// filesystem targets. The common path skips before querying the Graph.
pub struct StateOperationGuardPass;

impl SessionAnalysisPass for StateOperationGuardPass {
    fn name(&self) -> &'static str {
        "state_operation_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let candidate = ctx.execution_unit_resolve_records().iter().any(|record| {
            let bound = match &record.result {
                ResolveInvocationArtifactResult::Resolved(resolved) => &resolved.bound,
                ResolveInvocationArtifactResult::SelectionError {
                    partial_bound: Some(bound),
                    ..
                } => bound,
                _ => return false,
            };
            bound.effects.iter().any(|e| {
                e.kind == EffectKind::StateOperation
                    && e.state_operation
                        .is_some_and(|op| op.operation != StateOperationKind::Inspect)
            })
        });
        if !candidate {
            return;
        }

        let sequence = ctx.request().sequence_no;
        let mut query = caushell_query::ExecutionSemanticsQuery::new();
        if let Some(previous) = sequence.0.checked_sub(1) {
            query = query.after_sequence(caushell_types::CommandSequenceNo::new(previous));
        }
        if let Some(next) = sequence.0.checked_add(1) {
            query = query.before_sequence(caushell_types::CommandSequenceNo::new(next));
        }
        let facts = query.execute(caushell_query::QuerySession::from_session(&staged));
        for fact in facts.semantics() {
            for state in fact.state_operations() {
                let rule = match state.operation {
                    StateOperationKind::Inspect => continue,
                    StateOperationKind::Mutate => RuleId::StateMutation,
                    StateOperationKind::Control => RuleId::StateControl,
                    StateOperationKind::Opaque => RuleId::StateOpaqueOperation,
                };
                let reason = format!(
                    "{:?} {:?} state operation declared for {} ({}) at {}; filesystem workspace membership does not authorize this state operation",
                    state.domain,
                    state.operation,
                    fact.normalized_command_name(),
                    fact.form_id(),
                    fact.source().node_id().0
                );
                ctx.add_finding(rule, reason.clone());
                if let Some(decision) =
                    decision_for_rule_action(ctx.policy().rule_policy.action_for(rule))
                {
                    ctx.propose_decision(self.name(), rule, decision, reason);
                }
            }
        }
    }
}
