use std::collections::BTreeSet;

use caushell_profile::{BoundInvocation, EffectKind};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::RuleId;

use crate::path::{
    collect_effect_mutation_targets, effective_cwd_cases, path_target_is_inapplicable,
};
use crate::support::{
    bound_invocation, decision_for_rule_action, graph_backed_execution_resolve_records,
};

/// Ordinary filesystem deletion requires approval independently of location.
/// Moves are a distinct declared effect and remain governed by path policies.
pub struct FileDeletionGuardPass;

fn has_candidate(bound: &BoundInvocation) -> bool {
    bound
        .effects
        .iter()
        .any(|e| e.kind == EffectKind::DeletePath && !path_target_is_inapplicable(bound, &e.target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_profile::{BoundParameter, CommandName, Effect, FormId, SemanticType, SlotName};

    #[test]
    fn candidate_distinguishes_absent_effect_from_unresolved_target() {
        let mut bound = BoundInvocation::new(CommandName::new("custom"), FormId::new("delete"))
            .with_effect(Effect::new(EffectKind::DeletePath).for_slot("targets"));
        assert!(
            has_candidate(&bound),
            "missing target is not an empty effect"
        );
        let parameter = BoundParameter::new(SlotName::new("targets"), SemanticType::PlainValue);
        bound.bound_parameters.push(parameter);
        assert!(
            has_candidate(&bound),
            "unresolved target still requires approval"
        );
        bound.bound_parameters[0].projected_values = Some(Vec::new());
        assert!(
            !has_candidate(&bound),
            "proven empty projections are inapplicable"
        );
        bound
            .effects
            .push(Effect::new(EffectKind::DeletePath).for_slot("other"));
        assert!(
            has_candidate(&bound),
            "empty first slot cannot hide another deletion"
        );
    }

    #[test]
    fn move_and_write_effects_are_not_deletion_candidates() {
        let bound = BoundInvocation::new(CommandName::new("custom"), FormId::new("move"))
            .with_effect(Effect::new(EffectKind::MovePath).for_slot("source"))
            .with_effect(Effect::new(EffectKind::WritePath).for_slot("destination"));
        assert!(!has_candidate(&bound));
    }
}

impl SessionAnalysisPass for FileDeletionGuardPass {
    fn name(&self) -> &'static str {
        "file_deletion_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        // No command-name checks, path resolution or Graph queries on the
        // ordinary non-deleting path; empty protocol projections also skip.
        if !ctx
            .execution_unit_resolve_records()
            .iter()
            .any(|r| bound_invocation(&r.result).is_some_and(has_candidate))
        {
            return;
        }
        let fallback = ctx.request().shell_state_before.cwd();
        let home = ctx.request().home.as_deref();
        let mut reasons = BTreeSet::new();
        for record in graph_backed_execution_resolve_records(ctx) {
            let Some(bound) = bound_invocation(record.result()).filter(|b| has_candidate(b)) else {
                continue;
            };
            for case in effective_cwd_cases(
                ctx.execution_cwd_for_node(record.source_node_id()),
                fallback,
            ) {
                for target in
                    collect_effect_mutation_targets(record, case.resolution_base(fallback), home)
                {
                    if target.operation == EffectKind::DeletePath {
                        reasons.insert(format!("{} ({}) deletes filesystem objects via slot {}; deletion requires approval regardless of workspace or temporary-path location",
                            bound.command_name.as_str(), bound.form_id.as_str(), target.slot_name));
                    }
                }
            }
        }
        let action = ctx.policy().rule_policy.action_for(RuleId::FileDeletion);
        for reason in reasons {
            ctx.add_finding(RuleId::FileDeletion, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::FileDeletion, decision, reason);
            }
        }
    }
}
