use std::collections::BTreeSet;

use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_query::{PathFactsQuery, QuerySession};
use caushell_runner::{PathOperation, RunnerContext, SessionAnalysisPass, SessionView};
#[cfg(test)]
use caushell_types::PathResolution;
use caushell_types::{ResolvedPathPurpose, RuleId};

use crate::support::{decision_for_rule_action, graph_backed_execution_resolve_records};
#[cfg(test)]
use caushell_query::path_is_within_root;

/// Checks explicit code-file inputs, not tool-owned module search mechanisms.
/// Registered module CLI contracts and their unresolved dispatches retain their
/// existing dispatch/resolve policy; this pass does not guess module locations.
pub struct CodeLoadPathGuardPass;

impl SessionAnalysisPass for CodeLoadPathGuardPass {
    fn name(&self) -> &'static str {
        "code_load_path_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let loads_code = |result: &ResolveInvocationArtifactResult| {
            matches!(result, ResolveInvocationArtifactResult::Resolved(resolved)
                if resolved.bound.effects.iter().any(|effect| effect.kind == EffectKind::LoadInProcessCode))
        };
        if !ctx
            .execution_unit_resolve_records()
            .iter()
            .any(|record| loads_code(&record.result))
        {
            return;
        }

        let candidates: BTreeSet<_> = graph_backed_execution_resolve_records(ctx)
            .into_iter()
            .filter(|record| loads_code(record.result()))
            .map(|record| record.source_node_id().clone())
            .collect();
        if candidates.is_empty() {
            return;
        }

        let rule = RuleId::CodeLoadPath;
        let request = ctx.request();
        let policy = ctx.path_exemption_policy();
        let paths = PathFactsQuery::new()
            .purpose(ResolvedPathPurpose::InProcessCode)
            .used_by_root_sequence(request.sequence_no)
            .execute(QuerySession::from_session(&staged_session));
        let mut reasons = BTreeSet::new();
        for path in paths.facts() {
            if !path
                .used_by()
                .iter()
                .any(|usage| candidates.contains(usage.execution_unit().node_id()))
            {
                continue;
            }
            if policy
                .check(path.resolution(), PathOperation::LoadCodeFile, rule)
                .is_exempt()
            {
                continue;
            }
            reasons.insert(format!(
                "code load path for slot {} in command {} is outside the workspace/temporary scope or cannot be resolved: {:?}",
                path.slot_name(),
                path.normalized_command_name().unwrap_or("<unknown>"),
                path.resolution(),
            ));
        }

        let action = ctx.policy().rule_policy.action_for(rule);
        for reason in reasons {
            ctx.add_finding(rule, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), rule, decision, reason);
            }
        }
    }
}

#[cfg(test)]
fn resolution_is_trusted(resolution: &PathResolution, trusted: &impl Fn(&str) -> bool) -> bool {
    caushell_query::PathScopeQuery::new(resolution).prove_all(trusted)
        == caushell_query::PathScopeProof::Covered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_sets_require_every_bound_to_be_trusted_and_no_escape() {
        let trusted = |path: &str| path_is_within_root(path, "/workspace");
        for (roots, may_escape, expected) in [
            (vec!["/workspace/sub"], false, true),
            (vec!["/workspace/sub", "/workspace/other"], false, true),
            (vec!["/workspace", "/opt"], false, false),
            (vec!["/workspace"], true, false),
            (vec![], false, false),
            (vec!["relative"], false, false),
        ] {
            assert_eq!(
                resolution_is_trusted(
                    &PathResolution::BoundedPathSet {
                        roots: roots.into_iter().map(String::from).collect(),
                        may_escape,
                    },
                    &trusted,
                ),
                expected,
            );
        }
    }
}
