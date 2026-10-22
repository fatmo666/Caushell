use std::collections::BTreeSet;

use caushell_query::QuerySession;
use caushell_runner::{PathOperation, RunnerContext, SessionAnalysisPass, SessionView};
#[cfg(test)]
use caushell_types::PathResolution;
use caushell_types::{ProvenanceConsumeKind, RuleId};

use crate::support::{collect_outside_workspace_path_consumes, decision_for_rule_action};
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
        let rule = RuleId::CodeLoadPath;
        let paths = collect_outside_workspace_path_consumes(
            QuerySession::from_session(&staged_session),
            ctx,
            ProvenanceConsumeKind::InProcessCodeSource,
            PathOperation::LoadCodeFile,
            rule,
        );
        let reasons: BTreeSet<_> = paths.consumes.into_iter().map(|path| path.reason).collect();

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
