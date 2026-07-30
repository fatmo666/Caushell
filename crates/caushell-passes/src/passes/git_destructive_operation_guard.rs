use std::collections::BTreeSet;

use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{Evidence, FindingEnforcementClass, RepositoryOperationKind, RuleId};

use crate::support::{decision_for_rule_action, graph_backed_execution_resolve_records};

pub struct GitDestructiveOperationGuardPass;

impl SessionAnalysisPass for GitDestructiveOperationGuardPass {
    fn name(&self) -> &'static str {
        "git_destructive_operation_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let mut seen = BTreeSet::new();
        let operations = graph_backed_execution_resolve_records(ctx)
            .into_iter()
            .filter_map(|record| {
                let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                    return None;
                };
                if resolved.normalized_command_name != "git" {
                    return None;
                }

                let command = record
                    .parsed_scope()
                    .commands
                    .get(record.command_index())
                    .map(|command| command.text.clone())
                    .unwrap_or_else(|| record.parsed_scope().raw_command.clone());
                let operations = resolved
                    .bound
                    .effects
                    .iter()
                    .filter(|effect| effect.kind == EffectKind::RepositoryOperation)
                    .filter_map(|effect| effect.repository_operation)
                    .collect::<Vec<_>>();

                Some((record.source_node_id().clone(), command, operations))
            })
            .collect::<Vec<_>>();

        for (source_node_id, command, operations) in operations {
            for operation in operations {
                if !seen.insert((source_node_id.clone(), operation)) {
                    continue;
                }

                let rule_id = rule_id_for_operation(operation);
                let evidence = Evidence::repository_operation(
                    rule_id,
                    source_node_id.0.clone(),
                    command.clone(),
                    operation,
                );
                let reason = evidence.summary.clone();

                ctx.add_evidence(evidence);
                ctx.add_finding_with_class(
                    rule_id,
                    reason.clone(),
                    FindingEnforcementClass::Normal,
                );

                if let Some(decision) =
                    decision_for_rule_action(ctx.policy().rule_policy.action_for(rule_id))
                {
                    ctx.propose_decision(self.name(), rule_id, decision, reason);
                }
            }
        }
    }
}

fn rule_id_for_operation(operation: RepositoryOperationKind) -> RuleId {
    match operation {
        RepositoryOperationKind::TrackedWorktreeDiscard => RuleId::GitTrackedWorktreeDiscard,
        RepositoryOperationKind::UntrackedWorktreeDelete => RuleId::GitUntrackedWorktreeDelete,
        RepositoryOperationKind::ForcedWorktreeSwitch => RuleId::GitForcedWorktreeSwitch,
        RepositoryOperationKind::TrackedPathDelete => RuleId::GitTrackedPathDelete,
        RepositoryOperationKind::SavedStateDestroy => RuleId::GitSavedStateDestroy,
        RepositoryOperationKind::LocalRefDestroy => RuleId::GitLocalRefDestroy,
    }
}

#[cfg(test)]
mod tests {
    use super::GitDestructiveOperationGuardPass;
    use crate::{
        DecisionAssemblyPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, RepositoryOperationKind, RuleId,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities: caushell_types::ShellRuntimeCapabilities::request_only(
                ),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().expect("expected built-in registry"),
        ));
        runner.register_session_analysis_pass(GitDestructiveOperationGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(command));
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn assert_operation(
        command: &str,
        expected_rule_id: RuleId,
        expected_operation: RepositoryOperationKind,
    ) {
        let ctx = run_pass(command);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::NeedApproval),
            "{command}"
        );
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|proposal| proposal.rule_id == expected_rule_id),
            "{command}"
        );
        assert!(
            ctx.evidence.iter().any(|evidence| matches!(
                &evidence.kind,
                caushell_types::EvidenceKind::RepositoryOperation(operation)
                    if operation.operation == expected_operation
            )),
            "{command}"
        );
    }

    #[test]
    fn git_destructive_operation_guard_covers_repository_operation_classes() {
        let cases = [
            (
                "git reset --hard HEAD~1",
                RuleId::GitTrackedWorktreeDiscard,
                RepositoryOperationKind::TrackedWorktreeDiscard,
            ),
            (
                "git clean -fdx",
                RuleId::GitUntrackedWorktreeDelete,
                RepositoryOperationKind::UntrackedWorktreeDelete,
            ),
            (
                "git switch --discard-changes main",
                RuleId::GitForcedWorktreeSwitch,
                RepositoryOperationKind::ForcedWorktreeSwitch,
            ),
            (
                "git rm -f modified.txt",
                RuleId::GitTrackedPathDelete,
                RepositoryOperationKind::TrackedPathDelete,
            ),
            (
                "git stash clear",
                RuleId::GitSavedStateDestroy,
                RepositoryOperationKind::SavedStateDestroy,
            ),
            (
                "git branch -D feature/wip",
                RuleId::GitLocalRefDestroy,
                RepositoryOperationKind::LocalRefDestroy,
            ),
        ];

        for (command, rule_id, operation) in cases {
            assert_operation(command, rule_id, operation);
        }
    }

    #[test]
    fn git_destructive_operation_guard_preserves_safe_controls() {
        for command in [
            "git clean -n",
            "git clean -i",
            "git reset --soft HEAD~1",
            "git restore --staged README.md",
            "git checkout main",
            "git switch main",
            "git rm --cached modified.txt",
            "git rm --dry-run modified.txt",
            "git branch -d merged-feature",
            "git commit -m checkpoint",
            "git status --short",
        ] {
            let ctx = run_pass(command);
            assert_eq!(ctx.final_decision, Some(Decision::Allow), "{command}");
            assert!(ctx.decision_proposals.is_empty(), "{command}");
            assert!(ctx.evidence.is_empty(), "{command}");
        }
    }
}
