use caushell_query::{PathScopeProof, PathTargetQuery, QuerySession};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{PathTargetOperation, RuleId};

use crate::support::decision_for_rule_action;

pub struct CwdWorkspaceBoundaryPass;

impl SessionAnalysisPass for CwdWorkspaceBoundaryPass {
    fn name(&self) -> &'static str {
        "cwd_workspace_boundary"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let request = ctx.request();

        let Some(workspace_root) = &request.workspace_root else {
            return;
        };

        let source = caushell_runner::request_anchor_node_id(request);
        let targets =
            PathTargetQuery::new(request.sequence_no).execute(QuerySession::from_session(&staged));
        let mut cwd_targets = targets.iter().copied().filter(|fact| {
            fact.source_node_id == source.0
                && fact.operation == PathTargetOperation::WorkingDirectory
        });
        let mut workspace_targets = targets.iter().copied().filter(|fact| {
            fact.source_node_id == source.0 && fact.operation == PathTargetOperation::WorkspaceRoot
        });
        let proof = match (cwd_targets.next(), workspace_targets.next()) {
            (Some(cwd), Some(root))
                if cwd_targets.next().is_none() && workspace_targets.next().is_none() =>
            {
                PathTargetQuery::prove_within(cwd, root)
            }
            _ => PathScopeProof::Unproven,
        };
        if proof == PathScopeProof::Covered {
            return;
        }

        let reason = match proof {
            PathScopeProof::Outside => format!(
                "cwd {} is outside workspace root {}",
                request.shell_state_before.cwd(),
                workspace_root
            ),
            _ => format!(
                "cwd {} has no proven filesystem target within workspace root {}",
                request.shell_state_before.cwd(),
                workspace_root
            ),
        };
        ctx.add_finding(RuleId::CwdOutsideWorkspaceRoot, reason.clone());
        if let Some(decision) = decision_for_rule_action(
            ctx.policy()
                .rule_policy
                .action_for(RuleId::CwdOutsideWorkspaceRoot),
        ) {
            ctx.propose_decision(
                self.name(),
                RuleId::CwdOutsideWorkspaceRoot,
                decision,
                reason,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CwdWorkspaceBoundaryPass;
    use crate::{DecisionAssemblyPass, ProjectTopLevelCommandsPass, ResolvePathTargetsPass};
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RuleId,
        RulePolicyEntry, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(cwd: &str, workspace_root: Option<&str>) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: "pwd".to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new(cwd.to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: workspace_root.map(str::to_string),
        }
    }

    fn runner() -> PassRunner {
        let mut runner = PassRunner::new();
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolvePathTargetsPass);
        runner.register_session_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner
    }

    #[test]
    fn cwd_workspace_boundary_allows_when_cwd_is_inside_workspace_root() {
        let runner = runner();

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project/src", Some("/tmp/project")));
        crate::test_support::supply_filesystem(&mut ctx);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn cwd_workspace_boundary_requires_approval_by_default_when_cwd_is_outside_workspace_root() {
        let runner = runner();

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project2", Some("/tmp/project")));
        crate::test_support::supply_filesystem(&mut ctx);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].rule_id, RuleId::CwdOutsideWorkspaceRoot);
    }

    #[test]
    fn cwd_workspace_boundary_can_be_configured_to_observe() {
        let runner = runner();
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::CwdOutsideWorkspaceRoot,
            RulePolicyEntry::new(RuleAction::Observe),
        );

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::with_policy(
            sample_request("/tmp/project2", Some("/tmp/project")),
            policy,
        );
        crate::test_support::supply_filesystem(&mut ctx);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
        assert_eq!(ctx.findings.len(), 1);
    }

    #[test]
    fn cwd_workspace_boundary_skips_when_workspace_root_is_missing() {
        let runner = runner();

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project/src", None));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn cwd_workspace_boundary_does_not_fall_back_when_target_facts_are_missing() {
        let mut runner = PassRunner::new();
        runner.register_session_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project", Some("/tmp/project")));
        crate::test_support::supply_filesystem(&mut ctx);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(
            ctx.findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CwdOutsideWorkspaceRoot)
        );
    }
}
