use std::path::Path;

use caushell_runner::{RequestAnalysisPass, RunnerContext};
use caushell_types::RuleId;

use crate::support::decision_for_rule_action;

pub struct CwdWorkspaceBoundaryPass;

impl RequestAnalysisPass for CwdWorkspaceBoundaryPass {
    fn name(&self) -> &'static str {
        "cwd_workspace_boundary"
    }

    fn run(&self, ctx: &mut RunnerContext) {
        let request = ctx.request();

        let Some(workspace_root) = &request.workspace_root else {
            return;
        };

        if Path::new(request.shell_state_before.cwd()).starts_with(Path::new(workspace_root)) {
            return;
        }

        let reason = format!(
            "cwd {} is outside workspace root {}",
            request.shell_state_before.cwd(),
            workspace_root
        );
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
    use crate::DecisionAssemblyPass;
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

    #[test]
    fn cwd_workspace_boundary_allows_when_cwd_is_inside_workspace_root() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project/src", Some("/tmp/project")));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn cwd_workspace_boundary_requires_approval_by_default_when_cwd_is_outside_workspace_root() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project2", Some("/tmp/project")));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].rule_id, RuleId::CwdOutsideWorkspaceRoot);
    }

    #[test]
    fn cwd_workspace_boundary_can_be_configured_to_observe() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
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

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
        assert_eq!(ctx.findings.len(), 1);
    }

    #[test]
    fn cwd_workspace_boundary_skips_when_workspace_root_is_missing() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(CwdWorkspaceBoundaryPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request("/tmp/project/src", None));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }
}
