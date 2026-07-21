use caushell_runner::{FinalDecisionPass, RunnerContext};
use caushell_types::{Decision, FindingEnforcementClass};

pub struct DecisionAssemblyPass;

impl FinalDecisionPass for DecisionAssemblyPass {
    fn name(&self) -> &'static str {
        "decision_assembly"
    }

    fn run(&self, ctx: &mut RunnerContext) {
        let has_hard_deny_floor = ctx
            .findings
            .iter()
            .any(|finding| finding.enforcement_class == FindingEnforcementClass::HardDenyFloor);

        let decision = if has_hard_deny_floor
            || ctx
                .decision_proposals
                .iter()
                .any(|proposal| proposal.decision == Decision::Deny)
        {
            Decision::Deny
        } else if ctx
            .decision_proposals
            .iter()
            .any(|proposal| proposal.decision == Decision::NeedApproval)
        {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };

        ctx.set_final_decision(decision);
    }
}

#[cfg(test)]
mod tests {
    use super::DecisionAssemblyPass;
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, RequestAnalysisPass, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, FindingEnforcementClass, RuleId,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    struct NeedApprovalProposalPass;

    impl RequestAnalysisPass for NeedApprovalProposalPass {
        fn name(&self) -> &'static str {
            "need_approval_proposal"
        }

        fn run(&self, ctx: &mut RunnerContext) {
            ctx.propose_decision(
                self.name(),
                RuleId::CommandParseFailure,
                Decision::NeedApproval,
                "manual review required",
            );
        }
    }

    struct DenyProposalPass;

    impl RequestAnalysisPass for DenyProposalPass {
        fn name(&self) -> &'static str {
            "deny_proposal"
        }

        fn run(&self, ctx: &mut RunnerContext) {
            ctx.propose_decision(
                self.name(),
                RuleId::NonMonotonicSequence,
                Decision::Deny,
                "hard stop",
            );
        }
    }

    fn sample_request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: "ls -la".to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    #[test]
    fn decision_assembly_defaults_to_allow_without_proposals() {
        let mut runner = PassRunner::new();
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.executed_passes, vec!["decision_assembly".to_string()]);
        assert_eq!(ctx.final_decision, Some(Decision::Allow));
    }

    #[test]
    fn decision_assembly_promotes_need_approval_when_present() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(NeedApprovalProposalPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    }

    #[test]
    fn decision_assembly_prioritizes_deny_over_need_approval() {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(NeedApprovalProposalPass);
        runner.register_request_analysis_pass(DenyProposalPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
    }

    #[test]
    fn decision_assembly_denies_hard_floor_findings_without_a_proposal() {
        struct HardFloorFindingPass;

        impl RequestAnalysisPass for HardFloorFindingPass {
            fn name(&self) -> &'static str {
                "hard_floor_finding"
            }

            fn run(&self, ctx: &mut RunnerContext) {
                ctx.add_finding_with_class(
                    RuleId::TaintedExecution,
                    "catastrophic command target",
                    FindingEnforcementClass::HardDenyFloor,
                );
            }
        }

        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(HardFloorFindingPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
    }
}
