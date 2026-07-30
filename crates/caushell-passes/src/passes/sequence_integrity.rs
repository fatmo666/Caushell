use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::RuleId;

use crate::support::decision_for_rule_action;

pub struct SequenceIntegrityPass;

impl SessionAnalysisPass for SequenceIntegrityPass {
    fn name(&self) -> &'static str {
        "sequence_integrity"
    }

    fn run(
        &self,
        session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let request = ctx.request();

        if let Some(previous_max_sequence_no) = session.summary().last_sequence_no() {
            if request.sequence_no <= previous_max_sequence_no {
                let reason = format!(
                    "command sequence {} is not greater than prior max {} for session {}",
                    request.sequence_no.0,
                    previous_max_sequence_no.0,
                    request.session_id.0.as_str(),
                );
                ctx.add_finding(RuleId::NonMonotonicSequence, reason.clone());
                if let Some(decision) = decision_for_rule_action(
                    ctx.policy()
                        .rule_policy
                        .action_for(RuleId::NonMonotonicSequence),
                ) {
                    ctx.propose_decision(
                        self.name(),
                        RuleId::NonMonotonicSequence,
                        decision,
                        reason,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceIntegrityPass;
    use crate::DecisionAssemblyPass;
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RuleId,
        RulePolicyEntry, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(sequence_no: u64) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: format!("cmd-{sequence_no}"),
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
    fn sequence_integrity_allows_when_session_has_no_prior_sequence() {
        let mut runner = PassRunner::new();
        runner.register_session_analysis_pass(SequenceIntegrityPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(1));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn sequence_integrity_allows_strictly_increasing_sequence() {
        let mut runner = PassRunner::new();
        runner.register_session_analysis_pass(SequenceIntegrityPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.observe_sequence(CommandSequenceNo::new(1));
        let mut ctx = RunnerContext::new(sample_request(2));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn sequence_integrity_denies_non_monotonic_sequence_by_default() {
        let mut runner = PassRunner::new();
        runner.register_session_analysis_pass(SequenceIntegrityPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.observe_sequence(CommandSequenceNo::new(2));
        let mut ctx = RunnerContext::new(sample_request(1));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].rule_id, RuleId::NonMonotonicSequence);
    }

    #[test]
    fn sequence_integrity_can_be_configured_to_observe() {
        let mut runner = PassRunner::new();
        runner.register_session_analysis_pass(SequenceIntegrityPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::NonMonotonicSequence,
            RulePolicyEntry::new(RuleAction::Observe),
        );

        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.observe_sequence(CommandSequenceNo::new(2));
        let mut ctx = RunnerContext::with_policy(sample_request(1), policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.decision_proposals.is_empty());
        assert_eq!(ctx.findings.len(), 1);
    }
}
