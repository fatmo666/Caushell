use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{Evidence, RuleId};

use crate::support::decision_for_rule_action;

pub struct InteractiveEscapeGuardPass;

impl SessionAnalysisPass for InteractiveEscapeGuardPass {
    fn name(&self) -> &'static str {
        "interactive_escape_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let rule_action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::InteractiveEscapeSurface);
        let current_sequence = ctx.request().sequence_no;
        let lower_bound =
            caushell_types::CommandSequenceNo::new(current_sequence.0.saturating_sub(1));
        let semantics = caushell_query::ExecutionSemanticsQuery::new()
            .after_sequence(lower_bound)
            .before_sequence(current_sequence.next())
            .execute(caushell_query::QuerySession::from_session(&staged_session));

        for semantics in semantics.semantics() {
            if !semantics.opens_interactive_escape_surface() {
                continue;
            }

            let Some(surface_kind) = semantics.interactive_escape_surface_kind() else {
                continue;
            };

            let evidence = Evidence::interactive_escape_surface(
                semantics.source().node_id().0.clone(),
                semantics.source().root_command_sequence_no(),
                semantics.source().depth(),
                semantics.source().raw_text().to_string(),
                semantics.normalized_command_name().to_string(),
                semantics.form_id().to_string(),
                surface_kind,
                semantics.interactive_escape_capabilities().to_vec(),
                semantics.interactive_escape_requires_tty(),
            );
            let reason = evidence.summary.clone();

            ctx.add_evidence(evidence);
            ctx.add_finding(RuleId::InteractiveEscapeSurface, reason.clone());

            if let Some(decision) = decision_for_rule_action(rule_action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::InteractiveEscapeSurface,
                    decision,
                    reason,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InteractiveEscapeGuardPass;
    use crate::{
        DecisionAssemblyPass, ExtractExecutionSemanticsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, EvidenceKind, PolicyConfig, RuleAction, RuleId,
        RulePolicyEntry, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
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

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn policy_with_action(action: RuleAction) -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::InteractiveEscapeSurface,
            RulePolicyEntry::new(action),
        );
        policy
    }

    fn run_pass(command: &str, policy: PolicyConfig) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_analysis_pass(InteractiveEscapeGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::with_policy(sample_request(command), policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn interactive_escape_guard_observes_less_interactive_surface() {
        let ctx = run_pass("less README.md", policy_with_action(RuleAction::Observe));

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].rule_id, RuleId::InteractiveEscapeSurface);
        assert!(
            ctx.findings[0]
                .message
                .contains("pager interactive escape surface")
        );
        assert!(ctx.decision_proposals.is_empty());
        assert!(ctx.evidence.iter().any(|evidence| match &evidence.kind {
            EvidenceKind::InteractiveEscapeSurface(surface) => {
                surface.normalized_command_name == "less"
                    && surface.form_id == "interactive_read"
                    && surface.requires_tty
            }
            _ => false,
        }));
    }

    #[test]
    fn interactive_escape_guard_requires_approval_when_policy_demands_it() {
        let ctx = run_pass("top", policy_with_action(RuleAction::NeedApproval));

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::InteractiveEscapeSurface
        );
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert!(
            ctx.findings[0]
                .message
                .contains("terminal_ui interactive escape surface")
        );
    }

    #[test]
    fn interactive_escape_guard_observes_vim_interactive_surface() {
        let ctx = run_pass("vim notes.txt", policy_with_action(RuleAction::Observe));

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert_eq!(ctx.findings.len(), 1);
        assert!(
            ctx.findings[0]
                .message
                .contains("editor interactive escape surface")
        );
        assert!(ctx.evidence.iter().any(|evidence| match &evidence.kind {
            EvidenceKind::InteractiveEscapeSurface(surface) => {
                surface.normalized_command_name == "vim" && surface.form_id == "interactive_editor"
            }
            _ => false,
        }));
    }

    #[test]
    fn interactive_escape_guard_skips_vim_script_mode() {
        let ctx = run_pass(
            "vim -es -S script.vim",
            policy_with_action(RuleAction::NeedApproval),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
        assert!(ctx.evidence.is_empty());
    }

    #[test]
    fn interactive_escape_guard_skips_non_interactive_top_batch_mode() {
        let ctx = run_pass("top -b", policy_with_action(RuleAction::NeedApproval));

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
        assert!(ctx.evidence.is_empty());
    }
}
