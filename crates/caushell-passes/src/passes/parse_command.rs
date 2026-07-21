use caushell_parse::parse_command;
use caushell_runner::{RequestTransformPass, RunnerContext};
use caushell_types::{Decision, RuleId};

pub struct ParseCommandPass;

impl RequestTransformPass for ParseCommandPass {
    fn name(&self) -> &'static str {
        "parse_command"
    }

    fn run(&self, ctx: &mut RunnerContext) {
        let shell_kind = ctx.request().shell_kind;
        let command = ctx.request().command.clone();

        match parse_command(&command, shell_kind) {
            Ok(artifact) => {
                ctx.set_parsed_command(artifact);
            }
            Err(error) => {
                let reason = format!("command parsing failed for {:?}: {}", shell_kind, error);

                ctx.add_finding(RuleId::CommandParseFailure, reason.clone());
                ctx.propose_decision(
                    self.name(),
                    RuleId::CommandParseFailure,
                    Decision::NeedApproval,
                    reason,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ParseCommandPass;
    use crate::DecisionAssemblyPass;
    use caushell_graph::SessionGraph;
    use caushell_parse::ParseStatus;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, RuleId, RuntimeMetadata, SessionId,
        SessionSummary, ShellKind,
    };

    fn sample_request(shell_kind: ShellKind, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind,
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
    fn parse_command_pass_stores_parse_artifact_for_supported_shells() {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(ShellKind::Bash, "echo hi"));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.executed_passes, vec!["parse_command".to_string()]);
        assert!(ctx.decision_proposals.is_empty());

        let parsed = ctx
            .parsed_command()
            .expect("expected parsed command artifact to exist");

        assert_eq!(parsed.status, ParseStatus::Complete);
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].command_name.as_deref(), Some("echo"));
    }

    #[test]
    fn parse_command_pass_requires_approval_for_unsupported_shells() {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(ShellKind::Powershell, "Write-Host hello"));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert!(ctx.parsed_command().is_none());
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.decision_proposals[0].source_pass, "parse_command");
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::CommandParseFailure
        );
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "command parsing failed for Powershell: shell kind Powershell is not supported by caushell-parse"
        );
    }
}
