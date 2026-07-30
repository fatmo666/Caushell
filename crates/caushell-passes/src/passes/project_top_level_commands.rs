use caushell_runner::{
    PendingMutation, RunnerContext, SessionTransformPass, SessionView, request_anchor_node_id,
};

use crate::support::collect_top_level_units;

pub struct ProjectTopLevelCommandsPass;

impl SessionTransformPass for ProjectTopLevelCommandsPass {
    fn name(&self) -> &'static str {
        "project_top_level_commands"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let request = ctx.request().clone();

        ctx.stage_mutation(PendingMutation::AddRequestAnchor {
            node_id: request_anchor_node_id(&request),
            session_id: request.session_id.clone(),
            sequence_no: request.sequence_no,
            raw_text: request.command.clone(),
            cwd_before: request.shell_state_before.cwd.clone(),
            shell_kind: request.shell_kind,
        });

        let Some(parsed) = ctx.parsed_command() else {
            return;
        };

        let mut mutations = Vec::new();

        for unit in collect_top_level_units(parsed) {
            mutations.push(PendingMutation::AddTopLevelCommandInvocation {
                node_id: unit.node_id(&request),
                session_id: request.session_id.clone(),
                sequence_no: request.sequence_no,
                command_index: unit.unit_index,
                raw_text: unit.raw_text(parsed),
                cwd_before: request.shell_state_before.cwd.clone(),
                shell_kind: request.shell_kind,
            });
        }

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProjectTopLevelCommandsPass;
    use crate::ParseCommandPass;
    use caushell_graph::{NodeId, SessionGraph};
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn project_top_level_commands_projects_bare_redirection_as_execution_unit() {
        let ctx = run_pass("> /dev/sda");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddTopLevelCommandInvocation {
                    node_id: NodeId::new("command:sess-1:2:0"),
                    session_id: SessionId::new("sess-1"),
                    sequence_no: CommandSequenceNo::new(2),
                    command_index: 0,
                    raw_text: "> /dev/sda".to_string(),
                    cwd_before: "/tmp/project".to_string(),
                    shell_kind: ShellKind::Bash,
                })
        );
    }
}
