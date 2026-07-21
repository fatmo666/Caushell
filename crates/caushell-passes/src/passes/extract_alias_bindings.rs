use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{CommandSequenceNo, SessionAliasBinding};

use crate::support::{alias_assignments, unalias_names};

pub struct ExtractAliasBindingsPass;

impl SessionTransformPass for ExtractAliasBindingsPass {
    fn name(&self) -> &'static str {
        "extract_alias_bindings"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let observed_at = ctx.request().sequence_no;
        let Some(parsed) = ctx.parsed_command() else {
            return;
        };

        for mutation in collect_alias_mutations(&parsed.commands, observed_at) {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_alias_mutations(
    commands: &[caushell_parse::CommandFact],
    observed_at: CommandSequenceNo,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for command in commands {
        for assignment in alias_assignments(command) {
            mutations.push(PendingMutation::UpsertAliasBinding {
                binding: SessionAliasBinding::new(assignment.name, assignment.body, observed_at),
            });
        }

        for name in unalias_names(command) {
            mutations.push(PendingMutation::UnsetAlias { name, observed_at });
        }
    }

    mutations
}

#[cfg(test)]
mod tests {
    use super::ExtractAliasBindingsPass;
    use crate::ParseCommandPass;
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionAliasBinding, SessionId,
        SessionSummary, ShellKind,
    };

    fn sample_request(sequence_no: u64, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
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

    fn run_pass(sequence_no: u64, command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ExtractAliasBindingsPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(sequence_no, command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_alias_bindings_stages_alias_assignment_mutations() {
        let ctx = run_pass(3, "alias ll='ls -l' g=\"grep --color=auto\"");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UpsertAliasBinding {
                    binding: SessionAliasBinding::new("ll", "ls -l", CommandSequenceNo::new(3)),
                },
                PendingMutation::UpsertAliasBinding {
                    binding: SessionAliasBinding::new(
                        "g",
                        "grep --color=auto",
                        CommandSequenceNo::new(3),
                    ),
                },
            ]
        );
    }

    #[test]
    fn extract_alias_bindings_stages_unalias_mutations() {
        let ctx = run_pass(5, "unalias ll g");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UnsetAlias {
                    name: "ll".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                },
                PendingMutation::UnsetAlias {
                    name: "g".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                },
            ]
        );
    }

    #[test]
    fn extract_alias_bindings_ignores_option_forms_in_v1() {
        let ctx = run_pass(7, "unalias -a");

        assert!(ctx.pending_mutations().is_empty());
    }
}
