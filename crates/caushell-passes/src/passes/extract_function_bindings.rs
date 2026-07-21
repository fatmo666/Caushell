use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{CommandSequenceNo, SessionFunctionBinding};

pub struct ExtractFunctionBindingsPass;

impl SessionTransformPass for ExtractFunctionBindingsPass {
    fn name(&self) -> &'static str {
        "extract_function_bindings"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let observed_at = ctx.request().sequence_no;
        let Some(parsed) = ctx.parsed_command() else {
            return;
        };

        for mutation in collect_function_mutations(parsed, observed_at) {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_function_mutations(
    parsed: &caushell_parse::ParsedCommandArtifact,
    observed_at: CommandSequenceNo,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for definition in &parsed.function_definitions {
        mutations.push(PendingMutation::UpsertFunctionBinding {
            binding: SessionFunctionBinding::new(
                definition.name.clone(),
                definition.body_text.clone(),
                observed_at,
            ),
        });
    }

    for unset in &parsed.unset_commands {
        if !unset.options.iter().any(|option| option == "-f") {
            continue;
        }

        for name in &unset.names {
            mutations.push(PendingMutation::UnsetFunction {
                name: name.clone(),
                observed_at,
            });
        }
    }

    mutations
}

#[cfg(test)]
mod tests {
    use super::ExtractFunctionBindingsPass;
    use crate::ParseCommandPass;
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionFunctionBinding, SessionId,
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
        runner.register_session_transform_pass(ExtractFunctionBindingsPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(sequence_no, command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_function_bindings_stages_function_definition() {
        let ctx = run_pass(3, "deploy() { bash ./scripts/build.sh; }");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertFunctionBinding {
                binding: SessionFunctionBinding::new(
                    "deploy",
                    "bash ./scripts/build.sh;",
                    CommandSequenceNo::new(3),
                ),
            }]
        );
    }

    #[test]
    fn extract_function_bindings_stages_unset_function() {
        let ctx = run_pass(5, "unset -f deploy helper");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UnsetFunction {
                    name: "deploy".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                },
                PendingMutation::UnsetFunction {
                    name: "helper".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                },
            ]
        );
    }
}
