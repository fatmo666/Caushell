use caushell_graph::EdgeKind;
use caushell_runner::{
    ParsedCommandScope, PendingMutation, RunnerContext, SessionTransformPass, SessionView,
};
use caushell_types::DerivedInvocationOrigin;

use crate::support::{
    collect_pipeline_groups, pipeline_segment_node_id, top_level_node_id_for_command,
};

pub struct ExtractPipelineFlowPass;

impl SessionTransformPass for ExtractPipelineFlowPass {
    fn name(&self) -> &'static str {
        "extract_pipeline_flow"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let Some(parsed) = ctx.parsed_command() else {
            return;
        };

        for mutation in collect_top_level_pipeline_flow_mutations(ctx.request(), parsed)
            .into_iter()
            .chain(collect_scoped_pipeline_flow_mutations(
                ctx.parsed_command_scopes(),
            ))
        {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_top_level_pipeline_flow_mutations(
    request: &caushell_types::CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for group in collect_pipeline_groups(parsed) {
        let Some(parent_node_id) =
            top_level_node_id_for_command(request, parsed, group.commands[0].command_index)
        else {
            continue;
        };

        for command in &group.commands {
            mutations.push(PendingMutation::AddDerivedInvocation {
                node_id: pipeline_segment_node_id(
                    &request.session_id,
                    request.sequence_no,
                    command.command_index,
                ),
                root_command_sequence_no: request.sequence_no,
                origin: DerivedInvocationOrigin::PipelineSegment {
                    command_index: command.command_index,
                },
                derived_command_index: command.command_index,
                raw_text: command.command.text.clone(),
                command_name: command.command.command_name.clone(),
                shell_kind: request.shell_kind,
                depth: 0,
                parent_node_id: parent_node_id.clone(),
                relation_from_parent: EdgeKind::ExpandsTo,
            });
        }

        for pair in group.commands.windows(2) {
            let from = &pair[0];
            let to = &pair[1];

            mutations.push(PendingMutation::AddExecutionUnitFlow {
                from_node_id: pipeline_segment_node_id(
                    &request.session_id,
                    request.sequence_no,
                    from.command_index,
                ),
                to_node_id: pipeline_segment_node_id(
                    &request.session_id,
                    request.sequence_no,
                    to.command_index,
                ),
            });
        }
    }

    mutations
}

fn collect_scoped_pipeline_flow_mutations(scopes: &[ParsedCommandScope]) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for scope in scopes {
        for group in collect_pipeline_groups(&scope.parsed) {
            for pair in group.commands.windows(2) {
                let from = &pair[0];
                let to = &pair[1];
                let (Some(from_node_id), Some(to_node_id)) = (
                    scope.command_node_id(from.command_index),
                    scope.command_node_id(to.command_index),
                ) else {
                    continue;
                };

                mutations.push(PendingMutation::AddExecutionUnitFlow {
                    from_node_id: from_node_id.clone(),
                    to_node_id: to_node_id.clone(),
                });
            }
        }
    }

    mutations
}

#[cfg(test)]
mod tests {
    use super::ExtractPipelineFlowPass;
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
    use caushell_graph::{NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, DerivedInvocationOrigin, RuntimeMetadata,
        SessionFunctionBinding, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(4),
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

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ExtractPipelineFlowPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_scoped_pass(summary: &SessionSummary, command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPipelineFlowPass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_pipeline_flow_projects_segments_and_adjacent_flow() {
        let ctx = run_pass("cat payload.sh | bash");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::AddRequestAnchor {
                    node_id: NodeId::new("command-request:sess-1:4"),
                    session_id: SessionId::new("sess-1"),
                    sequence_no: CommandSequenceNo::new(4),
                    raw_text: "cat payload.sh | bash".to_string(),
                    cwd_before: "/tmp/project".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                PendingMutation::AddTopLevelCommandInvocation {
                    node_id: NodeId::new("command:sess-1:4:0"),
                    session_id: SessionId::new("sess-1"),
                    sequence_no: CommandSequenceNo::new(4),
                    command_index: 0,
                    raw_text: "cat payload.sh | bash".to_string(),
                    cwd_before: "/tmp/project".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                PendingMutation::AddDerivedInvocation {
                    node_id: NodeId::new("pipeline-segment:sess-1:4:0"),
                    root_command_sequence_no: CommandSequenceNo::new(4),
                    origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                    derived_command_index: 0,
                    raw_text: "cat payload.sh".to_string(),
                    command_name: Some("cat".to_string()),
                    shell_kind: ShellKind::Bash,
                    depth: 0,
                    parent_node_id: NodeId::new("command:sess-1:4:0"),
                    relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
                },
                PendingMutation::AddDerivedInvocation {
                    node_id: NodeId::new("pipeline-segment:sess-1:4:1"),
                    root_command_sequence_no: CommandSequenceNo::new(4),
                    origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                    derived_command_index: 1,
                    raw_text: "bash".to_string(),
                    command_name: Some("bash".to_string()),
                    shell_kind: ShellKind::Bash,
                    depth: 0,
                    parent_node_id: NodeId::new("command:sess-1:4:0"),
                    relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
                },
                PendingMutation::AddExecutionUnitFlow {
                    from_node_id: NodeId::new("pipeline-segment:sess-1:4:0"),
                    to_node_id: NodeId::new("pipeline-segment:sess-1:4:1"),
                },
            ]
        );
    }

    #[test]
    fn extract_pipeline_flow_does_not_connect_separate_pipelines() {
        let ctx = run_pass("cat a | bash; echo ok | sh");

        let flow_edges: Vec<_> = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddExecutionUnitFlow {
                    from_node_id,
                    to_node_id,
                } => Some((from_node_id.0.as_str(), to_node_id.0.as_str())),
                _ => None,
            })
            .collect();

        assert_eq!(
            flow_edges,
            vec![
                ("pipeline-segment:sess-1:4:0", "pipeline-segment:sess-1:4:1"),
                ("pipeline-segment:sess-1:4:2", "pipeline-segment:sess-1:4:3"),
            ]
        );
    }

    #[test]
    fn extract_pipeline_flow_projects_all_segments_for_find_xargs_head_pipeline() {
        let ctx = run_pass(
            "find . -name \"*.md\" -o -name \"*.txt\" | xargs grep -l \"site:\\|inurl:\\|intitle:\\|filetype:\" 2>/dev/null | head -10",
        );

        let derived_segments: Vec<_> = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddDerivedInvocation { node_id, .. }
                    if node_id.0.starts_with("pipeline-segment:sess-1:4:") =>
                {
                    Some(node_id.0.clone())
                }
                _ => None,
            })
            .collect();
        let flow_edges: Vec<_> = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddExecutionUnitFlow {
                    from_node_id,
                    to_node_id,
                } => Some((from_node_id.0.clone(), to_node_id.0.clone())),
                _ => None,
            })
            .collect();

        assert_eq!(
            derived_segments,
            vec![
                "pipeline-segment:sess-1:4:0".to_string(),
                "pipeline-segment:sess-1:4:1".to_string(),
                "pipeline-segment:sess-1:4:2".to_string(),
            ]
        );
        assert_eq!(
            flow_edges,
            vec![
                (
                    "pipeline-segment:sess-1:4:0".to_string(),
                    "pipeline-segment:sess-1:4:1".to_string(),
                ),
                (
                    "pipeline-segment:sess-1:4:1".to_string(),
                    "pipeline-segment:sess-1:4:2".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn extract_pipeline_flow_connects_function_body_pipeline_units() {
        let mut summary = SessionSummary::new();
        summary.upsert_function_binding(SessionFunctionBinding::new(
            "deploy",
            "cat ./payload.sh | bash;",
            CommandSequenceNo::new(1),
        ));
        let ctx = run_scoped_pass(&summary, "deploy");

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } if from_node_id == &NodeId::new("derived-function:sess-1:4:0:0")
                && to_node_id == &NodeId::new("derived-function:sess-1:4:0:1")
        )));
    }

    #[test]
    fn extract_pipeline_flow_connects_assignment_command_substitution_pipeline_units() {
        let summary = SessionSummary::new();
        let ctx = run_scoped_pass(&summary, r#"TMP_SCRIPT="$(cat ./payload.sh | bash)""#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } if from_node_id == &NodeId::new("expanded-subst-assign:command:sess-1:4:0:0:0:0:0")
                && to_node_id == &NodeId::new("expanded-subst-assign:command:sess-1:4:0:0:0:0:1")
        )));
    }

    #[test]
    fn extract_pipeline_flow_connects_process_substitution_pipeline_units() {
        let summary = SessionSummary::new();
        let ctx = run_scoped_pass(&summary, r#"echo ok > >(cat ./payload.sh | bash)"#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } if from_node_id
                == &NodeId::new("expanded-procsub-body:command:sess-1:4:0:redir:0:0:0")
                && to_node_id
                    == &NodeId::new("expanded-procsub-body:command:sess-1:4:0:redir:0:0:1")
        )));
    }

    #[test]
    fn extract_pipeline_flow_connects_nested_payload_pipeline_units() {
        let summary = SessionSummary::new();
        let ctx = run_scoped_pass(&summary, r#"bash -c 'cat ./payload.sh | bash'"#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } if from_node_id == &NodeId::new("derived:sess-1:4:0:0")
                && to_node_id == &NodeId::new("derived:sess-1:4:0:1")
        )));
    }
}
