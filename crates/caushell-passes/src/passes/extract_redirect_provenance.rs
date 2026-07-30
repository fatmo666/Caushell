use std::collections::BTreeMap;

use caushell_graph::{EdgeKind, NodeId};
use caushell_parse::RedirectionKind;
use caushell_profile::ResolveInvocationArtifactResult;
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    InlineShellContentCarrier, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
};

use crate::path::{
    collect_redirection_path_facts, provenance_artifact_for_path, provenance_path_artifact_node_id,
};
use crate::support::{
    graph_backed_execution_resolve_records, redirection_parent_command_index,
    redirection_targets_stdin_payload, source_node_id_for_redirection,
};

pub struct ExtractRedirectProvenancePass;

impl SessionTransformPass for ExtractRedirectProvenancePass {
    fn name(&self) -> &'static str {
        "extract_redirect_provenance"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let mut mutations = Vec::new();
        let cwd = ctx.request().shell_state_before.cwd();
        let home = ctx.request().home.as_deref();

        for record in graph_backed_execution_resolve_records(ctx) {
            let parsed_scope = record.parsed_scope();
            let normalized_command_name = match record.result() {
                ResolveInvocationArtifactResult::Resolved(resolved) => {
                    Some(resolved.normalized_command_name.clone())
                }
                _ => None,
            };
            let path_by_redirection_index = redirection_paths_by_index(parsed_scope, cwd, home);

            for (redirection_index, redirection) in parsed_scope.redirections.iter().enumerate() {
                if redirection_parent_command_index(parsed_scope, redirection)
                    != Some(record.command_index())
                {
                    continue;
                }
                if !redirection_targets_stdin_payload(redirection) {
                    continue;
                }

                let Some(mutation) = project_stdin_redirection_provenance_mutation(
                    ctx.request().sequence_no.0,
                    record.source_node_id(),
                    normalized_command_name.clone(),
                    redirection_index,
                    redirection,
                    path_by_redirection_index.get(&redirection_index),
                ) else {
                    continue;
                };

                mutations.push(mutation);
            }
        }

        if let Some(parsed_command) = ctx.parsed_command() {
            let path_by_redirection_index = redirection_paths_by_index(parsed_command, cwd, home);

            for (redirection_index, redirection) in parsed_command.redirections.iter().enumerate() {
                if redirection_parent_command_index(parsed_command, redirection).is_some() {
                    continue;
                }
                if !redirection_targets_stdin_payload(redirection) {
                    continue;
                }

                let source_node_id =
                    source_node_id_for_redirection(ctx.request(), parsed_command, redirection);

                let Some(mutation) = project_stdin_redirection_provenance_mutation(
                    ctx.request().sequence_no.0,
                    &source_node_id,
                    None,
                    redirection_index,
                    redirection,
                    path_by_redirection_index.get(&redirection_index),
                ) else {
                    continue;
                };

                mutations.push(mutation);
            }
        }

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

fn redirection_paths_by_index(
    parsed_command: &caushell_parse::ParsedCommandArtifact,
    cwd: &str,
    home: Option<&str>,
) -> BTreeMap<usize, String> {
    collect_redirection_path_facts(parsed_command, cwd, home)
        .into_iter()
        .filter_map(|record| {
            let concrete_path = record.resolution.concrete_path()?.to_string();
            Some((record.redirection_index, concrete_path))
        })
        .collect()
}

fn project_stdin_redirection_provenance_mutation(
    version: u64,
    source_node_id: &NodeId,
    normalized_command_name: Option<String>,
    redirection_index: usize,
    redirection: &caushell_parse::RedirectionFact,
    path: Option<&String>,
) -> Option<PendingMutation> {
    let slot_name = stdin_redirection_slot_name(redirection, redirection_index);

    let (node_id, artifact) = match redirection.kind {
        RedirectionKind::File => {
            let path = path?;
            (
                provenance_path_artifact_node_id(path),
                provenance_artifact_for_path(path),
            )
        }
        RedirectionKind::HereString => {
            let content = redirection.content.as_ref()?;
            (
                inline_shell_content_artifact_node_id(source_node_id, redirection_index),
                ProvenanceArtifact::InlineShellContent {
                    carrier: InlineShellContentCarrier::HereString,
                    text: content.text.clone(),
                    quoted: content.quoted,
                    node_kind: content.node_kind.clone(),
                    version,
                },
            )
        }
        RedirectionKind::HereDoc => {
            let content = redirection.content.as_ref()?;
            (
                inline_shell_content_artifact_node_id(source_node_id, redirection_index),
                ProvenanceArtifact::InlineShellContent {
                    carrier: InlineShellContentCarrier::HereDoc,
                    text: content.text.clone(),
                    quoted: content.quoted,
                    node_kind: content.node_kind.clone(),
                    version,
                },
            )
        }
    };

    Some(PendingMutation::AddProvenanceArtifact {
        source_node_id: source_node_id.clone(),
        node_id,
        artifact,
        relation: EdgeKind::Consumes,
        semantics: ProvenanceEdgeSemantics::Consume {
            consume_kind: ProvenanceConsumeKind::StdinExplicit,
            slot_name: Some(slot_name),
            normalized_command_name,
            domain_label: None,
        },
    })
}

fn stdin_redirection_slot_name(
    redirection: &caushell_parse::RedirectionFact,
    redirection_index: usize,
) -> String {
    match redirection.kind {
        RedirectionKind::File => format!("redirect_target_{redirection_index}"),
        RedirectionKind::HereString | RedirectionKind::HereDoc => {
            format!("redirect_content_{redirection_index}")
        }
    }
}

fn inline_shell_content_artifact_node_id(
    source_node_id: &NodeId,
    redirection_index: usize,
) -> NodeId {
    NodeId::new(format!(
        "artifact:inline-shell-content:{}:{redirection_index}",
        source_node_id.0
    ))
}

#[cfg(test)]
mod tests {
    use super::ExtractRedirectProvenancePass;
    use crate::{
        ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, InlineShellContentCarrier, ProvenanceArtifact,
        ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuntimeMetadata, SessionId, SessionSummary,
        ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(3),
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

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPipelineFlowPass);
        runner.register_session_transform_pass(ExtractRedirectProvenancePass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_redirect_provenance_stages_explicit_stdin_path_consume() {
        let ctx = run_pass("bash < ./payload.sh");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:3:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
                    artifact: ProvenanceArtifact::PathContent {
                        path: "/tmp/project/payload.sh".to_string(),
                        version: None,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StdinExplicit,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_redirect_provenance_stages_herestring_inline_content() {
        let ctx = run_pass(r#"bash <<< "echo ok""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:3:0"),
                    node_id: NodeId::new("artifact:inline-shell-content:command:sess-1:3:0:0"),
                    artifact: ProvenanceArtifact::InlineShellContent {
                        carrier: InlineShellContentCarrier::HereString,
                        text: "echo ok".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        version: 3,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StdinExplicit,
                        slot_name: Some("redirect_content_0".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_redirect_provenance_uses_pipeline_segment_as_redirection_owner() {
        let ctx = run_pass("cat < ./payload.sh | bash");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
                    artifact: ProvenanceArtifact::PathContent {
                        path: "/tmp/project/payload.sh".to_string(),
                        version: None,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StdinExplicit,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: Some("cat".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_redirect_provenance_projects_shell_payload_child_redirection_owner() {
        let ctx = run_pass(r#"bash -lc 'cat < ./payload.sh'"#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("expanded-shell-payload:command:sess-1:3:0:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
                    artifact: ProvenanceArtifact::PathContent {
                        path: "/tmp/project/payload.sh".to_string(),
                        version: None,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StdinExplicit,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: Some("cat".to_string()),
                        domain_label: None,
                    },
                })
        );
    }
}
