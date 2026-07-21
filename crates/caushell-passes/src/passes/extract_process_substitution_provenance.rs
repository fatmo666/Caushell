use std::collections::BTreeMap;

use crate::support::{
    graph_backed_execution_resolve_records, normalized_command_names_by_source_node,
    redirection_targets_stdin_payload,
};
use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::{
    BoundParameter, BoundValue, PathPurpose, PathRole, PayloadSource,
    ResolveInvocationArtifactResult, SemanticType,
};
use caushell_runner::{
    ExecutionUnitOriginKind, ExecutionUnitOriginLocator, ExecutionUnitResolveRecord,
    PendingMutation, ProcessSubstitutionLocationKind, ProcessSubstitutionOuterRelation,
    RunnerContext, SessionTransformPass, SessionView,
};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceDomainLabel, ProvenanceEdgeSemantics,
    ProvenanceProduceKind, ResolvedPathPurpose, ResolvedPathRole,
};

pub struct ExtractProcessSubstitutionProvenancePass;

impl SessionTransformPass for ExtractProcessSubstitutionProvenancePass {
    fn name(&self) -> &'static str {
        "extract_process_substitution_provenance"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let normalized_command_names = normalized_command_names_by_source_node(ctx);
        let records = collect_process_substitution_provenance_records(ctx);

        for record in &records {
            let artifact_node_id =
                process_substitution_channel_artifact_node_id(ctx.request(), &record.artifact_key);
            let artifact = ProvenanceArtifact::ProcessSubstitutionChannel {
                expression: record.expression_text.clone(),
                body_text: record.body_text.clone(),
                operator: record.operator.as_str().to_string(),
                version: ctx.request().sequence_no.0,
            };

            match record.operator {
                caushell_parse::ProcessSubstitutionOperator::Input => {
                    for producer_node_id in &record.derived_command_node_ids {
                        ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                            source_node_id: producer_node_id.clone(),
                            node_id: artifact_node_id.clone(),
                            artifact: artifact.clone(),
                            relation: EdgeKind::Produces,
                            semantics: ProvenanceEdgeSemantics::Produce {
                                produce_kind: ProvenanceProduceKind::ProcessSubstitutionOutput,
                                slot_name: None,
                                normalized_command_name: normalized_command_names
                                    .get(producer_node_id)
                                    .cloned(),
                                domain_label: None,
                            },
                        });
                    }

                    stage_outer_relation(
                        ctx,
                        &normalized_command_names,
                        &record.parent_execution_node_id,
                        &artifact_node_id,
                        artifact,
                        &record.outer_relation,
                    );
                }
                caushell_parse::ProcessSubstitutionOperator::Output => {
                    stage_outer_relation(
                        ctx,
                        &normalized_command_names,
                        &record.parent_execution_node_id,
                        &artifact_node_id,
                        artifact.clone(),
                        &record.outer_relation,
                    );

                    for consumer_node_id in &record.derived_command_node_ids {
                        ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                            source_node_id: consumer_node_id.clone(),
                            node_id: artifact_node_id.clone(),
                            artifact: artifact.clone(),
                            relation: EdgeKind::Consumes,
                            semantics: ProvenanceEdgeSemantics::Consume {
                                consume_kind: ProvenanceConsumeKind::StdinImplicit,
                                slot_name: None,
                                normalized_command_name: normalized_command_names
                                    .get(consumer_node_id)
                                    .cloned(),
                                domain_label: None,
                            },
                        });
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ProcessSubstitutionArtifactKey {
    BodyLocator {
        parent_node_id: NodeId,
        location_kind: ProcessSubstitutionLocationKind,
        outer_index: usize,
        location_subindex: usize,
        substitution_index: usize,
    },
}

#[derive(Debug, Clone)]
struct ProcessSubstitutionProvenanceRecord {
    artifact_key: ProcessSubstitutionArtifactKey,
    expression_text: String,
    body_text: String,
    operator: caushell_parse::ProcessSubstitutionOperator,
    parent_execution_node_id: NodeId,
    outer_relation: ProcessSubstitutionOuterRelation,
    derived_command_node_ids: Vec<NodeId>,
}

fn collect_process_substitution_provenance_records(
    ctx: &RunnerContext,
) -> Vec<ProcessSubstitutionProvenanceRecord> {
    let graph_backed_records = graph_backed_execution_resolve_records(ctx);
    let records_by_node_id: BTreeMap<NodeId, &ExecutionUnitResolveRecord> = ctx
        .execution_unit_resolve_records()
        .iter()
        .map(|record| (record.source_node_id.clone(), record))
        .collect();
    let mut grouped: BTreeMap<ProcessSubstitutionArtifactKey, ProcessSubstitutionProvenanceRecord> =
        BTreeMap::new();

    for record_ref in graph_backed_records {
        let Some(record) = records_by_node_id.get(record_ref.source_node_id()).copied() else {
            continue;
        };
        if record.origin_kind != ExecutionUnitOriginKind::ProcessSubstitutionBody {
            continue;
        }
        let ExecutionUnitOriginLocator::ProcessSubstitutionBody {
            location_kind,
            outer_index,
            location_subindex,
            substitution_index,
        } = record.origin_locator
        else {
            continue;
        };
        let Some(parent_record) = records_by_node_id
            .get(&record.parent_execution_node_id)
            .copied()
        else {
            continue;
        };
        let Some(descriptor) = process_substitution_descriptor_from_parent(
            parent_record,
            location_kind,
            outer_index,
            location_subindex,
            substitution_index,
        ) else {
            continue;
        };

        let entry = grouped
            .entry(descriptor.artifact_key.clone())
            .or_insert_with(|| descriptor);
        if !entry
            .derived_command_node_ids
            .contains(&record.source_node_id)
        {
            entry
                .derived_command_node_ids
                .push(record.source_node_id.clone());
        }
    }

    grouped.into_values().collect()
}

fn process_substitution_descriptor_from_parent(
    parent_record: &ExecutionUnitResolveRecord,
    location_kind: ProcessSubstitutionLocationKind,
    outer_index: usize,
    location_subindex: usize,
    substitution_index: usize,
) -> Option<ProcessSubstitutionProvenanceRecord> {
    match location_kind {
        ProcessSubstitutionLocationKind::Argument => {
            let ResolveInvocationArtifactResult::Resolved(resolved) = &parent_record.result else {
                return None;
            };
            let parameter = resolved.bound.bound_parameters.get(outer_index)?;
            let value = parameter.values.get(location_subindex)?;
            let BoundValue::Argument {
                text, node_kind, ..
            } = value
            else {
                return None;
            };
            if node_kind != "process_substitution" {
                return None;
            }
            let substitution =
                caushell_parse::parse_process_substitutions(text, parent_record.shell_kind)
                    .ok()?
                    .into_iter()
                    .nth(substitution_index)?;

            Some(ProcessSubstitutionProvenanceRecord {
                artifact_key: ProcessSubstitutionArtifactKey::BodyLocator {
                    parent_node_id: parent_record.source_node_id.clone(),
                    location_kind: ProcessSubstitutionLocationKind::Argument,
                    outer_index,
                    location_subindex,
                    substitution_index,
                },
                expression_text: substitution.text.clone(),
                body_text: substitution.body_text.clone(),
                operator: substitution.operator,
                parent_execution_node_id: parent_record.source_node_id.clone(),
                outer_relation: process_substitution_argument_outer_relation(
                    parameter,
                    substitution.operator,
                ),
                derived_command_node_ids: Vec::new(),
            })
        }
        ProcessSubstitutionLocationKind::Redirection => {
            let parsed_scope = &parent_record.parsed_scope;
            let redirection = parsed_scope.redirections.get(outer_index)?;
            let target = redirection.target.as_ref()?;
            if target.node_kind != "process_substitution" {
                return None;
            }
            let substitution =
                caushell_parse::parse_process_substitutions(&target.text, parent_record.shell_kind)
                    .ok()?
                    .into_iter()
                    .nth(substitution_index)?;

            Some(ProcessSubstitutionProvenanceRecord {
                artifact_key: ProcessSubstitutionArtifactKey::BodyLocator {
                    parent_node_id: parent_record.source_node_id.clone(),
                    location_kind: ProcessSubstitutionLocationKind::Redirection,
                    outer_index,
                    location_subindex,
                    substitution_index,
                },
                expression_text: substitution.text.clone(),
                body_text: substitution.body_text.clone(),
                operator: substitution.operator,
                parent_execution_node_id: parent_record.source_node_id.clone(),
                outer_relation: process_substitution_redirection_outer_relation(
                    redirection,
                    outer_index,
                    substitution.operator,
                ),
                derived_command_node_ids: Vec::new(),
            })
        }
    }
}

fn stage_outer_relation(
    ctx: &mut RunnerContext,
    normalized_command_names: &std::collections::BTreeMap<NodeId, String>,
    source_node_id: &NodeId,
    artifact_node_id: &NodeId,
    artifact: ProvenanceArtifact,
    relation: &ProcessSubstitutionOuterRelation,
) {
    match relation {
        ProcessSubstitutionOuterRelation::Consume {
            consume_kind,
            slot_name,
            domain_label,
        } => {
            ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                source_node_id: source_node_id.clone(),
                node_id: artifact_node_id.clone(),
                artifact,
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: *consume_kind,
                    slot_name: slot_name.clone(),
                    normalized_command_name: normalized_command_names.get(source_node_id).cloned(),
                    domain_label: domain_label.clone(),
                },
            });
        }
        ProcessSubstitutionOuterRelation::Produce {
            produce_kind,
            slot_name,
            domain_label,
        } => {
            ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                source_node_id: source_node_id.clone(),
                node_id: artifact_node_id.clone(),
                artifact,
                relation: EdgeKind::Produces,
                semantics: ProvenanceEdgeSemantics::Produce {
                    produce_kind: *produce_kind,
                    slot_name: slot_name.clone(),
                    normalized_command_name: normalized_command_names.get(source_node_id).cloned(),
                    domain_label: domain_label.clone(),
                },
            });
        }
    }
}

fn process_substitution_channel_artifact_node_id(
    request: &caushell_types::CheckRequest,
    record_key: &ProcessSubstitutionArtifactKey,
) -> NodeId {
    match record_key {
        ProcessSubstitutionArtifactKey::BodyLocator {
            parent_node_id,
            location_kind,
            outer_index,
            location_subindex,
            substitution_index,
        } => NodeId::new(format!(
            "artifact:process-substitution-channel:{}:{}:{}:{}:{}:{}:{}",
            request.session_id.0.as_str(),
            request.sequence_no.0,
            parent_node_id.0,
            match location_kind {
                ProcessSubstitutionLocationKind::Argument => "arg",
                ProcessSubstitutionLocationKind::Redirection => "redir",
            },
            outer_index,
            location_subindex,
            substitution_index,
        )),
    }
}

fn process_substitution_argument_outer_relation(
    parameter: &BoundParameter,
    operator: caushell_parse::ProcessSubstitutionOperator,
) -> ProcessSubstitutionOuterRelation {
    let slot_name = Some(parameter.name.as_str().to_string());
    let domain_label = process_substitution_domain_label(&parameter.semantic);

    match operator {
        caushell_parse::ProcessSubstitutionOperator::Input => {
            ProcessSubstitutionOuterRelation::Consume {
                consume_kind: process_substitution_argument_consume_kind(parameter),
                slot_name,
                domain_label,
            }
        }
        caushell_parse::ProcessSubstitutionOperator::Output => {
            ProcessSubstitutionOuterRelation::Produce {
                produce_kind: ProvenanceProduceKind::ProcessSubstitutionOutput,
                slot_name,
                domain_label,
            }
        }
    }
}

fn process_substitution_argument_consume_kind(parameter: &BoundParameter) -> ProvenanceConsumeKind {
    match parameter.semantic {
        SemanticType::Path(path) => process_substitution_path_consume_kind(path.role, path.purpose),
        SemanticType::Payload(payload) if payload.source == PayloadSource::ScriptFileRef => {
            ProvenanceConsumeKind::ScriptSource
        }
        SemanticType::PlainValue
        | SemanticType::Payload(_)
        | SemanticType::CommandRef(_)
        | SemanticType::StructuredValue(_)
        | SemanticType::Endpoint(_)
        | SemanticType::ProcessTarget(_)
        | SemanticType::InProcessCodeLoad(_) => ProvenanceConsumeKind::PathRead,
        SemanticType::PackageLocator(_) => ProvenanceConsumeKind::PackageLocator,
    }
}

fn process_substitution_redirection_outer_relation(
    redirection: &caushell_parse::RedirectionFact,
    redirection_index: usize,
    operator: caushell_parse::ProcessSubstitutionOperator,
) -> ProcessSubstitutionOuterRelation {
    let slot_name = Some(format!("redirect_target_{redirection_index}"));

    match operator {
        caushell_parse::ProcessSubstitutionOperator::Input => {
            ProcessSubstitutionOuterRelation::Consume {
                consume_kind: if redirection_targets_stdin_payload(redirection) {
                    ProvenanceConsumeKind::StdinExplicit
                } else {
                    ProvenanceConsumeKind::PathRead
                },
                slot_name,
                domain_label: None,
            }
        }
        caushell_parse::ProcessSubstitutionOperator::Output => {
            ProcessSubstitutionOuterRelation::Produce {
                produce_kind: ProvenanceProduceKind::ProcessSubstitutionOutput,
                slot_name,
                domain_label: None,
            }
        }
    }
}

fn process_substitution_domain_label(semantic: &SemanticType) -> Option<ProvenanceDomainLabel> {
    let SemanticType::Path(path) = semantic else {
        return None;
    };

    Some(ProvenanceDomainLabel::Path {
        role: resolved_path_role_for_process_substitution(path.role),
        purpose: path
            .purpose
            .map(resolved_path_purpose_for_process_substitution),
    })
}

fn process_substitution_path_consume_kind(
    role: PathRole,
    purpose: Option<PathPurpose>,
) -> ProvenanceConsumeKind {
    match role {
        PathRole::Config => match purpose {
            Some(PathPurpose::ProjectConfig) => ProvenanceConsumeKind::ProjectConfigSource,
            Some(PathPurpose::ToolConfig) => ProvenanceConsumeKind::ToolConfigSource,
            Some(PathPurpose::TaskConfig) => ProvenanceConsumeKind::TaskDefinitionSource,
            Some(PathPurpose::ScriptSource) => ProvenanceConsumeKind::ScriptSource,
            Some(PathPurpose::InProcessCode) => ProvenanceConsumeKind::InProcessCodeSource,
            Some(PathPurpose::StartupConfig)
            | Some(PathPurpose::GenericOperand)
            | Some(PathPurpose::WorkingDirectory)
            | None => ProvenanceConsumeKind::StartupConfigSource,
        },
        PathRole::Read | PathRole::Write | PathRole::Target | PathRole::CwdAnchor => {
            match purpose {
                Some(PathPurpose::ScriptSource) => ProvenanceConsumeKind::ScriptSource,
                Some(PathPurpose::InProcessCode) => ProvenanceConsumeKind::InProcessCodeSource,
                Some(PathPurpose::StartupConfig) => ProvenanceConsumeKind::StartupConfigSource,
                Some(PathPurpose::ProjectConfig) => ProvenanceConsumeKind::ProjectConfigSource,
                Some(PathPurpose::ToolConfig) => ProvenanceConsumeKind::ToolConfigSource,
                Some(PathPurpose::TaskConfig) => ProvenanceConsumeKind::TaskDefinitionSource,
                Some(PathPurpose::GenericOperand) | Some(PathPurpose::WorkingDirectory) | None => {
                    ProvenanceConsumeKind::PathRead
                }
            }
        }
        PathRole::MetadataMutation => ProvenanceConsumeKind::PathRead,
    }
}

fn resolved_path_role_for_process_substitution(role: PathRole) -> ResolvedPathRole {
    match role {
        PathRole::Read => ResolvedPathRole::Read,
        PathRole::Write => ResolvedPathRole::Write,
        PathRole::MetadataMutation => ResolvedPathRole::MetadataMutation,
        PathRole::Target => ResolvedPathRole::Target,
        PathRole::Config => ResolvedPathRole::Config,
        PathRole::CwdAnchor => ResolvedPathRole::CwdAnchor,
    }
}

fn resolved_path_purpose_for_process_substitution(purpose: PathPurpose) -> ResolvedPathPurpose {
    match purpose {
        PathPurpose::GenericOperand => ResolvedPathPurpose::GenericOperand,
        PathPurpose::ScriptSource => ResolvedPathPurpose::ScriptSource,
        PathPurpose::InProcessCode => ResolvedPathPurpose::InProcessCode,
        PathPurpose::StartupConfig => ResolvedPathPurpose::StartupConfig,
        PathPurpose::ProjectConfig => ResolvedPathPurpose::ProjectConfig,
        PathPurpose::ToolConfig => ResolvedPathPurpose::ToolConfig,
        PathPurpose::TaskConfig => ResolvedPathPurpose::TaskConfig,
        PathPurpose::WorkingDirectory => ResolvedPathPurpose::WorkingDirectory,
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractProcessSubstitutionProvenancePass;
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceEdgeSemantics, ProvenanceProduceKind, RuntimeMetadata, SessionId, SessionSummary,
        ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(6),
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
        runner.register_session_transform_pass(ExtractProcessSubstitutionProvenancePass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn process_substitution_provenance_bridges_inner_producer_to_outer_argument_consumer() {
        let ctx = run_pass(r#"cat <(curl https://example.test/payload.sh)"#);
        let artifact_node_id = NodeId::new(
            "artifact:process-substitution-channel:sess-1:6:command:sess-1:6:0:arg:0:0:0",
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new(
                        "expanded-procsub-body:command:sess-1:6:0:arg:0:0:0"
                    ),
                    node_id: artifact_node_id.clone(),
                    artifact: ProvenanceArtifact::ProcessSubstitutionChannel {
                        expression: "<(curl https://example.test/payload.sh)".to_string(),
                        body_text: "curl https://example.test/payload.sh".to_string(),
                        operator: "input".to_string(),
                        version: 6,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ProcessSubstitutionOutput,
                        slot_name: None,
                        normalized_command_name: Some("curl".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddProvenanceArtifact {
                    source_node_id,
                    node_id,
                    artifact:
                        ProvenanceArtifact::ProcessSubstitutionChannel {
                            expression,
                            body_text,
                            operator,
                            version,
                        },
                    relation: EdgeKind::Consumes,
                    semantics:
                        ProvenanceEdgeSemantics::Consume {
                            consume_kind: ProvenanceConsumeKind::PathRead,
                            normalized_command_name,
                            ..
                        },
                } if source_node_id == &NodeId::new("command:sess-1:6:0")
                    && node_id == &artifact_node_id
                    && expression == "<(curl https://example.test/payload.sh)"
                    && body_text == "curl https://example.test/payload.sh"
                    && operator == "input"
                    && *version == 6
                    && normalized_command_name.as_deref() == Some("cat")
            )
        }));
    }

    #[test]
    fn process_substitution_provenance_bridges_outer_producer_to_inner_stdin_consumer() {
        let ctx = run_pass(r#"echo ok > >(bash)"#);
        let artifact_node_id = NodeId::new(
            "artifact:process-substitution-channel:sess-1:6:command:sess-1:6:0:redir:0:0:0",
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddProvenanceArtifact {
                    source_node_id,
                    node_id,
                    artifact:
                        ProvenanceArtifact::ProcessSubstitutionChannel {
                            expression,
                            body_text,
                            operator,
                            version,
                        },
                    relation: EdgeKind::Produces,
                    semantics:
                        ProvenanceEdgeSemantics::Produce {
                            produce_kind: ProvenanceProduceKind::ProcessSubstitutionOutput,
                            ..
                        },
                } if source_node_id == &NodeId::new("command:sess-1:6:0")
                    && node_id == &artifact_node_id
                    && expression == ">(bash)"
                    && body_text == "bash"
                    && operator == "output"
                    && *version == 6
            )
        }));

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new(
                        "expanded-procsub-body:command:sess-1:6:0:redir:0:0:0"
                    ),
                    node_id: artifact_node_id,
                    artifact: ProvenanceArtifact::ProcessSubstitutionChannel {
                        expression: ">(bash)".to_string(),
                        body_text: "bash".to_string(),
                        operator: "output".to_string(),
                        version: 6,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StdinImplicit,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }
}
