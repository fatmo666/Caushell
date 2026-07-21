use caushell_graph::{EdgeKind, NodeId};
use caushell_parse::SourceSpan;
use caushell_profile::{
    BindingOrigin, BoundInvocation, BoundValue, EffectKind, ResolveInvocationArtifactResult,
    ValueMaterialization,
};
use caushell_runner::{
    PendingMutation, RunnerContext, SessionTransformPass, SessionView,
    variable_value_artifact_node_id,
};
use caushell_types::{
    CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
    ProvenanceMaterializedValueState, ProvenanceProduceKind, ProvenanceVariableValueState,
    RuntimeInputCapture, RuntimeInputSource, SessionSummary, SessionVariableBinding,
    SessionVariableValue,
};

use crate::support::{
    ExecutionResolveRecordRef, graph_backed_execution_resolve_records, pipeline_has_upstream,
    redirection_parent_command_index, redirection_targets_stdin_payload,
    top_level_node_id_for_command, top_level_node_id_for_span,
};

pub struct ExtractValueProvenancePass;

impl SessionTransformPass for ExtractValueProvenancePass {
    fn name(&self) -> &'static str {
        "extract_value_provenance"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        let records = graph_backed_execution_resolve_records(ctx);
        let explicit_stdin_payload_sources = explicit_stdin_payload_sources(ctx, &records);
        let pipeline_stdin_payload_sources = pipeline_stdin_payload_sources(ctx, &records);
        let mut mutations = collect_variable_binding_provenance_mutations(ctx);
        mutations.extend(collect_variable_expansion_provenance_mutations(
            session.summary(),
            &records,
            ctx.request().sequence_no,
        ));
        mutations.extend(collect_runtime_input_provenance_mutations(
            &records,
            ctx.request().sequence_no,
            &explicit_stdin_payload_sources,
            &pipeline_stdin_payload_sources,
        ));

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_variable_binding_provenance_mutations(ctx: &RunnerContext) -> Vec<PendingMutation> {
    let binding_sources = current_request_variable_binding_sources(ctx);
    let mut latest_bindings = std::collections::BTreeMap::new();

    ctx.pending_mutations()
        .iter()
        .filter_map(|mutation| match mutation {
            PendingMutation::UpsertVariableBinding { binding } => Some(binding),
            _ => None,
        })
        .for_each(|binding| {
            latest_bindings.insert(binding.name.as_str(), binding);
        });

    latest_bindings
        .into_values()
        .filter_map(|binding| {
            binding_sources
                .get(binding.name.as_str())
                .map(|source_node_id| {
                    variable_binding_provenance_mutation(source_node_id.clone(), binding)
                })
        })
        .collect()
}

fn variable_binding_provenance_mutation(
    source_node_id: NodeId,
    binding: &SessionVariableBinding,
) -> PendingMutation {
    PendingMutation::AddProvenanceArtifact {
        source_node_id,
        node_id: variable_value_artifact_node_id(&binding.name, binding.observed_at),
        artifact: variable_value_artifact(binding),
        relation: EdgeKind::Produces,
        semantics: ProvenanceEdgeSemantics::Produce {
            produce_kind: ProvenanceProduceKind::VariableBinding,
            slot_name: Some(binding.name.clone()),
            normalized_command_name: None,
            domain_label: None,
        },
    }
}

fn current_request_variable_binding_sources(
    ctx: &RunnerContext,
) -> std::collections::BTreeMap<String, NodeId> {
    let mut sources = std::collections::BTreeMap::new();
    let Some(parsed) = ctx.parsed_command() else {
        return sources;
    };

    for declaration in &parsed.declaration_commands {
        if declaration.kind != caushell_parse::DeclarationCommandKind::Export {
            continue;
        }

        let Some(source_node_id) =
            top_level_node_id_for_span(ctx.request(), parsed, &declaration.top_level_span)
        else {
            continue;
        };
        for assignment in &declaration.assignments {
            sources.insert(assignment.name.clone(), source_node_id.clone());
        }
    }

    for (command_index, command) in parsed.commands.iter().enumerate() {
        let Some(command_name) = command.command_name.as_deref() else {
            continue;
        };

        if command_name != "export" {
            continue;
        }

        let Some(source_node_id) =
            top_level_node_id_for_command(ctx.request(), parsed, command_index)
        else {
            continue;
        };

        for token in &command.tokens {
            if let Some((name, _)) = token.text.split_once('=') {
                sources.insert(name.to_string(), source_node_id.clone());
            }
        }
    }

    for assignment_command in &parsed.assignment_commands {
        let Some(source_node_id) =
            top_level_node_id_for_span(ctx.request(), parsed, &assignment_command.top_level_span)
        else {
            continue;
        };

        for assignment in &assignment_command.assignments {
            sources.insert(assignment.name.clone(), source_node_id.clone());
        }
    }

    sources
}

fn collect_variable_expansion_provenance_mutations(
    summary: &SessionSummary,
    records: &[ExecutionResolveRecordRef<'_>],
    sequence_no: CommandSequenceNo,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for &record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        for (arg_index, (arg, resolution)) in resolved
            .materialized_projection
            .invocation
            .args
            .iter()
            .zip(resolved.materialized_projection.arg_resolutions.iter())
            .enumerate()
        {
            let Some(expansion) = variable_expansion(summary, resolution, sequence_no) else {
                if let Some(materialized_state) = materialized_value_state(resolution) {
                    let slot_name = slot_name_for_arg(&resolved.bound, &arg.span);

                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id: record.source_node_id().clone(),
                        node_id: materialized_value_artifact_node_id(
                            record.source_node_id(),
                            &format!("arg-{arg_index}"),
                        ),
                        artifact: ProvenanceArtifact::MaterializedValue {
                            source_kind: materialized_value_source_kind(resolution),
                            state: materialized_state,
                            version: materialized_value_version(summary, resolution, sequence_no),
                        },
                        relation: EdgeKind::Produces,
                        semantics: ProvenanceEdgeSemantics::Produce {
                            produce_kind: ProvenanceProduceKind::MaterializedValue,
                            slot_name,
                            normalized_command_name: Some(resolved.normalized_command_name.clone()),
                            domain_label: None,
                        },
                    });
                }

                continue;
            };

            let slot_name = slot_name_for_arg(&resolved.bound, &arg.span);
            let (node_id, artifact) = match expansion {
                VariableExpansion::SessionBinding(binding) => (
                    variable_value_artifact_node_id(&binding.name, binding.observed_at),
                    variable_value_artifact(binding),
                ),
                VariableExpansion::InheritedEnvironment {
                    name,
                    state,
                    version,
                } => (
                    inherited_env_artifact_node_id(&name, version),
                    inherited_env_value_artifact(&name, state, version),
                ),
            };

            mutations.push(PendingMutation::AddProvenanceArtifact {
                source_node_id: record.source_node_id().clone(),
                node_id,
                artifact,
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::VariableExpansion,
                    slot_name: slot_name.clone(),
                    normalized_command_name: Some(resolved.normalized_command_name.clone()),
                    domain_label: None,
                },
            });

            if let Some(materialized_state) = materialized_value_state(resolution) {
                mutations.push(PendingMutation::AddProvenanceArtifact {
                    source_node_id: record.source_node_id().clone(),
                    node_id: materialized_value_artifact_node_id(
                        record.source_node_id(),
                        &format!("arg-{arg_index}"),
                    ),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: materialized_value_source_kind(resolution),
                        state: materialized_state,
                        version: materialized_value_version(summary, resolution, sequence_no),
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name,
                        normalized_command_name: Some(resolved.normalized_command_name.clone()),
                        domain_label: None,
                    },
                });
            }
        }
    }

    mutations
}

enum VariableExpansion<'a> {
    SessionBinding(&'a SessionVariableBinding),
    InheritedEnvironment {
        name: String,
        state: ProvenanceVariableValueState,
        version: u64,
    },
}

fn variable_expansion<'a>(
    summary: &'a SessionSummary,
    resolution: &ValueMaterialization,
    sequence_no: CommandSequenceNo,
) -> Option<VariableExpansion<'a>> {
    match resolution {
        ValueMaterialization::ResolvedExactScalar {
            variable_name,
            origin,
            value,
        } => match origin {
            BindingOrigin::SessionBinding => Some(VariableExpansion::SessionBinding(
                summary.variable_binding(variable_name)?,
            )),
            BindingOrigin::InheritedEnvironment => Some(VariableExpansion::InheritedEnvironment {
                name: variable_name.clone(),
                state: ProvenanceVariableValueState::ExactScalar {
                    value: value.clone(),
                },
                version: sequence_no.0,
            }),
        },
        ValueMaterialization::ResolvedRuntimeProduced {
            variable_name,
            origin,
            value,
            kind,
        } => match origin {
            BindingOrigin::SessionBinding => Some(VariableExpansion::SessionBinding(
                summary.variable_binding(variable_name)?,
            )),
            BindingOrigin::InheritedEnvironment => Some(VariableExpansion::InheritedEnvironment {
                name: variable_name.clone(),
                state: ProvenanceVariableValueState::RuntimeProduced {
                    value: value.clone(),
                    value_kind: *kind,
                },
                version: sequence_no.0,
            }),
        },
        ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            origin,
            repr,
        } => match origin {
            BindingOrigin::SessionBinding => Some(VariableExpansion::SessionBinding(
                summary.variable_binding(variable_name)?,
            )),
            BindingOrigin::InheritedEnvironment => Some(VariableExpansion::InheritedEnvironment {
                name: variable_name.clone(),
                state: ProvenanceVariableValueState::OpaqueDynamic { repr: repr.clone() },
                version: sequence_no.0,
            }),
        },
        ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            origin,
            value,
        } => match origin {
            BindingOrigin::SessionBinding => Some(VariableExpansion::SessionBinding(
                summary.variable_binding(variable_name)?,
            )),
            BindingOrigin::InheritedEnvironment => Some(VariableExpansion::InheritedEnvironment {
                name: variable_name.clone(),
                state: ProvenanceVariableValueState::ExactScalar {
                    value: value.clone(),
                },
                version: sequence_no.0,
            }),
        },
        ValueMaterialization::RequiresRuntimeInput {
            source,
            capture,
            variable_name: Some(variable_name),
            origin: Some(origin),
        } => match origin {
            BindingOrigin::SessionBinding => Some(VariableExpansion::SessionBinding(
                summary.variable_binding(variable_name)?,
            )),
            BindingOrigin::InheritedEnvironment => {
                let runtime_input_source = source.to_runtime_input_source().expect(
                    "materialized runtime input binding should not use inherited-environment implicit source",
                );

                Some(VariableExpansion::InheritedEnvironment {
                    name: variable_name.clone(),
                    state: ProvenanceVariableValueState::RuntimeInput {
                        source: runtime_input_source,
                        capture: capture.clone().unwrap_or(RuntimeInputCapture::NotCaptured),
                    },
                    version: sequence_no.0,
                })
            }
        },
        ValueMaterialization::Static
        | ValueMaterialization::MissingBinding { .. }
        | ValueMaterialization::UnsupportedDynamicText { .. }
        | ValueMaterialization::RequiresRuntimeInput { .. } => None,
    }
}

fn collect_runtime_input_provenance_mutations(
    records: &[ExecutionResolveRecordRef<'_>],
    sequence_no: CommandSequenceNo,
    explicit_stdin_payload_sources: &std::collections::BTreeSet<NodeId>,
    pipeline_stdin_payload_sources: &std::collections::BTreeSet<NodeId>,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for &record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        let consumes_runtime_input_as_payload = resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload);
        let binds_variable_from_runtime_input = resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::BindVariableFromRuntimeInput);

        if !consumes_runtime_input_as_payload && !binds_variable_from_runtime_input {
            continue;
        }

        for input in &resolved.bound.bound_implicit_inputs {
            let Some(runtime_input_source) = input.source.to_runtime_input_source() else {
                continue;
            };

            if runtime_input_source == RuntimeInputSource::StdinPayload
                && (explicit_stdin_payload_sources.contains(record.source_node_id())
                    || pipeline_stdin_payload_sources.contains(record.source_node_id()))
            {
                continue;
            }

            mutations.push(PendingMutation::AddProvenanceArtifact {
                source_node_id: record.source_node_id().clone(),
                node_id: runtime_input_artifact_node_id(
                    record.source_node_id(),
                    runtime_input_source_name(runtime_input_source),
                ),
                artifact: ProvenanceArtifact::RuntimeInput {
                    source: runtime_input_source,
                    capture: RuntimeInputCapture::NotCaptured,
                    version: sequence_no.0,
                },
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::RuntimeInput,
                    slot_name: None,
                    normalized_command_name: Some(resolved.normalized_command_name.clone()),
                    domain_label: None,
                },
            });
        }
    }

    mutations
}

fn explicit_stdin_payload_sources(
    _ctx: &RunnerContext,
    records: &[ExecutionResolveRecordRef<'_>],
) -> std::collections::BTreeSet<NodeId> {
    records
        .iter()
        .filter_map(|record| {
            let parsed_scope = record.parsed_scope();
            parsed_scope
                .redirections
                .iter()
                .any(|redirection| {
                    redirection_parent_command_index(parsed_scope, redirection)
                        == Some(record.command_index())
                        && redirection_targets_stdin_payload(redirection)
                })
                .then_some(record.source_node_id().clone())
        })
        .collect()
}

fn pipeline_stdin_payload_sources(
    _ctx: &RunnerContext,
    records: &[ExecutionResolveRecordRef<'_>],
) -> std::collections::BTreeSet<NodeId> {
    records
        .iter()
        .filter_map(|record| {
            pipeline_has_upstream(record.parsed_scope(), record.command_index())
                .then(|| record.source_node_id().clone())
        })
        .collect()
}

fn slot_name_for_arg(invocation: &BoundInvocation, span: &SourceSpan) -> Option<String> {
    invocation
        .bound_parameters
        .iter()
        .find(|parameter| {
            parameter.values.iter().any(|value| {
                matches!(value, BoundValue::Argument { span: value_span, .. } if value_span == span)
            })
        })
        .map(|parameter| parameter.name.as_str().to_string())
}

fn materialized_value_artifact_node_id(source_node_id: &NodeId, suffix: &str) -> NodeId {
    NodeId::new(format!(
        "artifact:materialized-value:{}:{suffix}",
        source_node_id.0,
    ))
}

fn variable_value_artifact(binding: &SessionVariableBinding) -> ProvenanceArtifact {
    ProvenanceArtifact::VariableValue {
        name: binding.name.clone(),
        state: variable_value_state(&binding.value),
        exported: binding.exported,
        version: binding.observed_at.0,
    }
}

fn inherited_env_artifact_node_id(name: &str, version: u64) -> NodeId {
    NodeId::new(format!("artifact:inherited-env-value:{name}:{version}"))
}

fn runtime_input_artifact_node_id(source_node_id: &NodeId, source: &str) -> NodeId {
    NodeId::new(format!(
        "artifact:runtime-input:{}:{source}",
        source_node_id.0
    ))
}

fn inherited_env_value_artifact(
    name: &str,
    state: ProvenanceVariableValueState,
    version: u64,
) -> ProvenanceArtifact {
    ProvenanceArtifact::InheritedEnvValue {
        name: name.to_string(),
        state,
        version,
    }
}

fn variable_value_state(value: &SessionVariableValue) -> ProvenanceVariableValueState {
    match value {
        SessionVariableValue::ExactScalar(value) => ProvenanceVariableValueState::ExactScalar {
            value: value.clone(),
        },
        SessionVariableValue::RuntimeProduced { value, kind } => {
            ProvenanceVariableValueState::RuntimeProduced {
                value: value.clone(),
                value_kind: *kind,
            }
        }
        SessionVariableValue::OpaqueDynamic { repr } => {
            ProvenanceVariableValueState::OpaqueDynamic { repr: repr.clone() }
        }
        SessionVariableValue::RuntimeInput { source, capture } => {
            ProvenanceVariableValueState::RuntimeInput {
                source: *source,
                capture: capture.clone(),
            }
        }
    }
}

fn materialized_value_state(
    resolution: &ValueMaterialization,
) -> Option<ProvenanceMaterializedValueState> {
    match resolution {
        ValueMaterialization::Static => None,
        ValueMaterialization::ResolvedExactScalar { value, .. } => {
            Some(ProvenanceMaterializedValueState::ExactScalar {
                value: value.clone(),
            })
        }
        ValueMaterialization::ResolvedRuntimeProduced { value, kind, .. } => {
            Some(ProvenanceMaterializedValueState::RuntimeProduced {
                value: value.clone(),
                value_kind: *kind,
            })
        }
        ValueMaterialization::MissingBinding { variable_name } => {
            Some(ProvenanceMaterializedValueState::MissingBinding {
                variable_name: variable_name.clone(),
            })
        }
        ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            repr,
            ..
        } => Some(
            ProvenanceMaterializedValueState::UnsupportedDynamicBinding {
                variable_name: variable_name.clone(),
                repr: repr.clone(),
            },
        ),
        ValueMaterialization::UnsupportedDynamicText { text } => {
            Some(ProvenanceMaterializedValueState::UnsupportedDynamicText { text: text.clone() })
        }
        ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            value,
            ..
        } => Some(ProvenanceMaterializedValueState::UnsafeUnquotedScalar {
            variable_name: variable_name.clone(),
            value: value.clone(),
        }),
        ValueMaterialization::RequiresRuntimeInput { source, .. } => {
            Some(ProvenanceMaterializedValueState::RequiresRuntimeInput {
                source: source
                    .to_runtime_input_source()
                    .expect("implicit runtime input source must map to provenance runtime input"),
            })
        }
    }
}

fn materialized_value_source_kind(resolution: &ValueMaterialization) -> String {
    match resolution {
        ValueMaterialization::ResolvedExactScalar {
            variable_name,
            origin,
            ..
        }
        | ValueMaterialization::ResolvedRuntimeProduced {
            variable_name,
            origin,
            ..
        } => match origin {
            BindingOrigin::SessionBinding => format!("variable_expansion:{variable_name}"),
            BindingOrigin::InheritedEnvironment => {
                format!("inherited_environment:{variable_name}")
            }
        },
        ValueMaterialization::MissingBinding { variable_name } => {
            format!("variable_expansion:{variable_name}")
        }
        ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            origin,
            ..
        }
        | ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            origin,
            ..
        } => match origin {
            BindingOrigin::SessionBinding => format!("variable_expansion:{variable_name}"),
            BindingOrigin::InheritedEnvironment => {
                format!("inherited_environment:{variable_name}")
            }
        },
        ValueMaterialization::UnsupportedDynamicText { .. } => "dynamic_text".to_string(),
        ValueMaterialization::RequiresRuntimeInput {
            source,
            variable_name,
            origin,
            ..
        } => match (variable_name, origin) {
            (Some(variable_name), Some(BindingOrigin::SessionBinding)) => {
                format!("variable_expansion:{variable_name}")
            }
            (Some(variable_name), Some(BindingOrigin::InheritedEnvironment)) => {
                format!("inherited_environment:{variable_name}")
            }
            _ => format!("runtime_input:{}", source.as_str()),
        },
        ValueMaterialization::Static => "static".to_string(),
    }
}

fn materialized_value_version(
    summary: &SessionSummary,
    resolution: &ValueMaterialization,
    sequence_no: CommandSequenceNo,
) -> u64 {
    match resolution {
        ValueMaterialization::ResolvedExactScalar {
            variable_name,
            origin,
            ..
        }
        | ValueMaterialization::ResolvedRuntimeProduced {
            variable_name,
            origin,
            ..
        }
        | ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            origin,
            ..
        }
        | ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            origin,
            ..
        } => match origin {
            BindingOrigin::SessionBinding => summary
                .variable_binding(variable_name)
                .map(|binding| binding.observed_at.0)
                .unwrap_or(sequence_no.0),
            BindingOrigin::InheritedEnvironment => sequence_no.0,
        },
        ValueMaterialization::RequiresRuntimeInput {
            variable_name,
            origin,
            ..
        } => match (variable_name, origin) {
            (Some(variable_name), Some(BindingOrigin::SessionBinding)) => summary
                .variable_binding(variable_name)
                .map(|binding| binding.observed_at.0)
                .unwrap_or(sequence_no.0),
            (Some(_), Some(BindingOrigin::InheritedEnvironment)) | (None, _) | (_, None) => {
                sequence_no.0
            }
        },
        ValueMaterialization::MissingBinding { .. }
        | ValueMaterialization::UnsupportedDynamicText { .. }
        | ValueMaterialization::Static => sequence_no.0,
    }
}

fn runtime_input_source_name(source: RuntimeInputSource) -> &'static str {
    match source {
        RuntimeInputSource::StdinPayload => "stdin_payload",
        RuntimeInputSource::StdinData => "stdin_data",
        RuntimeInputSource::InteractiveSession => "interactive_session",
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractValueProvenancePass;
    use crate::{
        ExtractPipelineFlowPass, ExtractVariableBindingsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceEdgeSemantics, ProvenanceMaterializedValueState, ProvenanceProduceKind,
        ProvenanceVariableValueState, RuntimeMetadata, SessionFunctionBinding, SessionId,
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

    fn run_pass(summary: &SessionSummary, sequence_no: u64, command: &str) -> RunnerContext {
        run_pass_with_options(summary, sample_request(sequence_no, command), true)
    }

    fn run_pass_without_pipeline_flow(
        summary: &SessionSummary,
        sequence_no: u64,
        command: &str,
    ) -> RunnerContext {
        run_pass_with_options(summary, sample_request(sequence_no, command), false)
    }

    fn run_pass_with_request(summary: &SessionSummary, request: CheckRequest) -> RunnerContext {
        run_pass_with_options(summary, request, true)
    }

    fn run_pass_with_options(
        summary: &SessionSummary,
        request: CheckRequest,
        include_pipeline_flow: bool,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        if include_pipeline_flow {
            runner.register_session_transform_pass(ExtractPipelineFlowPass);
        }
        runner.register_session_transform_pass(ExtractVariableBindingsPass);
        runner.register_session_transform_pass(ExtractValueProvenancePass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(request);

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_value_provenance_stages_variable_binding_artifact_for_export_assignment() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 3, "export SCRIPT=build.sh");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:3:0"),
                    node_id: NodeId::new("artifact:variable-value:SCRIPT:3"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "SCRIPT".to_string(),
                        state: ProvenanceVariableValueState::ExactScalar {
                            value: "build.sh".to_string(),
                        },
                        exported: true,
                        version: 3,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::VariableBinding,
                        slot_name: Some("SCRIPT".to_string()),
                        normalized_command_name: None,
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_folds_duplicate_variable_bindings_to_final_value() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            1,
            r#"count=0; count=$((count + 1)); echo "$count""#,
        );

        let variable_artifacts = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddProvenanceArtifact {
                    node_id, artifact, ..
                } if *node_id == NodeId::new("artifact:variable-value:count:1") => Some(artifact),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(variable_artifacts.len(), 1);
        assert!(matches!(
            variable_artifacts[0],
            ProvenanceArtifact::VariableValue {
                state: ProvenanceVariableValueState::OpaqueDynamic { repr },
                ..
            } if repr == "$((count + 1))"
        ));
    }

    #[test]
    fn extract_value_provenance_stages_variable_consume_and_materialized_value_for_exact_scalar() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", true, CommandSequenceNo::new(1));

        let ctx = run_pass(&summary, 2, r#"bash "$SCRIPT""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:variable-value:SCRIPT:1"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "SCRIPT".to_string(),
                        state: ProvenanceVariableValueState::ExactScalar {
                            value: "build.sh".to_string(),
                        },
                        exported: true,
                        version: 1,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:2:0:arg-0"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "variable_expansion:SCRIPT".to_string(),
                        state: ProvenanceMaterializedValueState::ExactScalar {
                            value: "build.sh".to_string(),
                        },
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_variable_consume_and_unresolved_materialized_value_for_dynamic_binding()
     {
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable(
            "USER_CMD",
            "$payload",
            true,
            CommandSequenceNo::new(7),
        );

        let ctx = run_pass(&summary, 8, r#"bash "$USER_CMD""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:8:0"),
                    node_id: NodeId::new("artifact:variable-value:USER_CMD:7"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "USER_CMD".to_string(),
                        state: ProvenanceVariableValueState::OpaqueDynamic {
                            repr: "$payload".to_string(),
                        },
                        exported: true,
                        version: 7,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:8:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:8:0:arg-0"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "variable_expansion:USER_CMD".to_string(),
                        state: ProvenanceMaterializedValueState::UnsupportedDynamicBinding {
                            variable_name: "USER_CMD".to_string(),
                            repr: "$payload".to_string(),
                        },
                        version: 7,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_runtime_input_variable_consume_for_committed_binding() {
        let mut summary = SessionSummary::new();
        summary.set_runtime_input_variable(
            "USER_CMD",
            caushell_types::RuntimeInputSource::StdinData,
            caushell_types::RuntimeInputCapture::Descriptor {
                descriptor: "read USER_CMD".to_string(),
            },
            false,
            CommandSequenceNo::new(7),
        );

        let ctx = run_pass(&summary, 8, r#"bash -c "$USER_CMD""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:8:0"),
                    node_id: NodeId::new("artifact:variable-value:USER_CMD:7"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "USER_CMD".to_string(),
                        state: ProvenanceVariableValueState::RuntimeInput {
                            source: caushell_types::RuntimeInputSource::StdinData,
                            capture: caushell_types::RuntimeInputCapture::Descriptor {
                                descriptor: "read USER_CMD".to_string(),
                            },
                        },
                        exported: false,
                        version: 7,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:8:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:8:0:arg-1"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "variable_expansion:USER_CMD".to_string(),
                        state: ProvenanceMaterializedValueState::RequiresRuntimeInput {
                            source: caushell_types::RuntimeInputSource::StdinData,
                        },
                        version: 7,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_runtime_input_artifact_for_stdin_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass_without_pipeline_flow(&summary, 5, "bash -s");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:5:0"),
                    node_id: NodeId::new("artifact:runtime-input:command:sess-1:5:0:stdin_payload"),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinPayload,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_runtime_input_artifact_for_read_builtin() {
        let summary = SessionSummary::new();
        let ctx = run_pass_without_pipeline_flow(&summary, 5, "read USER_CMD");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:5:0"),
                    node_id: NodeId::new("artifact:runtime-input:command:sess-1:5:0:stdin_data"),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinData,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("read".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_skips_generic_runtime_input_when_explicit_stdin_is_present() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 5, "bash < ./payload.sh");

        assert!(
            !ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:5:0"),
                    node_id: NodeId::new("artifact:runtime-input:command:sess-1:5:0:stdin_payload"),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinPayload,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_skips_generic_runtime_input_when_pipeline_stream_is_present() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 5, "cat ./payload.sh | bash");

        assert!(
            !ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("pipeline-segment:sess-1:5:1"),
                    node_id: NodeId::new(
                        "artifact:runtime-input:pipeline-segment:sess-1:5:1:stdin_payload"
                    ),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinPayload,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_skips_generic_runtime_input_for_function_body_pipeline_sink() {
        let mut summary = SessionSummary::new();
        summary.upsert_function_binding(SessionFunctionBinding::new(
            "deploy",
            "cat ./payload.sh | bash;",
            CommandSequenceNo::new(1),
        ));
        let ctx = run_pass(&summary, 5, "deploy");

        assert!(
            !ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("derived-function:sess-1:5:0:1"),
                    node_id: NodeId::new(
                        "artifact:runtime-input:derived-function:sess-1:5:0:1:stdin_payload"
                    ),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinPayload,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_unsupported_dynamic_text_materialized_value() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 6, r#"bash "$(cat ./payload.sh)""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:6:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:6:0:arg-0"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "dynamic_text".to_string(),
                        state: ProvenanceMaterializedValueState::UnsupportedDynamicText {
                            text: "$(cat ./payload.sh)".to_string(),
                        },
                        version: 6,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_inherited_env_consume_for_exact_scalar() {
        let summary = SessionSummary::new();
        let mut request = sample_request(9, r#"bash -c "$USER_CMD""#);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_exact_scalar_variable("USER_CMD", "echo ok", true)
            .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly);

        let ctx = run_pass_with_request(&summary, request);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:9:0"),
                    node_id: NodeId::new("artifact:inherited-env-value:USER_CMD:9"),
                    artifact: ProvenanceArtifact::InheritedEnvValue {
                        name: "USER_CMD".to_string(),
                        state: ProvenanceVariableValueState::ExactScalar {
                            value: "echo ok".to_string(),
                        },
                        version: 9,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:9:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:9:0:arg-1"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "inherited_environment:USER_CMD".to_string(),
                        state: ProvenanceMaterializedValueState::ExactScalar {
                            value: "echo ok".to_string(),
                        },
                        version: 9,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_stages_inherited_env_runtime_input_consume() {
        let summary = SessionSummary::new();
        let mut request = sample_request(9, r#"bash -c "$USER_CMD""#);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_runtime_input_variable(
                "USER_CMD",
                caushell_types::RuntimeInputSource::StdinData,
                caushell_types::RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
                true,
            )
            .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly);

        let ctx = run_pass_with_request(&summary, request);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:9:0"),
                    node_id: NodeId::new("artifact:inherited-env-value:USER_CMD:9"),
                    artifact: ProvenanceArtifact::InheritedEnvValue {
                        name: "USER_CMD".to_string(),
                        state: ProvenanceVariableValueState::RuntimeInput {
                            source: caushell_types::RuntimeInputSource::StdinData,
                            capture: caushell_types::RuntimeInputCapture::Descriptor {
                                descriptor: "read USER_CMD".to_string(),
                            },
                        },
                        version: 9,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:9:0"),
                    node_id: NodeId::new("artifact:materialized-value:command:sess-1:9:0:arg-1"),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "inherited_environment:USER_CMD".to_string(),
                        state: ProvenanceMaterializedValueState::RequiresRuntimeInput {
                            source: caushell_types::RuntimeInputSource::StdinData,
                        },
                        version: 9,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("payload".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_skips_generic_runtime_input_for_shell_payload_child_with_explicit_stdin()
     {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 5, r#"bash -lc 'bash < ./payload.sh'"#);

        assert!(
            !ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("expanded-shell-payload:command:sess-1:5:0:0"),
                    node_id: NodeId::new(
                        "artifact:runtime-input:expanded-shell-payload:command:sess-1:5:0:0:stdin_payload"
                    ),
                    artifact: ProvenanceArtifact::RuntimeInput {
                        source: caushell_types::RuntimeInputSource::StdinPayload,
                        capture: caushell_types::RuntimeInputCapture::NotCaptured,
                        version: 5,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::RuntimeInput,
                        slot_name: None,
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_projects_variable_expansion_for_shell_payload_child() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", true, CommandSequenceNo::new(1));

        let ctx = run_pass(&summary, 2, r#"bash -lc 'bash "$SCRIPT"'"#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("expanded-shell-payload:command:sess-1:2:0:0"),
                    node_id: NodeId::new("artifact:variable-value:SCRIPT:1"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "SCRIPT".to_string(),
                        state: ProvenanceVariableValueState::ExactScalar {
                            value: "build.sh".to_string(),
                        },
                        exported: true,
                        version: 1,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_value_provenance_projects_materialized_value_for_shell_payload_child() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", true, CommandSequenceNo::new(1));

        let ctx = run_pass(&summary, 2, r#"bash -lc 'bash "$SCRIPT"'"#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("expanded-shell-payload:command:sess-1:2:0:0"),
                    node_id: NodeId::new(
                        "artifact:materialized-value:expanded-shell-payload:command:sess-1:2:0:0:arg-0"
                    ),
                    artifact: ProvenanceArtifact::MaterializedValue {
                        source_kind: "variable_expansion:SCRIPT".to_string(),
                        state: ProvenanceMaterializedValueState::ExactScalar {
                            value: "build.sh".to_string(),
                        },
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );
    }
}
