//! Data-origin links for native template replacements, shared by provenance passes.
use caushell_graph::EdgeKind;
use caushell_profile::BoundValue;
use caushell_runner::{PendingMutation, RunnerContext, SessionView};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuntimeInputSource,
};

/// Reify compiler-owned data holes before ordinary shell-frame replay. A job
/// may run `set` or `shift`; that cannot alter replacements already performed
/// by the native tool. User-written positional references never enter here.
pub(crate) fn bind_symbolic_template_inputs(
    parsed: &mut caushell_parse::ParsedCommandArtifact,
    arguments: &[caushell_profile::ProjectedArg],
    origin: &caushell_runner::NativeTemplateInput,
) -> bool {
    if parsed.raw_command != origin.source_text {
        return false;
    }
    let mut owned = 0;
    for command in &mut parsed.commands {
        for token in &mut command.tokens {
            if !origin.data_ranges.iter().any(|range| {
                range.start == token.span.start_byte && range.end == token.span.end_byte
            }) {
                continue;
            }
            let batch = token.text == "$@";
            let position = if batch {
                Some(1)
            } else {
                token
                    .text
                    .strip_prefix("${")
                    .and_then(|text| text.strip_suffix('}'))
                    .and_then(|text| text.parse::<usize>().ok())
            };
            let Some(argument) = position
                .filter(|position| *position > 0)
                .and_then(|position| arguments.get(position))
            else {
                return false;
            };
            let Some(source) = argument.implicit_input_source else {
                return false;
            };
            if !token.quoted
                || token.node_kind != "string"
                || batch != (argument.node_kind == "runtime_argument_list")
            {
                return false;
            }
            token.text.clear();
            token.implicit_input_source = Some(source);
            token.runtime_argument_domain = argument.runtime_argument_domain.clone();
            token.runtime_data = false;
            token.node_kind = argument.node_kind.clone();
            owned += 1;
        }
    }
    owned == origin.data_ranges.len()
}

/// Connect replacements to actual parameter slots, not a blanket dispatcher
/// control edge. Native decoding must not erase known bytes' data origins.
pub(crate) fn collect_native_template_input_mutations(
    session: SessionView<'_>,
    ctx: &RunnerContext,
) -> Vec<PendingMutation> {
    use caushell_graph::{NodeKind, SessionRead};
    use caushell_runner::StagedSession;
    if !ctx
        .execution_unit_resolve_records()
        .iter()
        .any(|r| r.inherited_scope.native_template_input.is_some())
    {
        return Vec::new();
    }
    let staged = StagedSession::new(
        session.graph(),
        ctx.request(),
        session.summary(),
        ctx.pending_mutations(),
    );
    let graph = staged.graph();
    let mut mutations = Vec::new();
    for record in ctx.execution_unit_resolve_records() {
        let Some(origin) = &record.inherited_scope.native_template_input else {
            continue;
        };
        if record.parsed_scope.raw_command != origin.source_text
            && !(record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                && record.parent_execution_node_id != origin.producer_node_id)
        {
            continue;
        }
        let Some(bound) = crate::support::bound_invocation(&record.result) else {
            continue;
        };
        for parameter in &bound.bound_parameters {
            if !parameter.values.iter().any(|value| {
                let span = match value {
                    BoundValue::Argument { span, .. } => Some(span),
                    BoundValue::ImplicitInput {
                        origin: Some(input),
                        ..
                    } => Some(&input.span),
                    _ => None,
                };
                span.is_some_and(|span| {
                    origin
                        .data_ranges
                        .iter()
                        .any(|range| span.start_byte < range.end && range.start < span.end_byte)
                })
            }) {
                continue;
            }
            // Copy only actual replacement inputs. Returned child stdout is
            // not the source of jobs that were already generated from a list.
            for edge in graph.outgoing_edges(&origin.producer_node_id) {
                if edge.kind != EdgeKind::Consumes {
                    continue;
                }
                let Some(ProvenanceEdgeSemantics::Consume {
                    slot_name,
                    consume_kind,
                    ..
                }) = &edge.semantics
                else {
                    continue;
                };
                let stream = matches!(
                    consume_kind,
                    ProvenanceConsumeKind::StdinExplicit
                        | ProvenanceConsumeKind::StdinImplicit
                        | ProvenanceConsumeKind::PipelineInput
                );
                let Some(node) = graph.get_node(&edge.to) else {
                    continue;
                };
                let NodeKind::ProvenanceArtifact { artifact } = &node.kind else {
                    continue;
                };
                let runtime_stdin = matches!(
                    artifact,
                    ProvenanceArtifact::RuntimeInput {
                        source: RuntimeInputSource::StdinData | RuntimeInputSource::StdinPayload,
                        ..
                    }
                );
                if !(slot_name
                    .as_ref()
                    .is_some_and(|slot| origin.input_slots.contains(slot))
                    || (origin.stdin && (stream || runtime_stdin)))
                {
                    continue;
                }
                mutations.push(PendingMutation::AddProvenanceArtifact {
                    source_node_id: record.source_node_id.clone(),
                    node_id: edge.to.clone(),
                    artifact: artifact.clone(),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: if bound.is_auxiliary_input_slot(parameter.name.as_str()) {
                            ProvenanceConsumeKind::AuxiliaryInput
                        } else {
                            ProvenanceConsumeKind::RuntimeInput
                        },
                        slot_name: Some(parameter.name.as_str().into()),
                        normalized_command_name: None,
                        domain_label: None,
                    },
                });
            }
        }
    }
    mutations
}
