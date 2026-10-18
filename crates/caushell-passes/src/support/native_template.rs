//! Data-origin links for native template replacements, shared by provenance passes.
use caushell_graph::EdgeKind;
use caushell_profile::BoundValue;
use caushell_runner::{PendingMutation, RunnerContext, SessionView};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuntimeInputSource,
};

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
                matches!(value,
                BoundValue::Argument {span, ..} if origin.data_ranges.iter().any(|range|
                    span.start_byte < range.end && range.start < span.end_byte))
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
