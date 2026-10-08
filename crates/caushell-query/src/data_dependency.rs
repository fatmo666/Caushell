//! Output-specific data dependency. Control/dispatch edges are not content.
use caushell_graph::{Edge, EdgeKind, GraphRead, NodeId, NodeKind};
use caushell_types::{
    ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind, StreamDataDependency,
};

pub struct DataDependencyQuery;

impl DataDependencyQuery {
    /// A dispatcher receiving a child's returned stdout is a real data
    /// consumer, but those returned bytes are not launch context for that
    /// child. Keep this classification separate from ordinary data tracing.
    pub fn is_dispatch_return_input(graph: &dyn GraphRead, edge: &Edge) -> bool {
        edge.kind == EdgeKind::Consumes && matches!(&edge.semantics,
            Some(ProvenanceEdgeSemantics::Consume {consume_kind: caushell_types::ProvenanceConsumeKind::TransformInput, ..}))
            && graph.get_node(&edge.to).is_some_and(|node| matches!(&node.kind,
                NodeKind::ProvenanceArtifact {artifact: caushell_types::ProvenanceArtifact::MaterializedValue {source_kind, ..}}
                    if source_kind == "dispatch_stdout"))
    }

    pub fn output_dependency(edge: &Edge) -> StreamDataDependency {
        match &edge.semantics {
            Some(ProvenanceEdgeSemantics::Produce {
                domain_label: Some(ProvenanceDomainLabel::StreamOutput { dependency, .. }),
                ..
            }) => *dependency,
            _ => StreamDataDependency::Unknown,
        }
    }

    pub fn carries_inputs(edge: &Edge) -> bool {
        Self::output_dependency(edge) != StreamDataDependency::Independent
    }

    /// Keep legacy unprojected graphs conservative. Once a pipeline's actual
    /// stream exists, its structural shortcut must obey that same dependency
    /// and the consumer's actual consumption (including ignored stdin).
    pub fn control_edge_carries_inputs(graph: &dyn GraphRead, control: &Edge) -> bool {
        if control.kind != EdgeKind::FlowsTo {
            return true;
        }
        let mut projected = false;
        for output in graph.outgoing_edges(&control.from) {
            if output.kind != EdgeKind::Produces
                || !matches!(
                    &output.semantics,
                    Some(ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::PipelineOutput
                            | ProvenanceProduceKind::TransformOutput,
                        ..
                    })
                )
            {
                continue;
            }
            projected = true;
            if Self::carries_inputs(output)
                && graph
                    .outgoing_edges(&control.to)
                    .any(|input| input.kind == EdgeKind::Consumes && input.to == output.to)
            {
                return true;
            }
        }
        !projected
    }

    /// Only content relations; a shell wire or dispatch alone proves no bytes.
    pub fn input_artifacts(graph: &dyn GraphRead, execution: &NodeId) -> Vec<NodeId> {
        graph
            .outgoing_edges(execution)
            .filter(|edge| edge.kind == EdgeKind::Consumes)
            .filter(|edge| is_artifact(graph, &edge.to))
            .map(|edge| edge.to.clone())
            .collect()
    }

    pub fn input_producers(graph: &dyn GraphRead, artifact: &NodeId) -> Vec<NodeId> {
        graph
            .incoming_edges(artifact)
            .filter(|edge| edge.kind == EdgeKind::Produces)
            .filter(|edge| Self::carries_inputs(edge))
            .filter(|edge| {
                graph.get_node(&edge.from).is_some_and(|node| {
                    matches!(
                        node.kind,
                        NodeKind::CommandInvocation { .. } | NodeKind::DerivedInvocation { .. }
                    )
                })
            })
            .map(|edge| edge.from.clone())
            .collect()
    }
}

fn is_artifact(graph: &dyn GraphRead, node: &NodeId) -> bool {
    graph
        .get_node(node)
        .is_some_and(|node| matches!(node.kind, NodeKind::ProvenanceArtifact { .. }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn returned_stdout_is_separate_from_launch_context_but_remains_data() {
        use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
        use caushell_types::{
            ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
            ProvenanceMaterializedValueState,
        };
        let mut graph = SessionGraph::new();
        for kind in ["dispatch_stdout", "command_string"] {
            graph.add_node(GraphNode::new_provenance_artifact(
                NodeId::new(kind),
                ProvenanceArtifact::MaterializedValue {
                    source_kind: kind.into(),
                    state: ProvenanceMaterializedValueState::UnsupportedDynamicText {
                        text: "unknown".into(),
                    },
                    version: 1,
                },
            ));
        }
        for (artifact, consume_kind, returned) in [
            (
                "dispatch_stdout",
                ProvenanceConsumeKind::TransformInput,
                true,
            ),
            (
                "dispatch_stdout",
                ProvenanceConsumeKind::CommandString,
                false,
            ),
            (
                "command_string",
                ProvenanceConsumeKind::TransformInput,
                false,
            ),
        ] {
            let edge = Edge::with_semantics(
                NodeId::new("caller"),
                NodeId::new(artifact),
                EdgeKind::Consumes,
                ProvenanceEdgeSemantics::Consume {
                    consume_kind,
                    slot_name: None,
                    normalized_command_name: None,
                    domain_label: None,
                },
            );
            assert_eq!(
                super::DataDependencyQuery::is_dispatch_return_input(&graph, &edge),
                returned
            );
            // Classification alone never deletes or sanitizes ordinary data.
            assert!(super::is_artifact(&graph, &edge.to));
        }
    }
}
