//! Live stream growth within one request, not historical file-content taint.
use crate::DataDependencyQuery;
use caushell_graph::{Edge, EdgeKind, GraphRead, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, ProvenanceArtifact, ProvenanceDomainLabel, ProvenanceEdgeSemantics,
    StreamGrowth, StreamRecordFraming,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundedFileWrite {
    pub producer: NodeId,
    pub writer: NodeId,
    pub path: String,
}

#[derive(Debug, Default)]
pub struct StreamGrowthResult {
    pub writes: Vec<UnboundedFileWrite>,
    pub truncated: bool,
}

pub struct StreamGrowthQuery {
    pub max_steps: usize,
}

impl Default for StreamGrowthQuery {
    fn default() -> Self {
        Self { max_steps: 16_384 }
    }
}

pub fn output_growth(edge: &Edge) -> Option<StreamGrowth> {
    match &edge.semantics {
        Some(ProvenanceEdgeSemantics::Produce {
            domain_label: Some(ProvenanceDomainLabel::StreamOutput { growth, .. }),
            ..
        }) => *growth,
        _ => None,
    }
}

impl StreamGrowthQuery {
    /// Seeds are this request's already-projected continuous output edges.
    /// Traversal never crosses a persistent file or argv/value capture.
    pub fn execute(
        &self,
        graph: &dyn GraphRead,
        sequence: CommandSequenceNo,
        seeds: impl IntoIterator<Item = (NodeId, NodeId, StreamRecordFraming)>,
    ) -> StreamGrowthResult {
        let mut result = StreamGrowthResult::default();
        let mut queue = VecDeque::new();
        let mut visited = BTreeSet::new();
        let mut returning_dispatchers = BTreeMap::new();
        let mut reported = BTreeSet::new();
        for (producer, artifact, records) in seeds {
            queue.push_back((producer.clone(), producer, artifact, records));
        }
        let mut steps = 0;
        while let Some((producer, writer, artifact, records)) = queue.pop_front() {
            if steps >= self.max_steps {
                result.truncated = true;
                break;
            }
            steps += 1;
            if !visited.insert((producer.clone(), artifact.clone(), records)) {
                continue;
            }
            let Some(NodeKind::ProvenanceArtifact { artifact: value }) =
                graph.get_node(&artifact).map(|n| &n.kind)
            else {
                continue;
            };
            if let ProvenanceArtifact::PathContent { path, .. } = value {
                if !terminal_or_discard(path) {
                    let write = UnboundedFileWrite {
                        producer,
                        writer,
                        path: path.clone(),
                    };
                    if reported.insert((
                        write.producer.clone(),
                        write.writer.clone(),
                        write.path.clone(),
                    )) {
                        result.writes.push(write);
                    }
                }
                continue;
            }
            if !matches!(
                value,
                ProvenanceArtifact::PipelineStream { .. }
                    | ProvenanceArtifact::TransformOutput { .. }
                    | ProvenanceArtifact::DescriptorStream { .. }
                    | ProvenanceArtifact::ProcessSubstitutionChannel { .. }
            ) && !matches!(value, ProvenanceArtifact::MaterializedValue { source_kind, .. } if source_kind == "dispatch_stdout")
            {
                continue;
            }
            for input in graph.incoming_edges(&artifact) {
                if steps >= self.max_steps {
                    result.truncated = true;
                    break;
                }
                steps += 1;
                if input.kind != EdgeKind::Consumes
                    || !DataDependencyQuery::input_carries_content(input)
                    || !in_request(graph, &input.from, sequence)
                {
                    continue;
                }
                // Expanded dispatchers return their child's actual stdout.
                // Their launch stdin must pass through that child, not take
                // an additional shortcut straight to the wrapper's output.
                let returns_child_stdout =
                    if let Some(value) = returning_dispatchers.get(&input.from) {
                        *value
                    } else {
                        let mut found = false;
                        for edge in graph.outgoing_edges(&input.from) {
                            if steps >= self.max_steps {
                                result.truncated = true;
                                break;
                            }
                            steps += 1;
                            if DataDependencyQuery::is_dispatch_return_input(graph, edge) {
                                found = true;
                                break;
                            }
                        }
                        returning_dispatchers.insert(input.from.clone(), found);
                        found
                    };
                if result.truncated {
                    break;
                }
                if !DataDependencyQuery::is_dispatch_return_input(graph, input)
                    && returns_child_stdout
                {
                    continue;
                }
                for output in graph.outgoing_edges(&input.from) {
                    if steps >= self.max_steps {
                        result.truncated = true;
                        break;
                    }
                    steps += 1;
                    if output.kind != EdgeKind::Produces
                        || !DataDependencyQuery::carries_inputs(output)
                    {
                        continue;
                    }
                    let next_records = match output_growth(output) {
                        Some(StreamGrowth::Finite) => continue,
                        Some(StreamGrowth::RecordPrefix { records: separator })
                            if records != StreamRecordFraming::Unknown && records == separator =>
                        {
                            continue;
                        }
                        Some(StreamGrowth::PreserveRecords) => records,
                        _ => StreamRecordFraming::Unknown,
                    };
                    queue.push_back((
                        producer.clone(),
                        input.from.clone(),
                        output.to.clone(),
                        next_records,
                    ));
                }
            }
        }
        result
    }
}

fn in_request(graph: &dyn GraphRead, node: &NodeId, sequence: CommandSequenceNo) -> bool {
    match graph.get_node(node).map(|n| &n.kind) {
        Some(NodeKind::CommandInvocation { sequence_no, .. }) => *sequence_no == sequence,
        Some(NodeKind::DerivedInvocation {
            root_command_sequence_no,
            ..
        }) => *root_command_sequence_no == sequence,
        _ => false,
    }
}

fn terminal_or_discard(path: &str) -> bool {
    matches!(path, "/dev/null" | "/dev/tty" | "/dev/console")
        || path
            .strip_prefix("/dev/pts/")
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_graph::{GraphNode, SessionGraph};
    use caushell_types::{ProvenanceConsumeKind, ProvenanceProduceKind, SessionId, ShellKind};

    fn graph(
        growth: Option<StreamGrowth>,
        consumer_sequence: u64,
    ) -> (SessionGraph, Vec<(NodeId, NodeId, StreamRecordFraming)>) {
        let mut graph = SessionGraph::new();
        for (id, seq) in [("source", 1), ("consumer", consumer_sequence)] {
            graph.add_node(GraphNode::new_command_invocation(
                NodeId::new(id),
                SessionId::new("test"),
                CommandSequenceNo(seq),
                id,
                "/work",
                ShellKind::Bash,
            ));
        }
        graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("stream"),
            ProvenanceArtifact::PipelineStream {
                root_command_sequence_no: CommandSequenceNo(1),
                pipeline_group_index: 0,
                stream_index: 0,
            },
        ));
        graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("file"),
            ProvenanceArtifact::PathContent {
                path: "/work/out".into(),
                version: None,
            },
        ));
        graph
            .add_edge(Edge::with_semantics(
                NodeId::new("consumer"),
                NodeId::new("stream"),
                EdgeKind::Consumes,
                ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::PipelineInput,
                    slot_name: None,
                    normalized_command_name: None,
                    domain_label: None,
                },
            ))
            .unwrap();
        graph
            .add_edge(Edge::with_semantics(
                NodeId::new("consumer"),
                NodeId::new("file"),
                EdgeKind::Produces,
                ProvenanceEdgeSemantics::Produce {
                    produce_kind: ProvenanceProduceKind::PathWrite,
                    slot_name: None,
                    normalized_command_name: None,
                    domain_label: Some(ProvenanceDomainLabel::StreamOutput {
                        dependency: caushell_types::StreamDataDependency::Inputs,
                        growth,
                        domain: None,
                    }),
                },
            ))
            .unwrap();
        (
            graph,
            vec![(
                NodeId::new("source"),
                NodeId::new("stream"),
                StreamRecordFraming::Lines,
            )],
        )
    }

    #[test]
    fn framing_and_unit_bounds_are_independent_of_content_dependency() {
        for (growth, writes) in [
            (None, 1),
            (Some(StreamGrowth::Finite), 0),
            (
                Some(StreamGrowth::RecordPrefix {
                    records: StreamRecordFraming::Lines,
                }),
                0,
            ),
            (
                Some(StreamGrowth::RecordPrefix {
                    records: StreamRecordFraming::Nul,
                }),
                1,
            ),
            (Some(StreamGrowth::PreserveRecords), 1),
        ] {
            let (graph, seeds) = graph(growth, 1);
            let result = StreamGrowthQuery::default().execute(&graph, CommandSequenceNo(1), seeds);
            assert_eq!(result.writes.len(), writes);
            assert!(!result.truncated);
            assert_eq!(graph.edge_count(), 2);
        }
    }

    #[test]
    fn query_is_request_local_and_budget_exhaustion_is_explicit() {
        let (graph, seeds) = graph(None, 2);
        assert!(
            StreamGrowthQuery::default()
                .execute(&graph, CommandSequenceNo(1), seeds.clone())
                .writes
                .is_empty()
        );
        assert!(
            StreamGrowthQuery { max_steps: 0 }
                .execute(&graph, CommandSequenceNo(1), seeds)
                .truncated
        );
    }
}
