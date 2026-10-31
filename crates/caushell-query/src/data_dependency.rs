//! Output-specific data dependency. Control/dispatch edges are not content.
use caushell_graph::{Edge, EdgeKind, GraphRead, NodeId, NodeKind};
use caushell_types::{
    ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind, StreamDataDependency,
};

pub struct DataDependencyQuery;

impl DataDependencyQuery {
    pub fn input_carries_content(edge: &Edge) -> bool {
        !matches!(
            &edge.semantics,
            Some(ProvenanceEdgeSemantics::Consume {
                consume_kind: caushell_types::ProvenanceConsumeKind::AuxiliaryInput,
                ..
            })
        )
    }
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

    /// A wrapper's argv/environment belongs to launch context; its stream
    /// inputs and returned child stdout do not. Actual child stdin consumers
    /// trace their own content edges separately. Untyped edges stay conservative.
    pub fn is_dispatch_launch_input(graph: &dyn GraphRead, edge: &Edge) -> bool {
        if Self::is_dispatch_return_input(graph, edge) {
            return false;
        }
        use caushell_types::ProvenanceConsumeKind as Kind;
        match &edge.semantics {
            Some(ProvenanceEdgeSemantics::Consume {
                consume_kind:
                    Kind::StdinExplicit
                    | Kind::StdinImplicit
                    | Kind::PipelineInput
                    | Kind::TransformInput,
                ..
            }) => false,
            Some(ProvenanceEdgeSemantics::Consume {
                consume_kind: Kind::RuntimeInput,
                ..
            }) => !graph.get_node(&edge.to).is_some_and(|node| {
                matches!(
                    &node.kind,
                    NodeKind::ProvenanceArtifact {
                        artifact: caushell_types::ProvenanceArtifact::RuntimeInput {
                            source: caushell_types::RuntimeInputSource::StdinData
                                | caushell_types::RuntimeInputSource::StdinPayload,
                            ..
                        }
                    }
                )
            }),
            _ => true,
        }
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
        Self::input_artifacts_matching(graph, execution, |_| true)
    }

    /// Select one sink's actual inputs; original read facts and every other
    /// consumer remain unchanged. Missing scope metadata stays conservative.
    pub fn input_artifacts_matching(
        graph: &dyn GraphRead,
        execution: &NodeId,
        include: impl Fn(&Edge) -> bool,
    ) -> Vec<NodeId> {
        graph
            .outgoing_edges(execution)
            .filter(|edge| edge.kind == EdgeKind::Consumes)
            .filter(|edge| Self::input_carries_content(edge))
            .filter(|edge| include(edge))
            .filter(|edge| is_artifact(graph, &edge.to))
            .map(|edge| edge.to.clone())
            .collect()
    }

    /// One endpoint's declared request bytes, not every read by its process.
    pub fn request_input_artifacts(
        graph: &dyn GraphRead,
        execution: &NodeId,
        scope: Option<&(Vec<String>, bool)>,
    ) -> Vec<NodeId> {
        Self::input_artifacts_matching(graph, execution, |edge| {
            let Some((slots, stdin)) = scope else {
                return true;
            };
            let Some(ProvenanceEdgeSemantics::Consume {
                slot_name,
                consume_kind,
                ..
            }) = &edge.semantics
            else {
                return true;
            };
            use caushell_types::ProvenanceConsumeKind as Kind;
            let stream = matches!(
                consume_kind,
                Kind::StdinExplicit
                    | Kind::StdinImplicit
                    | Kind::PipelineInput
                    | Kind::TransformInput
            );
            (slot_name.is_none() && !stream)
                || slot_name.as_ref().is_some_and(|slot| slots.contains(slot))
                || (*stdin
                    && matches!(
                        consume_kind,
                        Kind::StdinExplicit
                            | Kind::StdinImplicit
                            | Kind::PipelineInput
                            | Kind::TransformInput
                    ))
        })
    }

    pub fn input_producers(graph: &dyn GraphRead, artifact: &NodeId) -> Vec<NodeId> {
        let mut artifacts = vec![artifact.clone()];
        if let Some(NodeKind::ProvenanceArtifact {
            artifact: caushell_types::ProvenanceArtifact::PathContent { path, .. },
        }) = graph.get_node(artifact).map(|n| &n.kind)
        {
            artifacts.extend(
                graph
                    .path_family_artifact_nodes_for_path(path)
                    .map(|n| n.id.clone()),
            );
        }
        let input = graph.get_node(artifact).and_then(|node| match &node.kind {
            NodeKind::ProvenanceArtifact {
                artifact: caushell_types::ProvenanceArtifact::PathContent { path, .. },
            } => Some(caushell_types::PathResolution::Concrete { path: path.clone() }),
            NodeKind::ProvenanceArtifact {
                artifact:
                    caushell_types::ProvenanceArtifact::PathSelectionContent { resolution, .. },
            } => Some(resolution.clone()),
            _ => None,
        });
        if let Some(input) = input {
            for node in graph.path_selection_artifact_nodes() {
                if let NodeKind::ProvenanceArtifact {
                    artifact:
                        caushell_types::ProvenanceArtifact::PathSelectionContent { resolution, .. },
                } = &node.kind
                    && domains_may_overlap(&input, resolution)
                {
                    artifacts.push(node.id.clone());
                }
            }
            if input.concrete_path().is_none() {
                for node in graph.path_content_artifact_nodes() {
                    let domain = match &node.kind {
                        NodeKind::ProvenanceArtifact {
                            artifact: caushell_types::ProvenanceArtifact::PathContent { path, .. },
                        } => Some(caushell_types::PathResolution::Concrete { path: path.clone() }),
                        NodeKind::ProvenanceArtifact {
                            artifact:
                                caushell_types::ProvenanceArtifact::PathFamily { directory, prefix },
                        } => Some(caushell_types::PathResolution::FileNamePrefix {
                            directory: directory.clone(),
                            prefix: prefix.clone(),
                        }),
                        _ => None,
                    };
                    if domain.is_some_and(|d| domains_may_overlap(&input, &d)) {
                        artifacts.push(node.id.clone());
                    }
                }
            }
        }
        artifacts.sort();
        artifacts.dedup();
        artifacts
            .iter()
            .flat_map(|id| graph.incoming_edges(id))
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

/// Possible content influence only: an unknown output cannot prove that a
/// later executable is unrelated. These domains never resolve a filename,
/// prove existence, or grant a filesystem permission.
fn domains_may_overlap(
    left: &caushell_types::PathResolution,
    right: &caushell_types::PathResolution,
) -> bool {
    use caushell_types::PathResolution as P;
    fn under(path: &str, root: &str) -> bool {
        path == root
            || path
                .strip_prefix(root.trim_end_matches('/'))
                .is_some_and(|s| s.starts_with('/'))
    }
    if let (Some(a), Some(b)) = (left.concrete_path(), right.concrete_path()) {
        return a == b;
    }
    match (left, right) {
        (P::FileNamePrefix { directory, prefix }, other)
        | (other, P::FileNamePrefix { directory, prefix }) => {
            if let Some(path) = other.concrete_path() {
                return path.rsplit_once('/').is_some_and(|(parent, name)| {
                    (if parent.is_empty() { "/" } else { parent }) == directory
                        && name.starts_with(prefix)
                        && name.len() > prefix.len()
                });
            }
            if let P::BoundedPathSet {
                roots,
                may_escape: false,
            } = other
            {
                return roots.is_empty()
                    || roots.iter().any(|r| {
                        under(directory, r)
                            || r.rsplit_once('/').is_some_and(|(parent, name)| {
                                parent == directory
                                    && name.starts_with(prefix)
                                    && name.len() > prefix.len()
                            })
                    });
            }
            if let P::FileNamePrefix {
                directory: d,
                prefix: p,
            } = other
            {
                return directory == d && (prefix.starts_with(p) || p.starts_with(prefix));
            }
            true
        }
        (P::BoundedPathSet { roots, may_escape }, other)
        | (other, P::BoundedPathSet { roots, may_escape }) => {
            if *may_escape || roots.is_empty() {
                return true;
            }
            if let Some(path) = other.concrete_path() {
                return roots.iter().any(|r| under(path, r));
            }
            if let P::BoundedPathSet {
                roots: other_roots,
                may_escape: false,
            } = other
            {
                return other_roots.is_empty()
                    || roots
                        .iter()
                        .any(|a| other_roots.iter().any(|b| under(a, b) || under(b, a)));
            }
            true
        }
        _ => true,
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
    fn subtree_output_origins_survive_snapshot_restore_without_covering_a_sibling() {
        use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
        use caushell_types::{
            CommandSequenceNo, PathResolution, ProvenanceArtifact, SessionId, ShellKind,
        };
        let mut graph = SessionGraph::new();
        let producer = NodeId::new("producer");
        graph.add_node(GraphNode::new_command_invocation(
            producer.clone(),
            SessionId::new("lineage"),
            CommandSequenceNo(1),
            "arbitrary-move-tool",
            "/work",
            ShellKind::Bash,
        ));
        let output = NodeId::new("output-domain");
        graph.add_node(GraphNode::new_provenance_artifact(
            output.clone(),
            ProvenanceArtifact::PathSelectionContent {
                resolution: PathResolution::BoundedPathSet {
                    roots: vec!["/work/source".into()],
                    may_escape: false,
                },
                selector: None,
            },
        ));
        graph
            .add_edge(Edge::new(producer.clone(), output, EdgeKind::Produces))
            .unwrap();
        for (id, path) in [
            ("child", "/work/source/bin/run"),
            ("sibling", "/work/source-peer/bin/run"),
        ] {
            graph.add_node(GraphNode::new_provenance_artifact(
                NodeId::new(id),
                ProvenanceArtifact::PathContent {
                    path: path.into(),
                    version: None,
                },
            ));
        }
        let restored = SessionGraph::from_snapshot(graph.to_snapshot()).unwrap();
        for graph in [&graph, &restored] {
            assert_eq!(
                super::DataDependencyQuery::input_producers(graph, &NodeId::new("child")),
                vec![producer.clone()]
            );
            assert!(
                super::DataDependencyQuery::input_producers(graph, &NodeId::new("sibling"))
                    .is_empty()
            );
        }
    }

    #[test]
    fn possible_content_domains_preserve_component_bounds_and_unknown_outputs() {
        use caushell_types::PathResolution as P;
        let exact = |path: &str| P::Concrete { path: path.into() };
        let tree = P::BoundedPathSet {
            roots: vec!["/work/source".into()],
            may_escape: false,
        };
        assert!(super::domains_may_overlap(&tree, &exact("/work/source")));
        assert!(super::domains_may_overlap(
            &tree,
            &exact("/work/source/bin/run")
        ));
        assert!(!super::domains_may_overlap(
            &tree,
            &exact("/work/source-peer/run")
        ));
        assert!(super::domains_may_overlap(
            &tree,
            &P::UnsupportedDynamicText {
                text: "unknown output".into()
            }
        ));
        let family = P::FileNamePrefix {
            directory: "/work".into(),
            prefix: "part".into(),
        };
        assert!(super::domains_may_overlap(&family, &exact("/work/part1")));
        for path in [
            "/work/part",
            "/work/other",
            "/work/part1/child",
            "/other/part1",
        ] {
            assert!(!super::domains_may_overlap(&family, &exact(path)), "{path}");
        }
    }

    #[test]
    fn auxiliary_reads_remain_auditable_without_becoming_content() {
        use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
        use caushell_types::{
            CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
            SessionId, ShellKind,
        };
        let mut graph = SessionGraph::new();
        let execution = NodeId::new("execution");
        let payload = NodeId::new("payload");
        let credential = NodeId::new("credential");
        graph.add_node(GraphNode::new_command_invocation(
            execution.clone(),
            SessionId::new("aux"),
            CommandSequenceNo(1),
            "declared-tool",
            "/tmp/project",
            ShellKind::Bash,
        ));
        for id in [&payload, &credential] {
            graph.add_node(GraphNode::new_provenance_artifact(
                id.clone(),
                ProvenanceArtifact::PathContent {
                    path: id.0.clone(),
                    version: None,
                },
            ));
        }
        for (id, kind) in [
            (payload.clone(), ProvenanceConsumeKind::PathRead),
            (credential.clone(), ProvenanceConsumeKind::AuxiliaryInput),
        ] {
            let edge = Edge::with_semantics(
                execution.clone(),
                id,
                EdgeKind::Consumes,
                ProvenanceEdgeSemantics::Consume {
                    consume_kind: kind,
                    slot_name: None,
                    normalized_command_name: None,
                    domain_label: None,
                },
            );
            graph.add_edge(edge).unwrap();
        }
        assert_eq!(
            super::DataDependencyQuery::input_artifacts(&graph, &execution),
            [payload]
        );
        assert_eq!(graph.edges().len(), 2);
        assert!(graph.get_node(&credential).is_some());
    }
    #[test]
    fn launch_context_keeps_argv_origins_without_promoting_wrapper_stdin() {
        use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
        use caushell_types::{
            ProvenanceArtifact, ProvenanceConsumeKind as Kind, ProvenanceEdgeSemantics,
            RuntimeInputCapture, RuntimeInputSource,
        };
        let mut graph = SessionGraph::new();
        for source in [
            RuntimeInputSource::StdinData,
            RuntimeInputSource::StdinPayload,
        ] {
            let id = NodeId::new(format!("{source:?}"));
            graph.add_node(GraphNode::new_provenance_artifact(
                id.clone(),
                ProvenanceArtifact::RuntimeInput {
                    source,
                    capture: RuntimeInputCapture::NotCaptured,
                    version: 1,
                },
            ));
            let edge = Edge::with_semantics(
                NodeId::new("wrapper"),
                id,
                EdgeKind::Consumes,
                ProvenanceEdgeSemantics::Consume {
                    consume_kind: Kind::RuntimeInput,
                    slot_name: None,
                    normalized_command_name: None,
                    domain_label: None,
                },
            );
            assert!(!super::DataDependencyQuery::is_dispatch_launch_input(
                &graph, &edge
            ));
        }
        for kind in [
            Kind::VariableExpansion,
            Kind::CommandString,
            Kind::PathRead,
            Kind::PipelineInput,
            Kind::StdinExplicit,
            Kind::StdinImplicit,
            Kind::TransformInput,
        ] {
            let edge = Edge::with_semantics(
                NodeId::new("wrapper"),
                NodeId::new("argument"),
                EdgeKind::Consumes,
                ProvenanceEdgeSemantics::Consume {
                    consume_kind: kind,
                    slot_name: Some("argv".into()),
                    normalized_command_name: None,
                    domain_label: None,
                },
            );
            assert_eq!(
                super::DataDependencyQuery::is_dispatch_launch_input(&graph, &edge),
                matches!(
                    kind,
                    Kind::VariableExpansion | Kind::CommandString | Kind::PathRead
                )
            );
        }
        assert!(super::DataDependencyQuery::is_dispatch_launch_input(
            &graph,
            &Edge::new(
                NodeId::new("wrapper"),
                NodeId::new("legacy"),
                EdgeKind::Consumes
            )
        ));
    }

    #[test]
    fn choosing_a_sink_input_does_not_remove_or_sanitize_other_reads() {
        use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
        use caushell_types::{
            ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
            ProvenanceMaterializedValueState,
        };
        let mut graph = SessionGraph::new();
        let caller = NodeId::new("caller");
        graph.add_node(GraphNode::new_command_invocation(
            caller.clone(),
            caushell_types::SessionId::new("test"),
            caushell_types::CommandSequenceNo::new(1),
            "arbitrary-uploader",
            "/tmp/project",
            caushell_types::ShellKind::Bash,
        ));
        for slot in ["authentication_key", "body"] {
            let id = NodeId::new(slot);
            graph.add_node(GraphNode::new_provenance_artifact(
                id.clone(),
                ProvenanceArtifact::MaterializedValue {
                    source_kind: slot.into(),
                    state: ProvenanceMaterializedValueState::ExactScalar {
                        value: "sensitive bytes".into(),
                    },
                    version: 1,
                },
            ));
            graph
                .add_edge(Edge::with_semantics(
                    caller.clone(),
                    id,
                    EdgeKind::Consumes,
                    ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some(slot.into()),
                        normalized_command_name: None,
                        domain_label: None,
                    },
                ))
                .unwrap();
        }
        let all = super::DataDependencyQuery::input_artifacts(&graph, &caller);
        assert_eq!(all.len(), 2);
        let chosen =
            super::DataDependencyQuery::input_artifacts_matching(&graph, &caller, |edge| {
                matches!(&edge.semantics,
            Some(ProvenanceEdgeSemantics::Consume {slot_name: Some(slot), ..}) if slot == "body")
            });
        assert_eq!(chosen, [NodeId::new("body")]);
        assert_eq!(
            super::DataDependencyQuery::input_artifacts(&graph, &caller),
            all
        );
        assert!(graph.get_node(&NodeId::new("authentication_key")).is_some());
    }
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
