use std::collections::BTreeMap;

use crate::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, MutationScopeResolution, PathMetadataMutation, PathResolution,
    ProvenanceArtifact, ResolvedMutationScopeOperation, ResolvedPathPurpose, ResolvedPathRole,
    SessionGraphEdgeSnapshot, SessionGraphSnapshot, SessionId, ShellKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    MissingSourceNode(NodeId),
    MissingTargetNode(NodeId),
}

#[derive(Debug, Clone, Default)]
pub struct SessionGraph {
    nodes: BTreeMap<NodeId, GraphNode>,
    edges: Vec<Edge>,
    outgoing_edge_index: BTreeMap<NodeId, Vec<usize>>,
    incoming_edge_index: BTreeMap<NodeId, Vec<usize>>,
    command_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    derived_invocation_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    nested_payload_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    execution_semantics_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    path_fact_node_index: Vec<NodeId>,
    path_fact_by_concrete_path_index: BTreeMap<String, Vec<NodeId>>,
    path_content_artifact_index: Vec<NodeId>,
    path_content_artifact_by_path_index: BTreeMap<String, Vec<NodeId>>,
}

impl SessionGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: GraphNode) -> Option<GraphNode> {
        let node_id = node.id.clone();
        let replaced = self.nodes.insert(node_id.clone(), node);

        if let Some(existing) = replaced.as_ref() {
            self.remove_node_indexes(existing);
        }

        let inserted = self
            .nodes
            .get_key_value(&node_id)
            .expect("inserted node must be retrievable")
            .1
            .clone();
        self.index_node(&inserted);
        replaced
    }

    pub fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.nodes.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &GraphNode> + '_ {
        self.nodes.values()
    }

    pub fn add_edge(&mut self, edge: Edge) -> Result<(), GraphError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(GraphError::MissingSourceNode(edge.from.clone()));
        }

        if !self.nodes.contains_key(&edge.to) {
            return Err(GraphError::MissingTargetNode(edge.to.clone()));
        }

        let edge_index = self.edges.len();
        self.outgoing_edge_index
            .entry(edge.from.clone())
            .or_default()
            .push(edge_index);
        self.incoming_edge_index
            .entry(edge.to.clone())
            .or_default()
            .push(edge_index);
        self.edges.push(edge);

        if let Some(inserted) = self.edges.get(edge_index).cloned() {
            self.index_edge(&inserted);
        }

        Ok(())
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    pub fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
        match self.outgoing_edge_index.get(id) {
            Some(indices) => Box::new(indices.iter().map(|index| &self.edges[*index])),
            None => Box::new(std::iter::empty()),
        }
    }

    pub fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
        match self.incoming_edge_index.get(id) {
            Some(indices) => Box::new(indices.iter().map(|index| &self.edges[*index])),
            None => Box::new(std::iter::empty()),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn add_command_invocation(
        &mut self,
        id: NodeId,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: impl Into<String>,
        cwd_before: impl Into<String>,
        shell_kind: ShellKind,
    ) -> Option<GraphNode> {
        let node = GraphNode::new_command_invocation(
            id,
            session_id,
            sequence_no,
            raw_text,
            cwd_before,
            shell_kind,
        );

        self.add_node(node)
    }

    pub fn add_request_anchor(
        &mut self,
        id: NodeId,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: impl Into<String>,
        cwd_before: impl Into<String>,
        shell_kind: ShellKind,
    ) -> Option<GraphNode> {
        let node = GraphNode::new_request_anchor(
            id,
            session_id,
            sequence_no,
            raw_text,
            cwd_before,
            shell_kind,
        );

        self.add_node(node)
    }

    pub fn add_path_fact(
        &mut self,
        id: NodeId,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
    ) -> Option<GraphNode> {
        let node = GraphNode::new_path_fact(
            id,
            resolution,
            role,
            purpose,
            slot_name,
            normalized_command_name,
        );

        self.add_node(node)
    }

    pub fn add_path_fact_with_metadata_mutation(
        &mut self,
        id: NodeId,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
        metadata_mutation: Option<PathMetadataMutation>,
    ) -> Option<GraphNode> {
        let node = GraphNode::new_path_fact_with_metadata_mutation(
            id,
            resolution,
            role,
            purpose,
            slot_name,
            normalized_command_name,
            metadata_mutation,
        );

        self.add_node(node)
    }

    pub fn add_mutation_scope_fact(
        &mut self,
        id: NodeId,
        resolution: MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
    ) -> Option<GraphNode> {
        let node = GraphNode::new_mutation_scope_fact(
            id,
            resolution,
            operation,
            slot_name,
            normalized_command_name,
        );

        self.add_node(node)
    }

    pub fn to_snapshot(&self) -> SessionGraphSnapshot {
        SessionGraphSnapshot {
            nodes: self.nodes.values().map(Into::into).collect(),
            edges: self
                .edges
                .iter()
                .map(|edge| SessionGraphEdgeSnapshot {
                    from: edge.from.0.clone(),
                    to: edge.to.0.clone(),
                    kind: edge.kind.into(),
                    semantics: edge.semantics.clone(),
                })
                .collect(),
        }
    }

    pub fn from_snapshot(snapshot: SessionGraphSnapshot) -> Result<Self, GraphError> {
        let mut graph = Self::new();

        for node in snapshot.nodes {
            let _ = graph.add_node(node.into());
        }

        for edge in snapshot.edges {
            graph.add_edge(Edge::new(
                NodeId::new(edge.from),
                NodeId::new(edge.to),
                edge.kind.into(),
            ))?;

            if let Some(last_edge) = graph.edges.last_mut() {
                last_edge.semantics = edge.semantics;
            }
        }

        Ok(graph)
    }

    fn index_node(&mut self, node: &GraphNode) {
        match &node.kind {
            NodeKind::CommandInvocation { sequence_no, .. } => self
                .command_node_index
                .entry(*sequence_no)
                .or_default()
                .push(node.id.clone()),
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                ..
            } => self
                .derived_invocation_node_index
                .entry(*root_command_sequence_no)
                .or_default()
                .push(node.id.clone()),
            NodeKind::NestedPayload {
                root_command_sequence_no,
                ..
            } => self
                .nested_payload_node_index
                .entry(*root_command_sequence_no)
                .or_default()
                .push(node.id.clone()),
            NodeKind::ExecutionSemantics { .. } => {
                if let Some(sequence_no) = self.execution_semantics_sequence_no(&node.id) {
                    self.execution_semantics_node_index
                        .entry(sequence_no)
                        .or_default()
                        .push(node.id.clone());
                }
            }
            NodeKind::PathFact { resolution, .. } => {
                self.path_fact_node_index.push(node.id.clone());
                if let Some(path) = resolution.concrete_path() {
                    self.path_fact_by_concrete_path_index
                        .entry(path.to_string())
                        .or_default()
                        .push(node.id.clone());
                }
            }
            NodeKind::ProvenanceArtifact { artifact } => {
                if let ProvenanceArtifact::PathContent { path, .. } = artifact {
                    self.path_content_artifact_index.push(node.id.clone());
                    self.path_content_artifact_by_path_index
                        .entry(path.clone())
                        .or_default()
                        .push(node.id.clone());
                }
            }
            _ => {}
        }
    }

    fn index_edge(&mut self, edge: &Edge) {
        if edge.kind != EdgeKind::Defines {
            return;
        }

        let Some(target_node) = self.nodes.get(&edge.to) else {
            return;
        };
        if !matches!(target_node.kind, NodeKind::ExecutionSemantics { .. }) {
            return;
        }

        let Some(sequence_no) = self.execution_unit_sequence_no(&edge.from) else {
            return;
        };

        let ids = self
            .execution_semantics_node_index
            .entry(sequence_no)
            .or_default();
        if !ids.contains(&edge.to) {
            ids.push(edge.to.clone());
        }
    }

    fn remove_node_indexes(&mut self, node: &GraphNode) {
        match &node.kind {
            NodeKind::CommandInvocation { sequence_no, .. } => {
                remove_index_entry(&mut self.command_node_index, sequence_no, &node.id)
            }
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                ..
            } => remove_index_entry(
                &mut self.derived_invocation_node_index,
                root_command_sequence_no,
                &node.id,
            ),
            NodeKind::NestedPayload {
                root_command_sequence_no,
                ..
            } => remove_index_entry(
                &mut self.nested_payload_node_index,
                root_command_sequence_no,
                &node.id,
            ),
            NodeKind::ExecutionSemantics { .. } => {
                if let Some(sequence_no) = self.execution_semantics_sequence_no(&node.id) {
                    remove_index_entry(
                        &mut self.execution_semantics_node_index,
                        &sequence_no,
                        &node.id,
                    );
                }
            }
            NodeKind::PathFact { resolution, .. } => {
                remove_vec_entry(&mut self.path_fact_node_index, &node.id);
                if let Some(path) = resolution.concrete_path() {
                    remove_index_entry(
                        &mut self.path_fact_by_concrete_path_index,
                        &path.to_string(),
                        &node.id,
                    );
                }
            }
            NodeKind::ProvenanceArtifact { artifact } => {
                if let ProvenanceArtifact::PathContent { path, .. } = artifact {
                    remove_vec_entry(&mut self.path_content_artifact_index, &node.id);
                    remove_index_entry(
                        &mut self.path_content_artifact_by_path_index,
                        path,
                        &node.id,
                    );
                }
            }
            _ => {}
        }
    }

    fn execution_unit_sequence_no(&self, node_id: &NodeId) -> Option<CommandSequenceNo> {
        let node = self.nodes.get(node_id)?;
        match &node.kind {
            NodeKind::CommandInvocation { sequence_no, .. } => Some(*sequence_no),
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                ..
            } => Some(*root_command_sequence_no),
            _ => None,
        }
    }

    fn execution_semantics_sequence_no(
        &self,
        semantics_node_id: &NodeId,
    ) -> Option<CommandSequenceNo> {
        for edge in self.incoming_edges(semantics_node_id) {
            if edge.kind != EdgeKind::Defines {
                continue;
            }

            if let Some(sequence_no) = self.execution_unit_sequence_no(&edge.from) {
                return Some(sequence_no);
            }
        }

        None
    }

    fn indexed_nodes<'a>(
        &'a self,
        node_ids: &'a [NodeId],
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        Box::new(
            node_ids
                .iter()
                .filter_map(|node_id| self.nodes.get(node_id)),
        )
    }

    fn nodes_in_window_from_index<'a>(
        &'a self,
        index: &'a BTreeMap<CommandSequenceNo, Vec<NodeId>>,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        use std::ops::Bound::{Excluded, Unbounded};

        let lower = after_sequence.map_or(Unbounded, Excluded);
        let upper = before_sequence.map_or(Unbounded, Excluded);

        Box::new(
            index
                .range((lower, upper))
                .flat_map(move |(_sequence_no, node_ids)| self.indexed_nodes(node_ids)),
        )
    }
}

impl GraphRead for SessionGraph {
    fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.get_node(id)
    }

    fn node_count(&self) -> usize {
        self.node_count()
    }

    fn edge_count(&self) -> usize {
        self.edge_count()
    }

    fn nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        Box::new(self.nodes())
    }

    fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
        Box::new(self.edges().iter())
    }

    fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
        self.outgoing_edges(id)
    }

    fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
        self.incoming_edges(id)
    }

    fn command_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.nodes_in_window_from_index(&self.command_node_index, after_sequence, before_sequence)
    }

    fn derived_invocation_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.nodes_in_window_from_index(
            &self.derived_invocation_node_index,
            after_sequence,
            before_sequence,
        )
    }

    fn nested_payload_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.nodes_in_window_from_index(
            &self.nested_payload_node_index,
            after_sequence,
            before_sequence,
        )
    }

    fn execution_semantics_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.nodes_in_window_from_index(
            &self.execution_semantics_node_index,
            after_sequence,
            before_sequence,
        )
    }

    fn path_fact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.indexed_nodes(&self.path_fact_node_index)
    }

    fn path_fact_nodes_by_concrete_path<'a>(
        &'a self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        match self.path_fact_by_concrete_path_index.get(path) {
            Some(node_ids) => self.indexed_nodes(node_ids),
            None => Box::new(std::iter::empty()),
        }
    }

    fn path_content_artifact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        self.indexed_nodes(&self.path_content_artifact_index)
    }

    fn path_content_artifact_nodes_by_path<'a>(
        &'a self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        match self.path_content_artifact_by_path_index.get(path) {
            Some(node_ids) => self.indexed_nodes(node_ids),
            None => Box::new(std::iter::empty()),
        }
    }
}

fn remove_index_entry<K: Ord>(index: &mut BTreeMap<K, Vec<NodeId>>, key: &K, node_id: &NodeId) {
    if let Some(node_ids) = index.get_mut(key) {
        remove_vec_entry(node_ids, node_id);
        if node_ids.is_empty() {
            index.remove(key);
        }
    }
}

fn remove_vec_entry(node_ids: &mut Vec<NodeId>, node_id: &NodeId) {
    if let Some(position) = node_ids.iter().position(|existing| existing == node_id) {
        node_ids.remove(position);
    }
}

#[cfg(test)]
mod tests {
    use super::{GraphError, SessionGraph};
    use crate::{Edge, EdgeKind, GraphNode, NodeId, NodeKind};
    use caushell_types::{
        CommandSequenceNo, PathResolution, ResolvedPathPurpose, ResolvedPathRole, SessionId,
        ShellKind,
    };

    fn sample_command_node(id: &str, sequence_no: u64) -> GraphNode {
        GraphNode::new_command_invocation(
            NodeId::new(id),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(sequence_no),
            "ls -la",
            "/tmp/project",
            ShellKind::Bash,
        )
    }

    #[test]
    fn session_graph_can_store_and_lookup_nodes() {
        let mut graph = SessionGraph::new();
        let node = sample_command_node("cmd-1", 1);

        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.add_node(node.clone()), None);
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.get_node(&NodeId::new("cmd-1")), Some(&node));
    }

    #[test]
    fn session_graph_rejects_edges_with_missing_source() {
        let mut graph = SessionGraph::new();
        graph.add_node(GraphNode::new(
            NodeId::new("path-1"),
            NodeKind::PathFact {
                resolution: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path".to_string(),
                normalized_command_name: None,
                metadata_mutation: None,
            },
        ));

        let result = graph.add_edge(Edge::new(
            NodeId::new("cmd-1"),
            NodeId::new("path-1"),
            EdgeKind::Reads,
        ));

        assert_eq!(
            result,
            Err(GraphError::MissingSourceNode(NodeId::new("cmd-1")))
        )
    }

    #[test]
    fn session_graph_accepts_edges_when_both_endpoints_exist() {
        let mut graph = SessionGraph::new();
        graph.add_node(sample_command_node("cmd-1", 1));
        graph.add_node(GraphNode::new(
            NodeId::new("path-1"),
            NodeKind::PathFact {
                resolution: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path".to_string(),
                normalized_command_name: None,
                metadata_mutation: None,
            },
        ));

        let result = graph.add_edge(Edge::new(
            NodeId::new("cmd-1"),
            NodeId::new("path-1"),
            EdgeKind::Reads,
        ));

        assert_eq!(result, Ok(()));
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.edges()[0].kind, EdgeKind::Reads);
    }

    #[test]
    fn session_graph_helper_can_add_command_invocation() {
        let mut graph = SessionGraph::new();

        let replaced = graph.add_command_invocation(
            NodeId::new("cmd-2"),
            SessionId::new("sess-2"),
            CommandSequenceNo::new(2),
            "pwd",
            "/tmp/project",
            ShellKind::Bash,
        );

        assert_eq!(replaced, None);
        assert_eq!(graph.node_count(), 1);

        let node = match graph.get_node(&NodeId::new("cmd-2")) {
            Some(node) => node,
            None => panic!("expected cmd-2 node to exist"),
        };

        match &node.kind {
            NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => {
                assert_eq!(node.id.0, "cmd-2");
                assert_eq!(session_id.0, "sess-2");
                assert_eq!(*sequence_no, CommandSequenceNo::new(2));
                assert_eq!(raw_text, "pwd");
                assert_eq!(cwd_before, "/tmp/project");
                assert_eq!(*shell_kind, ShellKind::Bash);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    #[test]
    fn session_graph_helper_can_add_path_fact() {
        let mut graph = SessionGraph::new();

        let replaced = graph.add_path_fact(
            NodeId::new("path-2"),
            PathResolution::Concrete {
                path: "/tmp/project/src".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            None,
        );

        assert_eq!(replaced, None);
        assert_eq!(graph.node_count(), 1);

        let node = match graph.get_node(&NodeId::new("path-2")) {
            Some(node) => node,
            None => panic!("expected path-2 node to exist"),
        };

        match &node.kind {
            NodeKind::PathFact {
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
            } => {
                assert_eq!(node.id.0, "path-2");
                assert_eq!(
                    resolution,
                    &PathResolution::Concrete {
                        path: "/tmp/project/src".to_string()
                    }
                );
                assert_eq!(*role, ResolvedPathRole::Read);
                assert_eq!(*purpose, Some(ResolvedPathPurpose::GenericOperand));
                assert_eq!(slot_name, "path");
                assert_eq!(*normalized_command_name, None);
                assert_eq!(metadata_mutation, &None);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    #[test]
    fn session_graph_exposes_nodes_iterator() {
        let mut graph = SessionGraph::new();
        graph.add_node(sample_command_node("cmd-1", 1));
        let _ = graph.add_path_fact(
            NodeId::new("path-1"),
            PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            None,
        );
        let ids: Vec<&str> = graph.nodes().map(|node| node.id.0.as_str()).collect();
        assert_eq!(ids, vec!["cmd-1", "path-1"])
    }

    #[test]
    fn session_graph_roundtrips_through_snapshot() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "pwd",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_path_fact(
            NodeId::new("resolved-path:0:script_path:/tmp/project/build.sh"),
            PathResolution::Concrete {
                path: "/tmp/project/build.sh".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::ScriptSource),
            "script_path",
            Some("bash".to_string()),
        );
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:1"),
                NodeId::new("resolved-path:0:script_path:/tmp/project/build.sh"),
                EdgeKind::Reads,
            ))
            .expect("expected graph edge to be valid");

        let snapshot = graph.to_snapshot();
        let restored =
            SessionGraph::from_snapshot(snapshot).expect("expected snapshot to restore graph");

        assert_eq!(restored.node_count(), 2);
        assert_eq!(restored.edge_count(), 1);
        assert_eq!(
            restored.nodes().collect::<Vec<_>>(),
            graph.nodes().collect::<Vec<_>>()
        );
        assert_eq!(restored.edges(), graph.edges());
        assert_eq!(
            restored
                .outgoing_edges(&NodeId::new("command:sess-1:1"))
                .collect::<Vec<_>>(),
            graph
                .outgoing_edges(&NodeId::new("command:sess-1:1"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            restored
                .incoming_edges(&NodeId::new(
                    "resolved-path:0:script_path:/tmp/project/build.sh"
                ))
                .collect::<Vec<_>>(),
            graph
                .incoming_edges(&NodeId::new(
                    "resolved-path:0:script_path:/tmp/project/build.sh"
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn session_graph_indexes_incoming_and_outgoing_edges_by_node() {
        let mut graph = SessionGraph::new();
        graph.add_node(sample_command_node("cmd-1", 1));
        graph.add_node(sample_command_node("cmd-2", 2));
        let _ = graph.add_path_fact(
            NodeId::new("path-1"),
            PathResolution::Concrete {
                path: "/tmp/project/input.sh".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::ScriptSource),
            "script_path",
            Some("bash".to_string()),
        );

        graph
            .add_edge(Edge::new(
                NodeId::new("cmd-1"),
                NodeId::new("path-1"),
                EdgeKind::Reads,
            ))
            .expect("expected first edge to be valid");
        graph
            .add_edge(Edge::new(
                NodeId::new("cmd-2"),
                NodeId::new("path-1"),
                EdgeKind::Targets,
            ))
            .expect("expected second edge to be valid");

        let outgoing_cmd_1: Vec<_> = graph.outgoing_edges(&NodeId::new("cmd-1")).collect();
        assert_eq!(outgoing_cmd_1.len(), 1);
        assert_eq!(outgoing_cmd_1[0].kind, EdgeKind::Reads);
        assert_eq!(outgoing_cmd_1[0].from, NodeId::new("cmd-1"));
        assert_eq!(outgoing_cmd_1[0].to, NodeId::new("path-1"));

        let incoming_path_1: Vec<_> = graph.incoming_edges(&NodeId::new("path-1")).collect();
        assert_eq!(incoming_path_1.len(), 2);
        assert_eq!(
            incoming_path_1
                .iter()
                .map(|edge| edge.kind)
                .collect::<Vec<_>>(),
            vec![EdgeKind::Reads, EdgeKind::Targets]
        );
        assert_eq!(
            incoming_path_1
                .iter()
                .map(|edge| edge.from.0.as_str())
                .collect::<Vec<_>>(),
            vec!["cmd-1", "cmd-2"]
        );
    }
}
