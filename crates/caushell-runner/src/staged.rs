use std::collections::{BTreeMap, btree_map};
use std::iter::Peekable;

use caushell_graph::{Edge, GraphNode, GraphRead, NodeId, NodeKind, SessionRead};
use caushell_types::{CheckRequest, CommandSequenceNo, ProvenanceArtifact, SessionSummary};

use crate::PendingMutation;

pub struct StagedSession<'a> {
    graph: OverlayGraphRead<'a>,
    summary: SessionSummary,
}

impl<'a> StagedSession<'a> {
    pub fn new(
        graph: &'a dyn GraphRead,
        _request: &CheckRequest,
        committed_summary: &SessionSummary,
        pending_mutations: &[PendingMutation],
    ) -> Self {
        let mut summary = committed_summary.clone();

        for mutation in pending_mutations {
            mutation.apply_summary(&mut summary);
        }

        Self {
            graph: OverlayGraphRead::new(graph, pending_mutations),
            summary,
        }
    }
}

impl SessionRead for StagedSession<'_> {
    fn graph(&self) -> &dyn GraphRead {
        &self.graph
    }

    fn summary(&self) -> &SessionSummary {
        &self.summary
    }
}

struct OverlayGraphRead<'a> {
    base: &'a dyn GraphRead,
    overlay_nodes: BTreeMap<NodeId, GraphNode>,
    overlay_edges: Vec<Edge>,
    overlay_outgoing_edge_index: BTreeMap<NodeId, Vec<usize>>,
    overlay_incoming_edge_index: BTreeMap<NodeId, Vec<usize>>,
    overlay_command_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    overlay_derived_invocation_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    overlay_nested_payload_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    overlay_execution_semantics_node_index: BTreeMap<CommandSequenceNo, Vec<NodeId>>,
    overlay_path_fact_node_index: Vec<NodeId>,
    overlay_path_fact_by_concrete_path_index: BTreeMap<String, Vec<NodeId>>,
    overlay_path_content_artifact_index: Vec<NodeId>,
    overlay_path_content_artifact_by_path_index: BTreeMap<String, Vec<NodeId>>,
}

impl<'a> OverlayGraphRead<'a> {
    fn new(base: &'a dyn GraphRead, pending_mutations: &[PendingMutation]) -> Self {
        let mut overlay_nodes = BTreeMap::new();
        let mut overlay_edges = Vec::new();
        let mut overlay_outgoing_edge_index: BTreeMap<NodeId, Vec<usize>> = BTreeMap::new();
        let mut overlay_incoming_edge_index: BTreeMap<NodeId, Vec<usize>> = BTreeMap::new();

        for mutation in pending_mutations {
            let projection = mutation.graph_projection(&NodeId::new("__overlay-anchor__"));

            for node in projection.nodes {
                overlay_nodes.insert(node.id.clone(), node);
            }

            for node in projection.replace_nodes {
                overlay_nodes.insert(node.id.clone(), node);
            }

            for edge in projection.edges {
                let edge_index = overlay_edges.len();
                overlay_outgoing_edge_index
                    .entry(edge.from.clone())
                    .or_default()
                    .push(edge_index);
                overlay_incoming_edge_index
                    .entry(edge.to.clone())
                    .or_default()
                    .push(edge_index);
                overlay_edges.push(edge);
            }
        }

        let mut graph = Self {
            base,
            overlay_nodes,
            overlay_edges,
            overlay_outgoing_edge_index,
            overlay_incoming_edge_index,
            overlay_command_node_index: BTreeMap::new(),
            overlay_derived_invocation_node_index: BTreeMap::new(),
            overlay_nested_payload_node_index: BTreeMap::new(),
            overlay_execution_semantics_node_index: BTreeMap::new(),
            overlay_path_fact_node_index: Vec::new(),
            overlay_path_fact_by_concrete_path_index: BTreeMap::new(),
            overlay_path_content_artifact_index: Vec::new(),
            overlay_path_content_artifact_by_path_index: BTreeMap::new(),
        };
        graph.rebuild_overlay_indexes();

        graph
    }

    fn overlay_outgoing_edges<'b>(
        &'b self,
        id: &NodeId,
    ) -> Box<dyn Iterator<Item = &'b Edge> + 'b> {
        match self.overlay_outgoing_edge_index.get(id) {
            Some(indices) => Box::new(indices.iter().map(|index| &self.overlay_edges[*index])),
            None => Box::new(std::iter::empty()),
        }
    }

    fn overlay_incoming_edges<'b>(
        &'b self,
        id: &NodeId,
    ) -> Box<dyn Iterator<Item = &'b Edge> + 'b> {
        match self.overlay_incoming_edge_index.get(id) {
            Some(indices) => Box::new(indices.iter().map(|index| &self.overlay_edges[*index])),
            None => Box::new(std::iter::empty()),
        }
    }

    fn overlay_indexed_nodes<'b>(
        &'b self,
        node_ids: &'b [NodeId],
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        Box::new(
            node_ids
                .iter()
                .filter_map(|node_id| self.overlay_nodes.get(node_id)),
        )
    }

    fn overlay_window_nodes<'b>(
        &'b self,
        index: &'b BTreeMap<CommandSequenceNo, Vec<NodeId>>,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        use std::ops::Bound::{Excluded, Unbounded};

        let lower = after_sequence.map_or(Unbounded, Excluded);
        let upper = before_sequence.map_or(Unbounded, Excluded);

        Box::new(
            index
                .range((lower, upper))
                .flat_map(move |(_sequence_no, node_ids)| self.overlay_indexed_nodes(node_ids)),
        )
    }

    fn merge_base_and_overlay_nodes<'b>(
        &'b self,
        base: Box<dyn Iterator<Item = &'b GraphNode> + 'b>,
        overlay: Box<dyn Iterator<Item = &'b GraphNode> + 'b>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        Box::new(
            base.filter(|node| !self.overlay_nodes.contains_key(&node.id))
                .chain(overlay),
        )
    }

    fn execution_unit_sequence_no(&self, node_id: &NodeId) -> Option<CommandSequenceNo> {
        let node = self.get_node(node_id)?;
        match &node.kind {
            NodeKind::CommandInvocation { sequence_no, .. } => Some(*sequence_no),
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                ..
            } => Some(*root_command_sequence_no),
            _ => None,
        }
    }

    fn rebuild_overlay_indexes(&mut self) {
        for node in self.overlay_nodes.values() {
            match &node.kind {
                NodeKind::CommandInvocation { sequence_no, .. } => self
                    .overlay_command_node_index
                    .entry(*sequence_no)
                    .or_default()
                    .push(node.id.clone()),
                NodeKind::DerivedInvocation {
                    root_command_sequence_no,
                    ..
                } => self
                    .overlay_derived_invocation_node_index
                    .entry(*root_command_sequence_no)
                    .or_default()
                    .push(node.id.clone()),
                NodeKind::NestedPayload {
                    root_command_sequence_no,
                    ..
                } => self
                    .overlay_nested_payload_node_index
                    .entry(*root_command_sequence_no)
                    .or_default()
                    .push(node.id.clone()),
                NodeKind::ExecutionSemantics { .. } => {
                    let sequence_no = self.overlay_incoming_edges(&node.id).find_map(|edge| {
                        if edge.kind != caushell_graph::EdgeKind::Defines {
                            return None;
                        }

                        self.execution_unit_sequence_no(&edge.from)
                    });
                    if let Some(sequence_no) = sequence_no {
                        self.overlay_execution_semantics_node_index
                            .entry(sequence_no)
                            .or_default()
                            .push(node.id.clone());
                    }
                }
                NodeKind::PathFact { resolution, .. } => {
                    self.overlay_path_fact_node_index.push(node.id.clone());
                    if let Some(path) = resolution.concrete_path() {
                        self.overlay_path_fact_by_concrete_path_index
                            .entry(path.to_string())
                            .or_default()
                            .push(node.id.clone());
                    }
                }
                NodeKind::ProvenanceArtifact { artifact } => {
                    if let ProvenanceArtifact::PathContent { path, .. } = artifact {
                        self.overlay_path_content_artifact_index
                            .push(node.id.clone());
                        self.overlay_path_content_artifact_by_path_index
                            .entry(path.clone())
                            .or_default()
                            .push(node.id.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

impl GraphRead for OverlayGraphRead<'_> {
    fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.overlay_nodes
            .get(id)
            .or_else(|| self.base.get_node(id))
    }

    fn node_count(&self) -> usize {
        let mut count = self.base.node_count();

        for node_id in self.overlay_nodes.keys() {
            if self.base.get_node(node_id).is_none() {
                count += 1;
            }
        }

        count
    }

    fn edge_count(&self) -> usize {
        self.base.edge_count() + self.overlay_edges.len()
    }

    fn nodes<'b>(&'b self) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        Box::new(MergedNodeIter::new(
            self.base.nodes(),
            self.overlay_nodes.iter().peekable(),
        ))
    }

    fn edges<'b>(&'b self) -> Box<dyn Iterator<Item = &'b Edge> + 'b> {
        Box::new(self.base.edges().chain(self.overlay_edges.iter()))
    }

    fn outgoing_edges<'b>(&'b self, id: &NodeId) -> Box<dyn Iterator<Item = &'b Edge> + 'b> {
        Box::new(
            self.base
                .outgoing_edges(id)
                .chain(self.overlay_outgoing_edges(id)),
        )
    }

    fn incoming_edges<'b>(&'b self, id: &NodeId) -> Box<dyn Iterator<Item = &'b Edge> + 'b> {
        Box::new(
            self.base
                .incoming_edges(id)
                .chain(self.overlay_incoming_edges(id)),
        )
    }

    fn command_nodes_in_window<'b>(
        &'b self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base
                .command_nodes_in_window(after_sequence, before_sequence),
            self.overlay_window_nodes(
                &self.overlay_command_node_index,
                after_sequence,
                before_sequence,
            ),
        )
    }

    fn derived_invocation_nodes_in_window<'b>(
        &'b self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base
                .derived_invocation_nodes_in_window(after_sequence, before_sequence),
            self.overlay_window_nodes(
                &self.overlay_derived_invocation_node_index,
                after_sequence,
                before_sequence,
            ),
        )
    }

    fn nested_payload_nodes_in_window<'b>(
        &'b self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base
                .nested_payload_nodes_in_window(after_sequence, before_sequence),
            self.overlay_window_nodes(
                &self.overlay_nested_payload_node_index,
                after_sequence,
                before_sequence,
            ),
        )
    }

    fn execution_semantics_nodes_in_window<'b>(
        &'b self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base
                .execution_semantics_nodes_in_window(after_sequence, before_sequence),
            self.overlay_window_nodes(
                &self.overlay_execution_semantics_node_index,
                after_sequence,
                before_sequence,
            ),
        )
    }

    fn path_fact_nodes<'b>(&'b self) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base.path_fact_nodes(),
            self.overlay_indexed_nodes(&self.overlay_path_fact_node_index),
        )
    }

    fn path_fact_nodes_by_concrete_path<'b>(
        &'b self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base.path_fact_nodes_by_concrete_path(path),
            match self.overlay_path_fact_by_concrete_path_index.get(path) {
                Some(node_ids) => self.overlay_indexed_nodes(node_ids),
                None => Box::new(std::iter::empty()),
            },
        )
    }

    fn path_content_artifact_nodes<'b>(&'b self) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base.path_content_artifact_nodes(),
            self.overlay_indexed_nodes(&self.overlay_path_content_artifact_index),
        )
    }

    fn path_content_artifact_nodes_by_path<'b>(
        &'b self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'b GraphNode> + 'b> {
        self.merge_base_and_overlay_nodes(
            self.base.path_content_artifact_nodes_by_path(path),
            match self.overlay_path_content_artifact_by_path_index.get(path) {
                Some(node_ids) => self.overlay_indexed_nodes(node_ids),
                None => Box::new(std::iter::empty()),
            },
        )
    }
}

struct MergedNodeIter<'a> {
    base: Box<dyn Iterator<Item = &'a GraphNode> + 'a>,
    overlay: Peekable<btree_map::Iter<'a, NodeId, GraphNode>>,
    pending_base: Option<&'a GraphNode>,
}

impl<'a> MergedNodeIter<'a> {
    fn new(
        base: Box<dyn Iterator<Item = &'a GraphNode> + 'a>,
        overlay: Peekable<btree_map::Iter<'a, NodeId, GraphNode>>,
    ) -> Self {
        Self {
            base,
            overlay,
            pending_base: None,
        }
    }
}

impl<'a> Iterator for MergedNodeIter<'a> {
    type Item = &'a GraphNode;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let base_node = match self.pending_base.take() {
                Some(node) => Some(node),
                None => self.base.next(),
            };
            let overlay_entry = self.overlay.peek().copied();

            match (base_node, overlay_entry) {
                (Some(base_node), Some((overlay_id, overlay_node))) => {
                    if base_node.id < *overlay_id {
                        return Some(base_node);
                    }

                    if base_node.id == *overlay_id {
                        let _ = self.overlay.next();
                        return Some(overlay_node);
                    }

                    self.pending_base = Some(base_node);
                    let (_, overlay_node) = self
                        .overlay
                        .next()
                        .expect("expected overlay entry after successful peek");
                    return Some(overlay_node);
                }
                (Some(base_node), None) => return Some(base_node),
                (None, Some((_overlay_id, overlay_node))) => {
                    let _ = self.overlay.next();
                    return Some(overlay_node);
                }
                (None, None) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StagedSession;
    use crate::{PendingMutation, request_anchor_node_id, top_level_command_node_id};
    use caushell_graph::SessionGraph;
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, NodeKind, SessionRead};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode,
        ExecutionSemantics, PathResolution, ProvenanceArtifact, ProvenanceVariableValueState,
        ResolvedPathPurpose, ResolvedPathRole, RuntimeMetadata, SessionId, SessionSummary,
        ShellKind, ShellStateSnapshot,
    };

    fn sample_request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(3),
            command: "bash -c 'echo ok'".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
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

    #[test]
    fn staged_session_and_committed_graph_share_mutation_projection() {
        let base = SessionGraph::new();
        let request = sample_request();
        let command_node_id = top_level_command_node_id(&request, 0);
        let request_anchor_node_id = request_anchor_node_id(&request);
        let mutations = vec![
            PendingMutation::AddRequestAnchor {
                node_id: request_anchor_node_id.clone(),
                session_id: request.session_id.clone(),
                sequence_no: request.sequence_no,
                raw_text: request.command.clone(),
                cwd_before: request.shell_state_before.cwd.clone(),
                shell_kind: request.shell_kind,
            },
            PendingMutation::AddTopLevelCommandInvocation {
                node_id: command_node_id.clone(),
                session_id: request.session_id.clone(),
                sequence_no: request.sequence_no,
                command_index: 0,
                raw_text: request.command.clone(),
                cwd_before: request.shell_state_before.cwd.clone(),
                shell_kind: request.shell_kind,
            },
            PendingMutation::AddPathFact {
                source_node_id: command_node_id.clone(),
                node_id: NodeId::new("resolved-path:command:sess-1:3:0:script_path"),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/build.sh".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::ScriptSource),
                slot_name: "script_path".to_string(),
                normalized_command_name: Some("bash".to_string()),
                relation: EdgeKind::Reads,
            },
            PendingMutation::AddNestedPayload {
                node_id: NodeId::new("nested:sess-1:3:0"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("echo ok".to_string()),
                input_fragments: vec![caushell_types::NestedPayloadInputFragmentSnapshot {
                    text: "echo ok".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=bash".to_string()),
                resolution_runtime_input_source: None,
                relation_from_command: None,
                relation_from_parent: Some(EdgeKind::ExpandsTo),
                parent_node_id: Some(command_node_id.clone()),
            },
            PendingMutation::AddDerivedInvocation {
                node_id: NodeId::new("derived:sess-1:3:0:0"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
                parent_node_id: NodeId::new("nested:sess-1:3:0"),
                relation_from_parent: EdgeKind::ExpandsTo,
            },
            PendingMutation::AddDerivedInvocation {
                node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                derived_command_index: 0,
                raw_text: "cat payload.sh".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
                parent_node_id: command_node_id.clone(),
                relation_from_parent: EdgeKind::Dispatches,
            },
            PendingMutation::AddDerivedInvocation {
                node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                derived_command_index: 1,
                raw_text: "bash".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
                parent_node_id: command_node_id.clone(),
                relation_from_parent: EdgeKind::Dispatches,
            },
            PendingMutation::AddExecutionUnitFlow {
                from_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
                to_node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
            },
            PendingMutation::AddExecutionSemantics {
                source_node_id: NodeId::new("derived:sess-1:3:0:0"),
                node_id: NodeId::new("execution-semantics:derived:sess-1:3:0:0"),
                semantics: ExecutionSemantics::new("echo", "ordinary_command"),
            },
        ];

        let staged = StagedSession::new(&base, &request, &SessionSummary::new(), &mutations);
        let mut committed = SessionGraph::new();
        let _ = committed.add_request_anchor(
            request_anchor_node_id,
            request.session_id.clone(),
            request.sequence_no,
            request.command.clone(),
            request.shell_state_before.cwd.clone(),
            request.shell_kind,
        );

        for mutation in &mutations {
            mutation
                .apply_graph(&mut committed, &command_node_id)
                .expect("expected graph mutation to apply");
        }

        let staged_nodes: Vec<_> = staged.graph().nodes().cloned().collect();
        let committed_nodes: Vec<_> = committed.nodes().cloned().collect();
        let staged_edges: Vec<_> = staged.graph().edges().cloned().collect();
        let committed_edges = committed.edges().to_vec();

        assert_eq!(staged_nodes, committed_nodes);
        assert_eq!(staged_edges, committed_edges);
    }

    #[test]
    fn staged_session_exposes_nested_payload_overlay_node() {
        let base = SessionGraph::new();
        let request = sample_request();
        let staged = StagedSession::new(
            &base,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::AddNestedPayload {
                node_id: NodeId::new("nested:sess-1:3:0"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("echo ok".to_string()),
                input_fragments: vec![caushell_types::NestedPayloadInputFragmentSnapshot {
                    text: "echo ok".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=bash".to_string()),
                resolution_runtime_input_source: None,
                relation_from_command: None,
                relation_from_parent: Some(EdgeKind::ExpandsTo),
                parent_node_id: Some(top_level_command_node_id(&request, 0)),
            }],
        );

        let node = staged
            .graph()
            .get_node(&NodeId::new("nested:sess-1:3:0"))
            .expect("expected staged nested payload node to exist");

        match &node.kind {
            NodeKind::NestedPayload {
                record_id,
                depth,
                input_text,
                ..
            } => {
                assert_eq!(*record_id, 0);
                assert_eq!(*depth, 1);
                assert_eq!(input_text.as_deref(), Some("echo ok"));
            }
            other => panic!("unexpected node kind: {other:?}"),
        }

        assert_eq!(staged.graph().edge_count(), 1);
    }

    #[test]
    fn staged_session_exposes_derived_invocation_overlay_node() {
        let mut base = SessionGraph::new();
        let _ = base.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:3:0"),
            NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(3),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("echo ok".to_string()),
                input_fragments: vec![caushell_types::NestedPayloadInputFragmentSnapshot {
                    text: "echo ok".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=bash".to_string()),
                resolution_runtime_input_source: None,
            },
        ));
        let request = sample_request();
        let staged = StagedSession::new(
            &base,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::AddDerivedInvocation {
                node_id: NodeId::new("derived:sess-1:3:0:0"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
                parent_node_id: NodeId::new("nested:sess-1:3:0"),
                relation_from_parent: EdgeKind::ExpandsTo,
            }],
        );

        let node = staged
            .graph()
            .get_node(&NodeId::new("derived:sess-1:3:0:0"))
            .expect("expected staged derived invocation node to exist");

        match &node.kind {
            NodeKind::DerivedInvocation {
                origin,
                derived_command_index,
                command_name,
                ..
            } => {
                assert_eq!(
                    *origin,
                    DerivedInvocationOrigin::NestedPayload {
                        nested_record_id: 0
                    }
                );
                assert_eq!(*derived_command_index, 0);
                assert_eq!(command_name.as_deref(), Some("echo"));
            }
            other => panic!("unexpected node kind: {other:?}"),
        }

        assert_eq!(staged.graph().edge_count(), 1);
    }

    #[test]
    fn staged_session_exposes_execution_unit_flow_overlay_edge() {
        let mut base = SessionGraph::new();
        let _ = base.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:3:0"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                derived_command_index: 0,
                raw_text: "cat payload.sh".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = base.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:3:1"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                derived_command_index: 1,
                raw_text: "bash".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let request = sample_request();
        let staged = StagedSession::new(
            &base,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::AddExecutionUnitFlow {
                from_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
                to_node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
            }],
        );

        let flow_edge = staged
            .graph()
            .edges()
            .find(|edge| edge.kind == EdgeKind::FlowsTo)
            .expect("expected staged flow edge to exist");

        assert_eq!(flow_edge.from, NodeId::new("pipeline-segment:sess-1:3:0"));
        assert_eq!(flow_edge.to, NodeId::new("pipeline-segment:sess-1:3:1"));
    }

    #[test]
    fn staged_session_exposes_execution_semantics_overlay_node() {
        let mut base = SessionGraph::new();
        let _ = base.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "bash -c 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let request = sample_request();
        let staged = StagedSession::new(
            &base,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::AddExecutionSemantics {
                source_node_id: NodeId::new("command:sess-1:3"),
                node_id: NodeId::new("execution-semantics:command:sess-1:3"),
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload(),
            }],
        );

        let node = staged
            .graph()
            .get_node(&NodeId::new("execution-semantics:command:sess-1:3"))
            .expect("expected staged semantics node to exist");

        match &node.kind {
            NodeKind::ExecutionSemantics { semantics } => {
                assert_eq!(semantics.normalized_command_name, "bash");
                assert_eq!(semantics.form_id, "command_string");
                assert_eq!(
                    semantics.payload_mode,
                    Some(ExecutionPayloadMode::CommandString)
                );
                assert!(semantics.executes_payload);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }

        let edge = staged
            .graph()
            .edges()
            .find(|edge| edge.kind == EdgeKind::Defines)
            .expect("expected staged semantics edge to exist");

        assert_eq!(edge.from, NodeId::new("command:sess-1:3"));
        assert_eq!(edge.to, NodeId::new("execution-semantics:command:sess-1:3"));
    }

    #[test]
    fn staged_session_exposes_replaced_provenance_artifact_node() {
        let mut base = SessionGraph::new();
        let artifact_node_id = NodeId::new("artifact:variable-value:SCRIPT:3");
        let _ = base.add_node(GraphNode::new_provenance_artifact(
            artifact_node_id.clone(),
            ProvenanceArtifact::VariableValue {
                name: "SCRIPT".to_string(),
                state: ProvenanceVariableValueState::ExactScalar {
                    value: "build.sh".to_string(),
                },
                exported: false,
                version: 3,
            },
        ));
        let request = sample_request();
        let staged = StagedSession::new(
            &base,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::ReplaceProvenanceArtifact {
                node_id: artifact_node_id.clone(),
                artifact: ProvenanceArtifact::VariableValue {
                    name: "SCRIPT".to_string(),
                    state: ProvenanceVariableValueState::RuntimeProduced {
                        value: "build.sh".to_string(),
                        value_kind: caushell_types::RuntimeProducedValueKind::Path,
                    },
                    exported: false,
                    version: 3,
                },
            }],
        );

        let node = staged
            .graph()
            .get_node(&artifact_node_id)
            .expect("expected replaced staged artifact node to exist");

        match &node.kind {
            NodeKind::ProvenanceArtifact { artifact } => match artifact {
                ProvenanceArtifact::VariableValue { state, .. } => {
                    assert_eq!(
                        *state,
                        ProvenanceVariableValueState::RuntimeProduced {
                            value: "build.sh".to_string(),
                            value_kind: caushell_types::RuntimeProducedValueKind::Path,
                        }
                    );
                }
                other => panic!("unexpected provenance artifact kind: {other:?}"),
            },
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    struct PanicOnEdgesGraph<'a> {
        inner: &'a SessionGraph,
    }

    impl GraphRead for PanicOnEdgesGraph<'_> {
        fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
            self.inner.get_node(id)
        }

        fn node_count(&self) -> usize {
            self.inner.node_count()
        }

        fn edge_count(&self) -> usize {
            self.inner.edge_count()
        }

        fn nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            Box::new(self.inner.nodes())
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("overlay adjacency should not require graph.edges()");
        }

        fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.outgoing_edges(id)
        }

        fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.incoming_edges(id)
        }

        fn command_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .command_nodes_in_window(after_sequence, before_sequence)
        }

        fn derived_invocation_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .derived_invocation_nodes_in_window(after_sequence, before_sequence)
        }

        fn nested_payload_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .nested_payload_nodes_in_window(after_sequence, before_sequence)
        }

        fn execution_semantics_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .execution_semantics_nodes_in_window(after_sequence, before_sequence)
        }

        fn path_fact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes()
        }

        fn path_fact_nodes_by_concrete_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes_by_concrete_path(path)
        }

        fn path_content_artifact_nodes<'a>(
            &'a self,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes()
        }

        fn path_content_artifact_nodes_by_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes_by_path(path)
        }
    }

    #[test]
    fn staged_session_adjacency_does_not_require_full_edge_scan() {
        let mut base = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:3");
        let path_node_id = NodeId::new("resolved-path:command:sess-1:3:0:script_path");
        let _ = base.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "bash ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = base.add_node(GraphNode::new_path_fact(
            path_node_id.clone(),
            PathResolution::Concrete {
                path: "/tmp/project/build.sh".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::ScriptSource),
            "script_path",
            Some("bash".to_string()),
        ));
        base.add_edge(Edge::new(
            command_node_id.clone(),
            path_node_id.clone(),
            EdgeKind::Reads,
        ))
        .expect("expected base edge to be insertable");

        let request = sample_request();
        let wrapped = PanicOnEdgesGraph { inner: &base };
        let staged = StagedSession::new(
            &wrapped,
            &request,
            &SessionSummary::new(),
            &[PendingMutation::AddExecutionSemantics {
                source_node_id: command_node_id.clone(),
                node_id: NodeId::new("execution-semantics:command:sess-1:3"),
                semantics: ExecutionSemantics::new("bash", "script_file")
                    .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                    .executing_payload(),
            }],
        );

        let outgoing: Vec<_> = staged.graph().outgoing_edges(&command_node_id).collect();
        assert_eq!(outgoing.len(), 2);
        assert!(outgoing.iter().any(|edge| edge.kind == EdgeKind::Reads));
        assert!(outgoing.iter().any(|edge| edge.kind == EdgeKind::Defines));
    }
}
