use crate::{QuerySession, SequenceWindow};
use caushell_graph::{NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, ImplicitInputSource, NestedPayload, NestedPayloadDecodeError,
    NestedPayloadInput, NestedPayloadInputFragment, NestedPayloadInputFragmentSnapshot,
    NestedPayloadLanguage, NestedPayloadOrigin, NestedPayloadResolution,
    NestedPayloadResolutionKind, NestedPayloadSource, RuntimeInputSource,
};

// Structure/analysis-record query over nested payload nodes.
//
// This surfaces recursively parsed payload containers and their parse
// outcomes. It describes shell expansion/analysis state, not provenance
// lineage by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NestedPayloadHistoryQuery {
    window: SequenceWindow,
}

impl NestedPayloadHistoryQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> NestedPayloadHistoryResult<'a> {
        let mut nested_payloads: Vec<NestedPayloadRef<'a>> = session
            .graph()
            .nested_payload_nodes_in_window(self.window.after_bound(), self.window.before_bound())
            .filter_map(NestedPayloadRef::from_node)
            .collect();

        nested_payloads.sort_by(|left, right| {
            left.root_command_sequence_no()
                .cmp(&right.root_command_sequence_no())
                .then_with(|| left.depth().cmp(&right.depth()))
                .then_with(|| left.record_id().cmp(&right.record_id()))
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        NestedPayloadHistoryResult { nested_payloads }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedPayloadHistoryResult<'a> {
    nested_payloads: Vec<NestedPayloadRef<'a>>,
}

impl<'a> NestedPayloadHistoryResult<'a> {
    pub fn nested_payloads(&self) -> &[NestedPayloadRef<'a>] {
        self.nested_payloads.as_slice()
    }

    pub fn len(&self) -> usize {
        self.nested_payloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nested_payloads.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestedPayloadRef<'a> {
    node_id: &'a NodeId,
    root_command_sequence_no: CommandSequenceNo,
    root_command_index: usize,
    record_id: usize,
    depth: u8,
    language: &'a str,
    source: &'a str,
    origin_kind: &'a str,
    origin_slot: Option<&'a str>,
    input_kind: &'a str,
    input_text: Option<&'a str>,
    input_fragments: &'a [NestedPayloadInputFragmentSnapshot],
    input_source: Option<ImplicitInputSource>,
    resolution_kind: &'a str,
    resolution_detail: Option<&'a str>,
    resolution_runtime_input_source: Option<RuntimeInputSource>,
}

impl<'a> NestedPayloadRef<'a> {
    pub(crate) fn from_node(node: &'a caushell_graph::GraphNode) -> Option<Self> {
        match &node.kind {
            NodeKind::NestedPayload {
                root_command_sequence_no,
                root_command_index,
                record_id,
                depth,
                language,
                source,
                origin_kind,
                origin_slot,
                input_kind,
                input_text,
                input_fragments,
                input_source,
                resolution_kind,
                resolution_detail,
                resolution_runtime_input_source,
            } => Some(Self {
                node_id: &node.id,
                root_command_sequence_no: *root_command_sequence_no,
                root_command_index: *root_command_index,
                record_id: *record_id,
                depth: *depth,
                language: language.as_str(),
                source: source.as_str(),
                origin_kind: origin_kind.as_str(),
                origin_slot: origin_slot.as_deref(),
                input_kind: input_kind.as_str(),
                input_text: input_text.as_deref(),
                input_fragments: input_fragments.as_slice(),
                input_source: *input_source,
                resolution_kind: resolution_kind.as_str(),
                resolution_detail: resolution_detail.as_deref(),
                resolution_runtime_input_source: *resolution_runtime_input_source,
            }),
            _ => None,
        }
    }

    pub fn node_id(&self) -> &'a NodeId {
        self.node_id
    }

    pub fn root_command_sequence_no(&self) -> CommandSequenceNo {
        self.root_command_sequence_no
    }

    pub fn root_command_index(&self) -> usize {
        self.root_command_index
    }

    pub fn record_id(&self) -> usize {
        self.record_id
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn language(&self) -> Result<NestedPayloadLanguage, NestedPayloadDecodeError> {
        NestedPayloadLanguage::from_storage(self.language)
    }

    pub fn source(&self) -> Result<NestedPayloadSource, NestedPayloadDecodeError> {
        NestedPayloadSource::from_storage(self.source)
    }

    pub fn origin(&self) -> Result<NestedPayloadOrigin, NestedPayloadDecodeError> {
        NestedPayloadOrigin::from_storage(self.origin_kind, self.origin_slot)
    }

    pub fn input(&self) -> Result<NestedPayloadInput, NestedPayloadDecodeError> {
        let input_fragments = self
            .input_fragments
            .iter()
            .map(|fragment| NestedPayloadInputFragment {
                text: fragment.text.clone(),
                quoted: fragment.quoted,
                node_kind: fragment.node_kind.clone(),
            })
            .collect::<Vec<_>>();

        NestedPayloadInput::from_storage(
            self.input_kind,
            self.input_text,
            &input_fragments,
            self.input_source,
        )
    }

    pub fn resolution_kind(&self) -> Result<NestedPayloadResolutionKind, NestedPayloadDecodeError> {
        NestedPayloadResolutionKind::from_storage(self.resolution_kind)
    }

    pub fn resolution_detail(&self) -> Option<&'a str> {
        self.resolution_detail
    }

    pub fn resolution_runtime_input_source(&self) -> Option<RuntimeInputSource> {
        self.resolution_runtime_input_source
    }

    pub fn to_nested_payload(&self) -> Result<NestedPayload, NestedPayloadDecodeError> {
        Ok(NestedPayload {
            node_id: self.node_id.0.clone(),
            root_sequence_no: self.root_command_sequence_no,
            root_command_index: self.root_command_index,
            record_id: self.record_id,
            depth: self.depth,
            language: self.language()?,
            source: self.source()?,
            origin: self.origin()?,
            input: self.input()?,
            resolution: NestedPayloadResolution {
                kind: self.resolution_kind()?,
                runtime_input_source: self.resolution_runtime_input_source,
                detail: self.resolution_detail.map(str::to_string),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{NestedPayloadHistoryQuery, NestedPayloadRef};
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{GraphNode, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, NestedPayload, NestedPayloadInput, NestedPayloadInputFragment,
        NestedPayloadInputFragmentSnapshot, NestedPayloadLanguage, NestedPayloadOrigin,
        NestedPayloadResolution, NestedPayloadResolutionKind, NestedPayloadSource, PathResolution,
        ResolvedPathPurpose, ResolvedPathRole, SessionSummary,
    };

    fn graph_with_nested_payloads() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:2:1"),
            caushell_graph::NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(2),
                root_command_index: 0,
                record_id: 1,
                depth: 2,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("echo child".to_string()),
                input_fragments: vec![NestedPayloadInputFragmentSnapshot {
                    text: "echo child".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=Bash;command_count=1".to_string()),
                resolution_runtime_input_source: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:2:0"),
            caushell_graph::NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(2),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("sh -c 'echo child'".to_string()),
                input_fragments: vec![NestedPayloadInputFragmentSnapshot {
                    text: "sh -c 'echo child'".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=Bash;command_count=1".to_string()),
                resolution_runtime_input_source: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:7:0"),
            caushell_graph::NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(7),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "implicit_input".to_string(),
                input_text: None,
                input_fragments: Vec::new(),
                input_source: Some(caushell_types::ImplicitInputSource::StdinPayload),
                resolution_kind: "requires_runtime_input".to_string(),
                resolution_detail: None,
                resolution_runtime_input_source: Some(
                    caushell_types::RuntimeInputSource::StdinPayload,
                ),
            },
        ));

        graph
    }

    #[test]
    fn nested_payload_history_query_returns_empty_when_graph_has_none() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = NestedPayloadHistoryQuery::new().execute(session);

        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn nested_payload_history_query_returns_nodes_sorted_by_sequence_depth_and_record() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = NestedPayloadHistoryQuery::new().execute(session);
        let ids: Vec<&str> = result
            .nested_payloads()
            .iter()
            .map(|nested| nested.node_id().0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "nested:sess-1:2:0",
                "nested:sess-1:2:1",
                "nested:sess-1:7:0"
            ]
        );
    }

    #[test]
    fn nested_payload_history_query_filters_strictly_before_sequence() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = NestedPayloadHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(7))
            .execute(session);

        assert_eq!(result.len(), 2);
        assert!(
            result
                .nested_payloads()
                .iter()
                .all(|nested| nested.root_command_sequence_no().0 == 2)
        );
    }

    #[test]
    fn nested_payload_history_query_filters_strictly_after_sequence() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = NestedPayloadHistoryQuery::new()
            .after_sequence(CommandSequenceNo::new(2))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.nested_payloads()[0].node_id().0, "nested:sess-1:7:0");
    }

    #[test]
    fn nested_payload_history_query_can_use_shared_sequence_window() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = NestedPayloadHistoryQuery::new()
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(2))
                    .before_sequence(CommandSequenceNo::new(8)),
            )
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.nested_payloads()[0].node_id().0, "nested:sess-1:7:0");
    }

    #[test]
    fn nested_payload_history_query_exposes_typed_fields() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let nested = NestedPayloadHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .nested_payloads()[0];

        assert_eq!(nested.node_id().0, "nested:sess-1:2:0");
        assert_eq!(nested.root_command_sequence_no(), CommandSequenceNo::new(2));
        assert_eq!(nested.root_command_index(), 0);
        assert_eq!(nested.record_id(), 0);
        assert_eq!(nested.depth(), 1);
        assert_eq!(nested.language(), Ok(NestedPayloadLanguage::Bash));
        assert_eq!(nested.source(), Ok(NestedPayloadSource::InlineString));
        assert_eq!(
            nested.origin(),
            Ok(NestedPayloadOrigin::Parameter {
                slot_name: "payload".to_string(),
            })
        );
        assert_eq!(
            nested.input(),
            Ok(NestedPayloadInput::ArgumentFragments {
                text: "sh -c 'echo child'".to_string(),
                fragments: vec![NestedPayloadInputFragment {
                    text: "sh -c 'echo child'".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
            })
        );
        assert_eq!(
            nested.resolution_kind(),
            Ok(NestedPayloadResolutionKind::Parsed)
        );
        assert_eq!(
            nested.resolution_detail(),
            Some("shell_kind=Bash;command_count=1")
        );
    }

    #[test]
    fn nested_payload_ref_ignores_non_nested_nodes() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_path_fact(
            NodeId::new("path-1"),
            PathResolution::Concrete {
                path: "/tmp/project/file".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            None,
        );

        let node = graph
            .get_node(&NodeId::new("path-1"))
            .expect("expected path node to exist");

        assert_eq!(NestedPayloadRef::from_node(node), None);
    }

    #[test]
    fn nested_payload_ref_exposes_runtime_input_source_when_present() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let nested = NestedPayloadHistoryQuery::new()
            .after_sequence(CommandSequenceNo::new(6))
            .execute(session)
            .nested_payloads()[0];

        assert_eq!(
            nested.input(),
            Ok(NestedPayloadInput::ImplicitInput {
                source: caushell_types::ImplicitInputSource::StdinPayload,
            })
        );
        assert_eq!(
            nested.resolution_kind(),
            Ok(NestedPayloadResolutionKind::RequiresRuntimeInput)
        );
        assert_eq!(
            nested.resolution_runtime_input_source(),
            Some(caushell_types::RuntimeInputSource::StdinPayload)
        );
    }

    #[test]
    fn nested_payload_ref_converts_to_contract_value() {
        let graph = graph_with_nested_payloads();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let nested = NestedPayloadHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .nested_payloads()[0];

        assert_eq!(
            nested.to_nested_payload(),
            Ok(NestedPayload {
                node_id: "nested:sess-1:2:0".to_string(),
                root_sequence_no: CommandSequenceNo::new(2),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: NestedPayloadLanguage::Bash,
                source: NestedPayloadSource::InlineString,
                origin: NestedPayloadOrigin::Parameter {
                    slot_name: "payload".to_string(),
                },
                input: NestedPayloadInput::ArgumentFragments {
                    text: "sh -c 'echo child'".to_string(),
                    fragments: vec![NestedPayloadInputFragment {
                        text: "sh -c 'echo child'".to_string(),
                        quoted: true,
                        node_kind: "raw_string".to_string(),
                    }],
                },
                resolution: NestedPayloadResolution {
                    kind: NestedPayloadResolutionKind::Parsed,
                    runtime_input_source: None,
                    detail: Some("shell_kind=Bash;command_count=1".to_string()),
                },
            })
        );
    }

    #[test]
    fn nested_payload_ref_decodes_config_defined_task_literal_text() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:8:0"),
            caushell_graph::NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(8),
                root_command_index: 0,
                record_id: 0,
                depth: 1,
                language: "sh".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "config_defined_task".to_string(),
                origin_slot: Some("/tmp/project/package.json#build".to_string()),
                input_kind: "literal_text".to_string(),
                input_text: Some("echo ok".to_string()),
                input_fragments: Vec::new(),
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: Some("shell_kind=Sh;command_count=1".to_string()),
                resolution_runtime_input_source: None,
            },
        ));

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let nested = NestedPayloadHistoryQuery::new()
            .execute(session)
            .nested_payloads()[0];

        assert_eq!(
            nested.origin(),
            Ok(NestedPayloadOrigin::ConfigDefinedTask {
                config_path: "/tmp/project/package.json".to_string(),
                task_name: "build".to_string(),
            })
        );
        assert_eq!(
            nested.input(),
            Ok(NestedPayloadInput::LiteralText {
                text: "echo ok".to_string(),
            })
        );
    }
}
