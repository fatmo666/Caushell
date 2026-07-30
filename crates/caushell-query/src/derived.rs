use crate::{QuerySession, SequenceWindow};
use caushell_graph::{NodeId, NodeKind};
use caushell_types::{CommandSequenceNo, DerivedInvocation, DerivedInvocationOrigin, ShellKind};

// Structure query over derived execution-unit nodes.
//
// These nodes capture shell expansion products such as dispatch children,
// pipeline segments, or nested parsed commands. This is not a provenance
// traversal surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DerivedInvocationHistoryQuery {
    window: SequenceWindow,
}

impl DerivedInvocationHistoryQuery {
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> DerivedInvocationHistoryResult<'a> {
        let mut derived_invocations: Vec<DerivedInvocationRef<'a>> = session
            .graph()
            .derived_invocation_nodes_in_window(
                self.window.after_bound(),
                self.window.before_bound(),
            )
            .filter_map(DerivedInvocationRef::from_node)
            .collect();

        derived_invocations.sort_by(|left, right| {
            left.root_command_sequence_no()
                .cmp(&right.root_command_sequence_no())
                .then_with(|| left.depth().cmp(&right.depth()))
                .then_with(|| left.origin_sort_key().cmp(&right.origin_sort_key()))
                .then_with(|| {
                    left.derived_command_index()
                        .cmp(&right.derived_command_index())
                })
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        DerivedInvocationHistoryResult {
            derived_invocations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedInvocationHistoryResult<'a> {
    derived_invocations: Vec<DerivedInvocationRef<'a>>,
}

impl<'a> DerivedInvocationHistoryResult<'a> {
    pub fn derived_invocations(&self) -> &[DerivedInvocationRef<'a>] {
        self.derived_invocations.as_slice()
    }

    pub fn len(&self) -> usize {
        self.derived_invocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.derived_invocations.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedInvocationRef<'a> {
    node_id: &'a NodeId,
    root_command_sequence_no: CommandSequenceNo,
    origin: &'a DerivedInvocationOrigin,
    derived_command_index: usize,
    raw_text: &'a str,
    command_name: Option<&'a str>,
    shell_kind: ShellKind,
    depth: u8,
}

impl<'a> DerivedInvocationRef<'a> {
    pub(crate) fn from_node(node: &'a caushell_graph::GraphNode) -> Option<Self> {
        match &node.kind {
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
            } => Some(Self {
                node_id: &node.id,
                root_command_sequence_no: *root_command_sequence_no,
                origin,
                derived_command_index: *derived_command_index,
                raw_text: raw_text.as_str(),
                command_name: command_name.as_deref(),
                shell_kind: *shell_kind,
                depth: *depth,
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

    pub fn origin(&self) -> &'a DerivedInvocationOrigin {
        self.origin
    }

    pub fn nested_record_id(&self) -> Option<usize> {
        match self.origin {
            DerivedInvocationOrigin::NestedPayload { nested_record_id } => Some(*nested_record_id),
            DerivedInvocationOrigin::CommandSubstitutionBody { .. }
            | DerivedInvocationOrigin::CommandSubstitutionMaterialization { .. }
            | DerivedInvocationOrigin::CommandSubstitutionAssignmentValue { .. }
            | DerivedInvocationOrigin::ProcessSubstitution { .. }
            | DerivedInvocationOrigin::ProcessSubstitutionBody { .. } => None,
            DerivedInvocationOrigin::Dispatch { .. }
            | DerivedInvocationOrigin::AliasExpansion { .. }
            | DerivedInvocationOrigin::FunctionExpansion { .. }
            | DerivedInvocationOrigin::ShellCommandStringPayload { .. }
            | DerivedInvocationOrigin::StaticXargs { .. }
            | DerivedInvocationOrigin::RecursivePayload { .. }
            | DerivedInvocationOrigin::PipelineSegment { .. } => None,
        }
    }

    pub fn pipeline_command_index(&self) -> Option<usize> {
        match self.origin {
            DerivedInvocationOrigin::PipelineSegment { command_index } => Some(*command_index),
            DerivedInvocationOrigin::NestedPayload { .. }
            | DerivedInvocationOrigin::CommandSubstitutionBody { .. }
            | DerivedInvocationOrigin::CommandSubstitutionMaterialization { .. }
            | DerivedInvocationOrigin::CommandSubstitutionAssignmentValue { .. }
            | DerivedInvocationOrigin::ProcessSubstitution { .. }
            | DerivedInvocationOrigin::ProcessSubstitutionBody { .. }
            | DerivedInvocationOrigin::Dispatch { .. }
            | DerivedInvocationOrigin::AliasExpansion { .. }
            | DerivedInvocationOrigin::FunctionExpansion { .. }
            | DerivedInvocationOrigin::ShellCommandStringPayload { .. }
            | DerivedInvocationOrigin::RecursivePayload { .. }
            | DerivedInvocationOrigin::StaticXargs { .. } => None,
        }
    }

    pub fn derived_command_index(&self) -> usize {
        self.derived_command_index
    }

    pub fn raw_text(&self) -> &'a str {
        self.raw_text
    }

    pub fn command_name(&self) -> Option<&'a str> {
        self.command_name
    }

    pub fn shell_kind(&self) -> ShellKind {
        self.shell_kind
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn to_derived_invocation(&self) -> DerivedInvocation {
        DerivedInvocation {
            node_id: self.node_id.0.clone(),
            root_sequence_no: self.root_command_sequence_no,
            origin: self.origin.clone(),
            derived_command_index: self.derived_command_index,
            raw_text: self.raw_text.to_string(),
            command_name: self.command_name.map(str::to_string),
            shell_kind: self.shell_kind,
            depth: self.depth,
        }
    }

    fn origin_sort_key(&self) -> (u8, usize, usize, usize, &str) {
        match self.origin {
            DerivedInvocationOrigin::NestedPayload { nested_record_id } => {
                (0, *nested_record_id, 0, 0, "")
            }
            DerivedInvocationOrigin::CommandSubstitutionBody {
                parent_node_id,
                token_index,
                substitution_index,
            } => (
                2,
                *token_index,
                *substitution_index,
                0,
                parent_node_id.as_str(),
            ),
            DerivedInvocationOrigin::CommandSubstitutionMaterialization {
                parent_node_id,
                command_index,
            } => (3, *command_index, 0, 0, parent_node_id.as_str()),
            DerivedInvocationOrigin::CommandSubstitutionAssignmentValue {
                parent_node_id,
                assignment_command_index,
                assignment_index,
                substitution_index,
            } => (
                4,
                *assignment_command_index,
                *assignment_index,
                *substitution_index,
                parent_node_id.as_str(),
            ),
            DerivedInvocationOrigin::ProcessSubstitution {
                process_substitution_record_id,
            } => (5, *process_substitution_record_id, 0, 0, ""),
            DerivedInvocationOrigin::ProcessSubstitutionBody {
                parent_node_id,
                location_kind,
                outer_index,
                location_subindex,
                substitution_index,
            } => (
                6,
                *outer_index,
                *location_subindex,
                *substitution_index,
                match location_kind.as_str() {
                    "argument" => parent_node_id.as_str(),
                    "redirection" => parent_node_id.as_str(),
                    _ => parent_node_id.as_str(),
                },
            ),
            DerivedInvocationOrigin::Dispatch {
                dispatch_index,
                source_command_index,
                command_slot,
            } => (
                7,
                *source_command_index,
                *dispatch_index,
                0,
                command_slot.as_str(),
            ),
            DerivedInvocationOrigin::AliasExpansion {
                source_command_index,
                alias_name,
            } => (8, *source_command_index, 0, 0, alias_name.as_str()),
            DerivedInvocationOrigin::FunctionExpansion {
                source_command_index,
                function_name,
            } => (9, *source_command_index, 0, 0, function_name.as_str()),
            DerivedInvocationOrigin::ShellCommandStringPayload { command_index } => {
                (10, *command_index, 0, 0, "")
            }
            DerivedInvocationOrigin::StaticXargs { child_index } => (11, *child_index, 0, 0, ""),
            DerivedInvocationOrigin::RecursivePayload {
                parent_node_id,
                command_index,
            } => (12, *command_index, 0, 0, parent_node_id.as_str()),
            DerivedInvocationOrigin::PipelineSegment { command_index } => {
                (13, *command_index, 0, 0, "")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DerivedInvocationHistoryQuery, DerivedInvocationRef};
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{GraphNode, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocation, DerivedInvocationOrigin, PathResolution,
        ResolvedPathPurpose, ResolvedPathRole, SessionSummary, ShellKind,
    };

    fn graph_with_derived_invocations() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:2:0:1"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(2),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 1,
                raw_text: "pwd".to_string(),
                command_name: Some("pwd".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:2:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(2),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:7:1:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(7),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 1,
                },
                derived_command_index: 0,
                raw_text: "sh -c \"echo later\"".to_string(),
                command_name: Some("sh".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 2,
            },
        ));

        graph
    }

    #[test]
    fn derived_invocation_history_query_returns_empty_when_graph_has_none() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = DerivedInvocationHistoryQuery::new().execute(session);

        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn derived_invocation_history_query_returns_nodes_sorted_by_sequence_and_index() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = DerivedInvocationHistoryQuery::new().execute(session);
        let ids: Vec<&str> = result
            .derived_invocations()
            .iter()
            .map(|derived| derived.node_id().0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "derived:sess-1:2:0:0",
                "derived:sess-1:2:0:1",
                "derived:sess-1:7:1:0"
            ]
        );
    }

    #[test]
    fn derived_invocation_history_query_filters_strictly_before_sequence() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = DerivedInvocationHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(7))
            .execute(session);

        assert_eq!(result.len(), 2);
        assert!(
            result
                .derived_invocations()
                .iter()
                .all(|derived| derived.root_command_sequence_no().0 == 2)
        );
    }

    #[test]
    fn derived_invocation_history_query_filters_strictly_after_sequence() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = DerivedInvocationHistoryQuery::new()
            .after_sequence(CommandSequenceNo::new(2))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.derived_invocations()[0].node_id().0,
            "derived:sess-1:7:1:0"
        );
    }

    #[test]
    fn derived_invocation_history_query_can_use_shared_sequence_window() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = DerivedInvocationHistoryQuery::new()
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(2))
                    .before_sequence(CommandSequenceNo::new(8)),
            )
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.derived_invocations()[0].command_name(), Some("sh"));
    }

    #[test]
    fn derived_invocation_history_query_exposes_typed_fields() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let derived = DerivedInvocationHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .derived_invocations()[0];

        assert_eq!(derived.node_id().0, "derived:sess-1:2:0:0");
        assert_eq!(
            derived.root_command_sequence_no(),
            CommandSequenceNo::new(2)
        );
        assert_eq!(
            derived.origin(),
            &DerivedInvocationOrigin::NestedPayload {
                nested_record_id: 0
            }
        );
        assert_eq!(derived.nested_record_id(), Some(0));
        assert_eq!(derived.derived_command_index(), 0);
        assert_eq!(derived.raw_text(), "echo ok");
        assert_eq!(derived.command_name(), Some("echo"));
        assert_eq!(derived.shell_kind(), ShellKind::Bash);
        assert_eq!(derived.depth(), 1);
    }

    #[test]
    fn derived_invocation_ref_ignores_non_derived_nodes() {
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

        assert_eq!(DerivedInvocationRef::from_node(node), None);
    }

    #[test]
    fn derived_invocation_ref_converts_to_contract_value() {
        let graph = graph_with_derived_invocations();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let derived = DerivedInvocationHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .derived_invocations()[0];

        assert_eq!(
            derived.to_derived_invocation(),
            DerivedInvocation {
                node_id: "derived:sess-1:2:0:0".to_string(),
                root_sequence_no: CommandSequenceNo::new(2),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            }
        );
    }
}
