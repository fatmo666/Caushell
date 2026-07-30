use crate::{ExecutionUnitHistoryQuery, ExecutionUnitRef, QuerySession, SequenceWindow};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{AliasHistoryAction, AliasHistoryEntry, CommandSequenceNo};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AliasHistoryQuery {
    name: Option<String>,
    window: SequenceWindow,
}

impl AliasHistoryQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> AliasHistoryResult<'a> {
        let mut entries = Vec::new();

        for source in ExecutionUnitHistoryQuery::new()
            .window(self.window)
            .execute(session)
            .execution_units()
        {
            for edge in session.graph().outgoing_edges(source.node_id()) {
                if edge.kind != EdgeKind::Defines {
                    continue;
                }

                let Some(node) = session.graph().get_node(&edge.to) else {
                    continue;
                };
                let Some(entry) =
                    AliasHistoryRef::from_node_with_source(*source, &node.id, &node.kind)
                else {
                    continue;
                };

                if self
                    .name
                    .as_ref()
                    .is_none_or(|name| name.as_str() == entry.name())
                {
                    entries.push(entry);
                }
            }
        }

        entries.sort_by(|left, right| {
            left.observed_at()
                .cmp(&right.observed_at())
                .then_with(|| left.name().cmp(right.name()))
                .then_with(|| {
                    alias_action_rank(left.action()).cmp(&alias_action_rank(right.action()))
                })
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        AliasHistoryResult { entries }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasHistoryResult<'a> {
    entries: Vec<AliasHistoryRef<'a>>,
}

impl<'a> AliasHistoryResult<'a> {
    pub fn entries(&self) -> &[AliasHistoryRef<'a>] {
        self.entries.as_slice()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasHistoryRef<'a> {
    node_id: &'a NodeId,
    source: ExecutionUnitRef<'a>,
    name: &'a str,
    action: AliasHistoryAction,
    body: Option<&'a str>,
    observed_at: CommandSequenceNo,
    version: u64,
}

impl<'a> AliasHistoryRef<'a> {
    fn from_node_with_source(
        source: ExecutionUnitRef<'a>,
        node_id: &'a NodeId,
        kind: &'a NodeKind,
    ) -> Option<Self> {
        match kind {
            NodeKind::AliasBinding {
                name,
                body,
                version,
            } => Some(Self {
                node_id,
                source,
                name: name.as_str(),
                action: AliasHistoryAction::Set,
                body: Some(body.as_str()),
                observed_at: CommandSequenceNo::new(*version),
                version: *version,
            }),
            NodeKind::AliasMutation {
                name,
                action,
                version,
            } => Some(Self {
                node_id,
                source,
                name: name.as_str(),
                action: (*action).into(),
                body: None,
                observed_at: CommandSequenceNo::new(*version),
                version: *version,
            }),
            _ => None,
        }
    }

    pub fn node_id(&self) -> &'a NodeId {
        self.node_id
    }

    pub fn source(&self) -> ExecutionUnitRef<'a> {
        self.source
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn action(&self) -> AliasHistoryAction {
        self.action
    }

    pub fn body(&self) -> Option<&'a str> {
        self.body
    }

    pub fn observed_at(&self) -> CommandSequenceNo {
        self.observed_at
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn to_alias_history_entry(&self) -> AliasHistoryEntry {
        AliasHistoryEntry {
            node_id: self.node_id.0.clone(),
            source: self.source.to_execution_unit(),
            name: self.name.to_string(),
            action: self.action,
            body: self.body.map(str::to_string),
            observed_at: self.observed_at,
            version: self.version,
        }
    }
}

fn alias_action_rank(action: AliasHistoryAction) -> u8 {
    match action {
        AliasHistoryAction::Set => 0,
        AliasHistoryAction::Unset => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::AliasHistoryQuery;
    use crate::QuerySession;
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, NodeKind, SessionGraph};
    use caushell_types::{
        AliasHistoryAction, AliasMutationAction, CommandSequenceNo, ExecutionUnitKind, SessionId,
        SessionSummary, ShellKind,
    };

    fn graph_with_alias_history() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "alias runbuild='bash ./scripts/build.sh'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "unalias runbuild",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("alias-binding:runbuild:1:test"),
            NodeKind::AliasBinding {
                name: "runbuild".to_string(),
                body: "bash ./scripts/build.sh".to_string(),
                version: 1,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("alias-mutation:runbuild:unset:3"),
            NodeKind::AliasMutation {
                name: "runbuild".to_string(),
                action: AliasMutationAction::Unset,
                version: 3,
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:1"),
                NodeId::new("alias-binding:runbuild:1:test"),
                EdgeKind::Defines,
            ))
            .expect("expected define edge");
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:3"),
                NodeId::new("alias-mutation:runbuild:unset:3"),
                EdgeKind::Defines,
            ))
            .expect("expected unset edge");

        graph
    }

    #[test]
    fn alias_history_query_returns_set_and_unset_entries() {
        let graph = graph_with_alias_history();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = AliasHistoryQuery::new().execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(result.entries()[0].name(), "runbuild");
        assert_eq!(result.entries()[0].action(), AliasHistoryAction::Set);
        assert_eq!(result.entries()[0].body(), Some("bash ./scripts/build.sh"));
        assert_eq!(result.entries()[0].observed_at(), CommandSequenceNo::new(1));
        assert_eq!(
            result.entries()[0]
                .source()
                .to_execution_unit()
                .execution_kind,
            ExecutionUnitKind::TopLevel
        );

        assert_eq!(result.entries()[1].name(), "runbuild");
        assert_eq!(result.entries()[1].action(), AliasHistoryAction::Unset);
        assert_eq!(result.entries()[1].body(), None);
        assert_eq!(result.entries()[1].observed_at(), CommandSequenceNo::new(3));
        assert_eq!(
            result.entries()[1].source().to_execution_unit().raw_text,
            "unalias runbuild"
        );
    }

    #[test]
    fn alias_history_query_filters_by_name_and_sequence_window() {
        let graph = graph_with_alias_history();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = AliasHistoryQuery::new()
            .name("runbuild")
            .after_sequence(CommandSequenceNo::new(1))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.entries()[0].action(), AliasHistoryAction::Unset);
    }

    struct PanicOnFullScanGraph<'a> {
        inner: &'a SessionGraph,
    }

    impl GraphRead for PanicOnFullScanGraph<'_> {
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
            panic!("alias query should not require graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("alias query should not require graph.edges()");
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
    fn alias_history_query_does_not_require_full_graph_scan() {
        let graph = graph_with_alias_history();
        let wrapped = PanicOnFullScanGraph { inner: &graph };
        let summary = SessionSummary::new();
        let session = QuerySession::new(&wrapped, &summary);

        let result = AliasHistoryQuery::new().execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(result.entries()[0].action(), AliasHistoryAction::Set);
        assert_eq!(result.entries()[1].action(), AliasHistoryAction::Unset);
    }
}
