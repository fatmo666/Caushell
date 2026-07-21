use crate::{ExecutionUnitHistoryQuery, ExecutionUnitRef, QuerySession, SequenceWindow};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, RuntimeInputSource, SessionVariableBinding, SessionVariableValue,
    VariableBindingIntentFact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableBindingQuery {
    name: String,
}

impl VariableBindingQuery {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> Option<VariableBindingRef<'a>> {
        session
            .summary()
            .variable_binding(self.name())
            .map(VariableBindingRef::from_binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VariableBindingIntentHistoryQuery {
    name: Option<String>,
    window: SequenceWindow,
}

impl VariableBindingIntentHistoryQuery {
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> VariableBindingIntentHistoryResult<'a> {
        let mut intents = Vec::new();

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

                let Some(intent) = VariableBindingIntentRef::from_node_with_source(node, *source)
                else {
                    continue;
                };

                if self
                    .name
                    .as_deref()
                    .is_none_or(|name| intent.variable_name() == name)
                {
                    intents.push(intent);
                }
            }
        }

        intents.sort_by(|left, right| {
            left.source()
                .root_command_sequence_no()
                .cmp(&right.source().root_command_sequence_no())
                .then_with(|| left.source().depth().cmp(&right.source().depth()))
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        VariableBindingIntentHistoryResult { intents }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariableBindingRef<'a> {
    name: &'a str,
    value: &'a SessionVariableValue,
    exported: bool,
    observed_at: CommandSequenceNo,
}

impl<'a> VariableBindingRef<'a> {
    fn from_binding(binding: &'a SessionVariableBinding) -> Self {
        Self {
            name: binding.name.as_str(),
            value: &binding.value,
            exported: binding.exported,
            observed_at: binding.observed_at,
        }
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn value(&self) -> &'a SessionVariableValue {
        self.value
    }

    pub fn exported(&self) -> bool {
        self.exported
    }

    pub fn observed_at(&self) -> CommandSequenceNo {
        self.observed_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableBindingIntentHistoryResult<'a> {
    intents: Vec<VariableBindingIntentRef<'a>>,
}

impl<'a> VariableBindingIntentHistoryResult<'a> {
    pub fn intents(&self) -> &[VariableBindingIntentRef<'a>] {
        self.intents.as_slice()
    }

    pub fn len(&self) -> usize {
        self.intents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariableBindingIntentRef<'a> {
    node_id: &'a NodeId,
    source: ExecutionUnitRef<'a>,
    variable_name: &'a str,
    runtime_input_source: Option<RuntimeInputSource>,
}

impl<'a> VariableBindingIntentRef<'a> {
    fn from_node_with_source(
        node: &'a caushell_graph::GraphNode,
        source: ExecutionUnitRef<'a>,
    ) -> Option<Self> {
        let NodeKind::VariableBindingIntent {
            name,
            runtime_input_source,
        } = &node.kind
        else {
            return None;
        };

        Some(Self {
            node_id: &node.id,
            source,
            variable_name: name.as_str(),
            runtime_input_source: *runtime_input_source,
        })
    }

    pub fn node_id(&self) -> &'a NodeId {
        self.node_id
    }

    pub fn source(&self) -> ExecutionUnitRef<'a> {
        self.source
    }

    pub fn variable_name(&self) -> &'a str {
        self.variable_name
    }

    pub fn runtime_input_source(&self) -> Option<RuntimeInputSource> {
        self.runtime_input_source
    }

    pub fn to_variable_binding_intent_fact(&self) -> VariableBindingIntentFact {
        VariableBindingIntentFact {
            node_id: self.node_id.0.clone(),
            source: self.source.to_execution_unit(),
            variable_name: self.variable_name().to_string(),
            runtime_input_source: self.runtime_input_source(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{VariableBindingIntentHistoryQuery, VariableBindingQuery};
    use crate::QuerySession;
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, RuntimeInputSource, SessionId, SessionSummary, SessionVariableValue,
        ShellKind, VariableBindingIntentFact,
    };

    #[test]
    fn variable_binding_query_returns_none_when_binding_is_missing() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = VariableBindingQuery::new("SCRIPT").execute(session);

        assert_eq!(result, None);
    }

    #[test]
    fn variable_binding_query_returns_exact_scalar_binding() {
        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(3));
        let session = QuerySession::new(&graph, &summary);

        let result = VariableBindingQuery::new("SCRIPT")
            .execute(session)
            .expect("expected SCRIPT binding");

        assert_eq!(result.name(), "SCRIPT");
        assert_eq!(
            result.value(),
            &SessionVariableValue::ExactScalar("build.sh".to_string())
        );
        assert!(!result.exported());
        assert_eq!(result.observed_at(), CommandSequenceNo::new(3));
    }

    #[test]
    fn variable_binding_query_returns_dynamic_binding() {
        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable(
            "USER_CMD",
            "$payload",
            true,
            CommandSequenceNo::new(7),
        );
        let session = QuerySession::new(&graph, &summary);

        let result = VariableBindingQuery::new("USER_CMD")
            .execute(session)
            .expect("expected USER_CMD binding");

        assert_eq!(result.name(), "USER_CMD");
        assert_eq!(
            result.value(),
            &SessionVariableValue::OpaqueDynamic {
                repr: "$payload".to_string(),
            }
        );
        assert!(result.exported());
        assert_eq!(result.observed_at(), CommandSequenceNo::new(7));
    }

    #[test]
    fn variable_binding_intent_history_query_returns_sorted_intents() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:4"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "read SECOND",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "read FIRST",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("variable-binding-intent:command:sess-1:4:SECOND"),
            caushell_graph::NodeKind::VariableBindingIntent {
                name: "SECOND".to_string(),
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("variable-binding-intent:command:sess-1:2:FIRST"),
            caushell_graph::NodeKind::VariableBindingIntent {
                name: "FIRST".to_string(),
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:4"),
                NodeId::new("variable-binding-intent:command:sess-1:4:SECOND"),
                EdgeKind::Defines,
            ))
            .expect("expected defines edge to be added");
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:2"),
                NodeId::new("variable-binding-intent:command:sess-1:2:FIRST"),
                EdgeKind::Defines,
            ))
            .expect("expected defines edge to be added");

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let result = VariableBindingIntentHistoryQuery::new().execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(result.intents()[0].variable_name(), "FIRST");
        assert_eq!(result.intents()[1].variable_name(), "SECOND");
        assert_eq!(
            result.intents()[0].runtime_input_source(),
            Some(RuntimeInputSource::StdinData)
        );
    }

    #[test]
    fn variable_binding_intent_ref_converts_to_contract_value() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "read USER_CMD",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("variable-binding-intent:command:sess-1:2:USER_CMD"),
            caushell_graph::NodeKind::VariableBindingIntent {
                name: "USER_CMD".to_string(),
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:2"),
                NodeId::new("variable-binding-intent:command:sess-1:2:USER_CMD"),
                EdgeKind::Defines,
            ))
            .expect("expected defines edge to be added");

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let intent = VariableBindingIntentHistoryQuery::new()
            .name("USER_CMD")
            .execute(session)
            .intents()[0];

        assert_eq!(
            intent.to_variable_binding_intent_fact(),
            VariableBindingIntentFact {
                node_id: "variable-binding-intent:command:sess-1:2:USER_CMD".to_string(),
                source: caushell_types::ExecutionUnit {
                    node_id: "command:sess-1:2".to_string(),
                    execution_kind: caushell_types::ExecutionUnitKind::TopLevel,
                    root_sequence_no: CommandSequenceNo::new(2),
                    depth: 0,
                    raw_text: "read USER_CMD".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                variable_name: "USER_CMD".to_string(),
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            }
        );
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
            panic!("variable query should not require graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("variable query should not require graph.edges()");
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
    fn variable_binding_intent_queries_do_not_require_full_graph_scan() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "read FIRST",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("variable-binding-intent:command:sess-1:2:FIRST"),
            caushell_graph::NodeKind::VariableBindingIntent {
                name: "FIRST".to_string(),
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:2"),
                NodeId::new("variable-binding-intent:command:sess-1:2:FIRST"),
                EdgeKind::Defines,
            ))
            .expect("expected defines edge to be added");

        let wrapped = PanicOnFullScanGraph { inner: &graph };
        let summary = SessionSummary::new();
        let session = QuerySession::new(&wrapped, &summary);
        let result = VariableBindingIntentHistoryQuery::new().execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.intents()[0].variable_name(), "FIRST");
    }
}
