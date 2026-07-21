use crate::{QuerySession, SequenceWindow};
use caushell_graph::{NodeId, NodeKind};
use caushell_types::{CommandSequenceNo, SessionId, ShellKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionCommandHistoryQuery {
    window: SequenceWindow,
}

impl SessionCommandHistoryQuery {
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> SessionCommandHistoryResult<'a> {
        let mut commands: Vec<CommandInvocationRef<'a>> = session
            .graph()
            .command_nodes_in_window(self.window.after_bound(), self.window.before_bound())
            .filter_map(CommandInvocationRef::from_node)
            .collect();

        commands.sort_by(|left, right| {
            left.sequence_no()
                .cmp(&right.sequence_no())
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        SessionCommandHistoryResult { commands }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCommandHistoryResult<'a> {
    commands: Vec<CommandInvocationRef<'a>>,
}

impl<'a> SessionCommandHistoryResult<'a> {
    pub fn commands(&self) -> &[CommandInvocationRef<'a>] {
        self.commands.as_slice()
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandInvocationRef<'a> {
    node_id: &'a NodeId,
    session_id: &'a SessionId,
    sequence_no: CommandSequenceNo,
    raw_text: &'a str,
    cwd_before: &'a str,
    shell_kind: ShellKind,
}

impl<'a> CommandInvocationRef<'a> {
    pub(crate) fn from_node(node: &'a caushell_graph::GraphNode) -> Option<Self> {
        match &node.kind {
            NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => Some(Self {
                node_id: &node.id,
                session_id,
                sequence_no: *sequence_no,
                raw_text: raw_text.as_str(),
                cwd_before: cwd_before.as_str(),
                shell_kind: *shell_kind,
            }),
            _ => None,
        }
    }

    pub fn node_id(&self) -> &'a NodeId {
        self.node_id
    }

    pub fn session_id(&self) -> &'a SessionId {
        self.session_id
    }

    pub fn sequence_no(&self) -> CommandSequenceNo {
        self.sequence_no
    }

    pub fn raw_text(&self) -> &'a str {
        self.raw_text
    }

    pub fn cwd_before(&self) -> &'a str {
        self.cwd_before
    }

    pub fn shell_kind(&self) -> ShellKind {
        self.shell_kind
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandInvocationRef, SessionCommandHistoryQuery};
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, PathResolution, ResolvedPathPurpose, ResolvedPathRole, SessionId,
        SessionSummary, ShellKind,
    };

    fn graph_with_commands() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:10"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(10),
            "cmd-10",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "cmd-2",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "cmd-1",
            "/tmp/project",
            ShellKind::Bash,
        );
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

        graph
    }

    #[test]
    fn command_history_query_returns_empty_when_graph_has_no_commands() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = SessionCommandHistoryQuery::new().execute(session);

        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
        assert!(result.commands().is_empty());
    }

    #[test]
    fn command_history_query_returns_commands_sorted_by_sequence() {
        let graph = graph_with_commands();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = SessionCommandHistoryQuery::new().execute(session);
        let sequence_nos: Vec<u64> = result
            .commands()
            .iter()
            .map(|command| command.sequence_no().0)
            .collect();
        let raw_texts: Vec<&str> = result
            .commands()
            .iter()
            .map(CommandInvocationRef::raw_text)
            .collect();

        assert_eq!(result.len(), 3);
        assert_eq!(sequence_nos, vec![1, 2, 10]);
        assert_eq!(raw_texts, vec!["cmd-1", "cmd-2", "cmd-10"]);
    }

    #[test]
    fn command_history_query_filters_commands_before_sequence_strictly() {
        let graph = graph_with_commands();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = SessionCommandHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(10))
            .execute(session);
        let sequence_nos: Vec<u64> = result
            .commands()
            .iter()
            .map(|command| command.sequence_no().0)
            .collect();

        assert_eq!(sequence_nos, vec![1, 2]);
    }

    #[test]
    fn command_history_query_filters_commands_after_sequence_strictly() {
        let graph = graph_with_commands();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = SessionCommandHistoryQuery::new()
            .after_sequence(CommandSequenceNo::new(1))
            .execute(session);
        let sequence_nos: Vec<u64> = result
            .commands()
            .iter()
            .map(|command| command.sequence_no().0)
            .collect();

        assert_eq!(sequence_nos, vec![2, 10]);
    }

    #[test]
    fn command_history_query_can_use_shared_sequence_window() {
        let graph = graph_with_commands();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = SessionCommandHistoryQuery::new()
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(1))
                    .before_sequence(CommandSequenceNo::new(10)),
            )
            .execute(session);
        let sequence_nos: Vec<u64> = result
            .commands()
            .iter()
            .map(|command| command.sequence_no().0)
            .collect();

        assert_eq!(sequence_nos, vec![2]);
    }

    #[test]
    fn command_history_query_exposes_typed_command_fields() {
        let graph = graph_with_commands();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let first = SessionCommandHistoryQuery::new()
            .execute(session)
            .commands()[0];

        assert_eq!(first.node_id().0, "command:sess-1:1");
        assert_eq!(first.session_id().0, "sess-1");
        assert_eq!(first.sequence_no(), CommandSequenceNo::new(1));
        assert_eq!(first.raw_text(), "cmd-1");
        assert_eq!(first.cwd_before(), "/tmp/project");
        assert_eq!(first.shell_kind(), ShellKind::Bash);
    }
}
