use caushell_graph::{GraphRead, SessionRead};
use caushell_types::SessionSummary;

#[derive(Clone, Copy)]
pub struct QuerySession<'a> {
    graph: &'a dyn GraphRead,
    summary: &'a SessionSummary,
}

impl<'a> QuerySession<'a> {
    pub fn new(graph: &'a dyn GraphRead, summary: &'a SessionSummary) -> Self {
        Self { graph, summary }
    }

    pub fn from_session(session: &'a dyn SessionRead) -> Self {
        Self::new(session.graph(), session.summary())
    }

    pub fn graph(&self) -> &'a dyn GraphRead {
        self.graph
    }

    pub fn summary(&self) -> &'a SessionSummary {
        self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::QuerySession;
    use caushell_graph::SessionGraph;
    use caushell_types::SessionSummary;

    #[test]
    fn query_session_exposes_graph_and_summary() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();

        let session = QuerySession::new(&graph, &summary);

        assert_eq!(session.graph().node_count(), 0);
        assert_eq!(session.graph().edge_count(), 0);
        assert_eq!(session.summary().last_sequence_no(), None);
    }

    #[test]
    fn query_session_is_copyable() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();

        let session = QuerySession::new(&graph, &summary);
        let copied = session;

        assert_eq!(copied.graph().node_count(), 0);
        assert_eq!(copied.summary().last_sequence_no(), None);
    }
}
