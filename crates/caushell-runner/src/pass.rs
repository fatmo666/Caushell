use crate::RunnerContext;
use caushell_graph::{GraphRead, SessionRead};
use caushell_types::SessionSummary;

#[derive(Clone, Copy)]
pub struct SessionView<'a> {
    graph: &'a dyn GraphRead,
    summary: &'a SessionSummary,
}

impl<'a> SessionView<'a> {
    pub fn new(graph: &'a dyn GraphRead, summary: &'a SessionSummary) -> Self {
        Self { graph, summary }
    }

    pub fn graph(&self) -> &'a dyn GraphRead {
        self.graph
    }

    pub fn summary(&self) -> &'a SessionSummary {
        self.summary
    }

    pub fn from_session(session: &'a dyn SessionRead) -> Self {
        Self::new(session.graph(), session.summary())
    }
}

impl SessionRead for SessionView<'_> {
    fn graph(&self) -> &dyn GraphRead {
        self.graph
    }

    fn summary(&self) -> &SessionSummary {
        self.summary
    }
}

// Request-scoped transform passes operate only on current-run state.
pub trait RequestTransformPass {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &mut RunnerContext);
}

// Session-scoped transform passes may inspect committed session state.
pub trait SessionTransformPass {
    fn name(&self) -> &'static str;
    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext);
}

// Request-scoped analysis passes operate only on current-run state.
pub trait RequestAnalysisPass {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &mut RunnerContext);
}

// Session-scoped analysis passes may inspect committed session state.
pub trait SessionAnalysisPass {
    fn name(&self) -> &'static str;
    fn run(
        &self,
        session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    );
}

// Final decision passes aggregate prior findings and proposals into one
// terminal decision for the current run.
pub trait FinalDecisionPass {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &mut RunnerContext);
}
