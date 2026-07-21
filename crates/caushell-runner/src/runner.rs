use crate::{
    RunnerContext, StagedSession,
    pass::{
        FinalDecisionPass, RequestAnalysisPass, RequestTransformPass, SessionAnalysisPass,
        SessionTransformPass, SessionView,
    },
};
use std::time::Instant;

#[derive(Default)]
pub struct PassRunner {
    request_transform_passes: Vec<Box<dyn RequestTransformPass>>,
    session_transform_passes: Vec<Box<dyn SessionTransformPass>>,
    request_analysis_passes: Vec<Box<dyn RequestAnalysisPass>>,
    session_analysis_passes: Vec<Box<dyn SessionAnalysisPass>>,
    final_decision_passes: Vec<Box<dyn FinalDecisionPass>>,
}

impl PassRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_request_transform_pass<P>(&mut self, pass: P)
    where
        P: RequestTransformPass + 'static,
    {
        self.request_transform_passes.push(Box::new(pass));
    }

    pub fn register_session_transform_pass<P>(&mut self, pass: P)
    where
        P: SessionTransformPass + 'static,
    {
        self.session_transform_passes.push(Box::new(pass));
    }

    pub fn register_request_analysis_pass<P>(&mut self, pass: P)
    where
        P: RequestAnalysisPass + 'static,
    {
        self.request_analysis_passes.push(Box::new(pass));
    }

    pub fn register_session_analysis_pass<P>(&mut self, pass: P)
    where
        P: SessionAnalysisPass + 'static,
    {
        self.session_analysis_passes.push(Box::new(pass));
    }

    pub fn register_final_decision_pass<P>(&mut self, pass: P)
    where
        P: FinalDecisionPass + 'static,
    {
        self.final_decision_passes.push(Box::new(pass));
    }

    // Order is structural rather than mixed registration order:
    // request-transform -> session-transform -> request-analysis ->
    // session-analysis -> final-decision.
    pub fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        for pass in &self.request_transform_passes {
            ctx.record_pass(pass.name());
            run_request_transform_pass(pass.as_ref(), ctx);
        }

        for pass in &self.session_transform_passes {
            ctx.record_pass(pass.name());
            run_session_transform_pass(pass.as_ref(), session, ctx);
        }

        for pass in &self.request_analysis_passes {
            ctx.record_pass(pass.name());
            run_request_analysis_pass(pass.as_ref(), ctx);
        }

        let staged_session_start = Instant::now();
        let staged_session = StagedSession::new(
            session.graph(),
            ctx.request(),
            session.summary(),
            ctx.pending_mutations(),
        );
        log_pass_timing(
            ctx,
            "session_analysis_stage",
            "__stage_session__",
            elapsed_ms(staged_session_start),
        );
        let staged_view = SessionView::from_session(&staged_session);

        for pass in &self.session_analysis_passes {
            ctx.record_pass(pass.name());
            run_session_analysis_pass(pass.as_ref(), session, staged_view, ctx);
        }

        for pass in &self.final_decision_passes {
            ctx.record_pass(pass.name());
            run_final_decision_pass(pass.as_ref(), ctx);
        }
    }

    pub fn pass_count(&self) -> usize {
        self.request_transform_passes.len()
            + self.session_transform_passes.len()
            + self.request_analysis_passes.len()
            + self.session_analysis_passes.len()
            + self.final_decision_passes.len()
    }
}

fn run_request_transform_pass(pass: &dyn RequestTransformPass, ctx: &mut RunnerContext) {
    let started = Instant::now();
    pass.run(ctx);
    log_pass_timing(ctx, "request_transform", pass.name(), elapsed_ms(started));
}

fn run_session_transform_pass(
    pass: &dyn SessionTransformPass,
    session: SessionView<'_>,
    ctx: &mut RunnerContext,
) {
    let started = Instant::now();
    pass.run(session, ctx);
    log_pass_timing(ctx, "session_transform", pass.name(), elapsed_ms(started));
}

fn run_request_analysis_pass(pass: &dyn RequestAnalysisPass, ctx: &mut RunnerContext) {
    let started = Instant::now();
    pass.run(ctx);
    log_pass_timing(ctx, "request_analysis", pass.name(), elapsed_ms(started));
}

fn run_session_analysis_pass(
    pass: &dyn SessionAnalysisPass,
    session: SessionView<'_>,
    staged_session: SessionView<'_>,
    ctx: &mut RunnerContext,
) {
    let started = Instant::now();
    pass.run(session, staged_session, ctx);
    log_pass_timing(ctx, "session_analysis", pass.name(), elapsed_ms(started));
}

fn run_final_decision_pass(pass: &dyn FinalDecisionPass, ctx: &mut RunnerContext) {
    let started = Instant::now();
    pass.run(ctx);
    log_pass_timing(ctx, "final_decision", pass.name(), elapsed_ms(started));
}

fn log_pass_timing(ctx: &RunnerContext, phase: &str, pass_name: &str, elapsed_ms: f64) {
    if !timing_enabled() {
        return;
    }

    eprintln!(
        "caushell-timing component=core-pass phase={} pass={} session_id={} sequence_no={} ms={:.3}",
        phase,
        pass_name,
        ctx.request().session_id.0,
        ctx.request().sequence_no.0,
        elapsed_ms,
    );
}

fn timing_enabled() -> bool {
    matches!(
        std::env::var("CAUSHELL_TIMING").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
