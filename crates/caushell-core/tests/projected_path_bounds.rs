//! Static requests/Graph only; none of the shell actions is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::*;
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("projected-bounds"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
#[test]
fn identity_projected_runtime_output_keeps_known_directory_bounds() {
    for command in [
        "find bills -type f -execdir sort -o '{}.sorted' '{}' ';'",
        "find bills -type f -exec sort -o '{}.sorted' '{}' ';'",
        "find . -type f -print0 | xargs -0 -I{} sort -o {}.sorted {}",
        "sort -o ./out ./input",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
    for command in [
        "find /opt/shared -type f -execdir sort -o '{}.sorted' '{}' ';'",
        "find /opt/shared -type f -exec sort -o '{}.sorted' '{}' ';'",
        "find -L . -type f -exec sort -o '{}.sorted' '{}' ';'",
        "printf '%s\\0' \"$UNKNOWN\" | xargs -0 -I{} sort -o {}.sorted {}",
        "sort -o \"$UNKNOWN\" ./input",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
}
#[test]
fn graph_keeps_a_bounded_write_not_a_fabricated_filename() {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(
        "find bills -type f -execdir sort -o '{}.sorted' '{}' ';'",
    ));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    let staged = StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations());
    assert!(staged.graph().nodes().any(|n| matches!(&n.kind,
        NodeKind::PathFact {role: ResolvedPathRole::Write, normalized_command_name: Some(name), resolution: PathResolution::BoundedPathSet{roots,may_escape:false}, ..}
        if name=="sort" && !roots.is_empty() && roots.iter().all(|r|r.starts_with("/bench/workspace")))));
}
