//! Decisions and staged Graph only; never mutate shell history or files.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("history-file-effects"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn staged(req: CheckRequest) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(req);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}
fn checked(req: CheckRequest, expected: Decision) -> Vec<GraphNode> {
    let r = ShellQueryCore::new().check(req.clone());
    assert_eq!(r.decision, expected, "{}: {r:#?}", req.command);
    let graph = staged(req);
    assert!(
        !graph
            .iter()
            .any(|n| matches!(&n.kind,NodeKind::PathFact{resolution,..}
        if resolution.concrete_path()==Some("/tmp/project/.bash_history"))),
        "{graph:#?}"
    );
    graph
}
fn writes(graph: &[GraphNode]) -> Vec<&PathResolution> {
    graph
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                resolution,
                ..
            } => Some(resolution),
            _ => None,
        })
        .collect()
}
fn target(command: &str, path: &str, expected: Decision) {
    let graph = checked(request(command), expected);
    let targets = writes(&graph);
    assert!(!targets.is_empty(), "{command}: no write target");
    assert!(
        targets.iter().all(|p| p.concrete_path() == Some(path)),
        "{command}: {targets:#?}"
    );
}

#[test]
fn actual_external_destinations_and_local_controls_have_precise_graph_targets() {
    for command in [
        "history -w /opt/shared/file",
        "history -a /opt/shared/file",
        "history -cw /opt/shared/file",
        "HISTFILE=/opt/shared/file history -w",
        "HISTFILE=/opt/shared/file; history -a",
        "unset HISTFILE; history -w /opt/shared/file",
        "HISTFILE=./history; history -w /opt/shared/file",
        "history -w /opt/shared/file ./ignored",
        "bash -c 'history -w /opt/shared/file'",
        "f() { local HISTFILE=/opt/shared/file; history -w; }; f",
    ] {
        target(command, "/opt/shared/file", Decision::NeedApproval);
    }
    for command in [
        "history -w ./history",
        "history -a ./history",
        "HISTFILE=./history history -w",
        "HISTFILE=./history; history -w",
        "HISTFILE=/opt/shared/file; history -w ./history",
        "history -w ./history /opt/shared/ignored",
        "history -w ./history -r",
        "f() { local HISTFILE=./history; history -w; }; f",
    ] {
        target(command, "/tmp/project/history", Decision::Allow);
    }
    target("history -w -- -r", "/tmp/project/-r", Decision::Allow);
    target(
        "history -w ~/.bash_history",
        "/home/alice/.bash_history",
        Decision::NeedApproval,
    );
    target(
        "HISTFILE='./cache/$literal*'; history -w",
        "/tmp/project/cache/$literal*",
        Decision::Allow,
    );
}

#[test]
fn unknown_defaults_are_real_unknown_targets_not_absent_or_guessed_paths() {
    for command in [
        "history -w",
        "history -a",
        "HISTFILE=\"$unknown\"; history -w",
        "HISTFILE=./history; history -w \"$unknown\"",
        "HISTFILE=./history; bash -c 'history -w'",
    ] {
        let graph = checked(request(command), Decision::NeedApproval);
        assert!(
            writes(&graph).iter().any(|p| p.concrete_path().is_none()),
            "{command}: {graph:#?}"
        );
    }
}

#[test]
fn known_unset_or_empty_default_has_no_write_but_explicit_filename_still_wins() {
    for command in [
        "unset HISTFILE; history -a",
        "HISTFILE=; history -w",
        "HISTFILE='' history -a",
    ] {
        let graph = checked(request(command), Decision::Allow);
        assert!(writes(&graph).is_empty(), "{command}: {graph:#?}");
    }
    let mut req = request("history -w");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    assert!(writes(&checked(req, Decision::Allow)).is_empty());
}

#[test]
fn snapshot_locals_and_child_export_boundaries_use_static_shell_frames() {
    for exported in [false, true] {
        for (path, decision) in [
            ("./history", Decision::Allow),
            ("/opt/shared/file", Decision::NeedApproval),
        ] {
            let mut req = request("history -w");
            req.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
            req.shell_state_before = req
                .shell_state_before
                .with_exact_scalar_variable("HISTFILE", path, exported);
            let graph = checked(req, decision);
            assert!(
                writes(&graph).iter().all(|p| p.concrete_path()
                    == Some(if path.starts_with('/') {
                        path
                    } else {
                        "/tmp/project/history"
                    })),
                "{graph:#?}"
            );
        }
    }
    target(
        "export HISTFILE=./history; bash -c 'history -w'",
        "/tmp/project/history",
        Decision::Allow,
    );
    let graph = checked(
        request(
            "HISTFILE=/opt/shared/file; f() { local HISTFILE=./history; history -w; }; f; history -w",
        ),
        Decision::NeedApproval,
    );
    let paths = writes(&graph);
    assert!(
        paths
            .iter()
            .any(|p| p.concrete_path() == Some("/tmp/project/history"))
    );
    assert!(
        paths
            .iter()
            .any(|p| p.concrete_path() == Some("/opt/shared/file"))
    );
}

#[test]
fn memory_and_query_operations_do_not_write_files_or_execute_history_text() {
    for command in [
        "history",
        "history 10",
        "history -c",
        "history -d 1",
        "history -d -1",
        "history -d1",
        "history -p 'rm /opt/shared/file'",
        "history -s 'rm /opt/shared/file'",
        "history -cw",
        "history -sw /opt/shared/file",
        "history -pw /opt/shared/file",
        "history -d 1 -w /opt/shared/file",
        "history -r /opt/shared/file",
        "history -n /opt/shared/file",
        "history -r",
        "history --help",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.loads_tool_config && s.normalized_command_name != "rm"),
            "{response:#?}"
        );
        assert!(writes(&staged(request(command))).is_empty(), "{command}");
    }
    target(
        "history > /opt/shared/file",
        "/opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn uncertain_or_malformed_operation_keeps_existing_resolution_approval() {
    for command in [
        "history --unknown",
        "history -aw /opt/shared/file",
        "history -nr ./history",
        "history -d",
        "history \"$mode\"",
        "history -c $args /opt/shared/file",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
}
