//! Static semantic checks: these command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, ResolvedPathRole, RuntimeMetadata, SessionId,
    SessionSummary, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfobins-batch30-a"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn check(command: &str, expected: Decision) -> (caushell_types::CheckResponse, Vec<GraphNode>) {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, expected, "{command}: {response:?}");
    (response, staged_graph(command))
}

fn staged_graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}

fn has_child(graph: &[GraphNode], name: &str) -> bool {
    graph.iter().any(|node| {
        matches!(&node.kind, NodeKind::DerivedInvocation { command_name, .. }
            if command_name.as_deref().and_then(|value| value.rsplit('/').next()) == Some(name))
    })
}

fn has_write(graph: &[GraphNode], path: &str) -> bool {
    graph.iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..}
            if resolution.concrete_path() == Some(path))
    })
}

#[test]
fn gtfo_shell_examples_resolve_as_child_shells_and_require_runtime_approval() {
    let cases = [
        "aa-exec /bin/sh",
        "aoss /bin/sh",
        "choom -n 0 /bin/sh",
        "cpulimit -l 100 -f -- /bin/sh",
        "multitime /bin/sh",
        "setarch -3 /bin/sh",
        "softlimit /bin/sh",
        "torify /bin/sh",
        "torsocks /bin/sh",
        "logsave /dev/null /bin/sh -i",
    ];
    for command in cases {
        let (response, graph) = check(command, Decision::NeedApproval);
        assert!(has_child(&graph, "sh"), "{command}: {graph:?}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| semantics.normalized_command_name == "sh"
                    && semantics.executes_payload),
            "{command}: {response:?}"
        );
        assert!(
            response
                .decision_trace
                .nested_payloads
                .iter()
                .any(|payload| payload.resolution.kind
                    == caushell_types::NestedPayloadResolutionKind::RequiresRuntimeInput),
            "{command}: {response:?}"
        );
    }
}

#[test]
fn safe_command_examples_and_child_argv_stay_with_the_wrapper_form() {
    for command in [
        "aa-exec -- /usr/bin/printf SAFE",
        "aoss /usr/bin/printf SAFE",
        "choom -n 0 -- /usr/bin/printf SAFE",
        "multitime -n 4 /usr/bin/printf SAFE",
        "setarch -3 -- /usr/bin/printf SAFE",
        "softlimit /usr/bin/printf SAFE",
        "torify /usr/bin/printf SAFE",
        "torsocks /usr/bin/printf SAFE",
        "logsave /dev/null /usr/bin/printf SAFE",
    ] {
        let (response, graph) = check(command, Decision::Allow);
        assert!(has_child(&graph, "printf"), "{command}: {graph:?}");
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| semantics.executes_payload),
            "{command}: {response:?}"
        );
    }
    let (_, graph) = check(
        "cpulimit -l 100 -f -- /usr/bin/printf SAFE",
        Decision::NeedApproval,
    );
    assert!(has_child(&graph, "printf"));
}

#[test]
fn nested_child_mutation_and_logfile_effects_reach_the_graph() {
    let cases = [
        "aa-exec -- sh -c 'printf DATA > /opt/shared/gtfo30-aa-exec'",
        "aoss sh -c 'printf DATA > /opt/shared/gtfo30-aoss'",
        "choom -n 0 -- sh -c 'printf DATA > /opt/shared/gtfo30-choom'",
        "cpulimit -l 100 -f -- sh -c 'printf DATA > /opt/shared/gtfo30-cpulimit'",
        "multitime sh -c 'printf DATA > /opt/shared/gtfo30-multitime'",
        "setarch -3 -- sh -c 'printf DATA > /opt/shared/gtfo30-setarch'",
        "softlimit sh -c 'printf DATA > /opt/shared/gtfo30-softlimit'",
        "torify sh -c 'printf DATA > /opt/shared/gtfo30-torify'",
        "torsocks sh -c 'printf DATA > /opt/shared/gtfo30-torsocks'",
        "logsave /dev/null sh -c 'printf DATA > /opt/shared/gtfo30-logsave'",
    ];
    let names = [
        "aa-exec",
        "aoss",
        "choom",
        "cpulimit",
        "multitime",
        "setarch",
        "softlimit",
        "torify",
        "torsocks",
        "logsave",
    ];
    for (index, command) in cases.into_iter().enumerate() {
        let (response, graph) = check(command, Decision::NeedApproval);
        assert!(has_child(&graph, "sh"), "{command}: {graph:?}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| semantics.normalized_command_name == "sh"),
            "{command}: {response:?}"
        );
        assert!(
            has_write(&graph, &format!("/opt/shared/gtfo30-{}", names[index])),
            "{command}: {graph:?}"
        );
    }

    let (response, graph) = check("logsave /dev/null /usr/bin/printf SAFE", Decision::Allow);
    assert!(has_child(&graph, "printf"), "{response:?} {graph:?}");

    let (response, graph) = check(
        "logsave /opt/shared/gtfo30-logfile /usr/bin/printf SAFE",
        Decision::NeedApproval,
    );
    assert!(has_child(&graph, "printf"), "{response:?} {graph:?}");
    assert!(has_write(&graph, "/opt/shared/gtfo30-logfile"), "{graph:?}");
}

#[test]
fn unknown_and_missing_wrapper_operands_do_not_become_safe_dispatches() {
    for command in [
        "aa-exec --unrecognized /usr/bin/true",
        "aa-exec --profile",
        "aoss",
        "choom -n",
        "choom -p 1",
        "cpulimit -l",
        "cpulimit -p 1 -l 50",
        "multitime -o 'cat > /tmp/out' /usr/bin/true",
        "multitime -q /usr/bin/printf SAFE",
        "setarch",
        "setarch --list",
        "softlimit",
        "torify",
        "torsocks --shell",
        "logsave /tmp/only-logfile",
        "logsave /tmp/log -",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
    }
}
