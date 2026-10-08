//! Independent parent acceptance for group B. Commands are analyzed, never run.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfo30f-b-independent"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-parent-acceptance".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
}

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut context);
    StagedSession::new(
        &base,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}

fn path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(
            &node.kind,
            NodeKind::PathFact { role: actual, resolution, .. }
            if *actual == role && resolution.concrete_path() == Some(expected)
        )
    })
}

fn semantic(command: &str, name: &str) -> ExecutionSemanticsFact {
    check(command)
        .decision_trace
        .execution_semantics
        .into_iter()
        .find(|fact| fact.normalized_command_name == name)
        .unwrap_or_else(|| panic!("missing semantic for {name}: {command}"))
}

#[test]
fn remote_printing_and_cancellation_do_not_become_local_filesystem_writes() {
    let lp = "lp /tmp/project/input -h printer.example:631";
    assert!(
        path(lp, "/tmp/project/input", ResolvedPathRole::Read),
        "{:#?}",
        graph(lp)
    );
    assert!(
        !graph(lp).iter().any(|node| matches!(
            &node.kind,
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                ..
            }
        )),
        "{:#?}",
        graph(lp)
    );
    assert_eq!(check(lp).decision, Decision::Allow);

    let cancel = "cancel -h print.example:12345 -u DATA";
    assert_eq!(semantic(cancel, "cancel").normalized_command_name, "cancel");
    assert!(
        !graph(cancel).iter().any(|node| matches!(
            &node.kind,
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                ..
            }
        )),
        "{:#?}",
        graph(cancel)
    );
    assert_eq!(check(cancel).decision, Decision::Allow);
}

#[test]
fn native_interactive_boundaries_do_not_parse_prompts_as_caller_commands() {
    let telnet = "telnet";
    assert!(semantic(telnet, "telnet").opens_interactive_escape_surface);
    assert_eq!(check(telnet).decision, Decision::NeedApproval);

    let tftp = "tftp attacker.example";
    assert!(
        !graph(tftp).iter().any(|node| matches!(
            &node.kind,
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                ..
            }
        )),
        "{:#?}",
        graph(tftp)
    );
    assert!(
        !check(tftp)
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| fact.normalized_command_name == "get"
                || fact.normalized_command_name == "put")
    );
}

#[test]
fn listener_upload_and_dispatch_semantics_survive_parent_resolution() {
    let socket = "socket -svp '/bin/sh -i' 12345";
    assert!(!semantic(socket, "socket").network_listeners.is_empty());
    assert!(semantic(socket, "socket").executes_payload);
    assert_eq!(check(socket).decision, Decision::NeedApproval);

    let ltrace = "ltrace -s 999 -o /tmp/project/trace.log ltrace -F DATA";
    assert!(semantic(ltrace, "ltrace").dispatches_child_command);
    assert!(
        path(ltrace, "/tmp/project/trace.log", ResolvedPathRole::Write),
        "{:#?}",
        graph(ltrace)
    );

    let attach = "ltrace -p 4242";
    assert!(
        !semantic(attach, "ltrace").dispatches_child_command,
        "{:#?}",
        check(attach)
    );
}

#[test]
fn opaque_code_callbacks_and_nmap_paths_keep_distinct_semantics() {
    let lua = "tshark -X lua_script:/tmp/project/plugin.lua";
    assert!(semantic(lua, "tshark").executes_payload);
    assert_eq!(check(lua).decision, Decision::NeedApproval);

    let config = "openvpn --config /opt/shared/client.conf";
    assert!(
        path(config, "/opt/shared/client.conf", ResolvedPathRole::Read),
        "{:#?}",
        graph(config)
    );
    assert_eq!(check(config).decision, Decision::NeedApproval);

    let callback = "openvpn --dev null --script-security 2 --up '/bin/sh -s'";
    assert!(semantic(callback, "openvpn").executes_payload);
    assert!(
        !semantic(callback, "openvpn").dispatches_child_command,
        "{:#?}",
        check(callback)
    );
    assert_eq!(check(callback).decision, Decision::NeedApproval);

    let nmap = "nmap -iL /opt/shared/hosts.txt";
    assert!(
        path(nmap, "/opt/shared/hosts.txt", ResolvedPathRole::Read),
        "{:#?}",
        graph(nmap)
    );
    assert_eq!(check(nmap).decision, Decision::Allow);
    assert!(!semantic("tmate -c '/bin/sh'", "tmate").dispatches_child_command);
}
