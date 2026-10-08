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
        session_id: SessionId::new("gtfobins-profile-test"),
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

fn check(command: &str, expected: Decision) -> Vec<GraphNode> {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, expected, "{command}: {response:?}");
    staged_graph(command)
}

fn staged_graph(command: &str) -> Vec<GraphNode> {
    // Approval proposals are not execution history. Inspect their staged Graph.
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

fn has_write(graph: &[GraphNode], path: &str) -> bool {
    graph.iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..}
            if resolution.concrete_path() == Some(path))
    })
}

#[test]
fn setlock_models_file_creation_and_real_child_argv() {
    for command in [
        "setlock lock printf SAFE",
        "setlock -nX lock printf SAFE",
        "setlock -N -x -- lock printf -- '%s' '-nX'",
        "/usr/bin/setlock lock printf SAFE",
    ] {
        let graph = check(command, Decision::Allow);
        assert!(has_write(&graph, "/tmp/project/lock"), "{command}");
        assert!(
            graph.iter().any(
                |n| matches!(&n.kind, NodeKind::DerivedInvocation {command_name, ..}
            if command_name.as_deref() == Some("printf"))
            ),
            "{command}"
        );
    }
}

#[test]
fn setlock_literal_dash_file_and_inherited_shell_input_are_preserved() {
    for command in ["setlock - /bin/sh", "setlock - /bin/sh -p"] {
        let graph = check(command, Decision::NeedApproval);
        assert!(has_write(&graph, "/tmp/project/-"));
        let response = ShellQueryCore::new().check(request(command));
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "sh" && s.executes_payload),
            "{response:?}"
        );
        assert!(
            response
                .decision_trace
                .nested_payloads
                .iter()
                .any(|p| p.resolution.kind
                    == caushell_types::NestedPayloadResolutionKind::RequiresRuntimeInput),
            "{response:?}"
        );
    }
}

#[test]
fn setlock_external_lock_and_nested_mutations_use_existing_guards() {
    for (command, path) in [
        ("setlock /opt/shared/lock printf SAFE", "/opt/shared/lock"),
        (
            "setlock lock sh -c 'printf DATA > /opt/shared/out'",
            "/opt/shared/out",
        ),
    ] {
        assert!(
            has_write(&check(command, Decision::NeedApproval), path),
            "{command}"
        );
    }
    let response = ShellQueryCore::new().check(request("setlock lock rm /opt/shared/file"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "rm"),
        "{response:?}"
    );
}

#[test]
fn setlock_child_options_are_not_parent_options_or_shell_programs() {
    for command in [
        "setlock lock printf '%s' '-n' '-X' '--bad-parent-option'",
        "setlock lock printf '%s' 'rm /opt/shared/file; true'",
        "setlock lock sh -c 'printf DATA > local'",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn setlock_unknown_or_missing_parent_semantics_are_not_silently_allowed() {
    for command in [
        "setlock",
        "setlock lock",
        "setlock --unknown lock printf SAFE",
        "setlock -nZ lock printf SAFE",
        "setlock \"$unknown_lock\" printf SAFE",
        "setlock lock \"$unknown_command\"",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn tar_old_style_archive_and_inputs_are_not_shifted_after_binding_options() {
    for command in [
        "tar cf archive.tar /opt/shared/input",
        "tar cvf archive.tar /opt/shared/input",
    ] {
        let graph = check(command, Decision::Allow);
        assert!(!has_write(&graph, "/opt/shared/input"), "{command}");
        assert!(graph.iter().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Read, resolution, ..}
            if resolution.concrete_path() == Some("/opt/shared/input"))), "{command}");
    }
    for command in [
        "tar cf /opt/shared/archive.tar input",
        "tar cvf /opt/shared/archive.tar input",
    ] {
        assert!(
            has_write(
                &check(command, Decision::NeedApproval),
                "/opt/shared/archive.tar"
            ),
            "{command}"
        );
    }
    // Archive bytes go to the inherited stream, not a fake device-file write.
    let graph = staged_graph("tar cf /dev/stdout /opt/shared/input");
    assert!(!has_write(&graph, "/dev/stdout"));
    assert!(graph.iter().any(|node| matches!(&node.kind,
        NodeKind::ProvenanceArtifact { artifact: caushell_types::ProvenanceArtifact::DescriptorStream {
            descriptor, unresolved: false, ..
        }} if descriptor == "1")));
    assert!(!has_write(&graph, "/opt/shared/input"));
}
