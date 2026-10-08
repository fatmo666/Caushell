//! Independent parent acceptance. Only static checks; no command is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, ResolvedPathRole, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn graph(command: &str) -> Vec<GraphNode> {
    let id = SessionId::new("gtfo30-parent-xz");
    let mut core = ShellQueryCore::new();
    let response = core.check(CheckRequest {
        session_id: id.clone(),
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
    });
    assert_eq!(
        response.decision,
        Decision::Allow,
        "{command}: {response:?}"
    );
    core.session_graph(&id).unwrap().nodes().cloned().collect()
}

fn has(nodes: &[GraphNode], role: ResolvedPathRole, target: &str) -> bool {
    nodes.iter().any(|n| {
        matches!(&n.kind,
        NodeKind::PathFact { role: r, resolution, .. }
        if *r == role && resolution.concrete_path() == Some(target))
    })
}

#[test]
fn xz_real_suffix_outputs_are_present_in_graph_not_only_profile_effects() {
    for (command, input, output) in [
        ("xz input", "/tmp/project/input", "/tmp/project/input.xz"),
        ("xz -k input", "/tmp/project/input", "/tmp/project/input.xz"),
        (
            "xz -d archive.xz",
            "/tmp/project/archive.xz",
            "/tmp/project/archive",
        ),
        (
            "xz -dk archive.xz",
            "/tmp/project/archive.xz",
            "/tmp/project/archive",
        ),
    ] {
        let nodes = graph(command);
        assert!(
            has(&nodes, ResolvedPathRole::Read, input),
            "{command}: {nodes:?}"
        );
        assert!(
            has(&nodes, ResolvedPathRole::Write, output),
            "{command}: {nodes:?}"
        );
    }
}

#[test]
fn xz_source_pipeline_stdout_and_literal_dash_prefixed_file_do_not_invent_mutations() {
    for (command, input) in [
        ("xz -c /opt/shared/input | xz -d", "/opt/shared/input"),
        ("xz -dc /opt/shared/input.xz", "/opt/shared/input.xz"),
        (
            "xz -c -- -looks-like-an-option",
            "/tmp/project/-looks-like-an-option",
        ),
    ] {
        let nodes = graph(command);
        assert!(
            has(&nodes, ResolvedPathRole::Read, input),
            "{command}: {nodes:?}"
        );
        assert!(
            !nodes.iter().any(|n| matches!(
                &n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write | ResolvedPathRole::MetadataMutation,
                    ..
                }
            )),
            "{command}: {nodes:?}"
        );
    }
}
