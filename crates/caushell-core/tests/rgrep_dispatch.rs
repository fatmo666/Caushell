//! Judge-only checks of the packaged rgrep wrapper and its recursive default.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn check(command: &str) -> (CheckResponse, Vec<PathResolution>) {
    let mut core = ShellQueryCore::new();
    let session_id = SessionId::new("rgrep-dispatch");
    let response = core.check(CheckRequest {
        session_id: session_id.clone(),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
    });
    let reads = core
        .session_graph(&session_id)
        .unwrap()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Read,
                resolution,
                ..
            } => Some(resolution.clone()),
            _ => None,
        })
        .collect();
    (response, reads)
}

fn reads(paths: &[PathResolution], path: &str) -> bool {
    paths.iter().any(|resolution| {
        resolution.concrete_path() == Some(path)
            || matches!(resolution, PathResolution::BoundedPathSet { roots, .. }
                if roots.iter().any(|root| root == path))
    })
}

#[test]
fn wrapper_routes_arguments_and_default_read_to_external_grep() {
    for command in ["rgrep . | wc -l", "rgrep -qi sample", "grep -r -e sample"] {
        let (response, paths) = check(command);
        assert_eq!(response.decision, Decision::Allow, "{command}: {:?}", response.reasons);
        assert!(response.decision_trace.execution_semantics.iter().any(|call| {
            call.normalized_command_name == "grep" && !call.operation_semantics_unresolved
        }), "{command}");
        assert!(reads(&paths, "/workspace"), "{command}: {paths:?}");
    }
}

#[test]
fn explicit_files_stdin_and_help_do_not_add_a_working_directory_read() {
    for command in ["rgrep -- sample input.txt", "rgrep sample -", "rgrep --help"] {
        let (response, paths) = check(command);
        assert_eq!(response.decision, Decision::Allow, "{command}: {:?}", response.reasons);
        assert!(!reads(&paths, "/workspace"), "{command}");
        if command.contains("input.txt") {
            assert!(reads(&paths, "/workspace/input.txt"), "{command}: {paths:?}");
        }
    }
    let (wrapped, wrapped_paths) = check("rgrep --unknown-option sample");
    let (direct, direct_paths) = check("grep -r --unknown-option sample");
    assert_eq!(wrapped.decision, direct.decision);
    assert_eq!(wrapped_paths, direct_paths);
}
