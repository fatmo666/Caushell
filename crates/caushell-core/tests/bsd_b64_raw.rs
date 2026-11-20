//! Static policy checks. No codec, shell, or command under test is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("bsd-b64-raw"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

#[test]
fn raw_codecs_distinguish_file_input_from_the_ignored_header_name() {
    for (command, form, input) in [
        ("b64encode -r ./header-name", "encode_raw_stdin", None),
        ("b64encode -r -", "encode_raw_stdin", None),
        (
            "b64encode -r ./input ./header-name",
            "encode_raw_file",
            Some("/bench/workspace/input"),
        ),
        (
            "b64encode -r - ./header-name",
            "encode_raw_file",
            Some("/bench/workspace/-"),
        ),
        ("b64decode -r", "decode_raw_stdin", None),
        (
            "b64decode -r ./input",
            "decode_raw_file",
            Some("/bench/workspace/input"),
        ),
    ] {
        let mut core = ShellQueryCore::new();
        let result = core.check(request(command));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert_eq!(result.decision_trace.execution_semantics[0].form_id, form);
        assert!(
            !result
                .decision_trace
                .path_targets
                .iter()
                .any(|target| target.operation.is_mutation())
        );
        let graph = core.session_graph(&SessionId::new("bsd-b64-raw")).unwrap();
        let mut paths: Vec<_> = graph
            .nodes()
            .filter_map(|node| {
                if let NodeKind::PathFact {
                    resolution,
                    role: ResolvedPathRole::Read,
                    ..
                } = &node.kind
                {
                    Some(resolution.concrete_path())
                } else {
                    None
                }
            })
            .collect();
        paths.sort_unstable();
        paths.dedup();
        let expected = input.map(Some).into_iter().collect::<Vec<_>>();
        assert_eq!(paths, expected, "{command}");
    }
}

#[test]
fn header_output_and_shell_execution_keep_approval() {
    for command in [
        "b64encode -r",
        "b64encode -r -o ./encoded ./label",
        "b64encode ./label",
        "b64decode",
        "b64decode -o ./decoded",
        "b64decode -r -o ./decoded",
        "b64decode -r ./one ./two",
        "b64decode -r > /opt/shared/decoded",
        "printf '%s' 'ZGF0YQ==' | b64decode -r | sh",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}
