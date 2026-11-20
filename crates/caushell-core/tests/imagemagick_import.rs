//! JudgeOnly coverage for the explicit ImageMagick import file operand.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("imagemagick-import-output"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/fixture".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn explicit_raster_destination_is_recorded_without_resolving_capture() {
    for (command, path) in [
        (
            "import -window root fixture.png",
            "/bench/workspace/fixture.png",
        ),
        (
            "/usr/bin/import -window root /tmp/fixture.JPG",
            "/tmp/fixture.JPG",
        ),
        (
            "import -window root fixture.jpeg",
            "/bench/workspace/fixture.jpeg",
        ),
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let capture = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "import")
            .expect("file output should have ImageMagick import execution semantics");
        assert_eq!(capture.form_id, "capture_root_to_raster_file");
        assert!(capture.operation_semantics_unresolved);
        let target = result
            .decision_trace
            .path_targets
            .iter()
            .find(|target| target.operation == PathTargetOperation::Write)
            .expect("capture file must be recorded as a write target");
        assert_eq!(target.slot_name, "capture_file");
        assert_eq!(target.spelling.as_deref(), Some(path));
        assert!(matches!(
            target.resolution,
            SemanticResolution::Unresolved { .. }
        ));
    }
}

#[test]
fn other_destinations_and_options_do_not_inherit_the_file_form() {
    for command in [
        "import",
        "import -window",
        "import -window root",
        "import -window other fixture.png",
        "import fixture.png",
        "import -window root -",
        "import -window root clipboard:",
        "import -window root png:fixture.png",
        "import -window root fixture-%d.png",
        "import -window root fixture.png other.png",
        "import -window root -display display.test:1 fixture.png",
        "import -window root \"$output\"",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| entry.form_id != "capture_root_to_raster_file"),
            "{command}"
        );
    }
}
