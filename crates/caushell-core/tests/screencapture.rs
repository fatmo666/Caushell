//! Static checks for the documented file output of macOS screencapture.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("screencapture-file-output"),
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
fn file_capture_records_the_output_and_keeps_approval() {
    for command in [
        "screencapture fixture.png",
        "/usr/sbin/screencapture -x fixture.png",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let capture = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "screencapture")
            .expect("file output should have screencapture execution semantics");
        assert_eq!(capture.form_id, "capture_to_file");
        assert!(capture.operation_semantics_unresolved);
        let target = result
            .decision_trace
            .path_targets
            .iter()
            .find(|target| target.operation == PathTargetOperation::Write)
            .expect("screenshot file must be recorded as a write target");
        assert_eq!(target.slot_name, "capture_file");
        assert_eq!(
            target.spelling.as_deref(),
            Some("/bench/workspace/fixture.png")
        );
    }
}

#[test]
fn other_capture_modes_do_not_inherit_the_file_form() {
    for command in [
        "screencapture",
        "screencapture -c fixture.png",
        "screencapture fixture.png -c",
        "screencapture -p fixture.png",
        "screencapture -i fixture.png",
        "screencapture -u fixture.png",
        "screencapture -- fixture.png",
        "screencapture fixture.png other.png",
        "screencapture ''",
        "screencapture \"$output\"",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| entry.form_id != "capture_to_file"),
            "{command}"
        );
    }
}
