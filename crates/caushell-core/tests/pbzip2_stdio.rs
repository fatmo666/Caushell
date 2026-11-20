//! Static checks for the limited pbzip2 stream forms and their tar caller.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, tar_options: Option<ShellEnvironmentValue>) -> CheckResponse {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    if let Some(value) = tar_options {
        state = state.with_environment_observation("TAR_OPTIONS", value);
        state.observability.variables = ShellStateKnowledge::Complete;
    }
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("pbzip2-stdio"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    })
}

fn assert_stream_form(result: &CheckResponse, form: &str) {
    let semantics = result
        .decision_trace
        .execution_semantics
        .iter()
        .find(|row| row.normalized_command_name == "pbzip2")
        .unwrap_or_else(|| panic!("{:?}", result.reasons));
    assert_eq!(semantics.form_id, form);
    assert!(!semantics.operation_semantics_unresolved);
    assert!(!result.decision_trace.path_targets.iter().any(|row| {
        row.source_node_id == semantics.source.node_id
            && matches!(
                row.operation,
                PathTargetOperation::Write | PathTargetOperation::Delete
            )
    }));
}

#[test]
fn stdin_compression_and_decompression_stay_on_standard_streams() {
    for (command, form) in [
        ("printf SAMPLE | pbzip2", "compress_stdin"),
        (
            "printf SAMPLE | pbzip2 --compress --stdout",
            "compress_stdin",
        ),
        ("cat fixture.bz2 | pbzip2 -d", "decompress_stdin"),
        ("cat fixture.bz2 | pbzip2 -dc", "decompress_stdin"),
    ] {
        let result = check(command, None);
        assert_stream_form(&result, form);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn tar_can_resolve_the_bare_child_in_each_native_mode() {
    for (command, form) in [
        ("tar -I pbzip2 -cf archive.bz2 input.txt", "compress_stdin"),
        ("tar -I pbzip2 -tf archive.bz2", "decompress_stdin"),
    ] {
        let result = check(command, Some(ShellEnvironmentValue::Absent));
        assert_stream_form(&result, form);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn missing_tar_options_and_unmodeled_file_modes_require_approval() {
    let result = check("tar -I pbzip2 -cf archive.bz2 input.txt", None);
    assert_eq!(result.decision, Decision::NeedApproval);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.contains("TAR_OPTIONS option environment is not observed"))
    );
    for command in [
        "pbzip2 fixture.txt",
        "pbzip2 -dc fixture.bz2",
        "pbzip2 -c -- fixture.txt",
        "pbzip2 -z -d",
        "pbzip2 -t",
        "pbzip2 \"$UNOBSERVED\"",
        "tar -I 'pbzip2 fixture.txt' -cf archive.bz2 input.txt",
    ] {
        let result = check(command, Some(ShellEnvironmentValue::Absent));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}
