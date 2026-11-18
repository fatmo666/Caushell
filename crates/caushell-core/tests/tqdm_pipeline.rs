//! Static coverage for the progress filter and its native argument boundary.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn decision(command: &str) -> Decision {
    ShellQueryCore::new()
        .check(CheckRequest {
            command: command.into(),
            session_id: SessionId::new("tqdm-pipeline"),
            sequence_no: CommandSequenceNo(1),
            shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
            shell_kind: ShellKind::Bash,
            workspace_root: Some("/bench/workspace".into()),
            home: Some("/home/test".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        })
        .decision
}

#[test]
fn progress_filter_works_in_the_original_find_pipeline() {
    let command = r"find / -name '*.py' -exec cat \{} \; | tqdm --unit loc --unit_scale True | wc -l";
    assert_eq!(decision(command), Decision::Allow, "{command}");
}

#[test]
fn proves_default_and_explicit_display_options() {
    for command in [
        "printf 'line\\n' | tqdm | wc -l",
        "printf 'line\\n' | tqdm --unit=lines --unit-scale=2 --total 12 | wc -l",
        "printf 'line\\n' | tqdm --unit-scale | wc -l",
    ] {
        assert_eq!(decision(command), Decision::Allow, "{command}");
    }
}

#[test]
fn keeps_unproved_arguments_and_independent_writes_guarded() {
    for command in [
        "tqdm --manpath /opt/shared/manuals",
        "tqdm --comppath /opt/shared/completions",
        "tqdm --unit 'lines --unreviewed'",
        "tqdm --unit-scale 'True --unreviewed'",
        "tqdm --unit 'lines\n--unreviewed'",
        "tqdm --unit --unreviewed",
        r#"tqdm --unit "$UNOBSERVED""#,
        "tqdm --unit lines file",
        "tqdm -- --unknown",
        "tqdm --unit lines > /opt/shared/report",
    ] {
        assert_eq!(decision(command), Decision::NeedApproval, "{command}");
    }
}
