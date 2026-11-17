use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("literal-tilde"), sequence_no: CommandSequenceNo::new(1),
        command: command.into(), shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash, home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata { runtime_name: "test".into(), tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell() },
    })
}

#[test]
fn original_read_only_backup_pattern_is_not_an_unbound_control_surface() {
    let text = r"find . -name .snapshot -prune -o \( \! -name *~ -print0 \)";
    let r = check(text);
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
}

#[test]
fn literal_pattern_proof_does_not_authorize_other_controls_or_code() {
    for text in [
        "find . -name *~ -delete",
        "find . -name $pattern~ -print",
        r#"find . -name *~ -exec sh -c "$code" \;"#,
    ] {
        let r = check(text);
        assert_ne!(r.decision, Decision::Allow, "{text}: {r:#?}");
    }
    // Supplied HOME can already prove an absolute glob prefix; this query is
    // safe even before this fix. Do not invent a new approval requirement.
    assert_eq!(check("find . -name ~/* -print").decision, Decision::Allow);
}
