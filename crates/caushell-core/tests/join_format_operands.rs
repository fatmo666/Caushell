//! Static judge requests only. No submitted shell text is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("join-format-operands"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn legacy_format_words_leave_two_input_operands() {
    for (command, sorts) in [
        ("join -o 1.1 1.2 2.1 left right", 0),
        ("join -o 1.1 1.2 left -", 0),
        ("join -j 2  -o 1.1 1.2 2.1 <(sort -k2 1) <(sort -k2 2)", 2),
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert_eq!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .filter(|effect| effect.normalized_command_name == "sort")
                .count(),
            sorts,
            "{command}"
        );
    }
}

#[test]
fn unknown_layouts_and_independent_write_remain_guarded() {
    for command in [
        "join -o auto 1.2 left right",
        "join -o 1.1 -- 1.2 left right",
        "join -o 1.1 left middle right",
        "join -o 1.1 1.2 left middle right",
        "join -o 1.1 1.2 left right >/outside/output",
        "join -o 1.1 1.2 \"$UNOBSERVED\" right",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}
