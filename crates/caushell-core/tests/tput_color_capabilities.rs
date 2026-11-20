//! JudgeOnly checks for the numeric terminfo color capabilities.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("tput-color-capabilities"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn numeric_color_capabilities_bind_as_database_reads_and_output() {
    for command in [
        "tput setaf 1",
        "tput setab 12",
        "watch --color 'tput setaf 3; printf fixture'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let capability = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "tput")
            .expect("tput query is resolved");
        assert_eq!(capability.form_id, "emit_color_capability");
        assert!(!capability.executes_payload);
        assert!(!capability.opens_interactive_escape_surface);
    }
}

#[test]
fn other_modes_and_independent_effects_keep_their_approval_boundary() {
    for command in [
        "tput init",
        "tput reset",
        "tput -S",
        "tput setaf",
        "tput setaf 1 reset",
        "tput setaf \"$unknown\"",
        "tput setaf 1 > /outside/fixture",
        "tput setaf 1 | sh",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}
