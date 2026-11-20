//! Check native argv attribution using only static requests.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuleId, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("script-positional-command"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-script-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn positional_child_and_its_argv_are_analyzed() {
    let response = check("script -q ./record.log /bin/cat -- 'fixture file.txt'");
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.normalized_command_name == "script"
                    && fact.form_id == "record_positional_command"
                    && fact.dispatches_child_command
            }),
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.normalized_command_name == "cat"
                    && fact.source.raw_text.contains("fixture file.txt")
            }),
        "{:?}",
        response.decision_trace.execution_semantics
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|path| path.slot_name == "output_path")
    );
}

#[test]
fn positional_child_does_not_erase_recording_or_terminal_approval() {
    let response = check("script -q /opt/fixture/record.log /bin/cat fixture.txt");
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|proposal| { proposal.rule_id == RuleId::OutsideWorkspaceMutation }),
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.form_id == "record_positional_command" && fact.opens_interactive_escape_surface
            }),
        "{:?}",
        response.reasons
    );
}

#[test]
fn default_shell_and_string_forms_keep_their_own_execution_semantics() {
    for (command, form) in [
        ("script -q ./record.log", "record_shell"),
        (
            "script -q -c 'printf fixture' ./record.log",
            "command_string",
        ),
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| {
                    fact.normalized_command_name == "script"
                        && fact.form_id == form
                        && !fact.dispatches_child_command
                }),
            "{command}: {:?}",
            response.reasons
        );
    }
}
