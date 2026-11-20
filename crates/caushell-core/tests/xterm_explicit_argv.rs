//! Judge-only checks for option ownership at the XTerm execution boundary.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("xterm-explicit-argv"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "xterm-static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn xterm_passes_flags_and_operands_to_external_child() {
    let response = check("xterm -e /bin/cat -n 'fixture file.txt'");
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.normalized_command_name == "xterm"
                    && fact.form_id == "explicit_command_argv"
                    && fact.dispatches_child_command
                    && fact.opens_interactive_escape_surface
                    && fact.operation_semantics_unresolved
            }),
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|invocation| {
                invocation.command_name.as_deref() == Some("/bin/cat")
                    && invocation.raw_text.contains("-n")
                    && invocation.raw_text.contains("fixture file.txt")
            }),
        "{:?}",
        response.decision_trace.derived_invocations
    );
}

#[test]
fn nohup_keeps_xterm_and_its_child_in_the_decision_graph() {
    let response = check("nohup xterm -e cat -n fixture.txt &");
    assert_eq!(response.decision, Decision::NeedApproval);
    for command_name in ["nohup", "xterm", "cat"] {
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| { fact.normalized_command_name == command_name }),
            "{command_name}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn incomplete_or_other_forms_do_not_claim_explicit_argv_dispatch() {
    for command in [
        "xterm",
        "xterm -e",
        "xterm -e /bin/cat",
        "xterm -unmodeled -e cat fixture",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| {
                    fact.normalized_command_name != "xterm" || !fact.dispatches_child_command
                }),
            "{command}: {:?}",
            response.reasons
        );
    }
}
