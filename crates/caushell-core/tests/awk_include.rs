//! Offline static checks. The AWK programs here are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("awk-include"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "awk-include-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn numeric_input_mode_does_not_load_code() {
    for command in [
        "gawk -n '{print $1 + 0}'",
        "awk --non-decimal-data '{print $1 + 0}'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| {
                    fact.form_id == "positional_program_transform" && !fact.executes_payload
                })
        );
    }
}

#[test]
fn include_registers_unverified_source_alongside_the_main_program() {
    for command in [
        "awk -nifruit '{print $1}'",
        "gawk -i ./fruit.awk -e '{print $1}'",
        "gawk --include=fruit '{print $1}'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| {
                    matches!(
                        fact.form_id.as_str(),
                        "positional_program_transform" | "explicit_program_transform"
                    ) && fact.executes_payload
                }),
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn unbound_or_unrecognized_controls_remain_conservative() {
    for command in [
        "gawk -i",
        "gawk -i \"$unknown\" '{print $1}'",
        "gawk --profile '{print $1}'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}
