//! Static checks for objdump input and operation boundaries.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("objdump-header-inputs"),
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
fn all_headers_reports_the_named_input_and_keeps_implicit_inputs_unresolved() {
    for command in [
        "objdump -x ./fixture.o",
        "/usr/bin/objdump --all-headers ./fixture.o",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let entry = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "objdump")
            .expect("known objdump form");
        assert_eq!(entry.form_id, "inspect_all_headers");
        assert!(entry.operation_semantics_unresolved);
    }
}

#[test]
fn response_files_extra_modes_and_unknown_ownership_still_require_approval() {
    for command in [
        "objdump -x @fixture.rsp",
        "objdump -x ./fixture.o --dwarf",
        "objdump -x",
        "objdump -x \"$unobserved\"",
        "objdump -x ./fixture.o > /outside/report",
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
