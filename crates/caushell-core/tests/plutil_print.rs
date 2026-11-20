//! Static checks for macOS property-list printing.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("plutil-print"),
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
fn print_accepts_named_property_lists_and_explicit_stdin() {
    for command in [
        "plutil -p ./first.plist",
        "/usr/bin/plutil -p ./first.plist ./second.plist",
        "plutil -p - < ./fixture.plist",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let print = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "plutil")
            .expect("known plutil form");
        assert_eq!(print.form_id, "print_property_lists");
        assert!(!print.executes_payload && !print.operation_semantics_unresolved);
    }
}

#[test]
fn competing_modes_unknown_operands_and_other_effects_still_require_review() {
    for command in [
        "plutil -p ./fixture.plist -convert xml1",
        "plutil -p -o ./copy.plist ./fixture.plist",
        "plutil -p -remove key ./fixture.plist",
        "plutil -p",
        "plutil -p \"$unknown\"",
        "plutil -p $unknown",
        "plutil -p ./fixture.plist > /outside/fixture.txt",
        "plutil -p ./fixture.plist | sh",
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
