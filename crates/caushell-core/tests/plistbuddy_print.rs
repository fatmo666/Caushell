//! Static policy checks. The command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("plistbuddy-print"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn a_single_static_print_is_a_plist_read() {
    for command in [
        "/usr/libexec/PlistBuddy -c 'Print :Component:0:Version' ./fixture.plist",
        "/usr/libexec/PlistBuddy -c 'print :Version' ./fixture.plist",
        "/usr/libexec/PlistBuddy -c 'pRiNT :Component:0:Version' ./fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Print :Version' /Applications/Example.app/Info.plist",
        "/usr/libexec/PlistBuddy -c Print './a file.plist'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let semantics = &result.decision_trace.execution_semantics;
        assert_eq!(semantics.len(), 1);
        let print = &semantics[0];
        assert_eq!(print.normalized_command_name, "/usr/libexec/PlistBuddy");
        assert_eq!(print.form_id, "print_plist_entry");
        assert!(!print.executes_payload && !print.operation_semantics_unresolved);
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .all(|fact| !fact.operation.is_mutation())
        );
    }
}

#[test]
fn unmodeled_plist_operations_and_independent_effects_stay_guarded() {
    for command in [
        "/usr/libexec/PlistBuddy fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Set :Version test' fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Print :Version' -c 'Save' fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Save' -c 'Print :Version' fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Print :Version; Save' fixture.plist",
        "/usr/libexec/PlistBuddy -c 'print :Version; save' fixture.plist",
        "/usr/libexec/PlistBuddy -c 'Print :Version\nSave' fixture.plist",
        "/usr/libexec/PlistBuddy -c \"$query\" fixture.plist",
        "/usr/libexec/PlistBuddy -c Print fixture.plist extra",
        "/usr/libexec/PlistBuddy -c Print -",
        "/usr/libexec/PlistBuddy -c Print fixture.plist >/opt/shared/result",
        "/usr/libexec/PlistBuddy -c Print fixture.plist | sh",
        "/opt/shared/PlistBuddy -c Print fixture.plist",
        "PlistBuddy -c Print fixture.plist",
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
