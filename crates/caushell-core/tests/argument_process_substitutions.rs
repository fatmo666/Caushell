//! Only static judgments; commands below are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("wc-input-contract"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(text: &str, decision: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(text));
    assert_eq!(r.decision, decision, "{text}: {r:#?}");
    r
}

#[test]
fn native_binding_cannot_hide_process_body_effects() {
    for text in [
        "wc --files0-from=<(rm -rf /)",
        "printf '%s' prefix<(rm -rf /)suffix",
        "printf '%s' \"prefix\"<(rm -rf /)",
        "head --help --ignored=<(rm -rf /)",
        "unprofiled_reader --input=<(rm -rf /)",
        "env printf '%s' prefix<(rm -rf /)",
        "bash -c 'wc --files0-from=<(rm -rf /)'",
    ] {
        check(text, Decision::Deny);
    }
}
#[test]
fn output_process_substitutions_retain_mutations() {
    check(
        "printf '%s' prefix>(touch /opt/shared/file)",
        Decision::NeedApproval,
    );
}
#[test]
fn literal_argv_and_quotes_remain_data_not_new_shell() {
    for text in [
        "printf '%s' '--input=<(rm -rf /)'",
        "printf '%s' \"--input=<(rm -rf /)\"",
        "printf '%s' 'prefix'\"<(rm -rf /)\"",
        "printf '%s' \"$(printf '%s' '<(rm -rf /)')\"",
        "printf '%s\\0' '--input=<(rm -rf /)' | xargs -0 printf '%s'",
    ] {
        let r = check(text, Decision::Allow);
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|e| e.normalized_command_name == "rm"),
            "{r:#?}"
        );
    }
}
#[test]
fn standalone_and_nested_processes_have_one_scope_owner() {
    for text in [
        "cat <(rm -rf /)",
        "cat --input=<(cat <(rm -rf /))",
        "printf '%s' \"$(cat <(rm -rf /))\"",
    ] {
        let r = check(text, Decision::Deny);
        assert_eq!(
            r.decision_trace
                .execution_semantics
                .iter()
                .filter(|e| e.normalized_command_name == "rm")
                .count(),
            1,
            "{r:#?}"
        );
    }
}
