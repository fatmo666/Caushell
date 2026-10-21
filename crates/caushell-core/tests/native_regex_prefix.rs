//! Static checks only; tested shell strings are not executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("native-regex-prefix"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn timestamp_templates_remain_query_operations() {
    for command in [
        "ping google.com | xargs -L 1 -I '{}' date '+%c: {}'",
        "ping google.com | xargs -L 1 -I '{}' date '+%+: {}'",
        "ping google.com | xargs -L 1 -I '{}' date '+event: {}'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "date" && s.form_id == "print_or_parse_date")
        );
    }
}

#[test]
fn uncertain_values_and_clock_mutation_are_not_exempt() {
    for command in [
        "date --set=tomorrow",
        "ping google.com | xargs -L 1 -I '{}' date '{}'",
        "ping google.com | xargs -L 1 -I '{}' date '+%s{}'",
        "ping google.com | xargs -L 1 -I '{}' date --set='{}'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
}
