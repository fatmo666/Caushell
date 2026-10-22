use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("structured-endpoint-bounds"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn uncertain_http_path_does_not_invent_an_upload() {
    for command in [
        "curl -s http://search.twitter.com/search.json?q=node.js | json",
        "curl -q -s \"https://example.test/$UNKNOWN\"",
        "curl -q -s -- \"https://example.test/query?q=$UNKNOWN\"",
        "curl -q -s -o ./result \"https://example.test/$UNKNOWN\"",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn possible_uploads_and_unknown_controls_still_require_approval() {
    for command in [
        "curl -q -s \"gopher://example.test/$UNKNOWN\"",
        "curl -q -s \"$UNKNOWN\"",
        "curl -q -s https://example.test/$UNKNOWN",
        "curl -q -s --data @./input \"https://example.test/$UNKNOWN\"",
        "curl -q -s --upload-file ./input \"https://example.test/$UNKNOWN\"",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn dropping_an_impossible_projection_never_drops_shell_substitution_effects() {
    let response = check("curl -q -s \"https://example.test/$(rm -rf /)\"");
    assert_eq!(response.decision, Decision::Deny, "{response:#?}");
}
