use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        command: command.into(),
        session_id: SessionId::new("find-region-runtime-argv"),
        sequence_no: CommandSequenceNo(1),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        workspace_root: Some("/bench/workspace".into()),
        home: Some("/home/test".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

fn ownership_gap(response: &CheckResponse) -> bool {
    response
        .decision_trace
        .decision_proposals
        .iter()
        .any(|proof| {
            proof
                .reason
                .contains("command find has unresolved operation semantics")
                && proof
                    .reason
                    .contains("argument region ownership is unresolved")
        })
}

#[test]
fn invalid_early_action_termination_does_not_hide_the_reader() {
    for (command, tool) in [
        (r#"find . -exec tail -n+5 -q "$file" {} +"#, "tail"),
        (
            r#"find . -name "$1" -type f -exec grep -i "$2" '{}' \;"#,
            "grep",
        ),
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
        assert!(!ownership_gap(&response));
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|unit| unit.normalized_command_name == tool)
        );
    }
}

#[test]
fn uncertain_width_and_valid_early_continuations_keep_ownership_gap() {
    for command in [
        r#"find . -exec grep -i "$pattern" -name \;"#,
        r#"find . -exec grep -i "$@" {} \;"#,
        r#"find . -exec grep -i $pattern {} \;"#,
        r#"find . -exec "$tool" {} \;"#,
    ] {
        let response = check(command);
        assert!(
            ownership_gap(&response),
            "{command}: {:?}",
            response.reasons
        );
        assert_eq!(response.decision, Decision::NeedApproval);
    }
}

#[test]
fn surviving_child_and_nested_source_keep_their_own_effects() {
    let opaque = check(r#"find . -exec sh -c "$body" _ {} \;"#);
    assert_eq!(opaque.decision, Decision::NeedApproval, "{:?}", opaque.reasons);
    assert!(!ownership_gap(&opaque));
    for command in [
        r#"find . -exec touch "$file" {} \;"#,
        r#"find . -exec grep -i "$(printf note >/opt/shared/fixture.txt)" {} \;"#,
    ] {
        let response = check(command);
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response.decision_trace.decision_proposals.iter().any(|p| {
                p.rule_id == RuleId::OutsideWorkspaceMutation
                    && p.decision == Decision::NeedApproval
            }),
            "{command}: {:?}",
            response.reasons
        );
    }
}
