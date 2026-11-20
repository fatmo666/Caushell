//! The source strings are submitted for static judgment only.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("quoted-dollar-argv-domain"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
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
fn literal_dollar_preserves_the_runtime_path_argument_domain() {
    let response =
        check(r#"find . -name '*.fixture' -exec sh -c 'mv "$0" "${0%.OLD}$.copy"' {} \;"#);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.normalized_command_name == "mv" && !fact.operation_semantics_unresolved
            }),
        "{:?}",
        response.reasons
    );
}

#[test]
fn escaped_dollar_is_also_a_literal_suffix() {
    let response =
        check(r#"find . -name '*.fixture' -exec sh -c 'mv "$0" "${0%.OLD}\$.copy"' {} \;"#);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|fact| {
                fact.normalized_command_name == "mv" && !fact.operation_semantics_unresolved
            }),
        "{:?}",
        response.reasons
    );
}

#[test]
fn external_paths_and_real_expansions_still_require_proof() {
    for command in [
        r#"find /opt/fixtures -name '*.fixture' -exec sh -c 'mv "$0" "${0%.OLD}$.copy"' {} \;"#,
        r#"find . -name '*.fixture' -exec sh -c 'mv "$0" "${0%.OLD}$UNOBSERVED.copy"' {} \;"#,
        r#"find . -name '*.fixture' -exec sh -c 'mv "$0" "${0%.OLD}$(printf copy)"' {} \;"#,
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
