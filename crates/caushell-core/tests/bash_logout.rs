//! Static checks. Commands in the tests only enter the analyzer.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("bash-logout"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn help_spelling_does_not_prove_a_side_effect_free_builtin() {
    let response = check("logout --help");
    assert_eq!(
        response.decision,
        Decision::NeedApproval,
        "{:?}",
        response.reasons
    );
    let fact = response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|item| item.normalized_command_name == "logout")
        .unwrap();
    assert_eq!(fact.form_id, "login_dependent_logout");
    assert!(
        !fact.terminates_current_shell && fact.executes_hook && fact.operation_semantics_unresolved
    );
}

#[test]
fn possible_login_logout_keeps_script_execution_and_approval() {
    for command in ["logout", "logout 7", "logout -1"] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|item| {
                    item.normalized_command_name == "logout"
                        && item.form_id == "login_dependent_logout"
                        && item.executes_hook
                        && item.executes_payload
                        && item.loads_startup_config
                        && item.operation_semantics_unresolved
                        && !item.terminates_current_shell
                }),
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn unproved_arguments_and_later_effects_are_checked() {
    for command in [
        "logout --help extra",
        "logout --help \"$VALUE\"",
        "logout \"$VALUE\"",
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
                .all(|item| !item.terminates_current_shell)
        );
    }
    let later = check("logout; printf '%s\\n' fixture > /opt/round-fixture/item");
    assert_eq!(later.decision, Decision::NeedApproval);
    assert!(later.decision_trace.path_targets.iter().any(|target| {
        target.lexical.concrete_path() == Some("/opt/round-fixture/item")
            && target.operation.is_mutation()
    }));
}

#[test]
fn the_builtin_profile_does_not_classify_external_paths_or_functions() {
    for command in [
        "/work/tools/logout --help",
        "command -p /work/tools/logout --help",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|item| { item.form_id != "login_dependent_logout" }),
            "{command}: {:?}",
            response.reasons
        );
    }
    let shadowed = check("logout() { printf '%s\\n' fixture; }; logout");
    assert_eq!(shadowed.decision, Decision::Allow, "{:?}", shadowed.reasons);
    assert!(
        shadowed
            .decision_trace
            .execution_semantics
            .iter()
            .all(|item| { item.form_id != "login_dependent_logout" })
    );
}
