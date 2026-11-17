//! Static checks only. No command under test is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("scope-return"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str, decision: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
    assert!(
        !response
            .reasons
            .iter()
            .any(|r| r == "command return has no registered profile")
    );
    response
}

#[test]
fn ordinary_returns_have_distinct_non_terminating_semantics() {
    for command in [
        "f() { return; }; f",
        "f() { return 0; }; f; printf caller",
        "f() { return 7; }; f || printf failed",
        "f() { false; return; }; f",
        "f() { local status=1; return \"$status\"; }; f",
        "f() { return -- 0; }; f",
        "f() { return -1; }; f",
        "f() { return 0 1; }; f",
        "f() { return \"$unknown_status\"; }; f",
        "f() { return --help; }; f",
        "g() { return 7; }; f() { g; printf inner; }; f; printf caller",
    ] {
        let response = check(command, Decision::Allow);
        assert!(
            response.decision_trace.execution_semantics.iter().any(|s| {
                s.normalized_command_name == "return"
                    && s.returns_from_shell_scope
                    && !s.terminates_current_shell
                    && !s.controls_process
            }),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn caller_and_condition_branches_are_never_erased_by_return() {
    for command in [
        "f() { return 0; }; f; touch /opt/shared/out",
        "f() { return 1; }; f || touch /opt/shared/out",
        "f() { return 0; }; f && touch /opt/shared/out",
        "f() { return; exit; }; f; touch /opt/shared/out",
        "f() { if test \"$flag\" = yes; then return 0; fi; exit; }; f; touch /opt/shared/out",
        "f() { g() { return 0; }; g; touch /opt/shared/out; }; f",
        "return 0; touch /opt/shared/out",
        "f() { return 0 < missing; touch /opt/shared/out; }; f",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| { p.rule_id == RuleId::OutsideWorkspaceMutation }),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn return_paths_do_not_install_post_return_assignments_as_caller_facts() {
    for body in [
        "return 0; slot=inside",
        "if test \"$flag\" = yes; then return 0; fi; slot=inside",
        "return invalid; slot=inside",
        "return 0 < missing; slot=inside",
        "g() { return 0; }; return 0; g; slot=inside",
    ] {
        let command = format!("slot=/opt/shared/out; f() {{ {body}; }}; f; touch -- \"$slot\"");
        check(&command, Decision::NeedApproval);
    }
    check(
        "slot=inside; f() { return 0; slot=inside; }; f; touch -- \"$slot\"",
        Decision::Allow,
    );
}

#[test]
fn return_join_is_preserved_across_persistent_requests() {
    let mut core = ShellQueryCore::new();
    let initial = core.check(request(
        "slot=/opt/shared/out; f() { return 0; slot=inside; }; f",
        1,
    ));
    assert_eq!(initial.decision, Decision::Allow, "{initial:#?}");
    let mut next = request("touch -- \"$slot\"", 2);
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let response = core.check(next);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn return_cwd_is_joined_before_normal_function_exit_cwd() {
    for command in [
        "f() { cd /opt/shared; return 0; cd /tmp/project; }; f; touch marker",
        "f() { cd /opt/shared && return 0; cd /tmp/project; }; f; touch marker",
        "g() { cd /opt/shared; return 0; cd /tmp/project; }; f() { g; }; f; touch marker",
    ] {
        check(command, Decision::NeedApproval);
    }
    check(
        "f() { (cd /opt/shared; return 0); }; f; touch marker",
        Decision::Allow,
    );
}

#[test]
fn source_return_cannot_hide_caller_state_or_effects() {
    check(
        "source /dev/stdin <<< 'return 7'; printf caller",
        Decision::Allow,
    );
    check(
        "source /dev/stdin <<< 'return 0'; touch /opt/shared/out",
        Decision::NeedApproval,
    );
    check(
        "slot=/opt/shared/out; source /dev/stdin <<< 'return 0; slot=inside'; touch -- \"$slot\"",
        Decision::NeedApproval,
    );
    check(
        "source /dev/stdin <<< 'cd /opt/shared; return 0; cd /tmp/project'; touch marker",
        Decision::NeedApproval,
    );
}

#[test]
fn argument_expansions_traps_and_shadowing_keep_their_real_effects() {
    for command in [
        "f() { return $(touch /opt/shared/out); }; f",
        "f() { return \"$(touch /opt/shared/out)\"; }; f",
        "f() { trap 'touch /opt/shared/out' RETURN; return 0; }; f",
        "return() { touch /opt/shared/out; }; return",
        "f() { return 0; }; f $(touch /opt/shared/out)",
        "slot=/opt/shared/out; f() { return 0; unset slot; }; f; touch -- \"$slot\"",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn unknown_commands_and_external_lookalikes_stay_ask() {
    for command in ["unknown_scope_command", "/opt/custom/return 0"] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn possible_return_exports_do_not_become_a_proved_absent_startup_input() {
    check(
        "unset BASH_ENV; f() { export BASH_ENV=/opt/shared/config; return 0; unset BASH_ENV; }; f; bash -c 'printf safe'",
        Decision::NeedApproval,
    );
}

#[test]
fn source_return_keeps_positionals_unknown_across_request_history() {
    let mut core = ShellQueryCore::new();
    let initial = core.check(request(
        "set -- /opt/shared/out; source /dev/stdin <<< 'return 0; set -- inside'",
        1,
    ));
    assert_eq!(initial.decision, Decision::Allow, "{initial:#?}");
    let response = core.check(request("touch -- \"$1\"", 2));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn top_level_fatal_return_error_cannot_commit_post_error_assignments() {
    let mut core = ShellQueryCore::new();
    let initial = core.check(request("slot=/opt/shared/out; return 0 1; slot=inside", 1));
    assert_eq!(initial.decision, Decision::Allow, "{initial:#?}");
    let response = core.check(request("touch -- \"$slot\"", 2));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn hard_deny_survives_return_and_parameter_expansion() {
    for command in [
        "f() { return 0; }; f; rm -rf /etc",
        "f() { return 0; rm -rf /etc; }; f",
        "f() { return $(rm -rf /etc); }; f",
    ] {
        check(command, Decision::Deny);
    }
}
