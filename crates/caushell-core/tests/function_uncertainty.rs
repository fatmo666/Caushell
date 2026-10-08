//! Static input only: none of the shell commands under test is executed.
use caushell_core::{SessionState, ShellQueryCore};
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("function-uncertainty"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn decision(command: &str, expected: Decision) {
    let reply = ShellQueryCore::new().check(request(1, command));
    assert_eq!(
        reply.decision, expected,
        "{command}: {:?}",
        reply.decision_trace
    );
}

#[test]
fn plain_unset_falls_back_only_after_variable_absence() {
    decision(
        "rm() { printf SAFE; }; unset rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm=LAB; rm() { printf SAFE; }; unset rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm=LAB; rm() { printf SAFE; }; unset rm rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; unset -v rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; export rm; unset rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; export -n rm; unset rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn conditional_function_deletion_is_uncertain_only_when_called() {
    decision(
        "f() { printf SAFE; }; if test -n \"$flag\"; then unset -f f; fi; printf DONE",
        Decision::Allow,
    );
    decision(
        "f() { printf SAFE; }; if test -n \"$flag\"; then unset -f f; fi; f",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; test -n \"$flag\" && unset -f rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn unconditional_definition_or_deletion_restores_certainty() {
    decision(
        "f() { printf SAFE; }; test -n \"$flag\" && unset -f f; f() { printf NEW; }; f",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; test -n \"$flag\" && unset -f rm; unset -f rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn isolated_unset_does_not_change_caller_but_changes_its_own_frame() {
    decision(
        "rm() { printf SAFE; }; (unset rm); rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; (unset rm; rm /opt/shared/file)",
        Decision::NeedApproval,
    );
}

#[test]
fn unknown_variable_namespace_does_not_prove_function_removal_or_survival() {
    let mut r = request(1, "f() { printf SAFE; }; unset f; f");
    r.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(
        ShellQueryCore::new().check(r).decision,
        Decision::NeedApproval
    );
    decision(
        "f() { printf SAFE; }; wait -p f; unset f; f",
        Decision::NeedApproval,
    );
    decision(
        "f() { printf SAFE; }; declare f; unset f; f",
        Decision::NeedApproval,
    );
}

#[test]
fn uncertain_binding_survives_snapshot_reload_and_runtime_facts_override_it() {
    let mut core = ShellQueryCore::new();
    let seed = core.check(request(
        1,
        "f() { printf SAFE; }; test -n \"$flag\" && unset -f f",
    ));
    assert_eq!(seed.decision, Decision::Allow);
    let saved = core
        .session_snapshot(&SessionId::new("function-uncertainty"), 1)
        .unwrap();
    let mut reloaded = ShellQueryCore::new();
    reloaded.insert_session_state(
        saved.session_id.clone(),
        SessionState::from_snapshot(saved).unwrap(),
    );
    let reply = reloaded.check(request(2, "f"));
    assert_eq!(reply.decision, Decision::NeedApproval);
    let mut r = request(3, "f");
    r.shell_state_before = r
        .shell_state_before
        .with_function_knowledge(ShellStateKnowledge::Complete)
        .with_function("f", "printf FACT;");
    assert_eq!(reloaded.check(r).decision, Decision::Allow);
}

#[test]
fn same_shell_nested_calls_keep_uncertainty_but_executables_do_not() {
    let prefix = "f() { printf SAFE; }; test -n \"$flag\" && unset -f f";
    for call in [
        "f",
        "eval 'f'",
        "printf '%s' \"$(f)\"",
        "cat <(f)",
        "alias a=f; a",
    ] {
        decision(&format!("{prefix}; {call}"), Decision::NeedApproval);
    }
    for call in [
        "command f",
        "env f",
        "bash -c 'f'",
        "printf LAB | xargs f",
        "find . -exec f \\;",
    ] {
        decision(&format!("{prefix}; {call}"), Decision::Allow);
    }
}

#[test]
fn unsupported_unset_targets_do_not_keep_stale_exact_functions() {
    for unset in [
        "unset -f \"$target\"",
        "unset \"$target\"",
        "unset \"$options\" f",
    ] {
        decision(
            &format!("f() {{ printf SAFE; }}; {unset}; f"),
            Decision::NeedApproval,
        );
        decision(
            &format!("f() {{ printf SAFE; }}; {unset}; printf DONE"),
            Decision::Allow,
        );
    }
    decision("f() { printf SAFE; }; unset -vf f; f", Decision::Allow);
}

#[test]
fn conditional_and_isolated_definitions_do_not_create_exact_caller_bindings() {
    decision(
        "if test -n \"$flag\"; then f() { printf SAFE; }; fi; f",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; (rm() { printf NEW; }); rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "(rm() { printf SAFE; }); rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn known_function_effects_update_the_callers_function_state() {
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; cleanup; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; test -n \"$flag\" && cleanup; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; (cleanup); rm /opt/shared/file",
        Decision::Allow,
    );
}

#[test]
fn known_unexported_variable_is_not_confused_with_absent_environment() {
    let mut r = request(1, "rm() { printf SAFE; }; unset rm; rm /opt/shared/file");
    r.shell_state_before = r
        .shell_state_before
        .with_variable_knowledge(ShellStateKnowledge::Unknown);
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "rm",
            ShellValueSnapshot::exact_scalar("LAB"),
            false,
        ));
    assert_eq!(ShellQueryCore::new().check(r).decision, Decision::Allow);
    let mut r = request(1, "f() { printf SAFE; }; unset f; f");
    r.shell_state_before.observability.variables = ShellStateKnowledge::ExportedOnly;
    assert_eq!(
        ShellQueryCore::new().check(r).decision,
        Decision::NeedApproval
    );
}

#[test]
fn exit_fences_do_not_commit_later_function_uncertainty() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(
            1,
            "f() { printf SAFE; }; exit; test -n \"$flag\" && unset -f f"
        ))
        .decision,
        Decision::Allow
    );
    assert_eq!(core.check(request(2, "f")).decision, Decision::Allow);
}

#[test]
fn bash_function_names_need_not_be_variable_identifiers() {
    for option in ["", "-f", "--"] {
        let mut core = ShellQueryCore::new();
        let reply = core.check(request(
            1,
            &format!("lab-f() {{ printf SAFE; }}; unset {option} lab-f; lab-f"),
        ));
        assert_eq!(reply.decision, Decision::Allow);
        assert!(reply.decision_trace.derived_invocations.is_empty());
        assert!(
            core.session_snapshot(&SessionId::new("function-uncertainty"), 1)
                .unwrap()
                .summary
                .function_binding("lab-f")
                .is_none()
        );
    }
}
