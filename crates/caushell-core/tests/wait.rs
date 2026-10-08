//! Static checks only: shell command strings here are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/tmp/project");
    shell.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("wait-test"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}
fn check(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(1, command));
    assert_eq!(
        result.decision, expected,
        "{command}: {:?}",
        result.decision_trace
    );
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}: {:?}",
        result.decision_trace
    );
}
#[test]
fn wait_is_not_process_control() {
    for c in [
        "wait",
        "wait -n",
        "wait -f",
        "wait -fn",
        "wait 123 456",
        "wait %1",
        "wait -n -p target",
        "wait -np target",
        "wait -p target",
        "wait -- 123",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn unknown_contracts_require_approval() {
    for c in [
        "wait --unknown",
        "wait -p",
        "wait -n -p \"$UNKNOWN\"",
        "wait -p 'a[0]'",
        "wait -p 'bad-name'",
        "wait -p ''",
        "wait -p target -p other",
        "target=cache/file; declare -n ref=target; wait -p ref",
        "declare -a target; wait -p target",
    ] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn runtime_write_forgets_old_value_in_same_action() {
    for c in [
        "target=cache/file; wait -n -p target; rm -f \"$target\"",
        "target=cache/file; wait -n -p target; rm -f \"${target:-/opt/shared/file}\"",
        "target=cache/file; name=target; wait -n -p \"$name\"; rm -f \"$target\"",
        "target=cache/file; if true; then wait -n -p target; fi; rm -f \"$target\"",
        "target=cache/file; read target; rm -f \"$target\"",
        "target=cache/file; bash -c 'wait -n -p target; rm -f \"$target\"'",
        "target=cache/file; (wait -n -p target; rm -f \"$target\")",
        "target=cache/file; f() { wait -n -p target; }; f; rm -f \"$target\"",
        "target=cache/file; f() { wait -n -p target; rm -f \"$target\"; }; f",
        "target=cache/file; alias wk='wait -n -p'; wk target; rm -f \"$target\"",
        "target=cache/file; f() { wait -n -p \"$1\"; }; f target; rm -f \"$target\"",
        "target=cache/file; wait -n -p target; printf 'rm -f %s' \"${target:-/opt/shared/file}\" | bash",
        "target=cache/file; printf x | { wait -n -p target; rm -f \"$target\"; }",
        "export target=cache/file; bash -c 'wait -p target; printf \"%s\" \"${target:-/opt/shared/file}\"' | xargs rm -f",
    ] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn restores_precision_without_polluting_parent_scope() {
    for c in [
        "target=cache/file; wait -n -p target; target=cache/new; rm -f \"$target\"",
        "target=cache/file; other=cache/other; wait -n -p target; rm -f \"$other\"",
        "target=cache/file; wait; rm -f \"$target\"",
        "target=cache/file; (wait -n -p target); rm -f \"$target\"",
        "target=cache/file; wait -n -p target & rm -f \"$target\"",
        "target=cache/file; printf x | read target; rm -f \"$target\"",
        "target=cache/file; bash -c 'wait -n -p target'; rm -f \"$target\"",
        "target=cache/file; f() { local target; wait -n -p target; }; f; rm -f \"$target\"",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn runtime_unknown_survives_across_actions_and_fresh_snapshot_wins() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(1, "target=cache/file")).decision,
        Decision::Allow
    );
    let mut second = request(2, "wait -n -p target");
    second.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(second).decision, Decision::Allow);
    let mut third = request(3, "rm -f \"$target\"");
    third.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(third).decision, Decision::NeedApproval);
    let mut fourth = request(4, "rm -f \"$target\"");
    fourth
        .shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "target",
            ShellValueSnapshot::exact_scalar("cache/new"),
            false,
        ));
    assert_eq!(core.check(fourth).decision, Decision::Allow);
}
#[test]
fn later_assignment_and_unset_win_in_persisted_state() {
    for (command, later, expected) in [
        (
            "target=cache/old; wait -n -p target; target=cache/new",
            "rm -f \"$target\"",
            Decision::Allow,
        ),
        (
            "target=cache/old; wait -n -p target; target=/opt/shared/file; target=cache/old",
            "rm -f \"$target\"",
            Decision::Allow,
        ),
        (
            "target=cache/old; wait -n -p target; unset target",
            "rm -f \"${target:-/opt/shared/file}\"",
            Decision::NeedApproval,
        ),
        (
            "target=cache/old; (wait -n -p target)",
            "rm -f \"$target\"",
            Decision::Allow,
        ),
        (
            "target=cache/old; wait -p target; set -- \"$target\"",
            "rm -f \"$1\"",
            Decision::NeedApproval,
        ),
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(
            core.check(request(1, command)).decision,
            Decision::Allow,
            "{command}"
        );
        let mut r = request(2, later);
        r.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        assert_eq!(core.check(r).decision, expected, "{command}");
    }
}

#[test]
fn declined_runtime_write_does_not_change_session_state() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(1, "target=cache/file")).decision,
        Decision::Allow
    );
    let mut denied = request(2, "wait -p target; rm -f /opt/shared/file");
    denied.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(denied).decision, Decision::NeedApproval);
    let mut later = request(3, "rm -f \"$target\"");
    later.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(later).decision, Decision::Allow);
}

#[test]
fn persisted_function_and_alias_runtime_writers_are_seen() {
    for (definition, invocation) in [
        ("f() { wait -p target; }", "f"),
        ("alias wk='wait -p target'", "wk"),
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(
            core.check(request(1, &format!("target=cache/file; {definition}")))
                .decision,
            Decision::Allow
        );
        let mut r = request(2, invocation);
        r.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        assert_eq!(core.check(r).decision, Decision::Allow);
        let mut r = request(3, "rm -f \"$target\"");
        r.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        assert_eq!(
            core.check(r).decision,
            Decision::NeedApproval,
            "{definition}"
        );
    }
}
