//! Guard checks only. None of these shell commands is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("read-completion"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-read-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, decision: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
}

#[test]
fn normal_prompts_and_readonly_loops_are_allowed() {
    for command in [
        "read -p prompt answer",
        "read -n1 c",
        "read -t10",
        "read -r -d '' f",
        "read -e -p 'Continue?' -i Y input",
        "read -u4 line",
        "read -N \"$BUFSIZE\" buffer",
        "read -a files",
        "read --",
        "read --help",
        "find . -type f -name '.*' -print0 | while IFS= read -r -d '' f; do basename \"$f\"; done",
        "find -print0 | while IFS= read -rd $'\\0' f; do echo \"[$f]\"; done",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn actual_destinations_are_recorded_in_the_graph() {
    for (command, expected) in [
        ("read -p prompt first second", vec!["first", "second"]),
        ("read -p prompt", vec!["REPLY"]),
        ("read -a files ignored REPLY", vec!["files"]),
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(core.check(request(command)).decision, Decision::Allow);
        let mut names = core
            .session_graph(&SessionId::new("read-completion"))
            .unwrap()
            .nodes()
            .filter_map(|n| match &n.kind {
                NodeKind::VariableBindingIntent { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, expected, "{command}");
    }
}

#[test]
fn runtime_input_cannot_keep_an_earlier_safe_mutation_target() {
    for command in [
        "target=./safe/file; read -p prompt target; rm \"$target\"",
        "first=unused; target=./safe/file; read -p prompt first target; rm \"$target\"",
        "REPLY=./safe/file; read -p prompt; rm \"$REPLY\"",
        "target=./safe/file; read -u4 target; rm \"$target\"",
        "target=./safe/file; read -a target; rm \"$target\"",
        "target=./safe/file; read -p prompt target; chmod 644 \"$target\"",
        "find . -print0 | while IFS= read -r -d '' f; do mv \"$f\" \"$destination\"; done",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn runtime_input_execution_still_requires_approval() {
    for command in [
        "cmd='echo safe'; read -p prompt cmd; bash -c \"$cmd\"",
        "first=unused; cmd='echo safe'; read first cmd; bash -c \"$cmd\"",
        "REPLY='echo safe'; read -r; bash -c \"$REPLY\"",
        "cmd='echo safe'; read -u4 cmd; bash -c \"$cmd\"",
        "cmd='echo safe'; read -a cmd; bash -c \"$cmd\"",
        "read -p prompt cmd; eval \"$cmd\"",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn array_mode_does_not_invalidate_ignored_destinations() {
    expect(
        "target=./safe/file; read -a files target; rm \"$target\"",
        Decision::Allow,
    );
    expect(
        "REPLY=./safe/file; read -a files; rm \"$REPLY\"",
        Decision::Allow,
    );
}

#[test]
fn known_zero_timeout_does_not_invalidate_prior_values() {
    for command in [
        "target=./safe/file; read -t0 target; rm \"$target\"",
        "REPLY=./safe/file; read -t0; rm \"$REPLY\"",
        "target=./safe/file; read -t0 -a target; rm \"$target\"",
    ] {
        expect(command, Decision::Allow);
    }
    expect(
        "target=./safe/file; read -t0 -t1 target; rm \"$target\"",
        Decision::NeedApproval,
    );
}

#[test]
fn uncertain_option_arity_does_not_keep_an_earlier_safe_value() {
    for command in [
        "target=./safe/file; read -p $prompt -t0 target; rm \"$target\"",
        "target=./safe/file; read -n $count first; rm \"$target\"",
        "target=./safe/file; count='1 extra target'; read -n $count first; rm \"$target\"",
        "target=./safe/file; read -p \"$@\" -t0 target; rm \"$target\"",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect(
        "target=./safe/file; read -p \"$prompt\" -t0 target; rm \"$target\"",
        Decision::Allow,
    );
    expect("read -n \"$count\" first", Decision::Allow);
}

#[test]
fn unsupported_options_or_destinations_do_not_silently_pass() {
    for command in [
        "read -Z target",
        "read -p",
        "read -a",
        "read 'a[0]'",
        "read \"$unknown\"",
        "read -- -p prompt target",
        "/usr/bin/read target",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn completed_input_actions_invalidate_state_across_session_actions() {
    for (read, mutation) in [
        ("read -p prompt target", "rm \"$target\""),
        ("read first target", "rm \"$target\""),
        ("read -p prompt", "rm \"$REPLY\""),
        ("read -a target", "rm \"$target\""),
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(
            core.check(request("target=./safe/file; REPLY=./safe/file"))
                .decision,
            Decision::Allow
        );
        let mut r = request(read);
        r.sequence_no = CommandSequenceNo::new(2);
        assert_eq!(core.check(r).decision, Decision::Allow);
        let mut r = request(mutation);
        r.sequence_no = CommandSequenceNo::new(3);
        let result = core.check(r);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{read}: {result:#?}"
        );
    }
}
