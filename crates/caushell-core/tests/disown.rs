//! Static guard inputs only. None of these shell commands is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("disown-test"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
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
fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(1, command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
    r
}

#[test]
fn disown_allows_ordinary_modes_and_unknown_job_targets() {
    for command in [
        "disown",
        "disown %1",
        "disown 123",
        "disown -h %1",
        "disown -a",
        "disown -r",
        "disown -ahr",
        "disown -- %1",
        "disown -h \"$job\"",
        "disown $job",
        "disown --help",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn job_management_intent_survives_graph_snapshot_without_control_or_fake_jobs() {
    for (command, operation) in [
        ("disown %1", ShellJobOperationKind::RemoveFromJobTable),
        ("disown -h \"$job\"", ShellJobOperationKind::SuppressSighup),
    ] {
        let mut core = ShellQueryCore::new();
        let req = request(1, command);
        assert_eq!(core.check(req.clone()).decision, Decision::Allow);
        let snapshot = core.session_snapshot(&req.session_id, 1).unwrap();
        let facts: Vec<_> = snapshot
            .graph
            .nodes
            .iter()
            .filter_map(|n| match &n.kind {
                SessionGraphNodeKindSnapshot::ExecutionSemantics { semantics } => Some(semantics),
                _ => None,
            })
            .collect();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].shell_job_operations, [operation]);
        assert!(facts[0].mutates_current_shell);
        assert!(
            !facts[0].controls_process
                && !facts[0].terminates_current_shell
                && !facts[0].executes_payload
        );
        assert!(facts[0].terminal_session_operations.is_empty());
        assert_eq!(snapshot.summary.variable_bindings().count(), 0);
    }
}

#[test]
fn disown_does_not_allow_other_dangerous_effects_or_rewrite_prior_history() {
    check("rm -f /opt/shared/file & disown", Decision::NeedApproval);
    check("kill %1; disown %1", Decision::NeedApproval);
    check("disown > /opt/shared/log", Decision::NeedApproval);
    check("rm -rf /; disown", Decision::Deny);
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(1, "sleep 60 &")).decision,
        Decision::Allow
    );
    assert_eq!(
        core.check(request(2, "disown -a")).decision,
        Decision::Allow
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("disown-test"), 2)
        .unwrap();
    assert!(snapshot.graph.nodes.iter().any(|n| matches!(&n.kind,
        SessionGraphNodeKindSnapshot::ExecutionSemantics {semantics} if semantics.normalized_command_name == "sleep")));
    assert_eq!(
        core.check(request(3, "kill %1")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn function_alias_and_child_frames_keep_their_own_semantics() {
    for command in [
        "f() { disown -h %1; }; f",
        "alias detach='disown -a'; detach",
        "(disown)",
        "disown | cat",
        "disown &",
        "bash -c 'disown -h %1'",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| !s.shell_job_operations.is_empty()),
            "{command}"
        );
    }
    let r = check(
        "disown() { rm -f /opt/shared/file; }; disown",
        Decision::NeedApproval,
    );
    assert!(
        !r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| !s.shell_job_operations.is_empty())
    );
}

#[test]
fn help_and_option_boundaries_do_not_invent_sighup_suppression() {
    let r = check("disown --help", Decision::Allow);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .all(|s| s.shell_job_operations.is_empty() && !s.mutates_current_shell)
    );
    for command in ["disown -- -h", "disown %1 -h"] {
        let r = check(command, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.shell_job_operations == [ShellJobOperationKind::RemoveFromJobTable])
        );
    }
    for command in [
        "disown -x",
        "disown -hx",
        "disown --future",
        "/bin/disown -a",
    ] {
        check(command, Decision::NeedApproval);
    }
}
