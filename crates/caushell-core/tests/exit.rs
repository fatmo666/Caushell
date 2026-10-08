//! Static inputs only. No command under test is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::SessionGraph;
use caushell_passes::*;
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/tmp/project");
    shell.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("exit-test"),
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
    let r = ShellQueryCore::new().check(request(1, command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
}
fn inspect(command: &str) -> RunnerContext {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ExtractAliasBindingsPass);
    runner.register_session_transform_pass(ExtractFunctionBindingsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractCurrentWorkingDirectoryPass);
    runner.register_session_transform_pass(ExtractVariableBindingsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(1, command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    ctx
}
#[test]
fn exit_allows_ordinary_termination_without_process_control() {
    for c in [
        "exit",
        "exit 0",
        "exit 7",
        "exit -1",
        "exit --",
        "exit -- 0",
        "exit --help",
        "status=0; exit \"$status\"",
    ] {
        check(c, Decision::Allow);
    }
    let ctx = inspect("exit 0");
    assert!(ctx.root_shell_terminates());
    assert!(ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::AddExecutionSemantics { semantics, .. }
        if semantics.terminates_current_shell && semantics.mutates_current_shell && !semantics.controls_process)));
}
#[test]
fn ambiguous_argument_forms_use_existing_approval() {
    for c in ["exit 0 1", "exit \"$status\"", "exit $status"] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn state_stops_but_risk_audit_does_not_prune_commands() {
    check(
        "target=/opt/shared/file; exit 0; target=cache/file; rm -f \"$target\"",
        Decision::NeedApproval,
    );
    let ctx = inspect(
        "target=/opt/shared/file; exit 0; target=cache/file; alias stop='exit'; later() { exit; }; set -- cache/file; cd /opt",
    );
    assert!(ctx.root_shell_terminates());
    assert!(
        ctx.parsed_command()
            .unwrap()
            .commands
            .iter()
            .any(|c| c.command_name.as_deref() == Some("cd"))
    );
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::UpsertAliasBinding { binding } if binding.name == "stop")));
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::UpsertFunctionBinding { binding } if binding.name == "later")));
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(
        m,
        PendingMutation::SetPositionalParameters { .. }
            | PendingMutation::SetCurrentWorkingDirectory { .. }
    )));
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::UpsertVariableBinding { binding }
        if binding.name == "target" && binding.value == SessionVariableValue::exact_scalar("cache/file"))));
}
#[test]
fn persistent_state_never_accepts_the_post_exit_safe_path() {
    for c in [
        "target=/opt/shared/file; exit 0; target=cache/file",
        "target=/opt/shared/file; finish() { exit 0; }; finish; target=cache/file",
        "target=/opt/shared/file; alias finish='exit 0'; finish; target=cache/file",
        "target=cache/file; finish() { target=/opt/shared/file; exit; target=cache/file; }; finish; target=cache/file",
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(core.check(request(1, c)).decision, Decision::Allow, "{c}");
        let mut next = request(2, "rm -f \"$target\"");
        next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        assert_eq!(core.check(next).decision, Decision::NeedApproval, "{c}");
    }
}
#[test]
fn function_exit_terminates_its_shell_not_merely_the_function() {
    for c in [
        "target=/opt/shared/file; finish() { exit; }; finish; target=cache/file; rm -f \"$target\"",
        "target=/opt/shared/file; f() { g() { exit; }; g; target=cache/file; }; f; rm -f \"$target\"",
    ] {
        check(c, Decision::NeedApproval);
        assert!(inspect(c).root_shell_terminates());
    }
    let ctx = inspect("exit() { printf done; }; exit; target=cache/file");
    assert!(
        !ctx.root_shell_terminates(),
        "a user function named exit is not the builtin"
    );
}
#[test]
fn isolated_frames_do_not_terminate_the_caller() {
    for c in [
        "target=cache/file; (exit; target=/opt/shared/file); rm -f \"$target\"",
        "target=cache/file; { exit; target=/opt/shared/file; } | cat; rm -f \"$target\"",
        "target=cache/file; { exit; target=/opt/shared/file; } & rm -f \"$target\"",
        "target=cache/file; bash -c 'exit; target=/opt/shared/file'; rm -f \"$target\"",
        "target=cache/file; f() { exit; }; (f); target=cache/new; rm -f \"$target\"",
    ] {
        check(c, Decision::Allow);
        assert!(!inspect(c).root_shell_terminates(), "{c}");
    }
    check(
        "target=/opt/shared/file; (exit; target=cache/file; rm -f \"$target\")",
        Decision::NeedApproval,
    );
}
#[test]
fn conditional_exits_do_not_claim_unconditional_termination() {
    for c in [
        "false && exit; target=cache/file",
        "if false; then exit; fi; target=cache/file",
        "f() { false && exit; }; f; target=cache/file",
    ] {
        assert!(!inspect(c).root_shell_terminates(), "{c}");
        check(c, Decision::Allow);
    }
    let ctx = inspect("target=/opt/shared/file; exit --help; target=cache/file");
    assert!(!ctx.root_shell_terminates());
    assert!(ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::UpsertVariableBinding { binding }
        if binding.value == SessionVariableValue::exact_scalar("cache/file"))));
}
#[test]
fn post_exit_unset_does_not_remove_the_pre_exit_binding() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(1, "target=/opt/shared/file; exit; unset target"))
            .decision,
        Decision::Allow
    );
    let mut next = request(2, "rm -f \"$target\"");
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(next).decision, Decision::NeedApproval);
}

#[test]
fn isolated_post_exit_definition_does_not_create_a_caller_terminator() {
    let ctx = inspect("(exit; finish() { exit; }); finish; target=cache/file");
    assert!(!ctx.root_shell_terminates());
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(m,
        PendingMutation::UpsertFunctionBinding { binding } if binding.name == "finish")));
}

#[test]
fn failed_entry_cannot_hide_a_real_continuing_path() {
    for c in [
        "target=cache/file; exit 0 < missing; target=/opt/shared/file; rm -f \"$target\"",
        "target=cache/file; f() { exit; }; f < missing; target=/opt/shared/file; rm -f \"$target\"",
        "target=cache/file; { exit; } < missing; target=/opt/shared/file; rm -f \"$target\"",
        "target=cache/file; /bin/exit; target=/opt/shared/file; rm -f \"$target\"",
    ] {
        check(c, Decision::NeedApproval);
        assert!(!inspect(c).root_shell_terminates(), "{c}");
    }
}

#[test]
fn unknown_function_control_flow_does_not_prove_a_later_exit_runs() {
    for c in [
        "target=cache/file; f() { return; exit; }; f; target=/opt/shared/file; rm -f \"$target\"",
        "target=cache/file; f() { eval 'return'; exit; }; f; target=/opt/shared/file; rm -f \"$target\"",
        "target=cache/file; f() { g() { exit; }; return; g; }; f; target=/opt/shared/file; rm -f \"$target\"",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(1, c)).decision,
            Decision::NeedApproval,
            "{c}"
        );
        assert!(!inspect(c).root_shell_terminates(), "{c}");
    }
}
