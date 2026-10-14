//! Static guard and trace assertions only; watch and its programs never run.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("watch-profile"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, decision: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
    assert!(
        !r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
        EvidenceKind::InteractiveEscapeSurface(s) if s.normalized_command_name == "watch")),
        "{r:#?}"
    );
    r
}
fn semantic(r: &CheckResponse, name: &str) -> bool {
    r.decision_trace
        .execution_semantics
        .iter()
        .any(|s| s.normalized_command_name == name)
}

#[test]
fn periodic_queries_are_semantic_and_not_interactive_escape_surfaces() {
    for command in [
        "watch -n 1 date",
        "watch -n10 cat /tmp/iostat.running",
        "watch -tdn0.5 ps -mo pid,tid",
        "watch --interval=10 ls -l",
        "watch 'ls -l | grep foo'",
        "watch --color 'tput setaf 1; echo foo'",
        "watch -n1 'ps x -o \"%p %r %c\" | grep test'",
        "watch -x ls -l",
        "watch --help",
        "watch -v",
        "watch ''",
    ] {
        check(command, Decision::Allow);
    }
    let r = check("watch 'ls -l | grep foo'", Decision::Allow);
    assert!(semantic(&r, "sh") && semantic(&r, "ls") && semantic(&r, "grep"));
}

#[test]
fn nested_deletions_and_external_writes_reach_existing_guards() {
    for command in [
        "watch 'rm /opt/shared/file'",
        "watch rm /opt/shared/file",
        "watch -n1 --exec rm /opt/shared/file",
        "watch 'printf SAFE; rm ./file'",
        "watch printf SAFE '; rm /opt/shared/file'",
        "watch -dx printf SAFE '; rm /opt/shared/file'",
        "env watch 'rm /opt/shared/file'",
        "timeout 2s watch 'rm /opt/shared/file'",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(semantic(&r, "rm"), "{command}: {r:#?}");
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::FileDeletion),
            "{command}: {r:#?}"
        );
    }
    for command in [
        "watch 'printf DATA > /opt/shared/out'",
        "watch 'cd /opt/shared; touch out'",
        "watch -x sh -c 'touch /opt/shared/out'",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {r:#?}"
        );
    }
    check("watch 'printf DATA > ./out'", Decision::Allow);
    check("watch 'printf DATA > /tmp/watch-out'", Decision::Allow);
    check("watch 'rm -rf /'", Decision::Deny);
}

#[test]
fn exec_data_and_child_flags_do_not_become_watch_options_or_shell_programs() {
    for command in [
        "watch -x printf '%s' '; rm /opt/shared/file'",
        "watch --exec -- printf '%s' 'a b' '| rm /opt/shared/file'",
        "watch -x printf -- '--help' '--exec'",
        "watch printf '%s' '--exec'",
        "watch -h rm /opt/shared/file",
        "watch --version rm /opt/shared/file",
    ] {
        let r = check(command, Decision::Allow);
        assert!(!semantic(&r, "rm"), "{command}: {r:#?}");
    }
    check("watch touch ./--exec", Decision::Allow);
    let r = check(
        "watch touch /opt/shared/file --help",
        Decision::NeedApproval,
    );
    assert!(semantic(&r, "touch"));
}

#[test]
fn unresolved_programs_options_and_real_child_interaction_still_ask() {
    for command in [
        "watch",
        "watch --future date",
        "watch -n",
        "watch -n1",
        "watch \"$PROGRAM\"",
        "watch printf \"$ARGS\"",
        "watch $(cat commands)",
        "watch 'sh'",
        "watch -x sh",
        "watch 'less README.md'",
        "watch -x node -e '1+1'",
        "watch 'python -c \"print(1)\"'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn shell_reinterpretation_and_child_environment_use_existing_scope_rules() {
    let r = check(
        "PROGRAM='rm /opt/shared/file'; watch \"$PROGRAM\"",
        Decision::NeedApproval,
    );
    assert!(semantic(&r, "rm"));
    check(
        "watch 'mkdir -p ./cache; touch ./cache/file'",
        Decision::Allow,
    );
    check(
        "target=./safe; watch 'touch \"$target\"'",
        Decision::NeedApproval,
    );
    check(
        "export target=./safe; watch 'touch \"$target\"'",
        Decision::Allow,
    );
    check(
        "export target=/opt/shared/file; watch 'touch \"$target\"'",
        Decision::NeedApproval,
    );
    check(
        "export target=/opt/shared/file; watch \"touch '\\$target'\"",
        Decision::Allow,
    );
}

#[test]
fn child_stdin_cannot_be_hidden_by_the_periodic_display_wrapper() {
    for command in [
        "printf 'rm /opt/shared/file' | watch -x sh",
        "printf 'rm /opt/shared/file' | watch sh",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(semantic(&r, "sh"));
    }
}

#[test]
fn nested_path_facts_are_present_in_the_staged_graph() {
    use caushell_graph::{NodeKind, SessionGraph, SessionRead};
    use caushell_passes::{
        ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
    for (command, expected) in [
        ("watch 'touch /opt/shared/out'", "/opt/shared/out"),
        ("watch 'cd /opt/shared; touch out'", "/opt/shared/out"),
        ("watch -x sh -c 'touch ./out'", "/workspace/project/out"),
    ] {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request(command));
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
        assert!(staged.graph().nodes().any(|n| matches!(&n.kind,
            NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..} if resolution.concrete_path() == Some(expected))), "{command}");
    }
}

#[test]
fn unknown_child_commands_reach_the_configured_no_profile_policy() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.no_profile.action = RuleAction::NeedApproval;
    for command in ["watch -n3 -d ./my_script.sh", "watch bash -c your_script"] {
        let r = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::NoProfile),
            "{command}: {r:#?}"
        );
    }
}
