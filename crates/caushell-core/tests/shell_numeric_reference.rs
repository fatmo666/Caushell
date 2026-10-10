//! Static decisions and staged path facts only; samples are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("numeric-reference"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn staged_graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}

fn assert_target(command: &str, target: &str, decision: Decision) {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
    let graph = staged_graph(command);
    let targets: Vec<_> = graph
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                resolution,
                ..
            } => Some(resolution),
            _ => None,
        })
        .collect();
    assert!(!targets.is_empty(), "{command}: no mutation target");
    assert!(
        targets.iter().all(|r| r.concrete_path() == Some(target)),
        "{command}: {targets:#?}"
    );
    if decision == Decision::NeedApproval {
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{response:#?}"
        );
    }
}

#[test]
fn unbraced_digits_append_to_first_parameter_not_tenth() {
    for (command, target) in [
        (
            r#"sh -c 'rm "$10"' _ /opt/shared/file"#,
            "/opt/shared/file0",
        ),
        (
            r#"bash -c 'rm "$11"' _ /opt/shared/file"#,
            "/opt/shared/file1",
        ),
        (
            r#"sh -c 'rm "$99"' _ a1 a2 a3 a4 a5 a6 a7 a8 /opt/shared/file"#,
            "/opt/shared/file9",
        ),
        (
            r#"sh -c 'touch $10' _ /opt/shared/file"#,
            "/opt/shared/file0",
        ),
        (
            r#"sh -c 'touch "${1}0"' _ /opt/shared/file"#,
            "/opt/shared/file0",
        ),
        (
            r#"sh -c 'touch "$10"' _ /opt/shared/file a2 a3 a4 a5 a6 a7 a8 a9 ./cache/file"#,
            "/opt/shared/file0",
        ),
    ] {
        assert_target(command, target, Decision::NeedApproval);
    }
    assert_target(
        r#"sh -c 'touch "$10"' _ ./cache/file a2 a3 a4 a5 a6 a7 a8 a9 /opt/shared/file"#,
        "/tmp/project/cache/file0",
        Decision::Allow,
    );
    assert_target(
        r#"sh -c 'touch "${10}"' _ /opt/shared/file a2 a3 a4 a5 a6 a7 a8 a9 ./cache/file"#,
        "/tmp/project/cache/file",
        Decision::Allow,
    );
    assert_target(
        r#"sh -c 'touch "${10}"' _ ./cache/file a2 a3 a4 a5 a6 a7 a8 a9 /opt/shared/file"#,
        "/opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn current_positional_frame_is_used_after_set_shift_and_in_functions() {
    for command in [
        r#"sh -c 'set -- /opt/shared/file; touch "$10"' _ ./cache/file"#,
        r#"sh -c 'shift; touch "$10"' _ ./cache/file /opt/shared/file"#,
        r#"f() { touch "$10"; }; f /opt/shared/file"#,
    ] {
        assert_target(command, "/opt/shared/file0", Decision::NeedApproval);
    }
    for command in [
        r#"sh -c 'shift; touch "$10"' _ /opt/shared/file ./cache/file"#,
        r#"sh -c 'set -- ./cache/file; touch "$10"' _ /opt/shared/file"#,
        r#"f() { touch "$10"; }; f ./cache/file"#,
    ] {
        assert_target(command, "/tmp/project/cache/file0", Decision::Allow);
    }
}

#[test]
fn argv0_is_separate_from_the_mutable_positional_list() {
    for command in [
        r#"sh -c 'rm "$00"' /opt/shared/file"#,
        r#"sh -c 'set -- ./cache/file; rm "$00"' /opt/shared/file"#,
        r#"sh -c 'shift; rm "$00"' /opt/shared/file ./cache/file"#,
    ] {
        assert_target(command, "/opt/shared/file0", Decision::NeedApproval);
    }
    assert_target(
        r#"sh -c 'rm "${00}"' /opt/shared/file"#,
        "/opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn literals_missing_parameters_and_read_only_controls_do_not_gain_approval() {
    for command in [
        r#"sh -c 'touch "$10"' _ ./cache/file"#,
        r#"sh -c 'touch "$10"' _"#,
        r#"sh -c 'rm "${10}"' _ /opt/shared/file"#,
        r#"sh -c 'printf "%s\n" "$10" "${10}"' _ /opt/shared/file"#,
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
    assert_target(
        r#"sh -c "touch '\$10'" _ /opt/shared/file"#,
        "/tmp/project/$10",
        Decision::Allow,
    );
    // Escaped references must stay literal, not be rebound to an external
    // numeric parameter. This checks the decision only: the older lexical path
    // resolver retains the backslash for this spelling, independently of
    // numeric materialization (a separately recorded normalization issue).
    let escaped = ShellQueryCore::new().check(request(r#"sh -c 'touch \$10' _ /opt/shared/file"#));
    assert_eq!(escaped.decision, Decision::Allow, "{escaped:#?}");
    assert_target(
        r#"sh -c 'touch "$10"' _ './cache/$literal*'"#,
        "/tmp/project/cache/$literal*0",
        Decision::Allow,
    );
}

#[test]
fn unknown_width_or_unsafe_splitting_never_manufactures_a_local_scalar() {
    for command in [
        r#"sh -c 'touch "$10"' _ "$unknown""#,
        r#"sh -c 'touch "$10"' _ $args"#,
        r#"producer | xargs -0 sh -c 'touch "$10"' _"#,
        r#"sh -c 'touch $10' _ './cache/a /opt/shared/file'"#,
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
}
