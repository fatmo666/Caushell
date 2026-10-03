//! Docker-only static checks. None of these command strings is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{EdgeKind, GraphRead, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ExtractPipelineStreamProvenancePass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("nsys-test"),
        sequence_no: CommandSequenceNo::new(1),
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

fn check(command: &str, expected: Decision) -> ShellQueryCore {
    let mut core = ShellQueryCore::new();
    let response = core.check(request(command));
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.decision_trace
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}: {:?}",
        response.decision_trace
    );
    core
}

fn inspect(command: &str, verify: impl FnOnce(&dyn GraphRead)) {
    // Approval proposals intentionally do not commit execution facts to session
    // history. Inspect the staged analysis graph, not a falsely executed history.
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_session_transform_pass(ExtractPipelineStreamProvenancePass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    verify(staged.graph());
}

#[test]
fn workspace_and_external_child_mutations_use_existing_guards() {
    for (command, decision) in [
        (
            "nsys stats -o '@rm -f result.txt' report.sqlite",
            Decision::Allow,
        ),
        (
            "nsys stats -o '@rm -f /opt/example' report.sqlite",
            Decision::NeedApproval,
        ),
        (
            "nsys analyze -o '@mkdir -p /opt/example' report.sqlite",
            Decision::NeedApproval,
        ),
        (
            "nsys stats -o '@tee /opt/example' report.sqlite",
            Decision::NeedApproval,
        ),
        (
            "nsys stats -o '@tee result.txt' report.sqlite",
            Decision::Allow,
        ),
        ("nsys stats -o '@cat' report.sqlite", Decision::Allow),
    ] {
        check(command, decision);
    }
}

#[test]
fn graph_keeps_parent_preparation_child_delete_and_stdin_provenance() {
    let command = "nsys stats -o '@rm -f /opt/example' report.nsys-rep";
    check(command, Decision::NeedApproval);
    inspect(command, |graph| {
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/report.nsys-rep"))));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, normalized_command_name, .. } if normalized_command_name.as_deref() == Some("nsys") && resolution.concrete_path() == Some("/tmp/project/report.sqlite"))));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { resolution, normalized_command_name, .. } if normalized_command_name.as_deref() == Some("rm") && resolution.concrete_path() == Some("/opt/example"))));
        let streams: Vec<_> = graph.nodes().filter(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::MaterializedValue { source_kind, state: ProvenanceMaterializedValueState::UnsupportedDynamicText { .. }, .. } } if source_kind == "dispatch_output")).collect();
        assert_eq!(streams.len(), 1);
        assert!(
            graph
                .edges()
                .any(|e| e.to == streams[0].id && e.kind == EdgeKind::Produces)
        );
        assert!(
            graph
                .edges()
                .any(|e| e.to == streams[0].id && e.kind == EdgeKind::Consumes)
        );
    });
}

#[test]
fn report_files_are_bounded_sets_not_fabricated_basename_writes() {
    for (command, root, decision) in [
        (
            "nsys stats -o /tmp/project/.. report.sqlite",
            "/tmp/project",
            Decision::Allow,
        ),
        (
            "nsys stats -o results/out report.sqlite",
            "/tmp/project/results",
            Decision::Allow,
        ),
        (
            "nsys stats -o /tmp/project/ report.sqlite",
            "/tmp/project",
            Decision::Allow,
        ),
        (
            "nsys stats -o /opt/out report.sqlite",
            "/opt",
            Decision::NeedApproval,
        ),
        (
            "nsys stats -o . /opt/report.sqlite",
            "/opt",
            Decision::NeedApproval,
        ),
        (
            "nsys stats -o . report.sqlite",
            "/tmp/project",
            Decision::Allow,
        ),
        (
            "nsys stats --sqlite=/opt/a.sqlite -o . report.nsys-rep",
            "/opt",
            Decision::NeedApproval,
        ),
    ] {
        check(command, decision);
        inspect(command, |graph| {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution: PathResolution::BoundedPathSet { roots, may_escape: false }, .. } if roots == &[root.to_string()])), "{command}");
            if command.contains("results/out") {
                assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/results/out"))));
            }
        });
    }
}

#[test]
fn console_output_still_checks_sqlite_preparation_and_explicit_paths() {
    for (command, decision) in [
        (
            "nsys stats -o - /opt/report.nsys-rep",
            Decision::NeedApproval,
        ),
        ("nsys stats -o - /opt/report.sqlite", Decision::Allow),
        (
            "nsys stats --sqlite result.sqlite -o - /opt/report.nsys-rep",
            Decision::Allow,
        ),
        (
            "nsys stats --sqlite /opt/result.sqlite -o - report.nsys-rep",
            Decision::NeedApproval,
        ),
        ("nsys analyze -o - report.nsys-rep", Decision::Allow),
    ] {
        check(command, decision);
    }
}

#[test]
fn unknown_and_empty_outputs_cannot_silently_drop_effects() {
    for command in [
        "nsys stats -o \"$OUTPUT\" report.sqlite",
        "nsys stats -o \"@rm $ARGS\" report.sqlite",
        "nsys stats -o '@' report.sqlite",
        "nsys stats report.sqlite -o",
        "nsys stats -o '@bash' report.sqlite",
        "env nsys stats -o '@bash' report.sqlite",
        "nsys stats -o '@env bash' report.sqlite",
        "nsys stats -o 'result,,@cat' report.sqlite",
        "env nsys stats -o '@' report.sqlite",
        "env nsys stats -o \"$OUTPUT\" report.sqlite",
        "nsys stats -o '' report.sqlite",
        "nsys stats --sqlite=\"$OUTPUT\" -o . report.nsys-rep",
        "nsys stats -o - \"$INPUT\"",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn literal_shell_symbols_and_inner_quotes_remain_argv_data() {
    for command in [
        "nsys stats -o '@echo $TOKEN ; rm -f /opt/example >out' report.sqlite",
        "nsys stats -o '@echo $(rm -f /opt/example)' report.sqlite",
        "nsys stats -o '@echo * ~' report.sqlite",
        "nsys stats -o '@rm -f \"/opt/example\"' report.sqlite",
        "nsys stats -o '@sh -c true' report.sqlite",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn multiple_children_and_nested_wrappers_are_all_checked() {
    for command in [
        "nsys stats -o '@echo ok,@rm -f /opt/example' report.sqlite",
        "nsys stats -o '@echo ok' -o '@rm -f /opt/example' report.sqlite",
        "env nsys stats -o '@rm -f /opt/example' report.sqlite",
        "nsys stats -o '@env rm -f /opt/example' report.sqlite",
        "nsys stats -o '@nsys stats -o @rm /opt/a.sqlite' report.sqlite",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn opaque_report_code_and_arguments_are_not_assumed_read_only() {
    for command in [
        "nsys stats --report custom_report report.sqlite",
        "nsys stats --report all report.sqlite",
        "nsys stats --report cuda_api_sum:unexpected report.sqlite",
        "nsys stats --format custom_formatter report.sqlite",
        "nsys stats --format csv:unexpected report.sqlite",
        "nsys stats --report-dir scripts report.sqlite",
        "env nsys stats --report custom_report report.sqlite",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "nsys stats --report cuda_api_sum --format csv report.sqlite",
        "nsys stats --report cuda_api_sum,cuda_gpu_kern_sum --format csv,table report.sqlite",
        "nsys analyze --rule cuda_memcpy_async --format csv report.sqlite",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn help_does_not_execute_output_commands_or_generate_reports() {
    for command in [
        "nsys --help",
        "nsys --version",
        "nsys stats --help",
        "nsys stats --help -o '@rm -f /opt/example' --sqlite /opt/a.sqlite",
        "nsys stats --help --report custom --report-dir scripts --format unknown",
    ] {
        let core = check(command, Decision::Allow);
        let graph = core.session_graph(&SessionId::new("nsys-test")).unwrap();
        assert!(
            !graph.nodes().any(|n| matches!(
                &n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    ..
                }
            )),
            "{command}"
        );
    }
}

#[test]
fn shell_variable_materialization_happens_once_before_tool_grammar() {
    let mut req = request("nsys stats -o \"$OUTPUT\" report.sqlite");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    req.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "OUTPUT",
            ShellValueSnapshot::exact_scalar("@rm -f /opt/example"),
            true,
        ));
    assert_eq!(
        ShellQueryCore::new().check(req).decision,
        Decision::NeedApproval
    );
}

#[test]
fn sqlite_read_sources_and_wrapper_stdin_reach_graph_consumers() {
    for command in [
        "nsys stats --sqlite existing.sqlite report.nsys-rep",
        "nsys stats report.nsys-rep",
    ] {
        inspect(command, |graph| {
            let expected = if command.contains("existing") {
                "/tmp/project/existing.sqlite"
            } else {
                "/tmp/project/report.sqlite"
            };
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some(expected))));
        });
    }
    inspect("nsys stats -o '@env cat' report.sqlite", |graph| {
        let stream = graph.nodes().find(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::MaterializedValue { source_kind, .. } } if source_kind == "dispatch_output")).unwrap();
        assert_eq!(
            graph
                .edges()
                .filter(|e| e.to == stream.id && e.kind == EdgeKind::Consumes)
                .count(),
            2
        );
    });
}
