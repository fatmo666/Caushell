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

#[test]
fn ordinary_collection_runs_the_same_child_guards_as_direct_commands() {
    for (command, expected) in [
        ("nsys profile echo ok", Decision::Allow),
        (
            "nsys profile -t cuda,nvtx -s none -o reports/run echo ok",
            Decision::Allow,
        ),
        (
            "nsys profile -o reports/run rm -f result.txt",
            Decision::Allow,
        ),
        (
            "nsys profile -o reports/run rm -f /opt/example",
            Decision::NeedApproval,
        ),
        (
            "env nsys profile -o reports/run mkdir -p /opt/example",
            Decision::NeedApproval,
        ),
        (
            "nsys profile -o reports/run env rm -f /opt/example",
            Decision::NeedApproval,
        ),
        (
            "nsys profile -o reports/run bash -c 'rm -f /opt/example'",
            Decision::NeedApproval,
        ),
        (
            "nsys profile --duration=10 --kill=none rm -rf /",
            Decision::Deny,
        ),
        (
            "nsys profile -- echo --output=/opt/not-profiler --duration=10",
            Decision::Allow,
        ),
        (
            "nsys profile echo --after-report-ready=callback --help",
            Decision::Allow,
        ),
    ] {
        check(command, expected);
    }
}

#[test]
fn collection_reports_are_bounded_families_with_real_cwd() {
    for (command, directory, expected) in [
        ("nsys profile echo ok", "/tmp/project", Decision::Allow),
        (
            "nsys profile -o reports/run --export=sqlite,jsonlines echo ok",
            "/tmp/project/reports",
            Decision::Allow,
        ),
        (
            "nsys profile -o '/opt/report one' echo ok",
            "/opt",
            Decision::NeedApproval,
        ),
        (
            "nsys profile -o /tmp/project/.. echo ok",
            "/tmp/project",
            Decision::Allow,
        ),
        (
            "nsys profile -o /tmp/project/ echo ok",
            "/tmp/project",
            Decision::Allow,
        ),
        (
            "nsys profile --duration=10 --kill=none -o /opt/report echo ok",
            "/opt",
            Decision::NeedApproval,
        ),
    ] {
        check(command, expected);
        inspect(command, |graph| {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, normalized_command_name, resolution: PathResolution::BoundedPathSet {roots, may_escape: false}, ..} if normalized_command_name.as_deref() == Some("nsys") && roots == &[directory.to_string()])), "{command}");
            assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, normalized_command_name, resolution, ..} if normalized_command_name.as_deref() == Some("nsys") && resolution.concrete_path().is_some())), "{command}");
        });
    }
    check("cd /opt && nsys profile echo ok", Decision::NeedApproval);
}

#[test]
fn modeled_termination_triggers_the_restored_process_rule() {
    for command in [
        "nsys profile --duration=10 echo ok",
        "nsys profile -c nvtx echo ok",
        "nsys profile -c cudaProfilerApi --capture-range-end=repeat-shutdown:3 echo ok",
        "nsys profile -d 10 --capture-range=nvtx --capture-range-end=stop echo ok",
        "nsys profile -d 10 --kill=\"$SIGNAL\" echo ok",
        "nsys profile -c nvtx --capture-range-end=\"$END\" echo ok",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl),
            "{command}"
        );
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "nsys"
                    && s.controls_process
                    && s.process_control_target_kind == Some(ProcessControlTargetKind::Unknown)
                    && s.process_control_action.is_none()),
            "{command}"
        );
    }
}

#[test]
fn explicit_no_kill_keeps_reports_and_child_control_independent() {
    for command in [
        "nsys profile --duration=10 --kill=none echo ok",
        "nsys profile --kill none -c nvtx echo ok",
        "nsys profile -c none echo ok",
        "nsys profile -c nvtx --capture-range-end=repeat:2:async echo ok",
        "nsys profile -c nvtx --capture-range-end=stop echo ok",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::Allow,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl),
            "{command}"
        );
    }
    let command = "nsys profile --duration=10 --kill=none kill 123";
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "kill" && s.controls_process)
    );
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "nsys" && !s.controls_process)
    );
    check(
        "nsys profile --duration=10 --kill=none -o /opt/report echo ok",
        Decision::NeedApproval,
    );
}

#[test]
fn process_configuration_cannot_override_filesystem_or_hard_denies() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::ProcessControl, RulePolicyEntry::new(action));
        let r = ShellQueryCore::with_policy(policy.clone())
            .check(request("nsys profile -d 10 echo ok"));
        assert_eq!(r.decision, expected);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl)
        );
        if action == RuleAction::Observe {
            assert_eq!(
                ShellQueryCore::with_policy(policy.clone())
                    .check(request("nsys profile -d 10 -o /opt/report echo ok"))
                    .decision,
                Decision::NeedApproval
            );
            assert_eq!(
                ShellQueryCore::with_policy(policy)
                    .check(request("nsys profile -d 10 rm -rf /"))
                    .decision,
                Decision::Deny
            );
        }
    }
}

#[test]
fn collection_opaque_modes_and_templates_require_approval() {
    for command in [
        "nsys profile --command-file settings.conf echo ok",
        "nsys profile --after-collection-start 'rm -f /opt/example' echo ok",
        "nsys profile --after-report-ready 'rm -rf /' echo ok",
        "nsys profile --session-new external echo ok",
        "nsys profile --enable custom echo ok",
        "nsys profile --run-as alice echo ok",
        "nsys profile --auto-report-name=true echo ok",
        "nsys profile --inherit-environment=false echo ok",
        "nsys profile --future-option echo ok",
        "nsys profile -d 10",
        "nsys profile -o '%q{OUT}/report' echo ok",
        "nsys profile -o 'reports/%p' echo ok",
        "nsys profile -o '' echo ok",
        "nsys profile -o \"$OUTPUT\" echo ok",
        "nsys profile -o report -o '%q{OUT}/report' echo ok",
        "nsys profile -d 10 --kill=none --kill=sigterm echo ok",
        "nsys profile -d 10 --kill=sigterm --kill=none echo ok",
        "nsys launch echo ok",
        "nsys start --session existing",
        "nsys stop --session existing",
        "nsys shutdown --kill=none --session existing",
        "nsys finalize",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn explicit_child_environment_changes_only_the_child_analysis() {
    for (command, expected) in [
        (
            "nsys profile -e 'TARGET=/opt/example,MODE=lab' bash -c 'rm -f \"$TARGET\"'",
            Decision::NeedApproval,
        ),
        (
            "nsys profile --env-var=TARGET=result.txt bash -c 'rm -f \"$TARGET\"'",
            Decision::Allow,
        ),
        (
            "nsys profile -e 'TARGET=/opt/example,EMPTY=' env bash -c 'rm -f \"$TARGET\"'",
            Decision::NeedApproval,
        ),
        (
            "nsys profile -e \"$ENV\" bash -c 'rm -f \"$TARGET\"'",
            Decision::NeedApproval,
        ),
    ] {
        check(command, expected);
    }
    // Require the decoded value, not a spurious approval caused by treating the
    // entire CSV operand as the value of TARGET.
    inspect(
        "nsys profile -e 'TARGET=/opt/example,MODE=lab' bash -c 'rm -f \"$TARGET\"'",
        |graph| {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Target, resolution, normalized_command_name, ..} if normalized_command_name.as_deref() == Some("rm") && resolution.concrete_path() == Some("/opt/example"))));
        },
    );
}

#[test]
fn unknown_projected_environment_cannot_preserve_a_false_safe_inherited_value() {
    let mut req = request("nsys profile -e \"$ENV\" bash -c 'rm -f \"$TARGET\"'");
    req.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "TARGET",
            ShellValueSnapshot::exact_scalar("result.txt"),
            true,
        ));
    let r = ShellQueryCore::new().check(req);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
}

#[test]
fn decoded_environment_data_is_not_expanded_a_second_time_or_leaked_to_parent() {
    let mut req = request(
        "nsys profile -e 'TARGET=$OUT,MODE=lab' bash -c 'rm -f \"$TARGET\"'; rm -f \"$TARGET\"",
    );
    req.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    req.shell_state_before.variables.extend([
        ShellVariableSnapshot::new(
            "OUT",
            ShellValueSnapshot::exact_scalar("/opt/example"),
            true,
        ),
        ShellVariableSnapshot::new(
            "TARGET",
            ShellValueSnapshot::exact_scalar("parent.txt"),
            true,
        ),
    ]);
    let mut core = ShellQueryCore::new();
    let r = core.check(req);
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    let graph = core.session_graph(&SessionId::new("nsys-test")).unwrap();
    for path in ["/tmp/project/$OUT", "/tmp/project/parent.txt"] {
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Target, resolution, normalized_command_name, ..} if normalized_command_name.as_deref() == Some("rm") && resolution.concrete_path() == Some(path))), "missing {path}");
    }
}

#[test]
fn collection_dispatch_and_stdout_origin_are_preserved_in_graph() {
    let command = "nsys profile -o reports/run cat input.txt";
    let core = check(command, Decision::Allow);
    let graph = core.session_graph(&SessionId::new("nsys-test")).unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Read, resolution, normalized_command_name, ..} if normalized_command_name.as_deref() == Some("cat") && resolution.concrete_path() == Some("/tmp/project/input.txt"))));
    let artifact = graph.nodes().find(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact {artifact: ProvenanceArtifact::MaterializedValue {source_kind, ..}} if source_kind == "dispatch_stdout")).unwrap();
    assert!(
        graph
            .edges()
            .iter()
            .any(|e| e.to == artifact.id && e.kind == EdgeKind::Produces)
    );
    assert!(
        graph
            .edges()
            .iter()
            .any(|e| e.to == artifact.id && e.kind == EdgeKind::Consumes)
    );
}

#[test]
fn pure_profile_help_does_not_exempt_mixed_or_outer_effects() {
    for command in ["nsys profile --help", "nsys profile -h trace"] {
        let core = check(command, Decision::Allow);
        let graph = core.session_graph(&SessionId::new("nsys-test")).unwrap();
        assert!(!graph.nodes().any(|n| matches!(
            &n.kind,
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                ..
            }
        )));
    }
    check(
        "nsys profile --help --after-report-ready 'rm -rf /'",
        Decision::NeedApproval,
    );
    check(
        "nsys profile --help > /opt/help.txt",
        Decision::NeedApproval,
    );
    check("nsys profile --help \"$(rm -rf /)\"", Decision::Deny);
}

#[test]
fn known_shell_output_macro_is_not_reclassified_as_a_literal_path() {
    let mut req = request("nsys profile -o \"$OUT\" echo ok");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    req.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "OUT",
            ShellValueSnapshot::exact_scalar("%q{DEST}/report"),
            true,
        ));
    assert_eq!(
        ShellQueryCore::new().check(req).decision,
        Decision::NeedApproval
    );
}
