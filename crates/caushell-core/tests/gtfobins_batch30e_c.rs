//! Static Graph and decision checks for GTFOBins batch 30e group C.
//! Commands and embedded recipes are analyzed as strings and never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfobins-batch30e-c"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-profile-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str, sequence: u64) -> CheckResponse {
    ShellQueryCore::new().check(request(command, sequence))
}

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let session_graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request(command, 1));
    runner.run(SessionView::new(&session_graph, &summary), &mut context);
    StagedSession::new(
        &session_graph,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}

fn semantics(command: &str, name: &str, form: &str) -> ExecutionSemanticsFact {
    let response = check(command, 1);
    response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|item| item.normalized_command_name == name && item.form_id == form)
        .cloned()
        .unwrap_or_else(|| panic!("{command}: {response:#?}"))
}

fn has_rule(response: &CheckResponse, rule: RuleId) -> bool {
    response
        .decision_trace
        .decision_proposals
        .iter()
        .any(|item| item.rule_id == rule)
        || response
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule)
}

#[test]
fn explicit_argv_wrappers_expose_only_real_child_command_boundaries() {
    for (command, expected_form, expected_decision) in [
        (
            "task execute /bin/sh -c 'id'",
            "execute_command",
            Decision::Allow,
        ),
        (
            "xdotool exec --sync /bin/sh -p",
            "exec_program",
            Decision::NeedApproval,
        ),
    ] {
        let fact = semantics(
            command,
            command.split_whitespace().next().unwrap(),
            expected_form,
        );
        assert!(fact.dispatches_child_command, "{command}: {fact:#?}");
        let response = check(command, 2);
        assert_eq!(
            response.decision, expected_decision,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|item| {
                    item.raw_text
                        == if command.starts_with("task ") {
                            "/bin/sh -c id"
                        } else {
                            "/bin/sh -p"
                        }
                }),
            "{command}: {response:#?}"
        );
    }
    let agetty = semantics(
        "agetty -l /bin/sh -o '-p -a root' tty",
        "agetty",
        "custom_login_program",
    );
    assert!(!agetty.dispatches_child_command);
    assert!(agetty.executes_payload);
}

#[test]
fn tasksh_and_runscript_keep_their_own_opaque_language_boundaries() {
    let tasksh = semantics("tasksh", "tasksh", "interactive_tasksh");
    assert!(tasksh.executes_payload);
    assert!(!tasksh.dispatches_child_command);
    assert_eq!(check("tasksh", 3).decision, Decision::NeedApproval);

    let runscript = semantics(
        "runscript /tmp/project/minicom.script",
        "runscript",
        "run_script_file",
    );
    assert!(runscript.executes_payload);
    assert!(!runscript.dispatches_child_command);
    assert!(graph("runscript /tmp/project/minicom.script").iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Read, resolution, ..}
            if resolution.concrete_path() == Some("/tmp/project/minicom.script"))
    }));
}

#[test]
fn at_retains_a_delayed_stdin_job_and_zip_requires_test_mode_for_template_payload() {
    let at = semantics("at now", "at", "submit_job");
    assert!(at.executes_payload);
    assert!(!at.dispatches_child_command);

    let zip = "zip /opt/shared/archive.zip /etc/hosts -T -TT '/bin/sh #'";
    let fact = semantics(zip, "zip", "test_archive");
    assert!(fact.executes_payload);
    assert!(!fact.dispatches_child_command);
    assert!(has_rule(&check(zip, 4), RuleId::NestedPayloadExpansion));
}

#[test]
fn archive_io_and_unknown_zone_outputs_are_graph_facts() {
    let zip = "zip /opt/shared/archive.zip /opt/shared/input";
    assert!(graph(zip).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Read, resolution, ..}
            if resolution.concrete_path() == Some("/opt/shared/input"))
    }));
    assert!(graph(zip).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..}
            if resolution.concrete_path() == Some("/opt/shared/archive.zip"))
    }));

    let zic = "zic -y /opt/shared/callback /opt/shared/zones";
    let fact = semantics(zic, "zic", "legacy_year_type_callback");
    assert!(fact.executes_payload);
    assert!(!fact.dispatches_child_command);
    assert!(has_rule(&check(zic, 5), RuleId::OutsideWorkspaceMutation));
    assert!(graph(zic).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Read, resolution, ..}
            if resolution.concrete_path() == Some("/opt/shared/zones"))
    }));
}

#[test]
fn gtester_report_path_is_retained_alongside_binary_execution() {
    let command = "gtester /tmp/project/test-binary -o /opt/shared/report.xml";
    let fact = semantics(command, "gtester", "write_test_report");
    assert!(fact.executes_payload);
    assert!(has_rule(
        &check(command, 6),
        RuleId::OutsideWorkspaceMutation
    ));
    assert!(graph(command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..}
            if resolution.concrete_path() == Some("/opt/shared/report.xml"))
    }));
}
