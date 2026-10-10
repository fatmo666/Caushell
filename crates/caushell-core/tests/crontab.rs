//! Guard/Graph analysis only; no cron table is installed, edited or deleted.
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
        session_id: SessionId::new("crontab-effects"),
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

fn inspect(command: &str) -> (ShellQueryCore, CheckResponse) {
    let mut core = ShellQueryCore::new();
    let response = core.check(request(command));
    (core, response)
}

fn staged_graph(command: &str) -> Vec<GraphNode> {
    // NeedApproval is not executed history. Inspect the same semantic stages
    // before decision/commit, not the (correctly unmodified) session graph.
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

#[test]
fn scheduler_writes_and_deletes_use_existing_mutation_guard() {
    for command in [
        "crontab ./jobs",
        "crontab /opt/shared/jobs",
        "crontab -",
        "printf '* * * * * echo okay\\n' | crontab -",
        "printf '* * * * * echo okay\\n' | crontab",
        "crontab -e",
        "crontab -r",
        "crontab -ir",
        "crontab -u alice ./jobs",
        "sudo crontab -e -u alice",
        "sh -c 'crontab ./jobs'",
        "crontab -u -l ./jobs",
        "crontab -- -l",
        "crontab -l | crontab -",
        "crontab \"$mode\"",
    ] {
        let (_, response) = inspect(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:#?}"
        );
        let graph = staged_graph(command);
        assert!(
            graph.iter().any(|n| matches!(
                &n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                    resolution: PathResolution::UnsupportedDynamicText { .. },
                    ..
                }
            )),
            "{command}"
        );
    }
}

#[test]
fn pure_queries_information_and_syntax_tests_remain_allowed() {
    for command in [
        "crontab -l",
        "crontab -u alice -l",
        "crontab -lu alice",
        "crontab -u -r -l",
        "crontab -h",
        "crontab -V",
        "crontab -T ./jobs",
        "crontab -T -",
        "printf okay > ./jobs",
    ] {
        let (_, response) = inspect(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:#?}"
        );
    }
    let (_, response) = inspect("crontab -l > /opt/shared/jobs");
    assert_eq!(response.decision, Decision::NeedApproval);
}

#[test]
fn stdin_installation_has_no_fictitious_dash_file_or_immediate_bash_child() {
    let command = "printf '* * * * * touch /opt/shared/file\\n' | crontab -";
    let (_, response) = inspect(command);
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "crontab"
                && s.executes_config_defined_task
                && !s.executes_payload)
    );
    assert!(
        !response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "touch")
    );
    let graph = staged_graph(command);
    assert!(
        !graph
            .iter()
            .any(|n| matches!(&n.kind, NodeKind::PathFact { resolution, .. }
        if resolution.concrete_path() == Some("/tmp/project/-")))
    );
}

#[test]
fn unrecognized_operations_keep_the_existing_resolution_policy() {
    for command in [
        "crontab -n ./jobs",
        "crontab -lr",
        "crontab -l ./jobs",
        "crontab -u",
        "crontab --unknown ./jobs",
    ] {
        let (_, response) = inspect(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {response:#?}"
        );
    }
}
