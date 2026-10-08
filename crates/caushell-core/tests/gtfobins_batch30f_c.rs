//! Static Graph and policy checks for GTFOBins batch 30f group C. Recipes are data only.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfobins-batch30f-c"),
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
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
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
            .any(|item| item.rule_id == rule)
}

#[test]
fn foreign_language_entrypoints_are_payloads_without_fabricated_command_dispatch() {
    for (command, name, form) in [
        ("dc -e '!/bin/sh'", "dc", "evaluate_dc_program"),
        (
            "gnuplot -e 'system(\"/bin/sh 1>&0\")'",
            "gnuplot",
            "evaluate_commands",
        ),
        (
            "elvish -c 'print (slurp </tmp/project/input)'",
            "elvish",
            "command_string",
        ),
        (
            "dosbox -c 'mount c /' -c 'type c:\\input'",
            "dosbox",
            "execute_dos_commands",
        ),
        (
            "expect -c 'spawn /bin/sh;interact'",
            "expect",
            "command_string",
        ),
        (
            "csh -c 'echo DATA >/tmp/project/out'",
            "csh",
            "command_string",
        ),
        (
            "tcsh -c 'echo DATA >/tmp/project/out'",
            "tcsh",
            "command_string",
        ),
    ] {
        let fact = semantics(command, name, form);
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(!fact.dispatches_child_command, "{command}: {fact:#?}");
        assert_eq!(
            check(command, 2).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
}

#[test]
fn explicit_paths_are_preserved_and_foreign_paths_are_not_invented() {
    let csv = graph("csvtool trim t /tmp/project/input.csv -o /tmp/project/output.csv");
    assert!(csv.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/input.csv"))));
    assert!(csv.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/output.csv"))));

    let expect = graph("expect /tmp/project/script.exp");
    assert!(expect.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/script.exp"))));

    let dosbox = graph("dosbox -c 'mount c /' -c 'type c:\\input'");
    assert!(
        !dosbox
            .iter()
            .any(|node| matches!(&node.kind, NodeKind::PathFact { .. }))
    );
    let elvish = graph("elvish -c 'print (slurp </tmp/project/input)'");
    assert!(
        !elvish
            .iter()
            .any(|node| matches!(&node.kind, NodeKind::PathFact { .. }))
    );
}

#[test]
fn configured_facter_directory_is_read_and_ruby_entry_remains_dynamic() {
    let command = "facter --custom-dir=/tmp/project/facts x";
    let response = check(command, 3);
    let fact = response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|item| {
            item.normalized_command_name == "facter" && item.form_id == "custom_facts_directory"
        })
        .unwrap();
    assert!(fact.executes_payload);
    assert!(!fact.dispatches_child_command);
    assert!(graph(command).iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/facts"))));
    assert_eq!(response.decision, Decision::NeedApproval);
}

#[test]
fn benign_file_read_does_not_trigger_code_execution_finding_and_interactive_shell_does() {
    let csv_read = check("csvtool trim t /tmp/project/input.csv", 4);
    assert!(!has_rule(&csv_read, RuleId::NestedPayloadExpansion));
    let fish = check("fish", 5);
    assert_eq!(fish.decision, Decision::NeedApproval);
    assert!(semantics("fish", "fish", "interactive_shell").executes_payload);
}
