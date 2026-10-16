//! Static argv/Graph checks: sample shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::SessionGraph;
use caushell_passes::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("runtime-text-templates"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str, expected: Decision) -> CheckResponse {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, expected, "{command}: {:?}", result.reasons);
    result
}

fn domains(command: &str) -> Vec<RuntimeArgumentDomain> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    ctx.execution_unit_resolve_records()
        .iter()
        .flat_map(|r| &r.parsed_scope.commands[r.command_ref.command_index].tokens)
        .filter_map(|token| token.runtime_argument_domain.clone())
        .collect()
}

#[test]
fn unknown_input_inside_a_native_format_argument_is_not_an_option() {
    for command in [
        "ping google.com | xargs -L 1 -I '{}' date '+%c: {}'",
        "ping google.com | xargs -L 1 -I '{}' date '+%+: {}'",
        "cat input | xargs -I @ date '+%c: @'",
        "cat input | xargs -I {} env date '+%c: {}'",
        "cat input | xargs -I {} date -d '{}' '+%c'",
        "cat input | xargs -r -I {} date '+%c: {}'",
        "printf '%s\\n' '--set=tomorrow' | xargs -r -I {} date '+%c: {}'",
    ] {
        check(command, Decision::Allow);
    }
    assert!(domains("cat input | xargs -I {} date '+%c: {}'").contains(
        &RuntimeArgumentDomain::TextTemplate {
            prefix: "+%c: ".into(),
            suffix: "".into(),
        }
    ));
}

#[test]
fn unknown_native_content_cannot_gain_path_containment_from_a_prefix() {
    for command in [
        "cat input | xargs -I {} touch 'cache/{}'",
        "cat input | xargs -I {} touch '/tmp/{}'",
        "cat input | xargs -I {} touch '/opt/{}'",
        "cat input | xargs -I {} touch -- '{}'",
    ] {
        let result = check(command, Decision::NeedApproval);
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:#?}"
        );
    }
}

#[test]
fn content_and_control_unknowns_are_not_waived_by_template_metadata() {
    for command in [
        "cat input | xargs -I {} date '{}'",
        "cat input | xargs -I {} date '{} END'",
        "cat input | xargs -I {} date '--{}'",
        "cat input | xargs -I {} date --set='{}'",
        "cat input | xargs -I {} date '202{}'",
        "cat input | xargs -r -I {} date '202{}'",
        "cat input | xargs -I {} sed 's/x/{}/' file",
        "cat input | xargs -I {} bash -c 'echo {}'",
        "cat input | xargs -I {} date \"$PREFIX{}\"",
        "cat input | xargs -r -I {} date \"$PREFIX{}\"",
        "cat input | xargs -I {} date ~unknown/{}",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn nonoption_runtime_dates_retain_their_actual_state_effect() {
    let result = check(
        "cat input | xargs -r -I {} date '202{}'",
        Decision::NeedApproval,
    );
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::StateMutation),
        "{:?}",
        result.reasons
    );
    assert!(result.decision_trace.execution_semantics.iter().any(|s| s.normalized_command_name == "date" && s.form_id == "set_system_clock_operand"));
}
