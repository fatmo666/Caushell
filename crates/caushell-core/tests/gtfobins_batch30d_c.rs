//! Static Graph and decision checks for GTFOBins batch 30d group C.
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
        session_id: SessionId::new("gtfobins-batch30d-c"),
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

fn has_path(command: &str, path: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {resolution, role: actual, ..}
            if *actual == role && resolution.concrete_path() == Some(path))
    })
}

fn semantics(command: &str, name: &str, form: &str) -> ExecutionSemanticsFact {
    let result = check(command, 1);
    result
        .decision_trace
        .execution_semantics
        .iter()
        .find(|item| item.normalized_command_name == name && item.form_id == form)
        .cloned()
        .unwrap_or_else(|| panic!("{command}: {result:#?}"))
}

fn has_rule(result: &CheckResponse, rule: RuleId) -> bool {
    if result
        .decision_trace
        .decision_proposals
        .iter()
        .any(|item| item.rule_id == rule)
    {
        return true;
    }
    result
        .decision_trace
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule)
}

#[test]
fn arch_nspawn_projects_the_rootfs_config_as_an_unknown_payload() {
    let command = "arch-nspawn /tmp/rootfs";
    let result = check(command, 1);
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        has_rule(&result, RuleId::NestedPayloadExpansion),
        "{result:#?}"
    );
    assert!(has_path(
        command,
        "/tmp/rootfs/etc/makepkg.conf",
        ResolvedPathRole::Read
    ));
    assert!(semantics(command, "arch-nspawn", "run_rootfs").executes_payload);
}

#[test]
fn genie_and_pidstat_expose_real_child_invocations() {
    let genie = "genie -c /bin/sh";
    let fact = semantics(genie, "genie", "run_command");
    assert!(fact.dispatches_child_command);
    let response = check(genie, 2);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text == "/bin/sh")
    );

    let pidstat = "pidstat -e /bin/sh -p";
    let fact = semantics(pidstat, "pidstat", "execute_program");
    assert!(fact.dispatches_child_command);
    let response = check(pidstat, 3);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text == "/bin/sh -p")
    );
}

#[test]
fn rustup_keeps_requested_child_but_does_not_claim_toolchain_binary_path() {
    let command = "rustup run x rustc";
    let fact = semantics(command, "rustup", "run_toolchain_command");
    assert!(fact.dispatches_child_command);
    let response = check(command, 4);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text == "rustc")
    );
    assert!(!graph(command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {resolution, ..}
            if resolution.concrete_path().is_some_and(|path| path.contains(".rustup/toolchains")))
    }));
}

#[test]
fn fzf_bind_and_listener_retain_the_opaque_action_boundary() {
    let bind = "fzf --bind 'enter:execute(/bin/sh)'";
    let fact = semantics(bind, "fzf", "opaque_bind_actions");
    assert!(fact.executes_payload);
    let response = check(bind, 5);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        has_rule(&response, RuleId::NestedPayloadExpansion),
        "{response:#?}"
    );
    assert!(
        !response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text.contains("/bin/sh"))
    );

    let listen = "fzf --listen=12345";
    let fact = semantics(listen, "fzf", "listen_tcp");
    assert!(fact.executes_payload);
    assert_eq!(check(listen, 6).decision, Decision::NeedApproval);
}

#[test]
fn scrot_dispatches_only_unformatted_shell_text_and_records_unknown_image_writes() {
    let static_command = "scrot -e /bin/sh";
    let fact = semantics(static_command, "scrot", "execute_shell_template");
    assert!(fact.dispatches_child_command);
    let response = check(static_command, 7);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text == "/bin/sh")
    );
    assert!(graph(static_command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..}
            if resolution.concrete_path().is_none())
    }));

    let formatted = "scrot -e 'echo $f'";
    let fact = semantics(formatted, "scrot", "execute_formatted_shell_template");
    assert!(fact.executes_payload);
    assert!(!fact.dispatches_child_command);

    let explicit_output = "scrot /opt/shared/capture.png";
    let response = check(explicit_output, 12);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(has_path(
        explicit_output,
        "/opt/shared/capture.png",
        ResolvedPathRole::Write
    ));
}

#[test]
fn sshuttle_projects_remote_target_and_nested_ssh_argv() {
    let command = "sshuttle -r x --ssh-cmd 'sh -c \"echo SAFE\"' localhost";
    let fact = semantics(command, "sshuttle", "proxy_with_ssh_command");
    assert!(fact.dispatches_child_command);
    let response = check(command, 8);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.command_name.as_deref() == Some("sh")
                && item.raw_text.contains("echo SAFE")),
        "{response:#?}"
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|item| item.normalized_command_name == "echo"),
        "{response:#?}"
    );
}

#[test]
fn xdg_argument_and_cowfile_keep_non_bash_payloads_and_path_facts() {
    let xdg = "xdg-user-dir '}; /bin/sh #'";
    let fact = semantics(xdg, "xdg-user-dir", "eval_argument");
    assert!(fact.executes_payload);
    assert!(check(xdg, 9).decision == Decision::NeedApproval);
    assert!(
        !check(xdg, 10)
            .decision_trace
            .derived_invocations
            .iter()
            .any(|item| item.raw_text.contains("/bin/sh"))
    );

    let cow = "cowthink -f /tmp/custom.cow hello";
    let fact = semantics(cow, "cowthink", "execute_cowfile");
    assert!(fact.executes_payload);
    assert!(has_path(cow, "/tmp/custom.cow", ResolvedPathRole::Read));
    assert_eq!(check(cow, 11).decision, Decision::NeedApproval);
}
