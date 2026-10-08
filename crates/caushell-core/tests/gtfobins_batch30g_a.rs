//! Independent parent graph checks for batch 30g group A. No recipe or native input is run.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 10] = [
    include_str!("../../caushell-profile/profiles/apport-cli.yaml"),
    include_str!("../../caushell-profile/profiles/asterisk.yaml"),
    include_str!("../../caushell-profile/profiles/bconsole.yaml"),
    include_str!("../../caushell-profile/profiles/debugfs.yaml"),
    include_str!("../../caushell-profile/profiles/ginsh.yaml"),
    include_str!("../../caushell-profile/profiles/iftop.yaml"),
    include_str!("../../caushell-profile/profiles/jtag.yaml"),
    include_str!("../../caushell-profile/profiles/minicom.yaml"),
    include_str!("../../caushell-profile/profiles/scanmem.yaml"),
    include_str!("../../caushell-profile/profiles/tdbtool.yaml"),
];
fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|source| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfo30g-a-isolated"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-isolated-acceptance".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry()));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut context);
    StagedSession::new(
        &base,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}
fn semantic(command: &str, name: &str) -> ExecutionSemantics {
    graph(command)
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. }
                if semantics.normalized_command_name == name =>
            {
                Some(semantics.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "missing semantic for {name}: {command}: {:#?}",
                graph(command)
            )
        })
}
fn path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: actual, resolution, .. } if *actual == role && resolution.concrete_path() == Some(expected)))
}

#[test]
fn ten_cli_forms_resolve_in_isolated_registry_and_preserve_observe_allow_policy() {
    for (command, name) in [
        ("apport-cli -f", "apport-cli"),
        ("asterisk -r", "asterisk"),
        ("bconsole", "bconsole"),
        ("debugfs", "debugfs"),
        ("ginsh", "ginsh"),
        ("iftop", "iftop"),
        ("jtag --interactive", "jtag"),
        ("minicom -D /dev/null", "minicom"),
        ("scanmem", "scanmem"),
        ("tdbtool", "tdbtool"),
    ] {
        let fact = semantic(command, name);
        assert!(
            fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::Allow,
            "{command}"
        );
    }
}

#[test]
fn bconsole_explicit_config_is_a_real_read_and_load_boundary() {
    assert!(
        path(
            "bconsole -c /opt/shared/bconsole.conf",
            "/opt/shared/bconsole.conf",
            ResolvedPathRole::Read
        ),
        "{:#?}",
        graph("bconsole -c /opt/shared/bconsole.conf")
    );
    let fact = semantic("bconsole -c /opt/shared/bconsole.conf", "bconsole");
    assert_eq!(fact.form_id, "console_with_config");
}

#[test]
fn debugfs_native_request_and_command_file_are_not_treated_as_plain_data() {
    let request = semantic("debugfs -R '! /bin/sh' /dev/null", "debugfs");
    assert!(request.executes_payload, "{request:#?}");
    let file = "debugfs -f /tmp/project/debugfs.cmd /dev/null";
    assert!(semantic(file, "debugfs").executes_payload);
    assert!(
        path(file, "/tmp/project/debugfs.cmd", ResolvedPathRole::Read),
        "{:#?}",
        graph(file)
    );
    assert!(
        path(file, "/dev/null", ResolvedPathRole::Target),
        "{:#?}",
        graph(file)
    );
}

#[test]
fn minicom_run_script_file_read_stays_distinct_from_shell_setup_writer() {
    let command = "echo '! exec /bin/sh </dev/tty 1>/dev/tty 2>/dev/tty' > /tmp/project/minicom.run && minicom -D /dev/null -S /tmp/project/minicom.run";
    assert!(
        path(command, "/tmp/project/minicom.run", ResolvedPathRole::Write),
        "{:#?}",
        graph(command)
    );
    assert!(
        path(command, "/tmp/project/minicom.run", ResolvedPathRole::Read),
        "{:#?}",
        graph(command)
    );
    let fact = semantic(command, "minicom");
    assert!(fact.executes_payload, "{fact:#?}");
}

#[test]
fn ordinary_controls_do_not_get_escape_surface_or_invent_executed_native_commands() {
    for (command, name) in [("asterisk -V", "asterisk"), ("jtag --version", "jtag")] {
        let fact = semantic(command, name);
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
    }
    for command in [
        "apport-cli -f",
        "debugfs",
        "ginsh",
        "iftop",
        "scanmem",
        "tdbtool",
    ] {
        let nodes = graph(command);
        let names: Vec<_> = nodes
            .iter()
            .filter_map(|node| match &node.kind {
                NodeKind::ExecutionSemantics { semantics, .. } => {
                    Some(semantics.normalized_command_name.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| matches!(name.as_str(), "!/bin/sh" | "@exec" | "shell" | "reset")),
            "{command}: {names:?}"
        );
    }
}
