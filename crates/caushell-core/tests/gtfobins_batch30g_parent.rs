//! Independent parent acceptance. Every shell string is analyzed, never run.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfo30g-independent"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-parent-acceptance".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
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
fn path(command: &str, expected: &str, expected_role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact { role, resolution, .. }
        if *role == expected_role && resolution.concrete_path() == Some(expected))
    })
}
fn has_write(command: &str) -> bool {
    graph(command).iter().any(|node| {
        matches!(
            &node.kind,
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                ..
            }
        )
    })
}
fn rule(command: &str, expected: RuleId) -> bool {
    let response = check(command);
    response
        .decision_trace
        .findings
        .iter()
        .any(|item| item.rule_id == expected)
        || response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|item| item.rule_id == expected)
}
fn semantic(command: &str, name: &str) -> ExecutionSemanticsFact {
    check(command)
        .decision_trace
        .execution_semantics
        .into_iter()
        .find(|item| item.normalized_command_name == name)
        .unwrap_or_else(|| panic!("missing semantic for {name}: {command}"))
}

#[test]
fn native_ui_escape_surface_is_not_fabricated_as_executed_bash() {
    for (name, command) in [
        ("apport-cli", "apport-cli -f"),
        ("asterisk", "asterisk -r"),
        ("bconsole", "bconsole"),
        ("debugfs", "debugfs"),
        ("ginsh", "ginsh"),
        ("iftop", "iftop"),
        ("jtag", "jtag --interactive"),
        ("minicom", "minicom -D /dev/null"),
        ("scanmem", "scanmem"),
        ("tdbtool", "tdbtool"),
    ] {
        let effect = semantic(command, name);
        assert!(
            effect.opens_interactive_escape_surface,
            "{command}: {effect:#?}"
        );
        assert!(
            !check(command)
                .decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("/bin/sh")),
            "{command}"
        );
    }
}

#[test]
fn native_configs_and_scripts_retain_real_file_identity() {
    for (command, expected) in [
        ("bconsole -c ./console.conf", "/tmp/project/console.conf"),
        (
            "minicom -D /dev/null -S ./connect.script",
            "/tmp/project/connect.script",
        ),
        ("lua ./program.lua", "/tmp/project/program.lua"),
        ("ruby ./program.rb", "/tmp/project/program.rb"),
        ("php -f ./program.php", "/tmp/project/program.php"),
        ("guile -s ./program.scm", "/tmp/project/program.scm"),
        ("tclsh ./program.tcl", "/tmp/project/program.tcl"),
        ("wish ./program.tcl", "/tmp/project/program.tcl"),
        ("clisp ./program.lisp", "/tmp/project/program.lisp"),
        ("R --no-save -f ./program.R", "/tmp/project/program.R"),
        ("julia ./program.jl", "/tmp/project/program.jl"),
        ("pwsh -File ./program.ps1", "/tmp/project/program.ps1"),
    ] {
        assert!(
            path(command, expected, ResolvedPathRole::Read),
            "{command}: {:#?}",
            graph(command)
        );
    }
}

#[test]
fn foreign_program_text_is_opaque_not_shell_side_effects() {
    for (name, command) in [
        ("lua", "lua -e 'rm /opt/shared/victim'"),
        ("ruby", "ruby -e 'rm /opt/shared/victim'"),
        ("php", "php -r 'rm /opt/shared/victim'"),
        ("guile", "guile -c 'rm /opt/shared/victim'"),
        ("clisp", "clisp -x 'rm /opt/shared/victim'"),
        ("R", "R --no-save -e 'rm /opt/shared/victim'"),
        ("julia", "julia -e 'rm /opt/shared/victim'"),
        ("pwsh", "pwsh -Command 'rm /opt/shared/victim'"),
        ("rpm", "rpm --eval '%(rm /opt/shared/victim)'"),
        ("rpmdb", "rpmdb --eval '%(rm /opt/shared/victim)'"),
        ("rpmquery", "rpmquery --eval '%(rm /opt/shared/victim)'"),
        ("rpmverify", "rpmverify --eval '%(rm /opt/shared/victim)'"),
    ] {
        assert!(semantic(command, name).executes_payload, "{command}");
        assert!(
            rule(command, RuleId::NestedPayloadExpansion),
            "{command}: {:#?}",
            check(command)
        );
        assert!(
            !rule(command, RuleId::OutsideWorkspaceMutation),
            "{command}"
        );
        assert!(
            !check(command)
                .decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("rm")),
            "{command}"
        );
        assert!(
            !path(command, "/opt/shared/victim", ResolvedPathRole::Target),
            "{command}"
        );
    }
}

#[test]
fn true_native_shell_callbacks_expand_real_child_effects() {
    for command in ["rpm --pipe 'rm /opt/shared/victim'"] {
        assert!(
            check(command)
                .decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("rm")),
            "{command}: {:#?}",
            check(command)
        );
        assert!(
            rule(command, RuleId::OutsideWorkspaceMutation),
            "{command}: {:#?}",
            check(command)
        );
    }
}

#[test]
fn apt_hook_has_explicit_opaque_boundary_but_shell_projection_remains_partial() {
    let command = "apt update -o 'APT::Update::Pre-Invoke::=rm /opt/shared/victim'";
    assert!(
        semantic(command, "apt").executes_payload,
        "{:#?}",
        check(command)
    );
    assert!(
        rule(command, RuleId::NestedPayloadExpansion),
        "{:#?}",
        check(command)
    );
    assert!(
        !rule(command, RuleId::OutsideWorkspaceMutation),
        "{:#?}",
        check(command)
    );
    assert!(
        !check(command)
            .decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.command_name.as_deref() == Some("rm"))
    );
    let ordinary = "apt update -o APT::Get::Assume-Yes=true";
    assert!(
        !semantic(ordinary, "apt").executes_payload,
        "{:#?}",
        check(ordinary)
    );
}

#[test]
fn local_package_installers_retain_real_input_and_execute_boundary() {
    for (name, command, input) in [
        ("dpkg", "dpkg -i ./package.deb", "/tmp/project/package.deb"),
        (
            "dnf",
            "dnf install -y ./package.rpm --disablerepo=*",
            "/tmp/project/package.rpm",
        ),
        ("rpm", "rpm -ivh ./package.rpm", "/tmp/project/package.rpm"),
        (
            "pkg",
            "pkg install -y --no-repo-update ./package.txz",
            "/tmp/project/package.txz",
        ),
    ] {
        assert!(
            path(command, input, ResolvedPathRole::Read),
            "{command}: {:#?}",
            graph(command)
        );
        let fact = semantic(command, name);
        assert!(
            fact.executes_payload || fact.executes_imported_package_logic,
            "{command}: {fact:#?}"
        );
        assert!(
            has_write(command),
            "Native package installation must retain its genuine unknown write target: {command}"
        );
        assert!(rule(command, RuleId::OutsideWorkspaceMutation), "{command}");
        assert_eq!(check(command).decision, Decision::NeedApproval, "{command}");
    }
}

#[test]
fn metadata_control_does_not_shadow_explicit_program_entry() {
    assert!(semantic("ruby -v -e 'puts 1'", "ruby").executes_payload);
    assert_eq!(
        check("ruby -v -e 'puts 1'").decision,
        Decision::NeedApproval
    );
    for (name, command) in [
        ("lua", "lua -v"),
        ("ruby", "ruby --version"),
        ("php", "php --version"),
        ("guile", "guile --version"),
        ("clisp", "clisp --version"),
        ("R", "R --version"),
        ("julia", "julia --version"),
        ("pwsh", "pwsh -Version"),
    ] {
        assert!(!semantic(command, name).executes_payload, "{command}");
        assert!(!has_write(command), "{command}");
    }
}

#[test]
fn php_builtin_server_retains_root_and_router_without_fake_listener_identity() {
    let public = "php -S 0.0.0.0:8765 -t ./public";
    // Existing scalar listener declarations cannot split native HOST:PORT.
    // This is a characterized partial mechanism, not accepted protection.
    assert!(
        semantic(public, "php").network_listeners.is_empty(),
        "{:#?}",
        check(public)
    );
    assert!(
        path(public, "/tmp/project/public", ResolvedPathRole::Read),
        "{:#?}",
        graph(public)
    );
    assert!(
        !rule(public, RuleId::NetworkListenerExposure),
        "{:#?}",
        check(public)
    );
    assert!(!has_write(public));
    let router = "php -S 127.0.0.1:8765 -t ./public ./router.php";
    assert!(
        path(router, "/tmp/project/router.php", ResolvedPathRole::Read),
        "{:#?}",
        graph(router)
    );
    assert!(
        semantic(router, "php").executes_payload,
        "{:#?}",
        check(router)
    );
    assert!(
        rule(router, RuleId::NestedPayloadExpansion),
        "{:#?}",
        check(router)
    );
}

#[test]
fn native_value_options_are_owned_once_and_not_package_or_script_operands() {
    for (name, command, input) in [
        (
            "apt",
            "apt -y install -c ./apt.conf sl",
            "/tmp/project/apt.conf",
        ),
        (
            "dnf",
            "dnf install -y ./package.rpm --disablerepo=*",
            "/tmp/project/package.rpm",
        ),
        (
            "R",
            "R --no-save --file=./program.R",
            "/tmp/project/program.R",
        ),
        (
            "pwsh",
            "pwsh -NoProfile -File ./program.ps1",
            "/tmp/project/program.ps1",
        ),
    ] {
        assert!(path(command, input, ResolvedPathRole::Read), "{command}");
        assert!(
            !semantic(command, name).operation_semantics_unresolved,
            "{command}: {:#?}",
            check(command)
        );
    }
    assert!(semantic("ruby -rsocket -e 'puts 1'", "ruby").executes_payload);
    assert!(!semantic("ruby -rsocket -e 'puts 1'", "ruby").operation_semantics_unresolved);
    assert_eq!(check("iftop -t").decision, Decision::Allow);
    assert!(!semantic("iftop -t", "iftop").opens_interactive_escape_surface);
    assert!(
        !semantic("apport-cli -f -p example-package", "apport-cli").operation_semantics_unresolved
    );
    assert_eq!(check("rpmverify bash").decision, Decision::Allow);
    assert!(rule("rpmverify --unknown-option", RuleId::SelectionError));
}

#[test]
fn dpkg_read_only_list_does_not_execute_transaction_hook() {
    let command = "dpkg --pre-invoke='rm /opt/shared/victim' -l dpkg";
    assert!(
        !semantic(command, "dpkg").executes_payload,
        "{:#?}",
        check(command)
    );
    assert!(!rule(command, RuleId::OutsideWorkspaceMutation));
    assert!(
        !check(command)
            .decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.command_name.as_deref() == Some("rm"))
    );
    assert_eq!(check(command).decision, Decision::Allow);
}
