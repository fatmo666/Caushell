//! Graph-level acceptance for opaque interpreter payloads. Tests are static.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 10] = [
    include_str!("../../caushell-profile/profiles/lua.yaml"),
    include_str!("../../caushell-profile/profiles/ruby.yaml"),
    include_str!("../../caushell-profile/profiles/php.yaml"),
    include_str!("../../caushell-profile/profiles/guile.yaml"),
    include_str!("../../caushell-profile/profiles/tclsh.yaml"),
    include_str!("../../caushell-profile/profiles/wish.yaml"),
    include_str!("../../caushell-profile/profiles/clisp.yaml"),
    include_str!("../../caushell-profile/profiles/R.yaml"),
    include_str!("../../caushell-profile/profiles/julia.yaml"),
    include_str!("../../caushell-profile/profiles/pwsh.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|raw| load_command_profile_from_str(raw).unwrap())
            .collect(),
    )
    .unwrap()
}

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfobins-batch30g-c"),
        sequence_no: CommandSequenceNo::new(1),
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

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry()));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut context);
    StagedSession::new(
        &graph,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}

fn semantics<'a>(nodes: &'a [GraphNode], name: &str) -> &'a ExecutionSemantics {
    nodes
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics }
                if semantics.normalized_command_name == name =>
            {
                Some(semantics)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name}: {nodes:#?}"))
}

#[test]
fn foreign_payloads_are_executable_opaque_semantics_without_child_dispatch() {
    for (command, name) in [
        ("lua -e 'os.execute(\"/bin/sh\")'", "lua"),
        ("lua -", "lua"),
        ("ruby -e 'exec \"/bin/sh\"'", "ruby"),
        ("php -r 'system(\"/bin/sh\");'", "php"),
        ("guile -c '(system \"/bin/sh\")'", "guile"),
        ("tclsh /tmp/project/script.tcl", "tclsh"),
        ("wish", "wish"),
        ("clisp -x '(ext:run-shell-command \"/bin/sh\")'", "clisp"),
        ("clisp -", "clisp"),
        ("R -e 'system(\"/bin/sh\")'", "R"),
        ("julia -e 'run(`/bin/sh`)'", "julia"),
        ("pwsh", "pwsh"),
    ] {
        let nodes = graph(command);
        let fact = semantics(&nodes, name);
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(!fact.dispatches_child_command, "{command}: {fact:#?}");
    }
}

#[test]
fn explicit_script_and_php_server_paths_are_graph_facts() {
    for (command, path, name) in [
        (
            "lua /tmp/project/script.lua",
            "/tmp/project/script.lua",
            "lua",
        ),
        (
            "ruby /tmp/project/script.rb",
            "/tmp/project/script.rb",
            "ruby",
        ),
        (
            "php /tmp/project/script.php",
            "/tmp/project/script.php",
            "php",
        ),
        (
            "guile /tmp/project/script.scm",
            "/tmp/project/script.scm",
            "guile",
        ),
        (
            "tclsh /tmp/project/script.tcl",
            "/tmp/project/script.tcl",
            "tclsh",
        ),
        ("wish /tmp/project/ui.tcl", "/tmp/project/ui.tcl", "wish"),
        (
            "clisp /tmp/project/script.lisp",
            "/tmp/project/script.lisp",
            "clisp",
        ),
        ("R -f /tmp/project/script.R", "/tmp/project/script.R", "R"),
        (
            "julia /tmp/project/script.jl",
            "/tmp/project/script.jl",
            "julia",
        ),
        (
            "pwsh -File /tmp/project/script.ps1",
            "/tmp/project/script.ps1",
            "pwsh",
        ),
    ] {
        let nodes = graph(command);
        let fact = semantics(&nodes, name);
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(nodes.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some(path))), "{command}: {nodes:#?}");
    }

    let command = "php -S 127.0.0.1:8765 -t /tmp/project/www /tmp/project/router.php";
    let nodes = graph(command);
    let fact = semantics(&nodes, "php");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(nodes.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/www"))), "{nodes:#?}");
    assert!(nodes.iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/router.php"))), "{nodes:#?}");
}
