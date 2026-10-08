//! Independent batch 30h group A graph checks. No GTFOBins example is executed.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 10] = [
    include_str!("../../caushell-profile/profiles/irb.yaml"),
    include_str!("../../caushell-profile/profiles/pry.yaml"),
    include_str!("../../caushell-profile/profiles/byebug.yaml"),
    include_str!("../../caushell-profile/profiles/cpan.yaml"),
    include_str!("../../caushell-profile/profiles/ghc.yaml"),
    include_str!("../../caushell-profile/profiles/ghci.yaml"),
    include_str!("../../caushell-profile/profiles/slsh.yaml"),
    include_str!("../../caushell-profile/profiles/octave.yaml"),
    include_str!("../../caushell-profile/profiles/jshell.yaml"),
    include_str!("../../caushell-profile/profiles/dotnet.yaml"),
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
        session_id: SessionId::new("gtfo30h-a-isolated"),
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

fn semantic(command: &str, expected_name: &str) -> ExecutionSemantics {
    let nodes = graph(command);
    nodes
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. }
                if semantics.normalized_command_name == expected_name =>
            {
                Some(semantics.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {expected_name} semantics for {command}: {nodes:#?}"))
}

fn has_path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind,
        NodeKind::PathFact { role: actual, resolution, .. }
            if *actual == role && resolution.concrete_path() == Some(expected))
    })
}

#[test]
fn opaque_native_entries_project_only_outer_execution_and_escape_surface() {
    for (command, name) in [
        ("irb", "irb"),
        ("pry", "pry"),
        ("cpan", "cpan"),
        ("ghci", "ghci"),
        ("jshell", "jshell"),
        ("slsh", "slsh"),
    ] {
        let fact = semantic(command, name);
        assert!(
            fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        let names: Vec<_> = graph(command)
            .iter()
            .filter_map(|node| match &node.kind {
                NodeKind::ExecutionSemantics { semantics, .. } => {
                    Some(semantics.normalized_command_name.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![name.to_string()],
            "native input became shell argv: {command}: {names:?}"
        );
    }
}

#[test]
fn expression_evaluation_is_opaque_payload_without_inner_command_graph() {
    for (command, name) in [
        ("ghc -e 'System.Process.callCommand \"/bin/sh\"'", "ghc"),
        ("slsh -e 'system(\"/bin/sh\")'", "slsh"),
        ("octave-cli --eval 'system(\"/bin/sh\")'", "octave-cli"),
    ] {
        let fact = semantic(command, name);
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
        let names: Vec<_> = graph(command)
            .iter()
            .filter_map(|node| match &node.kind {
                NodeKind::ExecutionSemantics { semantics, .. } => {
                    Some(semantics.normalized_command_name.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![name.to_string()],
            "opaque code was parsed into shell commands: {command}: {names:?}"
        );
        let nodes = graph(command);
        assert!(nodes.iter().any(|node| matches!(&node.kind,
            NodeKind::NestedPayload { language, source, resolution_kind, .. }
                if language == "opaque" && source == "inline_string" && resolution_kind == "unsupported_language")),
            "opaque code was not preserved as unsupported payload data: {command}: {nodes:#?}");
    }
    assert_eq!(
        semantic("octave-cli --eval 'disp(2 + 2)'", "octave-cli").form_id,
        "evaluate_code"
    );
}

#[test]
fn byebug_and_fsi_script_have_real_read_path_facts() {
    let byebug = "byebug --no-stop /tmp/project/target.rb -- benign-arg";
    let fact = semantic(byebug, "byebug");
    assert_eq!(fact.form_id, "debug_script");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(fact.opens_interactive_escape_surface, "{fact:#?}");
    assert!(
        has_path(byebug, "/tmp/project/target.rb", ResolvedPathRole::Read),
        "{:#?}",
        graph(byebug)
    );

    let fsi = "dotnet fsi /tmp/project/sample.fsx --quiet";
    let fact = semantic(fsi, "dotnet");
    assert_eq!(fact.form_id, "fsi_script");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(!fact.opens_interactive_escape_surface, "{fact:#?}");
    assert!(
        has_path(fsi, "/tmp/project/sample.fsx", ResolvedPathRole::Read),
        "{:#?}",
        graph(fsi)
    );
}

#[test]
fn octave_cli_native_alias_resolves_without_aliasing_other_interpreters() {
    let fact = semantic("octave-cli --eval 'disp(1)'", "octave-cli");
    assert_eq!(fact.form_id, "evaluate_code");
    for (command, name) in [
        ("irb", "irb"),
        ("pry", "pry"),
        ("byebug", "byebug"),
        ("cpan", "cpan"),
        ("ghc", "ghc"),
        ("ghci", "ghci"),
        ("slsh", "slsh"),
        ("jshell", "jshell"),
        ("dotnet fsi", "dotnet"),
    ] {
        assert!(!semantic(command, name).form_id.is_empty(), "{command}");
    }
}

#[test]
fn normal_information_controls_do_not_open_escape_surfaces() {
    for (command, name) in [
        ("irb --help", "irb"),
        ("pry --help", "pry"),
        ("byebug --help", "byebug"),
        ("cpan -h", "cpan"),
        ("ghc --version", "ghc"),
        ("ghci --help", "ghci"),
        ("slsh -help", "slsh"),
        ("octave --help", "octave"),
        ("jshell --version", "jshell"),
        ("dotnet --help", "dotnet"),
    ] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, "information", "{command}: {fact:#?}");
        assert!(!fact.executes_payload, "{command}: {fact:#?}");
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
    }
}

#[test]
fn help_precedence_keeps_mixed_haskell_eval_out_of_payload_execution() {
    for command in ["ghc -e '1 + 1' --help", "ghci -e '1 + 1' --help"] {
        let name = command.split_whitespace().next().unwrap();
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, "information", "{command}: {fact:#?}");
        assert!(!fact.executes_payload, "{command}: {fact:#?}");
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
    }
}
