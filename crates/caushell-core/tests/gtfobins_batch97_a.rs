//! Group A GTFOBins graph checks. Native recipes are inert test data and never executed.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass, ResolvePolicyPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 33] = [
    include_str!("../../caushell-profile/profiles/autoconf.yaml"),
    include_str!("../../caushell-profile/profiles/autoheader.yaml"),
    include_str!("../../caushell-profile/profiles/autoreconf.yaml"),
    include_str!("../../caushell-profile/profiles/bundle.yaml"),
    include_str!("../../caushell-profile/profiles/bundler.yaml"),
    include_str!("../../caushell-profile/profiles/cabal.yaml"),
    include_str!("../../caushell-profile/profiles/cobc.yaml"),
    include_str!("../../caushell-profile/profiles/composer.yaml"),
    include_str!("../../caushell-profile/profiles/easy_install.yaml"),
    include_str!("../../caushell-profile/profiles/exiftool.yaml"),
    include_str!("../../caushell-profile/profiles/gem.yaml"),
    include_str!("../../caushell-profile/profiles/go.yaml"),
    include_str!("../../caushell-profile/profiles/java.yaml"),
    include_str!("../../caushell-profile/profiles/jjs.yaml"),
    include_str!("../../caushell-profile/profiles/jrunscript.yaml"),
    include_str!("../../caushell-profile/profiles/latex.yaml"),
    include_str!("../../caushell-profile/profiles/latexmk.yaml"),
    include_str!("../../caushell-profile/profiles/lualatex.yaml"),
    include_str!("../../caushell-profile/profiles/luatex.yaml"),
    include_str!("../../caushell-profile/profiles/msfconsole.yaml"),
    include_str!("../../caushell-profile/profiles/pdflatex.yaml"),
    include_str!("../../caushell-profile/profiles/pdftex.yaml"),
    include_str!("../../caushell-profile/profiles/puppet.yaml"),
    include_str!("../../caushell-profile/profiles/rake.yaml"),
    include_str!("../../caushell-profile/profiles/rustc.yaml"),
    include_str!("../../caushell-profile/profiles/rustdoc.yaml"),
    include_str!("../../caushell-profile/profiles/tex.yaml"),
    include_str!("../../caushell-profile/profiles/vagrant.yaml"),
    include_str!("../../caushell-profile/profiles/xelatex.yaml"),
    include_str!("../../caushell-profile/profiles/xetex.yaml"),
    include_str!("../../caushell-profile/profiles/codex.yaml"),
    include_str!("../../caushell-profile/profiles/opencode.yaml"),
    include_str!("../../caushell-profile/profiles/ffmpeg.yaml"),
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

fn analysis(command: &str) -> (Vec<GraphNode>, Option<Decision>, bool) {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry()));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_request_analysis_pass(ResolvePolicyPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let request = CheckRequest {
        session_id: SessionId::new("gtfo97-a-isolated"),
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
    };
    let mut context = RunnerContext::new(request);
    runner.run(SessionView::new(&base, &summary), &mut context);
    let decision = context.final_decision;
    let has_selection_error = context
        .decision_proposals
        .iter()
        .any(|proposal| proposal.rule_id == RuleId::SelectionError);
    let nodes = StagedSession::new(
        &base,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect();
    (nodes, decision, has_selection_error)
}

fn graph(command: &str) -> Vec<GraphNode> {
    analysis(command).0
}

fn semantics(command: &str, name: &str) -> ExecutionSemantics {
    let nodes = graph(command);
    nodes
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. }
                if semantics.normalized_command_name == name =>
            {
                Some(semantics.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} semantics for {command}: {nodes:#?}"))
}

#[test]
fn native_foreign_code_stays_opaque_instead_of_becoming_bash_child_argv() {
    for (command, name) in [
        (
            r###"latex --shell-escape '\immediate\write18{echo SAFE}'"###,
            "latex",
        ),
        ("java Shell", "java"),
        (r###"go run /tmp/project/main.go"###, "go"),
        (r###"puppet apply -e "exec { '/bin/sh': }""###, "puppet"),
        ("opencode db 'SELECT name FROM project'", "opencode"),
    ] {
        let fact = semantics(command, name);
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
        let nodes = graph(command);
        assert!(nodes.iter().any(|node| matches!(&node.kind,
            NodeKind::NestedPayload { language, source, resolution_kind, .. }
                if language == "opaque" && source != "interactive" && resolution_kind == "unsupported_language")),
            "native code payload was not retained as opaque data: {command}: {nodes:#?}");
        let names: Vec<_> = nodes
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
            "native source leaked into shell graph: {command}: {names:?}"
        );
    }
}

#[test]
fn only_native_explicit_child_argv_creates_dispatch_nodes() {
    for (command, name) in [
        ("bundle exec /bin/sh -c 'rm /opt/shared/victim'", "bundle"),
        (
            "cabal exec --project-file=/dev/null -- /bin/sh -c 'rm /opt/shared/victim'",
            "cabal",
        ),
        (
            "codex sandbox linux /bin/sh -c 'rm /opt/shared/victim'",
            "codex",
        ),
    ] {
        let nodes = graph(command);
        assert!(nodes.iter().any(|node| matches!(&node.kind,
            NodeKind::ExecutionSemantics { semantics, .. }
                if semantics.normalized_command_name == name && semantics.dispatches_child_command)),
            "explicit native child wasn't dispatched: {command}: {nodes:#?}");
        assert!(nodes.iter().any(|node| matches!(&node.kind,
            NodeKind::DerivedInvocation { command_name: Some(child), raw_text, .. }
                if child == "/bin/sh" && raw_text.contains("-c") && raw_text.contains("rm /opt/shared/victim"))),
            "child command and trailing argv missing from derived graph: {command}: {nodes:#?}");
    }
}

#[test]
fn native_interactive_escape_capability_does_not_invent_a_child() {
    for (command, name) in [
        ("msfconsole", "msfconsole"),
        ("opencode", "opencode"),
        ("opencode db", "opencode"),
        ("jjs", "jjs"),
        ("jrunscript", "jrunscript"),
    ] {
        let fact = semantics(command, name);
        assert!(
            fact.opens_interactive_escape_surface,
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
            "interactive prompt became shell argv: {command}: {names:?}"
        );
    }
}

#[test]
fn information_and_output_path_cases_keep_control_and_file_facts_distinct() {
    for (command, name) in [
        ("rustc --explain E0001", "rustc"),
        ("latex --help", "latex"),
        ("java --help", "java"),
        ("ffmpeg -h", "ffmpeg"),
    ] {
        let fact = semantics(command, name);
        assert!(!fact.executes_payload, "{command}: {fact:#?}");
        assert!(!fact.dispatches_child_command, "{command}: {fact:#?}");
    }
    let tex_input = graph("latexmk /tmp/project/input.tex");
    assert!(
        tex_input.iter().any(|node| matches!(&node.kind,
        NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. }
            if resolution.concrete_path() == Some("/tmp/project/input.tex"))),
        "latexmk input file read was lost: {tex_input:#?}"
    );
    let rustc = semantics("rustc /tmp/project/main.rs -o /tmp/project/main", "rustc");
    assert!(
        rustc.form_id == "compile_source_explicit_output",
        "{rustc:#?}"
    );
}

#[test]
fn unknown_native_options_are_selection_errors_not_successful_controls() {
    for name in [
        "autoconf",
        "autoheader",
        "autoreconf",
        "bundle",
        "bundler",
        "cabal",
        "cobc",
        "composer",
        "easy_install",
        "exiftool",
        "gem",
        "go",
        "java",
        "jjs",
        "jrunscript",
        "latex",
        "latexmk",
        "lualatex",
        "luatex",
        "msfconsole",
        "pdflatex",
        "pdftex",
        "puppet",
        "rake",
        "rustc",
        "rustdoc",
        "tex",
        "vagrant",
        "xelatex",
        "xetex",
        "codex",
        "opencode",
        "ffmpeg",
    ] {
        let command = format!("{name} --caushell-unmodeled-option");
        let (_, decision, has_selection_error) = analysis(&command);
        assert_eq!(decision, Some(Decision::NeedApproval), "{command}");
        assert!(has_selection_error, "{command}");
    }
}
