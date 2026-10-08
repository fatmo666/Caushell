//! Isolated group C graph checks. GTFOBins source recipes are never executed.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
    ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 10] = [
    include_str!("../../caushell-profile/profiles/ansible-playbook.yaml"),
    include_str!("../../caushell-profile/profiles/bee.yaml"),
    include_str!("../../caushell-profile/profiles/sqlmap.yaml"),
    include_str!("../../caushell-profile/profiles/gcloud.yaml"),
    include_str!("../../caushell-profile/profiles/eb.yaml"),
    include_str!("../../caushell-profile/profiles/poetry.yaml"),
    include_str!("../../caushell-profile/profiles/pipx.yaml"),
    include_str!("../../caushell-profile/profiles/knife.yaml"),
    include_str!("../../caushell-profile/profiles/volatility.yaml"),
    include_str!("../../caushell-profile/profiles/forge.yaml"),
];

fn registry() -> ProfileRegistry {
    let mut profiles: Vec<_> = PROFILES
        .iter()
        .map(|source| load_command_profile_from_str(source).unwrap())
        .collect();
    profiles.push(
        load_command_profile_from_str(include_str!("../../caushell-profile/profiles/python.yaml"))
            .unwrap(),
    );
    ProfileRegistry::from_profiles(profiles).unwrap()
}

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfo30h-c-isolated"),
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

fn semantics(command: &str) -> Vec<ExecutionSemantics> {
    graph(command)
        .iter()
        .filter_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect()
}

fn semantic(command: &str, name: &str) -> ExecutionSemantics {
    semantics(command)
        .into_iter()
        .find(|item| item.normalized_command_name == name)
        .unwrap_or_else(|| {
            panic!(
                "missing {name} semantics for {command}: {:#?}",
                graph(command)
            )
        })
}

fn has_path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind,
        NodeKind::PathFact { role: actual, resolution, .. }
            if *actual == role && resolution.concrete_path() == Some(expected))
    })
}

#[test]
fn ansible_playbook_path_is_read_and_executed_as_opaque_native_input() {
    let command = "ansible-playbook /tmp/project/site.yml";
    let fact = semantic(command, "ansible-playbook");
    assert_eq!(fact.form_id, "run_playbook");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(
        has_path(command, "/tmp/project/site.yml", ResolvedPathRole::Read),
        "{:#?}",
        graph(command)
    );
    let names: Vec<_> = semantics(command)
        .iter()
        .map(|s| s.normalized_command_name.clone())
        .collect();
    assert_eq!(names, ["ansible-playbook"]);

    let check = "ansible-playbook --syntax-check /tmp/project/site.yml";
    let fact = semantic(check, "ansible-playbook");
    assert_eq!(fact.form_id, "syntax_check");
    assert!(!fact.executes_payload, "{fact:#?}");
    assert!(
        has_path(check, "/tmp/project/site.yml", ResolvedPathRole::Read),
        "{:#?}",
        graph(check)
    );
}

#[test]
fn foreign_php_python_and_ruby_values_never_become_shell_children() {
    for (command, name, form) in [
        ("bee --root /tmp/project eval 'print(1)'", "bee", "eval_php"),
        (
            "sqlmap -u http://127.0.0.1/item?id=1 --eval 'x=1'",
            "sqlmap",
            "evaluate_python_for_url",
        ),
        ("knife exec -E 'puts 1'", "knife", "exec_eval_ruby"),
    ] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, form, "{command}: {fact:#?}");
        let names: Vec<_> = semantics(command)
            .iter()
            .map(|s| s.normalized_command_name.clone())
            .collect();
        assert_eq!(
            names,
            [name],
            "foreign native code was projected as shell argv: {command}: {names:?}"
        );
        assert_eq!(
            semantics(command).len(),
            1,
            "opaque code cannot create a shell child: {command}"
        );
    }
    assert!(has_path(
        "bee --root /tmp/project eval 'print(1)'",
        "/tmp/project",
        ResolvedPathRole::Read
    ));
}

#[test]
fn gcloud_help_and_eb_logs_report_only_their_conditional_pager_surface() {
    for (command, name, form) in [
        ("gcloud help", "gcloud", "help_search_with_pager"),
        ("eb logs", "eb", "logs_with_pager"),
    ] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, form, "{command}: {fact:#?}");
        assert!(
            fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
        assert_eq!(
            semantics(command).len(),
            1,
            "no synthetic pager command: {command}"
        );
    }
    for (command, name) in [("gcloud --help", "gcloud"), ("eb --help", "eb")] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, "information");
        assert!(
            !fact.opens_interactive_escape_surface,
            "{command}: {fact:#?}"
        );
    }
}

#[test]
fn poetry_run_resolves_the_actual_child_command_and_preserves_its_argv() {
    let command = "poetry run python /tmp/project/job.py --quiet";
    let facts = semantics(command);
    assert_eq!(
        facts
            .iter()
            .map(|s| s.normalized_command_name.as_str())
            .collect::<Vec<_>>(),
        ["poetry", "python"]
    );
    let poetry = facts
        .iter()
        .find(|s| s.normalized_command_name == "poetry")
        .unwrap();
    assert_eq!(poetry.form_id, "run_command");
    let python = facts
        .iter()
        .find(|s| s.normalized_command_name == "python")
        .unwrap();
    assert_eq!(python.form_id, "script_file");
    assert!(python.executes_payload, "{python:#?}");
    assert!(
        has_path(command, "/tmp/project/job.py", ResolvedPathRole::Read),
        "{:#?}",
        graph(command)
    );

    let delimited = "poetry run -- python /tmp/project/job.py --quiet";
    let facts = semantics(delimited);
    assert_eq!(
        facts
            .iter()
            .map(|s| s.normalized_command_name.as_str())
            .collect::<Vec<_>>(),
        ["poetry", "python"]
    );
    let python = facts
        .iter()
        .find(|s| s.normalized_command_name == "python")
        .unwrap();
    assert_eq!(
        python.form_id, "script_file",
        "child args after -- remain child argv"
    );
    assert!(
        has_path(delimited, "/tmp/project/job.py", ResolvedPathRole::Read),
        "{:#?}",
        graph(delimited)
    );
}

#[test]
fn pipx_explicit_local_path_and_package_spec_have_different_graph_effects() {
    let local = "pipx run --path /tmp/project/script.py";
    let fact = semantic(local, "pipx");
    assert_eq!(fact.form_id, "run_local_path");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(
        has_path(local, "/tmp/project/script.py", ResolvedPathRole::Read),
        "{:#?}",
        graph(local)
    );
    assert_eq!(
        semantics(local).len(),
        1,
        "local script body is opaque, not shell argv"
    );

    let package = "pipx run --spec pycowsay pycowsay moo";
    let fact = semantic(package, "pipx");
    assert_eq!(fact.form_id, "run_package_spec");
    assert!(!has_path(
        package,
        "/tmp/project/script.py",
        ResolvedPathRole::Read
    ));
    assert_eq!(
        semantics(package).len(),
        1,
        "package app is native pipx input, not shell argv"
    );

    let ambiguous = "pipx run /tmp/project/script.py";
    let fact = semantic(ambiguous, "pipx");
    assert_eq!(fact.form_id, "run_ambiguous_app");
    assert!(
        fact.executes_payload,
        "ambiguous local/package input remains an opaque execution boundary: {fact:#?}"
    );
    assert!(
        !fact.dispatches_child_command,
        "no shell child is inferred from the native app operand"
    );
    assert!(!has_path(
        ambiguous,
        "/tmp/project/script.py",
        ResolvedPathRole::Read
    ));
}

#[test]
fn knife_script_operand_is_read_and_executed_without_parsing_its_ruby_body() {
    let command = "knife exec /tmp/project/task.rb";
    let fact = semantic(command, "knife");
    assert_eq!(fact.form_id, "exec_script_file");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(
        has_path(command, "/tmp/project/task.rb", ResolvedPathRole::Read),
        "{:#?}",
        graph(command)
    );
    assert_eq!(semantics(command).len(), 1);
}

#[test]
fn volatility_treats_dump_as_read_data_while_volshell_is_native_interaction() {
    let command = "volatility -f /tmp/project/core-dump volshell";
    let fact = semantic(command, "volatility");
    assert_eq!(fact.form_id, "volshell");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(fact.opens_interactive_escape_surface, "{fact:#?}");
    assert!(
        has_path(command, "/tmp/project/core-dump", ResolvedPathRole::Read),
        "{:#?}",
        graph(command)
    );
    assert!(
        !has_path(command, "/tmp/project/core-dump", ResolvedPathRole::Target),
        "dump must not be mistaken for executable code"
    );
    assert_eq!(
        semantics(command).len(),
        1,
        "volshell input is opaque; no synthetic Python or shell child"
    );
}

#[test]
fn forge_does_not_guess_compiler_identifiers_or_paths_or_hide_unknown_argv() {
    for selector in ["0.8.26", "/tmp/project/compiler"] {
        let command = format!("forge build --use {selector}");
        let fact = semantic(&command, "forge");
        assert_eq!(
            fact.form_id,
            if selector.starts_with('/') {
                "build_with_explicit_compiler_path"
            } else {
                "build_with_compiler_selector"
            },
            "{command}: {fact:#?}"
        );
        assert!(
            fact.executes_payload,
            "opaque compiler helper boundary: {fact:#?}"
        );
        assert!(
            !fact.dispatches_child_command,
            "dynamic helper argv cannot be represented as empty argv"
        );
        assert_eq!(
            has_path(&command, selector, ResolvedPathRole::Read),
            selector.starts_with('/'),
            "only explicit absolute path syntax proves a path: {:#?}",
            graph(&command)
        );
        assert_eq!(
            semantics(&command).len(),
            1,
            "no guessed compiler helper command"
        );
    }
}
