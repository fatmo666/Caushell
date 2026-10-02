//! Container static checks. The sample commands never execute.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractImportedPackageProvenancePass, ExtractPathFactsPass, ExtractPipelineFlowPass,
    ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/tmp/project");
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.variables.push(ShellVariableSnapshot::new(
        "UV_PROJECT_ENVIRONMENT",
        ShellValueSnapshot::exact_scalar("/tmp/project/.venv"),
        true,
    ));
    CheckRequest {
        session_id: SessionId::new("uv-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn check(req: CheckRequest, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(req.clone());
    assert_eq!(
        response.decision, expected,
        "{}: {:?}",
        req.command, response.decision_trace
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::NoProfile | RuleId::SelectionError)),
        "{}: {:?}",
        req.command,
        response.decision_trace
    );
    response
}

struct Facts {
    paths: Vec<(ResolvedPathRole, PathResolution, Option<String>)>,
    packages: Vec<ProvenanceArtifact>,
    scopes: Vec<MutationScopeResolution>,
    exit_cwd: Option<String>,
}

fn inspect(req: CheckRequest, expected: Decision) -> Facts {
    check(req.clone(), expected);
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
    runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(req);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let mut facts = Facts {
        paths: vec![],
        packages: vec![],
        scopes: vec![],
        exit_cwd: ctx.known_request_exit_cwd().map(str::to_string),
    };
    for node in staged.graph().nodes() {
        match &node.kind {
            NodeKind::MutationScopeFact { resolution, .. } => facts.scopes.push(resolution.clone()),
            NodeKind::PathFact {
                role,
                resolution,
                normalized_command_name,
                ..
            } => facts
                .paths
                .push((*role, resolution.clone(), normalized_command_name.clone())),
            NodeKind::ProvenanceArtifact {
                artifact: artifact @ ProvenanceArtifact::ImportedPackage { .. },
            } => facts.packages.push(artifact.clone()),
            _ => {}
        }
    }
    facts
}

fn has_path(facts: &Facts, command: &str, role: ResolvedPathRole, path: &str) -> bool {
    facts.paths.iter().any(|(r, p, c)| {
        *r == role && c.as_deref() == Some(command) && p.concrete_path() == Some(path)
    })
}

#[test]
fn wrapper_preparation_and_child_mutations_are_both_retained() {
    let facts = inspect(request("uv run --no-sync rm -f local.txt"), Decision::Allow);
    assert!(has_path(
        &facts,
        "uv",
        ResolvedPathRole::Write,
        "/tmp/project/.venv"
    ));
    assert!(has_path(
        &facts,
        "rm",
        ResolvedPathRole::Target,
        "/tmp/project/local.txt"
    ));
    let r = check(
        request("uv run --no-sync rm -f /opt/outside.txt"),
        Decision::NeedApproval,
    );
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}

#[test]
fn default_discovered_or_relative_project_environments_remain_unknown() {
    for value in [None, Some(".venv"), Some("$UNKNOWN")] {
        let mut req = request("uv run --no-sync echo ok");
        req.shell_state_before.variables.clear();
        if let Some(value) = value {
            req.shell_state_before
                .variables
                .push(ShellVariableSnapshot::new(
                    "UV_PROJECT_ENVIRONMENT",
                    ShellValueSnapshot::exact_scalar(value),
                    true,
                ));
        }
        let facts = inspect(req, Decision::NeedApproval);
        assert!(
            facts
                .paths
                .iter()
                .any(|(r, p, c)| *r == ResolvedPathRole::Write
                    && c.as_deref() == Some("uv")
                    && p.concrete_path().is_none())
        );
    }
}

#[test]
fn environment_unknownness_and_prefix_assignments_obey_existing_visibility() {
    let mut req = request("uv run --locked echo ok");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    req.shell_state_before.variables.clear();
    check(req, Decision::NeedApproval);
    check(
        request("UV_PROJECT_ENVIRONMENT=/opt/shared uv run --locked echo ok"),
        Decision::NeedApproval,
    );
    check(
        request("UV_PROJECT_ENVIRONMENT=/tmp/project/other uv run --locked echo ok"),
        Decision::Allow,
    );
    let mut req = request("uv run --locked echo ok");
    req.shell_state_before.variables[0].exported = false;
    check(req, Decision::NeedApproval);
}

#[test]
fn no_sync_does_not_erase_with_installations_or_inline_script_environment() {
    for command in [
        "uv run --no-sync --with numpy echo ok",
        "uv run --no-sync --with-requirements req echo ok",
        "uv run --no-sync --with-editable . echo ok",
        "uv run --no-sync script.py",
        "uv run --no-sync --script extensionless",
        "uv run --no-sync -",
    ] {
        let facts = inspect(request(command), Decision::NeedApproval);
        assert!(
            facts
                .paths
                .iter()
                .any(|(r, p, c)| *r == ResolvedPathRole::Write
                    && c.as_deref() == Some("uv")
                    && p.concrete_path().is_none()),
            "{command}"
        );
    }
}

#[test]
fn locked_and_frozen_do_not_exempt_outside_environment_modification() {
    for command in [
        "UV_PROJECT_ENVIRONMENT=/opt/shared uv run --locked echo ok",
        "UV_PROJECT_ENVIRONMENT=/opt/shared uv run --frozen echo ok",
        "UV_PROJECT_ENVIRONMENT=/opt/shared uv sync --locked",
        "UV_PROJECT_ENVIRONMENT=/opt/shared uv sync --frozen",
    ] {
        let facts = inspect(request(command), Decision::NeedApproval);
        assert!(has_path(
            &facts,
            "uv",
            ResolvedPathRole::Write,
            "/opt/shared"
        ));
    }
    check(request("uv run echo ok"), Decision::NeedApproval); // Undiscovered lockfile target.
    check(request("uv sync"), Decision::NeedApproval);
    check(request("uv sync --locked"), Decision::Allow);
}

#[test]
fn directory_changes_child_cwd_but_project_does_not() {
    let facts = inspect(
        request("uv --directory /opt run --no-sync rm -f victim"),
        Decision::NeedApproval,
    );
    assert!(has_path(
        &facts,
        "rm",
        ResolvedPathRole::Target,
        "/opt/victim"
    ));
    assert_eq!(facts.exit_cwd.as_deref(), Some("/tmp/project"));
    let facts = inspect(
        request("uv run --project /opt/repo --no-sync rm -f victim"),
        Decision::Allow,
    );
    assert!(has_path(
        &facts,
        "rm",
        ResolvedPathRole::Target,
        "/tmp/project/victim"
    ));
}

#[test]
fn relative_repeated_and_environment_directory_settings_are_resolved_at_entry() {
    for (command, target) in [
        (
            "uv run --directory nested --no-sync rm -f victim",
            "/tmp/project/nested/victim",
        ),
        (
            "uv --directory /opt run --directory nested --no-sync rm -f victim",
            "/tmp/project/nested/victim",
        ),
        (
            "UV_WORKING_DIR=nested uv run --no-sync rm -f victim",
            "/tmp/project/nested/victim",
        ),
        (
            "UV_WORKING_DIR=/opt uv run --directory nested --no-sync rm -f victim",
            "/tmp/project/nested/victim",
        ),
    ] {
        let facts = inspect(request(command), Decision::Allow);
        assert!(
            has_path(&facts, "rm", ResolvedPathRole::Target, target),
            "{command}: {:?}",
            facts.paths
        );
    }
}

#[test]
fn unknown_directory_does_not_turn_relative_targets_into_workspace_paths() {
    let facts = inspect(
        request("uv run --directory \"$UNKNOWN\" --no-sync rm -f victim"),
        Decision::NeedApproval,
    );
    assert!(
        facts
            .paths
            .iter()
            .any(|(r, p, c)| *r == ResolvedPathRole::Target
                && c.as_deref() == Some("rm")
                && p.concrete_path().is_none())
    );
    assert!(!has_path(
        &facts,
        "rm",
        ResolvedPathRole::Target,
        "/tmp/project/victim"
    ));
    check(
        request("uv run --directory \"$UNKNOWN\" --no-sync rm -f /tmp/project/victim"),
        Decision::Allow,
    );
}

#[test]
fn shell_redirections_stay_at_shell_entry_cwd() {
    let facts = inspect(
        request("uv --directory /opt run --no-sync echo ok > output.txt"),
        Decision::Allow,
    );
    assert!(
        facts
            .paths
            .iter()
            .any(|(r, p, c)| *r == ResolvedPathRole::Write
                && c.is_none()
                && p.concrete_path() == Some("/tmp/project/output.txt"))
    );
    assert!(
        !facts
            .paths
            .iter()
            .any(|(_, p, _)| p.concrete_path() == Some("/opt/output.txt"))
    );
    check(
        request("uv --directory nested run --no-sync echo ok > /opt/output.txt"),
        Decision::NeedApproval,
    );
}

#[test]
fn shell_expansions_happen_before_process_local_chdir() {
    let facts = inspect(
        request("uv --directory /opt run --no-sync echo \"$(rm -f local.txt)\""),
        Decision::Allow,
    );
    assert!(has_path(
        &facts,
        "rm",
        ResolvedPathRole::Target,
        "/tmp/project/local.txt"
    ));
    check(
        request("uv --directory nested run --no-sync echo \"$(rm -f /opt/victim)\""),
        Decision::NeedApproval,
    );
}

#[test]
fn nested_wrappers_shell_payloads_and_request_cd_keep_effective_paths() {
    for (command, decision, target) in [
        (
            "env uv --directory /opt run --no-sync bash -c 'rm -f victim'",
            Decision::NeedApproval,
            "/opt/victim",
        ),
        (
            "uv --directory /opt run --no-sync uv --directory /tmp/project run --no-sync rm -f victim",
            Decision::Allow,
            "/tmp/project/victim",
        ),
        (
            "mkdir -p nested && cd nested && uv run --no-sync rm -f victim",
            Decision::Allow,
            "/tmp/project/nested/victim",
        ),
    ] {
        let facts = inspect(request(command), decision);
        assert!(
            has_path(&facts, "rm", ResolvedPathRole::Target, target),
            "{command}: {:?}",
            facts.paths
        );
    }
}

#[test]
fn module_child_reaches_existing_uvicorn_listener_guard() {
    check(
        request("uv run --no-sync -m uvicorn app:app --host 0.0.0.0"),
        Decision::NeedApproval,
    );
    check(
        request("uv run --no-sync -m uvicorn app:app --host 127.0.0.1"),
        Decision::Allow,
    );
    check(
        request("uv run --no-sync uvicorn app:app --host 0.0.0.0"),
        Decision::NeedApproval,
    );
}

#[test]
fn opaque_env_file_cannot_preserve_a_known_safe_child_host() {
    check(
        request("uv run --no-sync --env-file .env uvicorn app:app"),
        Decision::NeedApproval,
    );
    check(
        request("UV_ENV_FILE=.env uv run --no-sync uvicorn app:app"),
        Decision::NeedApproval,
    );
    check(
        request("uv run --no-sync --env-file .env uvicorn app:app --host 127.0.0.1 --port 8000"),
        Decision::NeedApproval,
    ); // FD/UDS may also be configured.
}

#[test]
fn pip_known_outside_and_unknown_targets_follow_existing_guard() {
    for command in [
        "uv pip install --target /tmp/project/site numpy",
        "uv pip install --prefix /tmp/project/env numpy",
        "uv pip sync --target /tmp/project/site requirements",
        "uv pip uninstall --target /tmp/project/site numpy",
    ] {
        inspect(request(command), Decision::Allow);
    }
    for command in [
        "uv pip install numpy",
        "uv pip install --system numpy",
        "uv pip install --target /opt/site numpy",
        "uv pip install --prefix \"$UNKNOWN\" numpy",
        "uv pip uninstall numpy",
    ] {
        inspect(request(command), Decision::NeedApproval);
    }
}

#[test]
fn local_package_paths_use_uv_directory_and_unknown_sources_remain_unknown() {
    let facts = inspect(
        request("uv pip install --directory nested --target /tmp/project/site -e ./pkg"),
        Decision::Allow,
    );
    assert!(facts.packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { manager: PackageManagerKind::Uv, source_path: Some(path), .. } if path == "/tmp/project/nested/pkg")));
    let facts = inspect(
        request("uv pip install --directory \"$UNKNOWN\" --target /tmp/project/site -e ./pkg"),
        Decision::NeedApproval,
    );
    assert!(facts.packages.iter().any(|p| matches!(
        p,
        ProvenanceArtifact::ImportedPackage {
            locator_kind: PackageLocatorKind::UnknownDynamic,
            source_path: None,
            ..
        }
    )));
}

#[test]
fn imported_source_guard_checks_later_url_and_remote_run_sources() {
    for command in [
        "uv pip install --target /tmp/project/site numpy https://example.test/pkg.whl",
        "uv run https://example.test/script.py",
    ] {
        let facts = inspect(request(command), Decision::NeedApproval);
        assert!(
            facts.packages.iter().any(|p| matches!(
                p,
                ProvenanceArtifact::ImportedPackage {
                    manager: PackageManagerKind::Uv,
                    locator_kind: PackageLocatorKind::DirectUrl,
                    ..
                }
            )),
            "{command}"
        );
    }
}

#[test]
fn venv_explicit_targets_and_discovery_are_distinct() {
    let facts = inspect(request("uv venv local"), Decision::Allow);
    assert!(has_path(
        &facts,
        "uv",
        ResolvedPathRole::Write,
        "/tmp/project/local"
    ));
    check(request("uv venv /opt/local"), Decision::NeedApproval);
    check(request("uv venv"), Decision::NeedApproval);
    check(request("uv venv --no-project"), Decision::Allow);
    check(
        request("uv venv --directory /opt local"),
        Decision::NeedApproval,
    );
    let facts = inspect(request("uv venv --clear local"), Decision::Allow);
    assert!(has_path(
        &facts,
        "uv",
        ResolvedPathRole::Target,
        "/tmp/project/local"
    ));
}

#[test]
fn explicit_cache_paths_are_not_given_the_implicit_cache_exemption() {
    check(
        request("uv sync --locked --cache-dir /opt/cache"),
        Decision::NeedApproval,
    );
    check(
        request("UV_CACHE_DIR=/opt/cache uv sync --locked"),
        Decision::NeedApproval,
    );
    check(
        request("uv sync --locked --cache-dir cache"),
        Decision::Allow,
    );
    check(
        request("uv sync --locked --cache-dir \"$UNKNOWN\""),
        Decision::NeedApproval,
    );
}

#[test]
fn read_only_queries_and_help_are_allowed() {
    for command in [
        "uv --help",
        "uv run --help",
        "uv venv --help",
        "uv pip install --help",
        "uv pip list",
        "uv pip freeze",
        "uv pip tree",
        "uv pip show numpy",
        "uv pip check",
    ] {
        inspect(request(command), Decision::Allow);
    }
}

#[test]
fn package_identity_distinguishes_relative_cwds_but_not_absolute_paths() {
    let facts = inspect(
        request(
            "uv pip install --directory a --target /tmp/project/site -e .; uv pip install --directory b --target /tmp/project/site -e .",
        ),
        Decision::Allow,
    );
    let paths: Vec<_> = facts
        .packages
        .iter()
        .filter_map(|p| match p {
            ProvenanceArtifact::ImportedPackage { source_path, .. } => source_path.as_deref(),
            _ => None,
        })
        .collect();
    assert_eq!(paths.len(), 2, "{:?}", facts.packages);
    assert!(paths.contains(&"/tmp/project/a"));
    assert!(paths.contains(&"/tmp/project/b"));
    let facts = inspect(
        request(
            "uv pip install --directory a --target /tmp/project/site -e /tmp/project/pkg; uv pip install --directory b --target /tmp/project/site -e /tmp/project/pkg",
        ),
        Decision::Allow,
    );
    assert_eq!(facts.packages.len(), 1, "{:?}", facts.packages);
}

#[test]
fn nested_shell_redirections_use_child_entry_cwd_and_keep_unknowns() {
    let facts = inspect(
        request("uv --directory /opt run --no-sync bash -c 'echo ok > output.txt'"),
        Decision::NeedApproval,
    );
    assert!(
        facts
            .paths
            .iter()
            .any(|(r, p, c)| *r == ResolvedPathRole::Write
                && c.is_none()
                && p.concrete_path() == Some("/opt/output.txt"))
    );
    let facts = inspect(
        request("uv --directory \"$UNKNOWN\" run --no-sync bash -c 'echo ok > output.txt'"),
        Decision::NeedApproval,
    );
    assert!(
        facts
            .paths
            .iter()
            .any(|(r, p, c)| *r == ResolvedPathRole::Write
                && c.is_none()
                && p.concrete_path().is_none())
    );
    assert!(
        !facts
            .paths
            .iter()
            .any(|(_, p, _)| p.concrete_path() == Some("/tmp/project/output.txt"))
    );
}

#[test]
fn repository_mutation_scope_uses_child_cwd_not_request_cwd() {
    let facts = inspect(
        request("uv --directory /opt run --no-sync git clean -fd"),
        Decision::NeedApproval,
    );
    assert!(facts.scopes.iter().any(|scope| matches!(scope, MutationScopeResolution::RepositoryWorktree {root, ..} if root.concrete_path() == Some("/opt"))));
    let facts = inspect(
        request("uv --directory \"$UNKNOWN\" run --no-sync git clean -fd"),
        Decision::NeedApproval,
    );
    assert!(facts.scopes.iter().any(|scope| matches!(scope, MutationScopeResolution::RepositoryWorktree {root, ..} if root.concrete_path().is_none())));
}

#[test]
fn false_or_unknown_no_sync_values_do_not_suppress_lockfile_mutation() {
    for command in [
        "uv run --no-sync=false echo ok",
        "uv run --no-sync=\"$UNKNOWN\" echo ok",
        "uv run --locked --no-locked echo ok",
        "uv run --frozen --no-frozen echo ok",
    ] {
        let facts = inspect(request(command), Decision::NeedApproval);
        assert!(
            facts
                .paths
                .iter()
                .any(|(r, p, c)| *r == ResolvedPathRole::Write
                    && c.as_deref() == Some("uv")
                    && p.concrete_path().is_none()),
            "{command}"
        );
    }
}

#[test]
fn previews_retain_inputs_without_environment_mutations() {
    for command in [
        "uv sync --dry-run",
        "uv pip install --dry-run --target /opt/site numpy",
        "uv pip sync --dry-run --target /opt/site req",
        "uv pip uninstall --dry-run --target /opt/site numpy",
    ] {
        let facts = inspect(request(command), Decision::Allow);
        assert!(
            !facts
                .paths
                .iter()
                .any(|(r, _, c)| c.as_deref() == Some("uv")
                    && matches!(r, ResolvedPathRole::Write | ResolvedPathRole::Target)),
            "{command}: {:?}",
            facts.paths
        );
    }
}
