//! Static checks in Docker. No Conda transaction or shell command is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractImportedPackageProvenancePass, ExtractPathFactsPass, ExtractPipelineFlowPass,
    ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PackageLocatorKind, PackageManagerKind,
    PathResolution, ProvenanceArtifact, ResolvedPathRole, RuleId, RuntimeMetadata, SessionId,
    SessionSummary, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("conda-profile-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
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

struct Inspection {
    paths: Vec<(ResolvedPathRole, PathResolution)>,
    packages: Vec<ProvenanceArtifact>,
}

impl Inspection {
    fn mutations(&self) -> Vec<&PathResolution> {
        self.paths
            .iter()
            .filter_map(|(role, path)| {
                matches!(role, ResolvedPathRole::Write | ResolvedPathRole::Target).then_some(path)
            })
            .collect()
    }
}

fn inspect(command: &str, expected: Decision) -> Inspection {
    inspect_request(request(command), expected)
}

fn inspect_request(request: CheckRequest, expected: Decision) -> Inspection {
    let mut core = ShellQueryCore::new();
    let response = core.check(request.clone());
    assert_eq!(
        response.decision, expected,
        "{}: {:?}",
        request.command, response.decision_trace.findings
    );
    if expected != Decision::Allow {
        // NeedApproval must not commit planned effects to the live graph.
        assert!(
            !core
                .session_graph(&request.session_id)
                .unwrap()
                .nodes()
                .any(|n| matches!(
                    n.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                        ..
                    }
                ))
        );
    }

    // Inspect actual staged facts through the production modeling passes;
    // never force an approved decision just to observe a blocked graph.
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
    let mut ctx = RunnerContext::new(request);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let mut result = Inspection {
        paths: vec![],
        packages: vec![],
    };
    for node in staged.graph().nodes() {
        match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => result.paths.push((*role, resolution.clone())),
            NodeKind::ProvenanceArtifact {
                artifact: artifact @ ProvenanceArtifact::ImportedPackage { .. },
            } => result.packages.push(artifact.clone()),
            _ => {}
        }
    }
    result
}

#[test]
fn unresolved_default_named_and_definition_selected_targets_require_approval() {
    for command in [
        "conda install numpy",
        "conda install -n dev numpy",
        "conda create -n dev python",
        "conda create --file=environment.yml",
        "conda update --all",
        "conda upgrade numpy",
        "conda remove numpy",
        "conda remove --all",
        "conda uninstall -n dev numpy",
        "conda env create",
        "conda env create -f environment.yml",
        "conda env update --prune",
        "conda env remove -n dev",
    ] {
        let facts = inspect(command, Decision::NeedApproval);
        assert_eq!(facts.mutations().len(), 2, "{command}: {:?}", facts.paths);
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path().is_none()),
            "{command}: {:?}",
            facts.paths
        );
    }
}

#[test]
fn known_workspace_prefix_is_checked_normally_and_stored_as_write_and_delete() {
    for command in [
        "conda install -p ./env numpy",
        "conda create --prefix=env python",
        "conda update -p env --all",
        "conda remove -p env numpy",
        "conda remove -p env --all",
        "conda env create -p env -f environment.yml",
        "conda env update -p env --prune",
        "conda env remove -p env",
    ] {
        let facts = inspect(command, Decision::Allow);
        assert_eq!(facts.mutations().len(), 2, "{command}");
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path() == Some("/tmp/project/env")),
            "{command}: {:?}",
            facts.paths
        );
    }
}

#[test]
fn explicit_outside_prefix_requires_existing_mutation_rule() {
    for command in [
        "conda install -p /opt/env numpy",
        "conda create -p /opt/env python",
        "conda update -p /opt/env --all",
        "conda remove -p /opt/env --all",
        "conda env create -p /opt/env -f environment.yml",
        "conda env update -p /opt/env",
        "conda env remove -p /opt/env",
    ] {
        let facts = inspect(command, Decision::NeedApproval);
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path() == Some("/opt/env"))
        );
        let response = ShellQueryCore::new().check(request(command));
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
}

#[test]
fn prefix_missing_empty_and_dynamic_are_unknown_not_workspace_defaults() {
    for command in [
        "conda install --prefix= numpy",
        "conda install -p \"$MISSING\" numpy",
        "conda install -p '/tmp/project/$MISSING' numpy",
        "conda create --prefix='${MISSING}/env' python",
        "conda remove --all -p '~unknown/env'",
    ] {
        let facts = inspect(command, Decision::NeedApproval);
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path().is_none()),
            "{command}: {:?}",
            facts.paths
        );
    }
}

#[test]
fn last_prefix_wins_without_losing_unknowns() {
    for (command, expected, target) in [
        (
            "conda install -p /opt/old -p env numpy",
            Decision::Allow,
            Some("/tmp/project/env"),
        ),
        (
            "conda install -p env --prefix=/opt/new numpy",
            Decision::NeedApproval,
            Some("/opt/new"),
        ),
        (
            "conda install -p env --prefix=\"$MISSING\" numpy",
            Decision::NeedApproval,
            None,
        ),
    ] {
        let facts = inspect(command, expected);
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path() == target)
        );
    }
}

#[test]
fn prefix_expansion_uses_request_facts_not_host_environment() {
    for (command, target) in [
        ("conda create -p '~/env' python", "/home/alice/env"),
        ("conda install -p ../env numpy", "/tmp/env"),
    ] {
        let facts = inspect(command, Decision::NeedApproval);
        assert!(
            facts
                .mutations()
                .iter()
                .all(|p| p.concrete_path() == Some(target))
        );
    }
    let mut req = request("conda install -p \"$PREFIX\" numpy");
    req.shell_state_before =
        req.shell_state_before
            .with_exact_scalar_variable("PREFIX", "/tmp/project/env", true);
    let facts = inspect_request(req, Decision::Allow);
    assert!(
        facts
            .mutations()
            .iter()
            .all(|p| p.concrete_path() == Some("/tmp/project/env"))
    );
}

#[test]
fn active_conda_environment_variables_do_not_invent_a_target_prefix() {
    let mut req = request("conda install numpy");
    req.shell_state_before = req
        .shell_state_before
        .with_exact_scalar_variable("CONDA_PREFIX", "/tmp/project/env", true)
        .with_exact_scalar_variable("CONDA_DEFAULT_ENV", "dev", true);
    let facts = inspect_request(req, Decision::NeedApproval);
    assert!(
        facts
            .mutations()
            .iter()
            .all(|p| p.concrete_path().is_none())
    );
}

#[test]
fn known_prefix_without_workspace_still_requires_approval() {
    let mut req = request("conda install -p /tmp/project/env numpy");
    req.workspace_root = None;
    inspect_request(req, Decision::NeedApproval);
}

#[test]
fn preview_preserves_import_facts_but_has_no_environment_modification() {
    for command in [
        "conda install --dry-run -p /opt/env https://packages.example.test/numpy.conda",
        "conda create -d -n dev python",
        "conda remove --all --dry-run",
        "conda env create -d -f https://packages.example.test/env.yml",
        "conda env remove -d -n dev",
    ] {
        assert!(
            inspect(command, Decision::Allow).mutations().is_empty(),
            "{command}"
        );
    }
    assert!(
        !inspect("conda install --dry-run numpy", Decision::Allow)
            .packages
            .is_empty()
    );
}

#[test]
fn download_only_distinguishes_cache_acquisition_from_create_prefix_removal() {
    for command in [
        "conda install --download-only numpy",
        "conda update --download-only --all",
    ] {
        assert!(inspect(command, Decision::Allow).mutations().is_empty());
    }
    for command in [
        "conda create --download-only -n dev python",
        "conda create --download-only -p /opt/env python",
    ] {
        let facts = inspect(command, Decision::NeedApproval);
        assert_eq!(facts.mutations().len(), 1);
        assert!(
            facts
                .paths
                .iter()
                .any(|(role, _)| *role == ResolvedPathRole::Target)
        );
    }
    inspect(
        "conda create --download-only -p env python",
        Decision::Allow,
    );
}

#[test]
fn env_update_with_prune_preserves_environment_mutation_effects() {
    assert!(
        !inspect("conda env update -n dev --prune", Decision::NeedApproval)
            .mutations()
            .is_empty()
    );
}

#[test]
fn definition_input_is_not_an_environment_write_target() {
    let facts = inspect(
        "conda env create -p env -f /opt/definitions/dev.yml",
        Decision::Allow,
    );
    assert!(
        facts
            .mutations()
            .iter()
            .all(|p| p.concrete_path() == Some("/tmp/project/env"))
    );
    assert!(
        facts
            .packages
            .iter()
            .any(|p| matches!(p, ProvenanceArtifact::ImportedPackage {
        manager: PackageManagerKind::Conda, locator_kind: PackageLocatorKind::RequirementFile,
        source_path: Some(path), .. } if path == "/opt/definitions/dev.yml"))
    );
}

#[test]
fn multiple_definition_and_channel_sources_are_retained_in_graph() {
    let facts = inspect(
        "conda install --dry-run -f first.yml --file=second.yml -c conda-forge -c https://packages.example.test numpy",
        Decision::Allow,
    );
    for locator in [
        "first.yml",
        "second.yml",
        "conda-forge",
        "https://packages.example.test",
        "numpy",
    ] {
        assert!(facts.packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { manager: PackageManagerKind::Conda, locator: actual, .. } if actual == locator)), "{locator}: {:?}", facts.packages);
    }
    let facts = inspect(
        "conda env create --dry-run -f base.yml extra.yml",
        Decision::Allow,
    );
    for locator in ["base.yml", "extra.yml"] {
        assert!(facts.packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { locator: actual, .. } if actual == locator)));
    }
}

#[test]
fn remote_definition_url_does_not_become_a_fake_filesystem_config_path() {
    let facts = inspect(
        "conda env create -d -f https://packages.example.test/env.yml",
        Decision::Allow,
    );
    assert!(
        !facts
            .paths
            .iter()
            .any(|(_, p)| p.concrete_path().is_some_and(|p| p.contains("https:")))
    );
    assert!(facts.packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { locator_kind: PackageLocatorKind::DirectUrl, source_endpoint: Some(url), source_path: None, .. } if url == "https://packages.example.test/env.yml")));
}

#[test]
fn package_source_rule_remains_independent_of_known_workspace_prefix() {
    for command in [
        "conda install -p env https://packages.example.test/numpy.conda",
        "conda install -p env \"$PACKAGE\"",
        "conda env create -p env -f https://packages.example.test/env.yml",
        "conda install -p env -c https://packages.example.test",
    ] {
        inspect(command, Decision::NeedApproval);
        let response = ShellQueryCore::new().check(request(command));
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ImportedPackageExecution)
        );
    }
}

#[test]
fn a_registry_package_cannot_mask_a_second_untrusted_package_or_channel() {
    for command in [
        "conda install -p env numpy https://packages.example.test/other.conda",
        "conda install -p env https://packages.example.test/other.conda numpy",
        "conda install -p env -c https://packages.example.test numpy",
    ] {
        inspect(command, Decision::NeedApproval);
    }
}

#[test]
fn common_registry_local_file_and_channel_qualified_locators_keep_shared_policy() {
    for (locator, expected_kind) in [
        ("numpy", PackageLocatorKind::RegistryRef),
        (
            "conda-forge/linux-64::numpy",
            PackageLocatorKind::RegistryRef,
        ),
        ("./numpy.conda", PackageLocatorKind::LocalPath),
    ] {
        let facts = inspect(&format!("conda install -p env {locator}"), Decision::Allow);
        assert!(
            facts
                .packages
                .iter()
                .any(|p| matches!(p, ProvenanceArtifact::ImportedPackage {
            locator_kind, .. } if *locator_kind == expected_kind)),
            "{:?}",
            facts.packages
        );
    }
}

#[test]
fn queries_and_stdout_export_do_not_write_environment_or_export_file() {
    for command in [
        "conda list -p /opt/env --explicit",
        "conda list -n dev -f numpy",
        "conda info --envs --json",
        "conda search -f numpy -c https://packages.example.test",
        "conda env list",
        "conda export -p /opt/env",
        "conda env export -n dev",
    ] {
        assert!(
            inspect(command, Decision::Allow).mutations().is_empty(),
            "{command}"
        );
    }
}

#[test]
fn explicit_export_is_checked_as_a_separate_output_path() {
    for (command, expected, target) in [
        (
            "conda export -p /opt/env -f environment.yml",
            Decision::Allow,
            Some("/tmp/project/environment.yml"),
        ),
        (
            "conda env export -n dev --file=/etc/export.yml",
            Decision::NeedApproval,
            Some("/etc/export.yml"),
        ),
        ("conda export -f \"$OUTPUT\"", Decision::NeedApproval, None),
        (
            "conda export -f '/tmp/project/$LITERAL.yml'",
            Decision::Allow,
            Some("/tmp/project/$LITERAL.yml"),
        ),
        (
            "conda export -f '~/environment.yml'",
            Decision::Allow,
            Some("/tmp/project/~/environment.yml"),
        ),
    ] {
        let facts = inspect(command, expected);
        assert_eq!(facts.mutations().len(), 1, "{command}");
        assert_eq!(facts.mutations()[0].concrete_path(), target, "{command}");
    }
}

#[test]
fn standard_preview_never_exempts_shell_redirection_or_neighbor_commands() {
    for command in [
        "conda install -d numpy > /etc/conda-output",
        "conda list > /etc/conda-output",
        "conda install -d numpy; rm /etc/unrelated-file",
    ] {
        inspect(command, Decision::NeedApproval);
    }
}

#[test]
fn prefix_respects_the_effective_cwd_and_existing_shell_wrapper() {
    // The guard uses effective cwd independently of the base-cwd PathFacts.
    // Check its decision/evidence, not a nonexistent graph-rebasing guarantee.
    for command in [
        "cd /opt && conda install -p env numpy",
        "bash -c 'conda install -p /opt/env numpy'",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {:?}",
            response.decision_trace.findings
        );
    }
    let mut req = request("conda install -p env numpy");
    req.shell_state_before = ShellStateSnapshot::new("/opt");
    assert!(
        inspect_request(req, Decision::NeedApproval)
            .mutations()
            .iter()
            .all(|p| p.concrete_path() == Some("/opt/env"))
    );
}
