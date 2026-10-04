//! Static container-only decision/Graph checks, not real Homebrew transactions.
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
    let mut state = ShellStateSnapshot::new("/tmp/project");
    // Explicit fixture fact, not a probe: no inherited environment override.
    state.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("brew-static-scope"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
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
fn check(command: &str, expected: Decision) -> CheckResponse {
    let req = request(command);
    let mut core = ShellQueryCore::new();
    let r = core.check(req.clone());
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
    if expected != Decision::Allow {
        // A static proposal requiring approval has not been admitted to history.
        assert!(
            !core
                .session_graph(&req.session_id)
                .unwrap()
                .nodes()
                .any(|n| matches!(
                    n.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                        ..
                    }
                )),
            "{command}"
        );
    }
    r
}
fn proposed(r: &CheckResponse, rule: RuleId) -> bool {
    r.decision_trace
        .decision_proposals
        .iter()
        .any(|p| p.rule_id == rule)
}
fn stage(
    req: CheckRequest,
) -> (
    Vec<(ResolvedPathRole, PathResolution)>,
    Vec<ProvenanceArtifact>,
    Vec<ExecutionSemantics>,
) {
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
    let mut paths = vec![];
    let mut packages = vec![];
    let mut semantics = vec![];
    let mut snapshot = SessionGraph::new();
    for node in staged.graph().nodes() {
        snapshot.add_node(node.clone());
        match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => paths.push((*role, resolution.clone())),
            NodeKind::ProvenanceArtifact {
                artifact: a @ ProvenanceArtifact::ImportedPackage { .. },
            } => packages.push(a.clone()),
            NodeKind::ExecutionSemantics { semantics: s, .. } => semantics.push(s.clone()),
            _ => {}
        }
    }
    for edge in staged.graph().edges() {
        snapshot.add_edge(edge.clone()).unwrap();
    }
    let restored = SessionGraph::from_snapshot(snapshot.to_snapshot()).unwrap();
    let restored_semantics: Vec<_> = restored
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(semantics, restored_semantics);
    (paths, packages, semantics)
}
fn has_write(paths: &[(ResolvedPathRole, PathResolution)], expected: &str) -> bool {
    paths
        .iter()
        .any(|(r, p)| *r == ResolvedPathRole::Write && p.concrete_path() == Some(expected))
}

#[test]
fn default_queries_are_allowed_without_claiming_installation_execution() {
    for c in [
        "brew list",
        "brew ls --cask --versions",
        "brew info curl",
        "brew info --json curl",
        "brew info --json=v2 curl",
        "brew search --desc ssh",
        "brew outdated --json",
        "brew config",
        "brew --prefix",
        "brew --cache",
        "brew shellenv bash",
        "brew tap",
        "brew formulae",
        "brew casks",
    ] {
        let r = check(c, Decision::Allow);
        assert!(!proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.executes_imported_package_logic && !s.operation_semantics_unresolved),
            "{c}"
        );
        let (paths, packages, _) = stage(request(c));
        assert!(packages.is_empty(), "{c}");
        assert!(!has_write(&paths, "/opt/homebrew"), "{c}");
    }
}

#[test]
fn imports_use_existing_workspace_guard_for_unknown_modification_scope() {
    for c in [
        "brew install curl",
        "brew instal curl",
        "brew install --formula curl",
        "brew install --cask firefox",
        "brew reinstall curl",
        "brew upgrade",
        "brew upgrade curl",
        "brew install --skip-post-install --skip-link --force-bottle curl",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.decision == Decision::Deny),
            "{c}"
        );
        let (paths, _, _) = stage(request(c));
        assert!(
            paths
                .iter()
                .any(|(role, p)| *role == ResolvedPathRole::Write && p.concrete_path().is_none()),
            "{c}: {paths:?}"
        );
        assert!(
            !paths.iter().any(
                |(role, p)| *role == ResolvedPathRole::Target && p.concrete_path() == Some("/")
            ),
            "{c}"
        );
    }
}

#[test]
fn caller_prefix_and_cask_destinations_cannot_constrain_the_whole_transaction() {
    for c in [
        "HOMEBREW_PREFIX=/tmp/project/brew brew install curl",
        "HOMEBREW_PREFIX=/tmp/project/brew HOMEBREW_CELLAR=/tmp/project/cellar brew upgrade",
        "brew install --cask --appdir=/tmp/project/apps firefox",
        "brew install --appdir=apps --fontdir=fonts font-package",
        "env HOMEBREW_PREFIX=/tmp/project/brew brew install curl",
    ] {
        assert!(
            proposed(
                &check(c, Decision::NeedApproval),
                RuleId::OutsideWorkspaceMutation
            ),
            "{c}"
        );
    }
    let (paths, _, _) = stage(request(
        "HOMEBREW_PREFIX=/tmp/project/brew brew install --cask --appdir=apps firefox",
    ));
    assert!(has_write(&paths, "/tmp/project/apps"));
    assert!(!has_write(&paths, "/tmp/project/brew"));
}

#[test]
fn last_cask_override_wins_without_losing_other_destination_categories() {
    let c = "brew install --cask --appdir=/etc/old sample --appdir=/tmp/project/apps --fontdir=/Library/Fonts";
    check(c, Decision::NeedApproval);
    let (paths, packages, _) = stage(request(c));
    assert!(has_write(&paths, "/tmp/project/apps"), "{paths:?}");
    assert!(has_write(&paths, "/Library/Fonts"), "{paths:?}");
    assert!(!has_write(&paths, "/etc/old"), "{paths:?}");
    assert_eq!(packages.len(), 1);
}

#[test]
fn unknown_empty_or_escaping_destinations_do_not_fall_back_to_defaults() {
    for operand in [
        "\"$DEST\"",
        "''",
        "../outside",
        "/tmp/project-other/apps",
        "/tmp/project/../../etc",
    ] {
        let c = format!("brew install --cask --appdir={operand} sample");
        check(&c, Decision::NeedApproval);
        let (paths, _, _) = stage(request(&c));
        assert!(!has_write(&paths, "/Applications"), "{c}: {paths:?}");
    }
}

#[test]
fn homebrew_registry_and_tap_names_are_not_filesystem_paths() {
    for operand in [
        "curl",
        "python@3.14",
        "homebrew/core/curl",
        "owner/tap/tool",
        "foo.rb",
    ] {
        let c = format!("brew install {operand}");
        let r = check(&c, Decision::NeedApproval);
        assert!(!proposed(&r, RuleId::ImportedPackageExecution), "{c}");
        let (_, packages, _) = stage(request(&c));
        assert!(packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { manager: PackageManagerKind::Brew, locator_kind: PackageLocatorKind::RegistryRef, source_path: None, locator, .. } if locator == operand)), "{c}: {packages:?}");
    }
}

#[test]
fn remote_dynamic_and_explicit_local_spelling_stay_independent_source_risks() {
    for (operand, kind) in [
        ("https://example.test/recipe", PackageLocatorKind::DirectUrl),
        ("\"$PACKAGE\"", PackageLocatorKind::UnknownDynamic),
        ("./recipe", PackageLocatorKind::UnknownDynamic),
        ("/tmp/recipe.rb", PackageLocatorKind::UnknownDynamic),
        ("s3://bucket/recipe", PackageLocatorKind::UnknownDynamic),
    ] {
        let c = format!("brew install --appdir=/tmp/project/apps {operand}");
        let r = check(&c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::ImportedPackageExecution), "{c}");
        assert!(proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        let (_, packages, _) = stage(request(&c));
        assert!(packages.iter().any(|p| matches!(p, ProvenanceArtifact::ImportedPackage { manager: PackageManagerKind::Brew, locator_kind, .. } if *locator_kind == kind)), "{c}: {packages:?}");
    }
}

#[test]
fn deletion_scopes_are_unknown_not_incidental_exemptions_or_root_deletions() {
    for c in [
        "brew uninstall curl",
        "brew rm --force curl",
        "brew uninstall --cask --zap firefox",
        "brew cleanup",
        "brew cleanup --prune=all",
        "brew autoremove",
        "brew link --overwrite curl",
        "brew unlink curl",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        let (paths, packages, _) = stage(request(c));
        assert!(packages.is_empty(), "{c}");
        assert!(
            !paths.iter().any(|(_, p)| p.concrete_path() == Some("/")),
            "{c}"
        );
        if !c.contains("link") {
            assert!(
                paths
                    .iter()
                    .any(|(role, p)| *role == ResolvedPathRole::Target
                        && p.concrete_path().is_none()),
                "{c}: {paths:?}"
            );
        }
    }
}

#[test]
fn service_control_has_queryable_opacity_without_fabricated_pids_or_children() {
    for c in [
        "brew services start redis",
        "brew services stop redis",
        "brew services restart --all",
        "brew services run redis",
        "brew services kill redis",
        "brew services cleanup",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::SelectionError), "{c}");
        let (paths, packages, semantics) = stage(request(c));
        assert!(paths.is_empty() && packages.is_empty(), "{c}");
        assert_eq!(semantics.len(), 1, "{c}");
        assert!(semantics[0].operation_semantics_unresolved, "{c}");
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.process_control_action.is_none()),
            "{c}"
        );
    }
    for c in [
        "brew services",
        "brew services list --json",
        "brew services info --all",
        "brew services info redis --json",
    ] {
        check(c, Decision::Allow);
    }
}

#[test]
fn brewfile_ruby_and_external_execution_languages_are_not_reparsed_as_bash() {
    for c in [
        "brew bundle",
        "brew bundle list --install",
        "brew bundle exec rm -rf /",
        "brew bundle --file=./Brewfile install",
        "brew ruby -e 'system(\"rm -rf /\")'",
        "brew exec rm -rf /",
        "brew x rm -rf /",
        "brew custom-command rm -rf /",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::SelectionError), "{c}");
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "rm"),
            "{c}"
        );
    }
}

#[test]
fn unsupported_forms_and_option_gaps_require_approval() {
    for c in [
        "brew tap owner/repo",
        "brew untap owner/repo",
        "brew update",
        "brew pin curl",
        "brew install --with-feature curl",
        "brew list --future",
        "brew list -qZ",
        "brew install --appdir",
        "brew install --appdir=/tmp/project/apps --cc",
        "brew info --eval-all",
        "brew search --eval-all curl",
        "brew info ./recipe",
        "brew info https://example.test/recipe",
        "brew -q list",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "brew" && s.operation_semantics_unresolved),
            "{c}"
        );
    }
}

#[test]
fn known_effects_survive_a_future_option_without_scope_or_source_suppression() {
    let c = "brew install --appdir=/etc/output https://example.test/recipe --future";
    let r = check(c, Decision::NeedApproval);
    for rule in [
        RuleId::SelectionError,
        RuleId::OutsideWorkspaceMutation,
        RuleId::ImportedPackageExecution,
    ] {
        assert!(proposed(&r, rule), "{rule:?}");
    }
    let (paths, packages, semantics) = stage(request(c));
    assert!(has_write(&paths, "/etc/output"));
    assert!(!packages.is_empty());
    assert!(
        semantics
            .iter()
            .any(|s| s.operation_semantics_unresolved && s.executes_imported_package_logic)
    );
}

#[test]
fn cleanup_previews_and_help_do_not_become_mutations() {
    for c in [
        "brew cleanup -n",
        "brew cleanup --dry-run --prune=all",
        "brew autoremove --dry-run",
        "brew link -n --overwrite curl",
        "brew unlink --dry-run curl",
        "brew install --help --appdir=/etc/output curl",
    ] {
        check(c, Decision::Allow);
        let (paths, _, _) = stage(request(c));
        assert!(!has_write(&paths, "/etc/output"), "{c}");
        assert!(
            !paths
                .iter()
                .any(|(role, _)| *role == ResolvedPathRole::Target),
            "{c}"
        );
    }
    for c in [
        "brew install --dry-run curl",
        "brew upgrade -n",
        "brew reinstall --dry-run curl",
    ] {
        assert!(
            proposed(&check(c, Decision::NeedApproval), RuleId::SelectionError),
            "{c}"
        );
    }
}

#[test]
fn nested_shell_wrapper_and_cwd_changes_use_the_same_profile_and_guard() {
    for c in [
        "bash -c 'brew install curl'",
        "env brew install curl",
        "command brew install curl",
        "cd /etc; brew install curl",
        "(brew services stop redis)",
        "/opt/homebrew/bin/brew install curl",
        "/home/linuxbrew/.linuxbrew/bin/brew install curl",
    ] {
        check(c, Decision::NeedApproval);
    }
    for c in [
        "bash -c 'brew list'",
        "env brew info curl",
        "command brew list",
        "/opt/homebrew/bin/brew list",
        "/home/linuxbrew/.linuxbrew/bin/brew list",
    ] {
        check(c, Decision::Allow);
    }
    assert_eq!(
        check("brew list --future; rm -rf /", Decision::Deny).decision,
        Decision::Deny
    );
}

#[test]
fn explicit_cache_override_is_checked_but_default_cache_remains_incidental() {
    check(
        "HOMEBREW_CACHE=/etc/cache brew info curl",
        Decision::NeedApproval,
    );
    check(
        "HOMEBREW_CACHE=/tmp/project/cache brew info curl",
        Decision::Allow,
    );
    check("brew info curl", Decision::Allow);
}

#[test]
fn unknown_environment_is_not_fabricated_as_an_absent_cache_override() {
    let mut req = request("brew info curl");
    req.shell_state_before = ShellStateSnapshot::new("/tmp/project");
    let r = ShellQueryCore::new().check(req);
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(proposed(&r, RuleId::OutsideWorkspaceMutation));
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .all(|s| !s.executes_imported_package_logic && !s.operation_semantics_unresolved)
    );
}
