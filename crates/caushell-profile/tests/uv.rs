//! Static argv/DSL regression tests; no package manager is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => {
            assert!(
                resolved.bound.residuals.is_empty(),
                "{command}: {:?}",
                resolved.bound.residuals
            );
            resolved.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            _ => panic!(),
        })
        .collect()
}

#[test]
fn run_preserves_parent_preparation_and_typed_child_argv() {
    let bound = resolve("uv run --locked --with numpy --python 3.12 -- pytest --cache-clear -q");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic)
    );
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "pytest");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|v| v.text.as_str())
            .collect::<Vec<_>>(),
        ["--cache-clear", "-q"]
    );
    assert_eq!(values(&bound, "with_packages"), ["numpy"]);
    assert_eq!(values(&bound, "python"), ["3.12"]);
}

#[test]
fn no_sync_skips_dependency_sync_but_not_possible_environment_creation() {
    let bound = resolve("uv run --no-sync echo hello");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(!bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.purpose == Some(PathPurpose::ProjectConfig))));
    for command in [
        "uv run --no-sync --with numpy echo ok",
        "uv run --no-sync --with-editable . echo ok",
        "uv run --no-sync --with-requirements req echo ok",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic),
            "{command}"
        );
    }
}

#[test]
fn module_dispatch_constructs_interpreter_argv_not_a_fake_executable() {
    let bound = resolve("uv run --no-sync -m uvicorn app:app --host=0.0.0.0");
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "python");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|v| v.text.as_str())
            .collect::<Vec<_>>(),
        ["-m", "uvicorn", "app:app", "--host=0.0.0.0"]
    );
    assert!(child.argv[0].runtime_data);
}

#[test]
fn local_script_stdin_and_remote_script_have_distinct_execution_sources() {
    for command in [
        "uv run --no-sync script.py --help",
        "uv run --script extensionless arg",
        "uv run --no-sync -",
    ] {
        let bound = resolve(command);
        assert_eq!(
            collect_dispatch_command_candidates(&bound)[0].command.text,
            "python"
        );
        assert!(bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.missing == ConfiguredPathMissing::Unknown)), "{command}");
    }
    let bound = resolve("uv run https://example.test/script.py arg");
    assert!(collect_dispatch_command_candidates(&bound).is_empty());
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic)
    );
}

#[test]
fn global_options_can_follow_subcommand_but_never_steal_child_options() {
    let bound = resolve(
        "uv --directory /first run --directory /second --project /repo --no-sync echo --directory /child --help",
    );
    assert_eq!(values(&bound, "directory"), ["/first", "/second"]);
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(
        child
            .argv
            .iter()
            .map(|v| v.text.as_str())
            .collect::<Vec<_>>(),
        ["--directory", "/child", "--help"]
    );
}

#[test]
fn locked_and_frozen_keep_environment_writes_but_not_lockfile_writes() {
    for command in [
        "uv run --locked echo ok",
        "uv run --frozen -m pytest",
        "uv sync --locked",
        "uv sync --frozen",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
        assert!(!bound.effects.iter().any(|e| e.kind == EffectKind::WritePath && matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.purpose == Some(PathPurpose::ProjectConfig))), "{command}");
    }
}

#[test]
fn explicit_pip_targets_require_filesystem_effects_and_all_sources_are_retained() {
    for command in [
        "uv pip install --target local numpy https://example.test/pkg.whl",
        "uv pip install --prefix local -r req -e .",
        "uv pip sync --target local req",
        "uv pip uninstall --target local numpy",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DeletePath),
            "{command}"
        );
    }
    let bound = resolve("uv pip install --target local numpy https://example.test/pkg.whl");
    assert_eq!(
        values(&bound, "packages"),
        ["numpy", "https://example.test/pkg.whl"]
    );
    assert!(
        matches!(bound.bound_parameters.iter().find(|p| p.name.as_str() == "packages").unwrap().semantic, SemanticType::PackageLocator(ref p) if p.manager == PackageManagerKind::Uv)
    );
}

#[test]
fn venv_creation_and_clear_are_not_incidental_caches() {
    for command in [
        "uv venv local",
        "uv venv --no-project",
        "uv venv --clear local",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
        assert!(!bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.missing == ConfiguredPathMissing::IncidentalCache)));
    }
    assert!(
        resolve("uv venv --clear local")
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
}

#[test]
fn informational_and_read_only_pip_forms_do_not_modify_environments() {
    for command in [
        "uv --help",
        "uv --version",
        "uv run --help",
        "uv pip install --help",
        "uv sync --help",
        "uv venv --help",
        "uv pip list",
        "uv pip freeze",
        "uv pip show numpy",
        "uv pip tree",
        "uv pip check",
        "uv help run",
    ] {
        let bound = resolve(command);
        assert!(
            !bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::DeletePath
                    | EffectKind::DispatchCommand
                    | EffectKind::ExecuteImportedPackageLogic
            )),
            "{command}: {bound:?}"
        );
    }
}

#[test]
fn generic_literal_dispatch_rejects_ambiguous_command_sources() {
    let base = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary-wrapper}\nforms:\n  - id: run\n    effects:\n      - kind: dispatch_command\n        target: {kind: dispatch, command_literal: echo, argv_prefix: ['$(rm -rf /)', '']}\n";
    let profile = load_command_profile_from_str(base).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command("arbitrary-wrapper", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!()
    };
    let child = collect_dispatch_command_candidates(&resolved.bound).remove(0);
    assert_eq!(child.argv[0].text, "$(rm -rf /)");
    assert!(child.argv[0].runtime_data);
    assert_eq!(child.argv[1].text, "");
    assert!(
        load_command_profile_from_str(&base.replace(
            "command_literal: echo",
            "command_literal: echo, command: cmd"
        ))
        .is_err()
    );
}

#[test]
fn shared_cwd_and_environment_declarations_validate_their_contract() {
    let base = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary-wrapper}\nforms:\n  - id: run\n    effects:\n      - kind: set_execution_working_directory\n        target: {kind: configured_path, sources: [], missing: unknown}\n";
    assert!(load_command_profile_from_str(base).is_ok());
    assert!(
        load_command_profile_from_str(&base.replace(
            "{kind: configured_path, sources: [], missing: unknown}",
            "{kind: none}"
        ))
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&base.replace("missing: unknown", "missing: skip")).is_err()
    );
    assert!(
        load_command_profile_from_str(&base.replace(
            "missing: unknown",
            "missing: incidental_cache, purpose: incidental_cache"
        ))
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&base.replace(
            "missing: unknown",
            "missing: unknown, unresolved_relative_base: true, relative_to: {slot: root}"
        ))
        .is_err()
    );
    let dispatch = base
        .replace(
            "kind: set_execution_working_directory",
            "kind: dispatch_command",
        )
        .replace(
            "{kind: configured_path, sources: [], missing: unknown}",
            "{kind: dispatch, command_literal: echo, unknown_environment_when: [missing_modifier]}",
        );
    assert!(load_command_profile_from_str(&dispatch).is_err());
}

#[test]
fn run_without_command_still_dispatches_the_implicit_interpreter() {
    for command in [
        "uv run",
        "uv run --no-sync",
        "uv run --locked",
        "uv run --frozen",
    ] {
        let bound = resolve(command);
        let candidates = collect_dispatch_command_candidates(&bound);
        assert_eq!(candidates.len(), 1, "{command}");
        assert_eq!(candidates[0].command.text, "python");
        assert!(candidates[0].argv.is_empty());
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
}
