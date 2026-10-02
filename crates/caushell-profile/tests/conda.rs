//! Profile/argv tests only: no Conda command is executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    PackageManagerKind, ProfileRegistry, ResolveInvocationResult, SemanticType, resolve_invocation,
};
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => {
            assert!(
                result.bound.residuals.is_empty(),
                "{command}: {:?}",
                result.bound.residuals
            );
            result.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)
        .map(|p| {
            p.values
                .iter()
                .map(|v| match v {
                    BoundValue::Argument { text, .. } => text.clone(),
                    other => panic!("{slot}: {other:?}"),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn registers_conda_and_executable_path() {
    assert_eq!(
        ProfileRegistry::built_in()
            .unwrap()
            .lookup("conda")
            .profile
            .unwrap()
            .primary_name(),
        "conda"
    );
    assert_eq!(
        resolve("/usr/bin/conda install numpy")
            .command_name
            .as_str(),
        "conda"
    );
}

#[test]
fn all_transaction_entry_points_declare_target_mutations() {
    for command in [
        "conda install numpy",
        "conda update --all",
        "conda upgrade numpy",
        "conda create -n dev python",
        "conda create -p ./dev --clone base",
        "conda remove numpy",
        "conda uninstall numpy",
        "conda remove --all",
        "conda env create",
        "conda env create -f environment.yml",
        "conda env update",
        "conda env update -f environment.yml --prune",
        "conda env remove -n dev",
    ] {
        let bound = resolve(command);
        for kind in [EffectKind::WritePath, EffectKind::DeletePath] {
            assert!(bound.effects.iter().any(|e| e.kind == kind && matches!(&e.target, EffectTarget::ConfiguredPath(_))), "{command}: {bound:?}");
        }
    }
}

#[test]
fn name_is_plain_metadata_not_a_guessed_environment_path() {
    let bound = resolve("conda install --name=dev numpy");
    assert_eq!(values(&bound, "environment_name"), ["dev"]);
    assert!(values(&bound, "prefix").is_empty());
    assert!(
        bound
            .bound_parameters
            .iter()
            .filter(|p| p.name.as_str() == "environment_name")
            .all(|p| matches!(p.semantic, SemanticType::PlainValue))
    );
}

#[test]
fn prefix_aliases_equals_and_repetitions_preserve_real_argv_values() {
    let bound = resolve("conda install -p old --prefix=env numpy");
    assert_eq!(values(&bound, "prefix"), ["old", "env"]);
    assert_eq!(values(&bound, "packages"), ["numpy"]);
}

#[test]
fn package_imports_carry_manager_metadata_without_command_name_checks() {
    let bound = resolve("conda install -p env 'python>=3.12' conda-forge/linux-64::numpy");
    let packages = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "packages")
        .unwrap();
    assert!(
        matches!(&packages.semantic, SemanticType::PackageLocator(s) if s.manager == PackageManagerKind::Conda)
    );
    assert_eq!(
        values(&bound, "packages"),
        ["python>=3.12", "conda-forge/linux-64::numpy"]
    );
}

#[test]
fn standard_previews_have_no_environment_mutation_or_package_execution() {
    for command in [
        "conda install --dry-run numpy",
        "conda update -d --all",
        "conda create --dry-run -n dev python",
        "conda remove -d --all",
        "conda env create --dry-run",
        "conda env create -d -f environment.yml",
        "conda env remove --dry-run -n dev",
    ] {
        let bound = resolve(command);
        assert!(
            !bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::DeletePath
                    | EffectKind::ExecuteImportedPackageLogic
            )),
            "{command}: {bound:?}"
        );
    }
}

#[test]
fn download_only_is_not_a_blanket_create_exemption() {
    for command in [
        "conda install --download-only numpy",
        "conda update --download-only numpy",
    ] {
        assert!(!resolve(command).effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::WritePath
                | EffectKind::DeletePath
                | EffectKind::ExecuteImportedPackageLogic
        )));
    }
    let bound = resolve("conda create -n dev --download-only python");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic)
    );
}

#[test]
fn standard_file_and_channel_flags_bind_every_occurrence() {
    let bound = resolve(
        "conda install --solver=libmamba --revision 2 --file first.txt -f second.yml -c conda-forge --channel=https://packages.example.test -p env numpy",
    );
    assert_eq!(values(&bound, "definitions"), ["first.txt", "second.yml"]);
    assert_eq!(
        values(&bound, "channels"),
        ["conda-forge", "https://packages.example.test"]
    );
    assert_eq!(values(&bound, "packages"), ["numpy"]);
    assert_eq!(values(&bound, "option_values"), ["libmamba", "2"]);
}

#[test]
fn env_create_keeps_multiple_definition_inputs() {
    let bound = resolve("conda env create -p env -f base.yml extra.yml");
    assert_eq!(values(&bound, "definitions"), ["base.yml"]);
    assert_eq!(values(&bound, "extra_definitions"), ["extra.yml"]);
}

#[test]
fn query_short_flags_are_not_transaction_file_options() {
    for command in [
        "conda list -n dev -f numpy -c --fields=name,version",
        "conda info --envs --json",
        "conda env list --json",
        "conda search -f numpy -c conda-forge --info",
    ] {
        let bound = resolve(command);
        assert!(
            !bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::DeletePath
                    | EffectKind::ExecuteImportedPackageLogic
            )),
            "{command}: {bound:?}"
        );
        assert!(values(&bound, "definitions").is_empty());
    }
}

#[test]
fn export_file_is_an_output_and_does_not_expand_tool_environment_or_home() {
    for command in ["conda export -f out.yml", "conda env export --file=out.yml"] {
        let bound = resolve(command);
        assert_eq!(values(&bound, "export_file"), ["out.yml"]);
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::WritePath &&
            matches!(&e.target, EffectTarget::ConfiguredPath(path) if !path.expand_environment && !path.expand_user)));
    }
}

#[test]
fn global_flags_and_help_do_not_create_mutation_effects() {
    for command in [
        "conda --help",
        "conda --version",
        "conda",
        "conda env",
        "conda install --help",
        "conda --no-plugins --debug create --help",
        "conda env create --help",
        "conda remove --help",
    ] {
        assert!(resolve(command).effects.is_empty(), "{command}");
    }
}

#[test]
fn pending_activation_and_unmodeled_commands_are_not_claimed_as_resolved() {
    for command in [
        "conda run -n dev rm -rf /outside",
        "conda activate dev",
        "conda deactivate",
        "conda config --set auto_activate_base false",
        "conda clean --all",
        "conda init bash",
        "conda rename old new",
        "conda env config vars set KEY=value",
        "conda unknown-plugin-command",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            !matches!(
                resolve_invocation(
                    &ProfileRegistry::built_in().unwrap(),
                    &parsed.commands[0],
                    InvocationRuntimeContext::new()
                ),
                ResolveInvocationResult::Resolved(_)
            ),
            "{command}"
        );
    }
}
