use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
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

#[test]
fn pytest_registers_both_real_entry_points() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["pytest", "py.test", "/usr/bin/pytest"] {
        assert_eq!(
            registry.lookup(name).profile.unwrap().primary_name(),
            "pytest"
        );
    }
}

#[test]
fn selector_original_value_and_source_are_preserved() {
    let bound = resolve("pytest tests/test_api.py::TestAPI::test_login");
    let parameter = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "tests")
        .unwrap();
    let BoundValue::Argument {
        text,
        span,
        binding_source,
        ..
    } = &parameter.values[0]
    else {
        panic!()
    };
    assert_eq!(text, "tests/test_api.py::TestAPI::test_login");
    assert!(span.end_byte > span.start_byte);
    assert!(matches!(
        binding_source,
        caushell_profile::ArgumentBindingSource::Positional { .. }
    ));
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}

#[test]
fn overrides_bind_once_and_preserve_all_keys_and_occurrences() {
    let bound = resolve(
        "pytest -o cache_dir=/etc/old --override-ini=console_output_style=classic -o cache_dir=/work/cache -o log_file=/etc/log tests/test.py",
    );
    let overrides = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "overrides")
        .unwrap();
    assert_eq!(overrides.values.len(), 4);
    assert!(
        bound
            .effects
            .iter()
            .filter(|e| matches!(e.target, EffectTarget::ConfiguredPath(_)))
            .count()
            >= 2
    );
    assert_eq!(
        bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "tests")
            .unwrap()
            .values
            .len(),
        1
    );
}

#[test]
fn report_aliases_and_repeated_arguments_are_fully_bound() {
    for command in [
        "pytest --junitxml=a.xml --junit-xml=b.xml tests/test.py",
        "pytest --rootdir=/work --rootdir=/other -c config/pytest.ini --log-file=/etc/log --basetemp=/tmp/base tests/test.py",
        "pytest --debug=/etc/debug tests/test.py",
    ] {
        resolve(command);
    }
}

#[test]
fn normal_builtin_cli_options_do_not_become_test_paths() {
    let bound = resolve(
        "pytest -q -x -k login -m slow --maxfail=2 --capture=no --tb=short --color=no --show-capture=all -r a --import-mode=importlib --log-level=INFO tests/test_api.py::test_login",
    );
    assert_eq!(
        bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "tests")
            .unwrap()
            .values
            .len(),
        1
    );
}

#[test]
fn disabled_cache_does_not_emit_cache_writes_or_clears() {
    for command in [
        "pytest -p no:cacheprovider tests/",
        "pytest -p no:cacheprovider --cache-clear -o cache_dir=/etc/cache tests/",
    ] {
        let bound = resolve(command);
        assert!(!bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(path) if path.purpose == Some(caushell_profile::PathPurpose::IncidentalCache))), "{command}: {bound:?}");
    }
}

#[test]
fn pyargs_are_module_loads_not_filesystem_selectors() {
    for command in [
        "pytest --pyargs pkg.tests",
        "pytest --pyargs -p no:cacheprovider pkg.tests",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "modules")
        );
        assert!(
            !bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "tests")
        );
        assert!(!bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    }
}

#[test]
fn cache_show_does_not_claim_test_execution_or_cache_writes() {
    for command in [
        "pytest --cache-show",
        "pytest --cache-show 'cache/*' --cache-clear",
    ] {
        let bound = resolve(command);
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode)
        );
        assert!(!bound.effects.iter().any(|e| e.kind == EffectKind::WritePath && matches!(&e.target, EffectTarget::ConfiguredPath(path) if path.purpose == Some(caushell_profile::PathPurpose::IncidentalCache))));
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    }
}

#[test]
fn information_has_no_incidental_cache_or_test_execution() {
    for command in ["pytest -h", "pytest --version", "py.test -V"] {
        let bound = resolve(command);
        assert!(bound.effects.is_empty());
    }
}

const GENERIC: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: configured-tool}
forms:
  - id: run
    parameters:
      - {name: overrides, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
    effects:
      - kind: write_path
        target:
          kind: configured_path
          sources: [{slot: overrides, projection: {kind: key_value, key: cache, separator: '='}}]
          missing: incidental_cache
          purpose: incidental_cache
"#;

#[test]
fn configured_path_declarations_are_command_independent() {
    load_command_profile_from_str(GENERIC).unwrap();
}

#[test]
fn invalid_cache_exemptions_and_undeclared_slots_are_rejected() {
    for yaml in [
        GENERIC.replace("kind: write_path", "kind: delete_path"),
        GENERIC.replace("purpose: incidental_cache", "purpose: generic_operand"),
        GENERIC.replace("slot: overrides", "slot: typo"),
        GENERIC.replace("missing: incidental_cache", "missing: incidental_cache\n          default_value: cache"),
        GENERIC.replace("sources: [{slot: overrides, projection: {kind: key_value, key: cache, separator: '='}}]", "sources: []"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
}

#[test]
fn misspelled_configured_path_fields_are_not_silently_ignored() {
    for yaml in [
        GENERIC.replace("missing:", "misssing:"),
        GENERIC.replace("slot: overrides", "slot: overrides, surprise: true"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err());
    }
}
