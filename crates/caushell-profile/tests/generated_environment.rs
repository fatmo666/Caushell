use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{RuntimeArgumentDomain, ShellKind};

fn source(generated: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary_producer}}
forms:
  - id: produce
    selector: {{kind: all, items: []}}
    parameters:
      - {{name: prefix, semantic: {{kind: plain_value}}, binding: {{kind: positional_at, index: 0}}, cardinality: optional_one}}
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          command_literal: cat
          generated_environment: {generated}
modifiers: []
"#
    )
}

#[test]
fn declaration_validation_is_command_independent_and_checks_slot_ownership() {
    let valid = "[{name: OUTPUT, value: {kind: alphanumeric_file_name, prefix_slot: prefix, default_prefix: x}}]";
    let profile = load_command_profile_from_str(&source(valid)).unwrap();
    assert_eq!(profile.primary_name(), "arbitrary_producer");
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command("arbitrary_producer cache/p_", ShellKind::Bash).unwrap();
    let result = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = result else {
        panic!("{result:#?}")
    };
    assert_eq!(
        collect_dispatch_command_candidates(&result.bound)[0].generated_environment,
        vec![(
            "OUTPUT".into(),
            Some(RuntimeArgumentDomain::GeneratedFileName {
                prefix: "cache/p_".into(),
                suffix: "".into(),
            })
        )]
    );
    let duplicate = source(valid).replace(
        "          generated_environment:",
        "          unknown_environment_names: [OUTPUT]\n          generated_environment:",
    );
    assert!(load_command_profile_from_str(&duplicate).is_err());
    for generated in [
        "[{name: 'BAD-NAME', value: {kind: alphanumeric_file_name, prefix_slot: prefix, default_prefix: x}}]",
        "[{name: OUTPUT, value: {kind: alphanumeric_file_name, prefix_slot: missing, default_prefix: x}}]",
        "[{name: OUTPUT, value: {kind: alphanumeric_file_name, prefix_slot: prefix, suffix_slot: missing, default_prefix: x}}]",
        "[{name: OUTPUT, value: {kind: not_supported}}]",
        "[{name: OUTPUT, value: {kind: alphanumeric_file_name, prefix_slot: prefix, default_prefix: x}}, {name: OUTPUT, value: {kind: alphanumeric_file_name, prefix_slot: prefix, default_prefix: x}}]",
    ] {
        assert!(
            load_command_profile_from_str(&source(generated)).is_err(),
            "{generated}"
        );
    }
}

fn split(command: &str) -> Vec<(String, Option<RuntimeArgumentDomain>)> {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let result = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = result else {
        panic!("{result:#?}")
    };
    let candidates = collect_dispatch_command_candidates(&result.bound);
    assert_eq!(candidates.len(), 1, "{command}: {result:#?}");
    candidates[0].generated_environment.clone()
}

#[test]
fn split_declares_an_unknown_generated_name_not_a_fabricated_value() {
    for (command, prefix, suffix) in [
        ("split --filter='cat >$FILE'", "x", ""),
        ("split in cache/p_ --filter='cat >$FILE'", "cache/p_", ""),
        (
            "split --additional-suffix=.bak in /opt/p_ --filter='cat >$FILE'",
            "/opt/p_",
            ".bak",
        ),
        (
            "split --additional-suffix=.a --additional-suffix=.b in --filter='cat >$FILE'",
            "x",
            ".b",
        ),
    ] {
        assert_eq!(
            split(command),
            vec![(
                "FILE".into(),
                Some(RuntimeArgumentDomain::GeneratedFileName {
                    prefix: prefix.into(),
                    suffix: suffix.into(),
                })
            )]
        );
    }
    assert_eq!(
        split("split in \"$unknown\" --filter='cat >$FILE'"),
        vec![("FILE".into(), None)]
    );
}

#[test]
fn exported_domains_follow_environment_lifetime_and_scalar_reassignment() {
    let domain = RuntimeArgumentDomain::GeneratedFileName {
        prefix: "cache/p_".into(),
        suffix: "".into(),
    };
    let mut bindings = SessionBindings::new();
    bindings.set_child_environment_domain("OUTPUT", Some(domain.clone()));
    bindings.enter_child_shell_environment();
    assert_eq!(bindings.argument_domain("OUTPUT"), Some(&domain));
    let mut child = bindings.clone();
    child.unexport("OUTPUT");
    child.enter_child_shell_environment();
    assert_eq!(child.argument_domain("OUTPUT"), None);
    let mut child = bindings.clone();
    child.reset_child_environment(true);
    assert_eq!(child.argument_domain("OUTPUT"), None);
    bindings.insert_exact_scalar("OUTPUT", "/opt/changed");
    assert_eq!(bindings.argument_domain("OUTPUT"), None);
}
