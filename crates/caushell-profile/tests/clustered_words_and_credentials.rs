use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) else {
        panic!("{command}");
    };
    assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
    r.bound
}
fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .filter_map(|v| match v {
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(s) => Some(s.clone()),
                _ => None,
            },
            SemanticValueRef::Original(BoundValue::Argument { text, .. }) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn zip_clusters_retain_every_native_modifier() {
    for (command, modifiers) in [
        ("zip -rq cache/out.zip cache/input", vec!["archive_layout"]),
        (
            "zip -mT cache/out.zip cache/input",
            vec!["move_sources", "test_mode"],
        ),
        (
            "zip -jmT cache/out.zip cache/input",
            vec!["archive_layout", "move_sources", "test_mode"],
        ),
    ] {
        let b = resolve(command);
        for m in modifiers {
            assert!(
                b.applied_modifiers.iter().any(|v| v.as_str() == m),
                "{command}: {b:#?}"
            );
        }
        assert_eq!(values(&b, "input_paths"), ["cache/input"]);
    }
}

#[test]
fn generic_declared_words_own_attached_operands_and_longest_names() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: word-tool}
option_scope: permuted_options
option_matching: declared_short_words
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: paths, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - {id: flags, matcher: {kind: any_flag, flags: [-q, -T]}}
  - id: command
    matcher: {kind: any_flag, flags: [-TT]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
"#;
    let profile = load_command_profile_from_str(yaml).unwrap();
    for spelling in [
        "-qTTpayload",
        "-qTT=payload",
        "-qTT payload",
        "-TTpayload -q",
    ] {
        let command = format!("word-tool {spelling} target -- -TTdata");
        let parsed = parse_command(&command, ShellKind::Bash).unwrap();
        let projection =
            project_invocation(&parsed.commands[0], InvocationRuntimeContext::default());
        let selected = select_invocation(&profile, &projection).unwrap();
        let b = bind_invocation(&profile, &projection, &selected);
        assert!(b.residuals.is_empty(), "{command}: {b:#?}");
        assert_eq!(values(&b, "value"), ["payload"]);
        assert_eq!(values(&b, "paths"), ["target", "-TTdata"]);
        assert!(b.applied_modifiers.iter().any(|m| m.as_str() == "flags"));
    }
    for command in ["word-tool -qZ file", "word-tool -TT"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection =
            project_invocation(&parsed.commands[0], InvocationRuntimeContext::default());
        let selected = select_invocation(&profile, &projection);
        assert!(
            selected.is_err()
                || !bind_invocation(&profile, &projection, &selected.unwrap())
                    .residuals
                    .is_empty()
        );
    }
    assert!(
        load_command_profile_from_str(&yaml.replace("permuted_options", "all_arguments")).is_err()
    );
}

#[test]
fn passphrase_source_projects_typed_inputs_not_fake_payloads() {
    for (source, file, env) in [
        ("file:.env", Some(".env"), None),
        ("file:cache/a:b", Some("cache/a:b"), None),
        ("fd:03", Some("/dev/fd/3"), None),
        ("stdin", Some("/dev/stdin"), None),
        ("env:LAB_PASSWORD", None, Some("LAB_PASSWORD")),
        ("pass:", None, None),
        ("pass:literal", None, None),
    ] {
        let b = resolve(&format!(
            "openssl enc -aes-256-cbc -in cache/input -out cache/output -pass {source}"
        ));
        assert!(!b.operation_semantics_unresolved, "{b:#?}");
        assert_eq!(
            values(&b, "credential_file"),
            file.into_iter().map(String::from).collect::<Vec<_>>()
        );
        assert_eq!(
            values(&b, "credential_environment"),
            env.into_iter().map(String::from).collect::<Vec<_>>()
        );
        assert!(b.is_auxiliary_input_slot("passphrase_source"));
    }
    let b =
        resolve("openssl enc -in cache/input -out cache/output -pass file:.env -pass pass:literal");
    assert!(values(&b, "credential_file").is_empty());
    for source in ["file:", "env:", "fd:-1", "fd:999999999999", "bogus"] {
        let b = resolve(&format!("openssl enc -in cache/input -pass {source}"));
        assert!(b.operation_semantics_unresolved, "{source}: {b:#?}");
    }
}
