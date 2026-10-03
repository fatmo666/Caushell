use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: structured-tool}
forms:
  - id: transform
    parameters:
      - name: source
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        structured_projection:
          separator: ';'
          branches:
            - matcher: {kind: literal, value: console}
            - matcher: {kind: prefix, value: 'exec:'}
              target: {name: children, semantic: {kind: command_ref, dispatch: wrapper_command}}
          fallback: {name: paths, semantic: {kind: path, role: write}}
    effects:
      - {kind: dispatch_command, target: {kind: dispatch, command_whitespace_argv: children, stdin_from_parent: true}}
      - {kind: write_path, target: {kind: slot, name: paths}}
"#;

fn resolved(command: &str, bindings: &SessionBindings) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(PROFILE).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{other:?}"),
    }
}

#[test]
fn grammar_is_declarative_and_not_bound_to_a_command_name_or_separator() {
    let bound = resolved(
        "structured-tool 'console;data;exec:cat;exec:echo done'",
        &SessionBindings::new(),
    );
    let projection = collect_dispatch_command_projection(&bound);
    assert_eq!(
        projection
            .resolved
            .iter()
            .map(|c| c.command.text.as_str())
            .collect::<Vec<_>>(),
        ["cat", "echo"]
    );
    assert!(projection.resolved.iter().all(|c| c.stdin_from_parent));
    let paths = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "paths")
        .unwrap();
    assert_eq!(paths.structured_source.as_ref().unwrap().as_str(), "source");
    assert!(
        matches!(paths.semantic_values().next().unwrap(), SemanticValueRef::Projected { value: ProjectedSemanticValue { resolution: SemanticValueResolution::Known(value), .. }, .. } if value == "data")
    );
}

#[test]
fn resolved_outer_expansions_are_not_expanded_again_inside_encoded_argv() {
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("OUTPUT", "exec:echo $INNER");
    bindings.insert_exact_scalar("INNER", "should-not-expand");
    let bound = resolved("structured-tool \"$OUTPUT\"", &bindings);
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "echo");
    assert_eq!(child.argv[0].text, "$INNER");
}

#[test]
fn encoded_executable_is_argv_data_even_when_it_contains_shell_syntax() {
    let bound = resolved(
        "structured-tool 'exec:$PROGRAM /opt/example'",
        &SessionBindings::new(),
    );
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    let fact = child.to_command_fact();
    assert!(fact.command_name_runtime_data);
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("PROGRAM", "rm");
    let registry = ProfileRegistry::built_in().unwrap();
    assert!(
        matches!(resolve_invocation_with_bindings(&registry, &fact, InvocationRuntimeContext::new(), &bindings), ResolveInvocationResult::NoProfile { normalized_command_name, .. } if normalized_command_name == "$PROGRAM")
    );
}

#[test]
fn unknown_input_preserves_both_mutation_and_unresolved_execution() {
    let bound = resolved("structured-tool \"$UNKNOWN\"", &SessionBindings::new());
    assert_eq!(
        collect_dispatch_command_projection(&bound).unresolved.len(),
        1
    );
    let paths = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "paths")
        .unwrap();
    assert!(matches!(
        paths.semantic_values().next().unwrap(),
        SemanticValueRef::Projected {
            value: ProjectedSemanticValue {
                resolution: SemanticValueResolution::Unknown(_),
                ..
            },
            ..
        }
    ));
}

#[test]
fn projected_source_spans_and_original_operands_are_preserved() {
    let bound = resolved(
        "structured-tool 'file;exec:echo literal'",
        &SessionBindings::new(),
    );
    let source = &bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "source")
        .unwrap()
        .values[0];
    for parameter in bound
        .bound_parameters
        .iter()
        .filter(|p| p.structured_source.is_some())
    {
        assert!(parameter.values.iter().all(|v| v == source));
    }
}

#[test]
fn invalid_declarations_are_rejected_at_load_time() {
    load_command_profile_from_str(PROFILE).unwrap();
    for invalid in [
        PROFILE.replace("separator: ';'", "separator: ''"),
        PROFILE.replace("name: paths", "name: source"),
        PROFILE.replace(
            "name: paths, semantic:",
            "name: paths, sources: [missing], semantic:",
        ),
        PROFILE.replace(
            "command_whitespace_argv: children",
            "command_whitespace_argv: missing",
        ),
        PROFILE.replace(
            "command_whitespace_argv: children",
            "command_whitespace_argv: children, command_literal: echo",
        ),
        PROFILE.replace(
            "command_whitespace_argv: children",
            "command_whitespace_argv: children, argv_prefix: [extra]",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}
