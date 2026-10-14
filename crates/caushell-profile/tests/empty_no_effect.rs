use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn bound(command: &str, empty_is_disabled: bool, bindings: &SessionBindings) -> BoundInvocation {
    let branch = if empty_is_disabled {
        "branches: [{matcher: {kind: regex_capture, pattern: '^$', group: 0}, target: null}]"
    } else {
        "branches: []"
    };
    let profile = load_command_profile_from_str(&format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: encoded-value}}
forms:
  - id: run
    parameters:
      - name: operand
        semantic: {{kind: plain_value}}
        binding: {{kind: next_positional}}
        cardinality: required_one
        structured_projection:
          {branch}
          fallback: {{name: output, semantic: {{kind: path, role: write}}}}
    effects: [{{kind: write_path, target: {{kind: slot, name: output}}}}]
"#
    ))
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(value) => value.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{other:?}"),
    }
}

#[test]
fn explicitly_disabled_empty_scalar_is_not_missing_or_unknown() {
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("EMPTY", "");
    for command in ["encoded-value ''", "encoded-value \"$EMPTY\""] {
        let value = bound(command, true, &bindings);
        let output = value
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "output")
            .unwrap();
        assert!(output.semantic_values_are_inapplicable(), "{value:#?}");
    }
    for (command, branch) in [
        ("encoded-value", true),
        ("encoded-value \"$UNKNOWN\"", true),
        ("encoded-value ''", false),
    ] {
        let value = bound(command, branch, &bindings);
        let output = value
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "output")
            .unwrap();
        assert!(!output.semantic_values_are_inapplicable(), "{value:#?}");
    }
}
