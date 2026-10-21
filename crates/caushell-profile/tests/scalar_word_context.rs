use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn custom_profile(context: &str) -> CommandProfile {
    load_command_profile_from_str(&format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
{context}
identity: {{canonical_name: scalar_test, aliases: []}}
forms:
  - id: expression
    selector: {{kind: all, items: []}}
    parameters:
      - name: expression
        semantic: {{kind: plain_value}}
        binding: {{kind: remaining_args}}
        cardinality: optional_many
    effects:
      - kind: bind_variable_from_runtime_input
        target: {{kind: variable_name, name: result}}
"#
    ))
    .unwrap()
}

#[test]
fn scalar_context_is_opt_in_and_preserves_unknown_values() {
    for (declaration, expected) in [("", true), ("word_context: scalar", false)] {
        let registry = ProfileRegistry::from_profiles(vec![custom_profile(declaration)]).unwrap();
        let parsed = parse_command("scalar_test $unknown a* {a,b}", ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
            &SessionBindings::new(),
        ) else {
            panic!("expected resolved invocation")
        };
        assert_eq!(r.bound.operation_semantics_unresolved, expected);
        if !expected {
            assert_eq!(r.materialized_projection.invocation.args.len(), 3);
            let unknown = &r.materialized_projection.invocation.args[0];
            assert!(!unknown.quoted);
            assert!(!unknown.runtime_data);
            assert_eq!(
                argument_structure(unknown).fields,
                ArgumentFieldCount::ExactlyOne
            );
            assert_eq!(argument_structure(unknown).exact_value(), None);
            assert!(matches!(
                r.materialized_projection.arg_resolutions[0],
                ValueMaterialization::MissingBinding { .. }
            ));
            assert_eq!(r.materialized_projection.invocation.args[1].text, "a*");
            assert_eq!(r.materialized_projection.invocation.args[2].text, "{a,b}");
        }
    }
    assert_eq!(custom_profile("").word_context, WordContext::ShellArgument);
}

#[test]
fn scalar_context_keeps_empty_multiword_and_quoted_operands_single() {
    let registry =
        ProfileRegistry::from_profiles(vec![custom_profile("word_context: scalar")]).unwrap();
    let bindings = SessionBindings::new()
        .with_exact_scalar("empty", "")
        .with_exact_scalar("value", "a b *");
    let parsed = parse_command(
        "scalar_test $empty $value \"$value\" pre${value}post",
        ShellKind::Bash,
    )
    .unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &bindings,
    ) else {
        panic!("expected resolved invocation")
    };
    let args = &r.materialized_projection.invocation.args;
    assert_eq!(
        args.iter().map(|a| a.text.as_str()).collect::<Vec<_>>(),
        ["", "a b *", "a b *", "prea b *post"]
    );
    assert_eq!(
        args.iter().map(|a| a.quoted).collect::<Vec<_>>(),
        [false, false, true, false]
    );
    assert!(!r.bound.operation_semantics_unresolved);
}

#[test]
fn bash_regex_effect_depends_on_syntax_not_operand_text() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (source, expected) in [
        ("[[ $value =~ ^[a-z]+$ ]]", "regex_condition"),
        ("[[ $value == a* ]]", "condition"),
        ("[[ '=~' == $value ]]", "condition"),
        ("[[ $operator == $value ]]", "condition"),
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        let bindings = SessionBindings::new().with_exact_scalar("operator", "=~");
        let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
            &bindings,
        ) else {
            panic!("{source}")
        };
        assert_eq!(r.selection.form.id.as_str(), expected, "{source}: {r:#?}");
        assert!(!r.bound.operation_semantics_unresolved, "{source}: {r:#?}");
    }
}

#[test]
fn invalid_word_context_is_rejected() {
    let source = include_str!("../profiles/bash_condition.yaml")
        .replace("word_context: scalar", "word_context: anything");
    let error = load_command_profile_from_str(&source).unwrap_err();
    assert!(error.to_string().contains("unknown variant"), "{error}");
}
