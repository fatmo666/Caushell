//! A Profile's CLI prefix grammar, not Bash lexer changes or tool-name branches.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn load(body: &str) -> CommandProfile {
    load_command_profile_from_str(&format!("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-prefix-tool}}\n{body}")).unwrap()
}

fn profile() -> CommandProfile {
    load(
        r#"
option_prefixes: dash_and_plus
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: query
    parameters:
      - name: operands
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: optional_many
modifiers:
  - {id: minus_a, matcher: {kind: any_flag, flags: [-a]}}
  - {id: plus_a, matcher: {kind: any_flag, flags: [+a]}}
  - {id: plus_b, matcher: {kind: any_flag, flags: [+b]}}
  - id: minus_c
    matcher: {kind: any_flag, flags: [-c]}
    parameters:
      - name: name_filter
        semantic: {kind: plain_value}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        cardinality: required_many
  - id: plus_c
    matcher: {kind: any_flag, flags: [+c]}
    parameters:
      - name: width
        semantic: {kind: plain_value}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        cardinality: required_many
"#,
    )
}

fn projection(command: &str) -> ProjectedInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
}

fn bound(p: &CommandProfile, command: &str) -> BoundInvocation {
    let projected = projection(command);
    let original = projected.clone();
    let selected = select_invocation(p, &projected).unwrap_or_else(|e| panic!("{command}: {e}"));
    let result = bind_invocation(p, &projected, &selected);
    assert_eq!(
        projected, original,
        "public binding must not mutate argv or provenance"
    );
    assert!(result.residuals.is_empty(), "{command}: {result:?}");
    result
}

fn values<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

fn modifiers(b: &BoundInvocation) -> Vec<&str> {
    b.applied_modifiers.iter().map(|m| m.as_str()).collect()
}

#[test]
fn omitted_prefix_policy_preserves_plus_as_positional_data() {
    let p = load(
        "forms: [{id: query, parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]}]\n",
    );
    assert_eq!(p.option_prefixes, OptionPrefixPolicy::DashOnly);
    assert_eq!(
        values(&bound(&p, "arbitrary-prefix-tool +x +%F ++"), "data"),
        ["+x", "+%F", "++"]
    );
    for name in ["date", "chmod", "printf"] {
        assert_eq!(
            ProfileRegistry::built_in()
                .unwrap()
                .lookup(name)
                .profile
                .unwrap()
                .option_prefixes,
            OptionPrefixPolicy::DashOnly
        );
    }
}

#[test]
fn plus_declarations_require_explicit_opt_in() {
    for body in [
        "forms: [{id: query}]\nmodifiers: [{id: plus, matcher: {kind: any_flag, flags: [+a]}}]",
        "forms: [{id: query, parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: +a, operand_mode: next_arg}}]}]",
        "forms: [{id: query}]\nmodifiers: [{id: data, matcher: {kind: any_flag, flags: [-a]}, parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: +a, operand_mode: next_arg}}]}]",
        "forms: [{id: query}]\nsubcommands: {roots: [{name: sub, forms: [{id: query}], modifiers: [{id: plus, matcher: {kind: any_flag, flags: [+a]}}]}]}",
    ] {
        let yaml = format!(
            "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-prefix-tool}}\n{body}"
        );
        assert!(load_command_profile_from_str(&yaml).is_err(), "{body}");
    }
}

#[test]
fn invalid_prefix_policy_and_terminator_as_an_option_are_rejected() {
    for body in [
        "option_prefixes: all\nforms: [{id: query}]",
        "option_prefixes: dash_and_plus\noption_matching: exact_names\noption_scope: leading_options\nforms: [{id: query}]\nmodifiers: [{id: data, matcher: {kind: any_flag, flags: ['++']}}]",
    ] {
        let yaml = format!(
            "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-prefix-tool}}\n{body}"
        );
        assert!(load_command_profile_from_str(&yaml).is_err(), "{body}");
    }
}

#[test]
fn both_signs_remain_distinct_with_separate_and_attached_values() {
    for command in [
        "arbitrary-prefix-tool -c python +c 20",
        "arbitrary-prefix-tool -cpython +c20",
        "arbitrary-prefix-tool '-cpython' '+c20'",
    ] {
        let b = bound(&profile(), command);
        assert_eq!(modifiers(&b), ["minus_c", "plus_c"], "{command}");
        assert_eq!(values(&b, "name_filter"), ["python"]);
        assert_eq!(values(&b, "width"), ["20"]);
    }
}

#[test]
fn plus_clusters_preserve_flag_only_prefix_and_attached_operand() {
    for command in [
        "arbitrary-prefix-tool +abc20",
        "arbitrary-prefix-tool +abc 20",
    ] {
        let b = bound(&profile(), command);
        assert_eq!(modifiers(&b), ["plus_a", "plus_b", "plus_c"]);
        assert_eq!(values(&b, "width"), ["20"]);
    }
}

#[test]
fn operand_suffix_is_not_scanned_as_more_plus_options() {
    let b = bound(&profile(), "arbitrary-prefix-tool +caab");
    assert_eq!(modifiers(&b), ["plus_c"]);
    assert_eq!(values(&b, "width"), ["aab"]);
}

#[test]
fn both_terminators_make_remaining_tokens_data() {
    for separator in ["--", "++"] {
        let c = format!("arbitrary-prefix-tool +a {separator} +c20 -c python ++");
        let b = bound(&profile(), &c);
        assert_eq!(modifiers(&b), ["plus_a"]);
        assert_eq!(values(&b, "operands"), ["+c20", "-c", "python", "++"]);
    }
}

#[test]
fn first_positional_stops_option_recognition_and_single_plus_is_data() {
    for first in ["file.txt", "+", "-"] {
        let c = format!("arbitrary-prefix-tool {first} +a -c python ++");
        let b = bound(&profile(), &c);
        assert!(modifiers(&b).is_empty());
        assert_eq!(values(&b, "operands"), [first, "+a", "-c", "python", "++"]);
    }
}

#[test]
fn option_looking_values_and_terminators_belong_to_their_declared_operand() {
    for operand in ["+a", "-a", "++", "--"] {
        let c = format!("arbitrary-prefix-tool +c {operand} +a");
        let b = bound(&profile(), &c);
        assert_eq!(values(&b, "width"), [operand]);
        assert_eq!(modifiers(&b), ["plus_a", "plus_c"]);
        assert!(values(&b, "operands").is_empty());
    }
}

#[test]
fn unknown_plus_option_or_cluster_member_does_not_certify_a_complete_form() {
    for c in [
        "arbitrary-prefix-tool +q",
        "arbitrary-prefix-tool +aq",
        "arbitrary-prefix-tool +aqc20",
        "arbitrary-prefix-tool +c",
    ] {
        assert!(
            select_invocation(&profile(), &projection(c)).is_err(),
            "{c}"
        );
    }
    let registry = ProfileRegistry::from_profiles(vec![profile()]).unwrap();
    let parsed = parse_command("arbitrary-prefix-tool +aq", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::SelectionError {
        partial_bound: Some(b),
        ..
    } = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
    else {
        panic!("expected retained partial binding")
    };
    assert!(
        b.applied_modifiers.contains(&ModifierId::new("plus_a")),
        "{b:?}"
    );
}

#[test]
fn exact_name_policy_does_not_split_plus_words() {
    let p = load(
        r#"
option_prefixes: dash_and_plus
option_matching: exact_names
option_scope: leading_options
opaque_on_unresolved: true
forms: [{id: query}]
modifiers:
  - {id: a, matcher: {kind: any_flag, flags: [+a]}}
  - {id: ab, matcher: {kind: any_flag, flags: [+ab]}}
"#,
    );
    assert_eq!(modifiers(&bound(&p, "arbitrary-prefix-tool +ab")), ["ab"]);
    assert!(select_invocation(&p, &projection("arbitrary-prefix-tool +aba")).is_err());
}

#[test]
fn all_arguments_mode_also_obeys_opt_in_prefixes_and_terminators() {
    let mut p = profile();
    p.option_scope = OptionScopePolicy::AllArguments;
    assert_eq!(
        modifiers(&bound(&p, "arbitrary-prefix-tool +ab")),
        ["plus_a", "plus_b"]
    );
    assert!(modifiers(&bound(&p, "arbitrary-prefix-tool ++ +a -c20")).is_empty());
}

#[test]
fn materialized_values_use_the_selected_profile_grammar_without_losing_origin() {
    let registry = ProfileRegistry::from_profiles(vec![profile()]).unwrap();
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("SWITCH", "+abc20");
    let parsed = parse_command("arbitrary-prefix-tool \"$SWITCH\"", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &bindings,
    ) else {
        panic!("expected resolved scalar option")
    };
    assert_eq!(r.projection.args[0].text, "$SWITCH");
    assert_eq!(r.materialized_projection.invocation.args[0].text, "+abc20");
    assert_eq!(
        r.materialized_projection.invocation.args[0].span,
        r.projection.args[0].span
    );
    assert_eq!(modifiers(&r.bound), ["plus_a", "plus_b", "plus_c"]);
    assert_eq!(values(&r.bound, "width"), ["20"]);
}

#[test]
fn root_prefix_policy_applies_to_subcommand_grammars() {
    let p = load(
        r#"
option_prefixes: dash_and_plus
subcommands:
  roots:
    - name: query
      option_scope: leading_options
      forms: [{id: query}]
      modifiers:
        - {id: minus, matcher: {kind: any_flag, flags: [-a]}}
        - {id: plus, matcher: {kind: any_flag, flags: [+a]}}
"#,
    );
    let b = bound(&p, "arbitrary-prefix-tool query +a");
    assert_eq!(modifiers(&b), ["plus"]);
    assert_eq!(b.subcommand_path[0].as_str(), "query");
}

#[test]
fn child_argv_retains_its_own_prefix_grammar() {
    let parent = load(
        r#"
option_prefixes: dash_and_plus
option_scope: leading_options
forms:
  - id: wrapper
    parameters:
      - {name: child, semantic: {kind: plain_value}, binding: {kind: next_positional}}
      - {name: argv, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
modifiers: [{id: plus, matcher: {kind: any_flag, flags: [+a]}}]
"#,
    );
    let b = bound(&parent, "arbitrary-prefix-tool +a legacy-child +a ++ -a");
    assert_eq!(modifiers(&b), ["plus"]);
    assert_eq!(values(&b, "child"), ["legacy-child"]);
    assert_eq!(values(&b, "argv"), ["+a", "++", "-a"]);
    let child = load(
        "forms: [{id: child, parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]}]",
    );
    let b = bound(&child, "arbitrary-prefix-tool +a ++");
    assert_eq!(values(&b, "data"), ["+a", "++"]);
    assert!(modifiers(&b).is_empty());
}
