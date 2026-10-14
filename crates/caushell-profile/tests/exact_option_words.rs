//! Opt-in native option words, independent of command names or risk policy.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

#[test]
fn public_shapes_selectors_counts_and_constraints_obey_complete_word_context() {
    let mut p = load_command_profile_from_str(&yaml("leading_options", "[-stats]")).unwrap();
    p.forms.insert(
        0,
        Form::new("short_s")
            .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-s"))),
    );
    let mut shape = InvocationShape::new().with_flag("-stats");
    assert_eq!(
        select_form(&p, &shape).unwrap().id.as_str(),
        "complete_word"
    );
    assert_eq!(
        match_modifiers(&p, &shape)
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        ["stats"]
    );
    shape.exact_option_words.clone_from(&p.exact_option_words);
    assert!(shape.has_flag("-stats"));
    assert!(!shape.has_flag("-s"));
    assert_eq!(shape.flag_count("-s"), 0);
    assert_eq!(shape.flag_count("-stats"), 1);
    p.modifiers
        .iter_mut()
        .find(|m| m.id.as_str() == "stats")
        .unwrap()
        .constraints
        .push(ModifierConstraint::RequiresFlag(FlagName::new("-s")));
    assert!(match_modifiers(&p, &shape).is_empty());
}

#[test]
fn root_words_do_not_change_a_child_nodes_option_grammar() {
    let body = yaml("leading_options", "[-stats]")
        + r#"
subcommands:
  roots:
    - name: sub
      option_scope: leading_options
      forms:
        - id: child
          parameters: [{name: tail, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
      modifiers:
        - {id: child_s, matcher: {kind: any_flag, flags: [-s]}}
        - {id: child_t, matcher: {kind: any_flag, flags: [-t]}}
        - {id: child_a, matcher: {kind: any_flag, flags: [-a]}}
"#;
    let p = load_command_profile_from_str(&body).unwrap();
    let b = bind(&p, "arbitrary-tool -stats cpu sub -stats mem");
    assert_eq!(b.form_id.as_str(), "child");
    assert_eq!(values(&b, "keys"), ["cpu"]);
    assert_eq!(values(&b, "tail"), ["mem"]);
    for id in ["child_s", "child_t", "child_a"] {
        assert!(b.applied_modifiers.iter().any(|m| m.as_str() == id));
    }
}

fn yaml(scope: &str, words: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-tool}}
option_scope: {scope}
exact_option_words: {words}
forms:
  - id: complete_word
    selector: {{kind: has_flag, flag: '-stats'}}
    parameters: [{{name: tail, semantic: {{kind: plain_value}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}]
  - id: switches
    selector: {{kind: not, item: {{kind: has_flag, flag: '-stats'}}}}
    parameters: [{{name: tail, semantic: {{kind: plain_value}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}]
modifiers:
  - {{id: s, matcher: {{kind: any_flag, flags: [-s]}}}}
  - {{id: t, matcher: {{kind: any_flag, flags: [-t]}}}}
  - {{id: a, matcher: {{kind: any_flag, flags: [-a]}}}}
  - {{id: b, matcher: {{kind: any_flag, flags: [-b]}}}}
  - id: n
    matcher: {{kind: any_flag, flags: [-n]}}
    parameters: [{{name: count, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_one}}]
  - id: stats
    matcher: {{kind: any_flag, flags: [-stats]}}
    parameters: [{{name: keys, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_one}}]
"#
    )
}
fn bind(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let s = select_invocation(profile, &p).unwrap_or_else(|e| panic!("{command}: {e}"));
    let b = bind_invocation(profile, &p, &s);
    assert!(b.residuals.is_empty(), "{command}: {b:#?}");
    b
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
#[test]
fn complete_words_are_not_redecoded_as_short_flags_or_selectors() {
    for scope in ["leading_options", "permuted_options"] {
        let p = load_command_profile_from_str(&yaml(scope, "[-stats]")).unwrap();
        let b = bind(&p, "arbitrary-tool -stats cpu -bn1");
        assert_eq!(b.form_id.as_str(), "complete_word");
        assert_eq!(
            b.applied_modifiers
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>(),
            ["b", "n", "stats"]
        );
        assert_eq!(values(&b, "keys"), ["cpu"]);
        assert_eq!(values(&b, "count"), ["1"]);
        assert!(values(&b, "tail").is_empty());
        let b = bind(&p, "arbitrary-tool -sta -bn2");
        assert_eq!(b.form_id.as_str(), "switches");
        assert_eq!(values(&b, "count"), ["2"]);
    }
}
#[test]
fn values_terminators_and_child_argv_never_activate_complete_word_options() {
    let p = load_command_profile_from_str(&yaml("leading_options", "[-stats]")).unwrap();
    for c in [
        "arbitrary-tool -n -stats",
        "arbitrary-tool -- -stats cpu",
        "arbitrary-tool child -stats cpu",
    ] {
        let b = bind(&p, c);
        assert_eq!(b.form_id.as_str(), "switches", "{c}");
        assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "stats"));
    }
    assert_eq!(
        values(&bind(&p, "arbitrary-tool -n -stats"), "count"),
        ["-stats"]
    );
    assert_eq!(
        values(&bind(&p, "arbitrary-tool -stats -bn1"), "keys"),
        ["-bn1"]
    );
}
#[test]
fn exact_words_do_not_guess_prefixes_or_missing_operands() {
    let p = load_command_profile_from_str(&yaml("leading_options", "[-stats]")).unwrap();
    for c in [
        "arbitrary-tool -stats",
        "arbitrary-tool -stats=cpu",
        "arbitrary-tool -statscpu",
        "arbitrary-tool -unknown",
    ] {
        let parsed = parse_command(c, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(select_invocation(&p, &projected).is_err(), "{c}");
    }
}
#[test]
fn omission_keeps_existing_scoped_grammar() {
    let body = yaml("leading_options", "[]");
    assert!(load_command_profile_from_str(&body).is_err());
    let body = body.replace("flags: [-stats]", "flags: [--stats]");
    let p = load_command_profile_from_str(&body).unwrap();
    assert!(p.exact_option_words.is_empty());
    let b = bind(&p, "arbitrary-tool -stats -bn1");
    assert_eq!(b.form_id.as_str(), "switches");
    assert_eq!(values(&b, "count"), ["1"]);
    assert_eq!(
        b.applied_modifiers
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>(),
        ["s", "t", "a", "b", "n"]
    );
}
#[test]
fn malformed_or_dangling_declarations_are_rejected() {
    for (scope, words) in [
        ("all_arguments", "[-stats]"),
        ("leading_options", "[-stats, -stats]"),
        ("leading_options", "[-missing]"),
        ("leading_options", "[-s]"),
        ("leading_options", "[--stats]"),
        ("leading_options", "['-stats=cpu']"),
        ("leading_options", "['-stats cpu']"),
    ] {
        assert!(
            load_command_profile_from_str(&yaml(scope, words)).is_err(),
            "{scope} {words}"
        );
    }
}
