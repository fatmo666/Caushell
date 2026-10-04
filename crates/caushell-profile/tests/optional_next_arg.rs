//! Opt-in operand arity/ownership. No particular tool is privileged.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn load(body: &str) -> CommandProfile {
    load_command_profile_from_str(&format!("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-optional-tool}}\n{body}")).unwrap()
}
fn profile() -> CommandProfile {
    load(
        r#"
option_prefixes: dash_and_plus
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: inspect
    parameters:
      - {name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
modifiers:
  - {id: a, matcher: {kind: any_flag, flags: [-a]}}
  - {id: plus_a, matcher: {kind: any_flag, flags: [+a]}}
  - {id: b, matcher: {kind: any_flag, flags: [-b]}}
  - id: selection
    matcher: {kind: any_flag, flags: [-i, +i, --select]}
    parameters:
      - {name: selection, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_next_arg}, cardinality: optional_many}
  - id: required
    matcher: {kind: any_flag, flags: [-p]}
    parameters:
      - {name: required, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
"#,
    )
}
fn bound(p: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let s = select_invocation(p, &projection).unwrap_or_else(|e| panic!("{command}: {e}"));
    bind_invocation(p, &projection, &s)
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
fn clean(p: &CommandProfile, command: &str) -> BoundInvocation {
    let b = bound(p, command);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    assert!(!b.operation_semantics_unresolved, "{command}: {b:?}");
    b
}

#[test]
fn absent_operand_is_valid_without_a_residual_even_in_opaque_mode() {
    for c in [
        "arbitrary-optional-tool -i",
        "arbitrary-optional-tool +i",
        "arbitrary-optional-tool --select",
        "arbitrary-optional-tool -abi",
    ] {
        assert!(values(&clean(&profile(), c), "selection").is_empty());
    }
}
#[test]
fn attached_inline_and_separate_operands_bind_identically() {
    for c in [
        "arbitrary-optional-tool -iTCP",
        "arbitrary-optional-tool +iTCP",
        "arbitrary-optional-tool -i TCP",
        "arbitrary-optional-tool --select TCP",
        "arbitrary-optional-tool --select=TCP",
        "arbitrary-optional-tool -abiTCP",
        "arbitrary-optional-tool -abi TCP",
    ] {
        let b = clean(&profile(), c);
        assert_eq!(values(&b, "selection"), ["TCP"], "{c}");
        assert!(values(&b, "data").is_empty());
    }
}
#[test]
fn following_minus_and_plus_options_are_not_optional_values() {
    for c in [
        "arbitrary-optional-tool -i -a +a",
        "arbitrary-optional-tool -abi +a",
        "arbitrary-optional-tool --select -a +a",
    ] {
        let b = clean(&profile(), c);
        assert!(values(&b, "selection").is_empty());
        assert!(b.applied_modifiers.contains(&ModifierId::new("a")));
        assert!(b.applied_modifiers.contains(&ModifierId::new("plus_a")));
    }
}
#[test]
fn both_terminators_and_their_trailing_data_remain_unconsumed_by_optional_value() {
    for terminator in ["--", "++"] {
        let c = format!("arbitrary-optional-tool -i {terminator} -i +a file");
        let b = clean(&profile(), &c);
        assert!(values(&b, "selection").is_empty());
        assert_eq!(values(&b, "data"), ["-i", "+a", "file"]);
    }
}
#[test]
fn repeated_optional_flags_keep_values_and_absent_occurrences_separate() {
    let b = clean(
        &profile(),
        "arbitrary-optional-tool -i TCP -i -a --select=UDP +i +a",
    );
    assert_eq!(values(&b, "selection"), ["TCP", "UDP"]);
    assert!(values(&b, "data").is_empty());
}
#[test]
fn explicit_empty_and_single_sign_values_are_not_missing() {
    for (word, value) in [("''", ""), ("-", "-"), ("+", "+")] {
        let c = format!("arbitrary-optional-tool -i {word}");
        assert_eq!(values(&clean(&profile(), &c), "selection"), [value]);
    }
}
#[test]
fn legacy_required_argv_operands_can_still_own_flag_looking_values() {
    let b = clean(&profile(), "arbitrary-optional-tool -p +a -i TCP");
    assert_eq!(values(&b, "required"), ["+a"]);
    assert_eq!(values(&b, "selection"), ["TCP"]);
    assert!(!b.applied_modifiers.contains(&ModifierId::new("plus_a")));
}
#[test]
fn consumed_terminator_as_required_value_does_not_hide_later_plus_option_ownership() {
    for value in ["--", "++"] {
        let c = format!("arbitrary-optional-tool -p {value} -i +a");
        let b = clean(&profile(), &c);
        assert_eq!(values(&b, "required"), [value]);
        assert!(values(&b, "selection").is_empty());
        assert!(b.applied_modifiers.contains(&ModifierId::new("plus_a")));
    }
}
#[test]
fn default_dash_only_policy_allows_a_plus_prefixed_value() {
    let mut p = profile();
    p.option_prefixes = OptionPrefixPolicy::DashOnly;
    p.modifiers.retain(|m| m.id.as_str() != "plus_a");
    let b = clean(&p, "arbitrary-optional-tool -i +word");
    assert_eq!(values(&b, "selection"), ["+word"]);
}
#[test]
fn required_cardinality_still_reports_missing_optional_argv_operand() {
    let mut p = profile();
    p.modifiers
        .iter_mut()
        .find(|m| m.id.as_str() == "selection")
        .unwrap()
        .parameters[0]
        .cardinality = Cardinality::RequiredMany;
    let b = bound(&p, "arbitrary-optional-tool -i -a");
    assert!(b.operation_semantics_unresolved);
    assert!(!b.residuals.is_empty());
}
#[test]
fn rejected_present_value_is_not_silently_reclassified_as_absence() {
    let mut p = profile();
    p.modifiers
        .iter_mut()
        .find(|m| m.id.as_str() == "selection")
        .unwrap()
        .parameters[0]
        .value_constraints
        .push(ValueConstraint::ExcludeLiteral("invalid".into()));
    for c in [
        "arbitrary-optional-tool -i invalid",
        "arbitrary-optional-tool -iinvalid",
        "arbitrary-optional-tool --select=invalid",
    ] {
        let b = bound(&p, c);
        assert!(b.operation_semantics_unresolved, "{c}: {b:?}");
    }
}
#[test]
fn all_arguments_and_form_flag_bindings_support_the_same_optional_arity() {
    let p = load(
        r#"
opaque_on_unresolved: true
forms:
  - id: query
    parameters:
      - {name: value, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: -i, operand_mode: optional_next_arg}, cardinality: optional_many}
modifiers: [{id: a, matcher: {kind: any_flag, flags: [-a]}}]
"#,
    );
    for (c, expected) in [
        ("arbitrary-optional-tool -i", vec![]),
        ("arbitrary-optional-tool -iTCP", vec!["TCP"]),
        ("arbitrary-optional-tool -i TCP", vec!["TCP"]),
        ("arbitrary-optional-tool -i -a", vec![]),
    ] {
        assert_eq!(values(&clean(&p, c), "value"), expected);
    }
}
