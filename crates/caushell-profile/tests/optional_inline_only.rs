//! An explicit optional-inline mode; legacy modes and option ownership stay intact.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile() -> CommandProfile {
    load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-inline-tool}
option_prefixes: dash_and_plus
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - {id: flag, matcher: {kind: any_flag, flags: [-x, +x]}}
  - id: selection
    matcher: {kind: any_flag, flags: [--select, -i]}
    parameters: [{name: selection, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_inline_only}, cardinality: optional_many}]
  - id: required
    matcher: {kind: any_flag, flags: [-v]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#).unwrap()
}
fn bind(p: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(p, &projected).unwrap();
    bind_invocation(p, &projected, &selected)
}
fn clean(p: &CommandProfile, command: &str) -> BoundInvocation {
    let b = bind(p, command);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    assert!(!b.operation_semantics_unresolved, "{command}: {b:?}");
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
fn normalization_preserves_optional_inline_only() {
    assert_eq!(
        profile().modifiers[1].parameters[0].binding,
        BindingSpec::FollowingMatchedFlag {
            operand_mode: FlagOperandMode::OptionalInlineOnly
        }
    );
}
#[test]
fn bare_flag_accepts_absence_and_never_takes_a_following_value() {
    for c in ["arbitrary-inline-tool --select", "arbitrary-inline-tool -i"] {
        assert!(values(&clean(&profile(), c), "selection").is_empty());
    }
    let b = clean(&profile(), "arbitrary-inline-tool --select positional");
    assert!(values(&b, "selection").is_empty());
    assert_eq!(values(&b, "data"), ["positional"]);
}
#[test]
fn following_flags_and_both_terminators_remain_owned_by_their_parser() {
    for terminator in ["--", "++"] {
        let b = clean(
            &profile(),
            &format!("arbitrary-inline-tool --select -x +x {terminator} --select=literal -x"),
        );
        assert!(values(&b, "selection").is_empty());
        assert_eq!(values(&b, "data"), ["--select=literal", "-x"]);
        assert!(b.applied_modifiers.contains(&ModifierId::new("flag")));
    }
}
#[test]
fn inline_and_empty_values_are_real_operands_not_absence() {
    for (c, v) in [
        ("arbitrary-inline-tool --select=one", "one"),
        ("arbitrary-inline-tool --select=", ""),
        ("arbitrary-inline-tool --select=--help", "--help"),
    ] {
        let b = clean(&profile(), c);
        assert_eq!(values(&b, "selection"), [v]);
    }
}
#[test]
fn repeated_bare_and_inline_flags_remain_separate() {
    let b = clean(
        &profile(),
        "arbitrary-inline-tool --select --select=one position --select --select=two",
    );
    assert_eq!(values(&b, "selection"), ["one", "two"]);
    assert_eq!(values(&b, "data"), ["position"]);
}
#[test]
fn required_cardinality_still_reports_the_absent_operand() {
    let mut p = profile();
    p.modifiers[1].parameters[0].cardinality = Cardinality::RequiredMany;
    let b = bind(&p, "arbitrary-inline-tool --select positional");
    assert!(b.operation_semantics_unresolved);
    assert_eq!(values(&b, "data"), ["positional"]);
    assert!(!b.residuals.is_empty());
}
#[test]
fn rejected_present_inline_value_is_not_silently_treated_as_absence() {
    let mut p = profile();
    p.modifiers[1].parameters[0]
        .value_constraints
        .push(ValueConstraint::ExcludeLiteral("bad".into()));
    let b = bind(&p, "arbitrary-inline-tool --select=bad");
    assert!(b.operation_semantics_unresolved);
    assert!(!b.residuals.is_empty());
}
#[test]
fn required_argv_ownership_can_consume_a_literal_delimiter_before_optional_flag() {
    let b = clean(
        &profile(),
        "arbitrary-inline-tool -v -- --select position -- -x",
    );
    assert_eq!(values(&b, "value"), ["--"]);
    assert!(values(&b, "selection").is_empty());
    assert_eq!(values(&b, "data"), ["position", "-x"]);
}
#[test]
fn leading_and_legacy_all_arguments_scopes_share_the_opt_in_mode() {
    for scope in [
        OptionScopePolicy::LeadingOptions,
        OptionScopePolicy::AllArguments,
    ] {
        let mut p = profile();
        p.option_scope = scope;
        let b = clean(
            &p,
            "arbitrary-inline-tool --select --select=one -x position",
        );
        assert_eq!(values(&b, "selection"), ["one"]);
        assert_eq!(values(&b, "data"), ["position"]);
    }
}
#[test]
fn form_level_following_flag_binding_has_the_same_arity() {
    let mut p = profile();
    p.modifiers[1].parameters.clear();
    p.forms[0].parameters.insert(
        0,
        Parameter::new(
            "selection",
            SemanticType::PlainValue,
            BindingSpec::FollowingFlag {
                flag_name: FlagName::new("--select"),
                operand_mode: FlagOperandMode::OptionalInlineOnly,
            },
        )
        .optional()
        .variadic(),
    );
    for c in [
        "arbitrary-inline-tool --select position",
        "arbitrary-inline-tool --select=one position",
    ] {
        let b = clean(&p, c);
        assert_eq!(values(&b, "data"), ["position"]);
    }
}
#[test]
fn attached_short_values_are_not_an_optional_inline_long_operand() {
    let parsed = parse_command("arbitrary-inline-tool -ivalue", ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(&profile(), &projected).is_err());
}
#[test]
fn legacy_inline_only_still_rejects_a_bare_flag_in_opaque_mode() {
    let mut p = profile();
    p.modifiers[1].parameters[0].binding = BindingSpec::FollowingMatchedFlag {
        operand_mode: FlagOperandMode::InlineOnly,
    };
    let b = bind(&p, "arbitrary-inline-tool --select positional");
    assert!(b.operation_semantics_unresolved);
}
