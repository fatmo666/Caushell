//! Opt-in optional attached arity; no command name has special treatment.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile() -> CommandProfile {
    load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: attached-tool}
option_prefixes: dash_and_plus
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - {id: switch, matcher: {kind: any_flag, flags: [-q, +q]}}
  - id: optional
    matcher: {kind: any_flag, flags: [-p, +p, --password]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_inline_or_short_attached}, cardinality: optional_many}]
  - id: required
    matcher: {kind: any_flag, flags: [-r]}
    parameters: [{name: required, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#).unwrap()
}
fn bind(p: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(p, &projection).unwrap();
    bind_invocation(p, &projection, &selection)
}
fn clean(p: &CommandProfile, c: &str) -> BoundInvocation {
    let b = bind(p, c);
    assert!(
        b.residuals.is_empty() && !b.operation_semantics_unresolved,
        "{c}: {b:?}"
    );
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
fn raw_normalization_preserves_new_mode() {
    assert_eq!(
        profile().modifiers[1].parameters[0].binding,
        BindingSpec::FollowingMatchedFlag {
            operand_mode: FlagOperandMode::OptionalInlineOrShortAttached
        }
    );
}
#[test]
fn bare_short_and_long_never_consume_the_next_word() {
    for c in [
        "attached-tool -p db",
        "attached-tool --password db",
        "attached-tool +p db",
    ] {
        let b = clean(&profile(), c);
        assert!(values(&b, "value").is_empty());
        assert_eq!(values(&b, "data"), ["db"]);
    }
}
#[test]
fn short_attached_and_long_inline_bind_without_changing_other_ownership() {
    for c in [
        "attached-tool -pfixture db",
        "attached-tool +pfixture db",
        "attached-tool --password=fixture db",
    ] {
        let b = clean(&profile(), c);
        assert_eq!(values(&b, "value"), ["fixture"]);
        assert_eq!(values(&b, "data"), ["db"]);
    }
}
#[test]
fn following_option_and_terminator_are_not_operands() {
    for terminator in ["--", "++"] {
        let b = clean(
            &profile(),
            &format!("attached-tool -p -q {terminator} -pfixture db"),
        );
        assert!(values(&b, "value").is_empty());
        assert_eq!(values(&b, "data"), ["-pfixture", "db"]);
        assert!(b.applied_modifiers.contains(&ModifierId::new("switch")));
    }
}
#[test]
fn clusters_stop_at_the_optional_operand_including_flag_shaped_values() {
    let b = clean(&profile(), "attached-tool -qpfixture -qp -p--help -p-q db");
    assert_eq!(values(&b, "value"), ["fixture", "--help", "-q"]);
    assert_eq!(values(&b, "data"), ["db"]);
}
#[test]
fn option_letters_inside_password_do_not_become_modifiers() {
    let b = clean(&profile(), "attached-tool -pqr db");
    assert_eq!(values(&b, "value"), ["qr"]);
    assert!(!b.applied_modifiers.contains(&ModifierId::new("switch")));
    assert!(!b.applied_modifiers.contains(&ModifierId::new("required")));
}
#[test]
fn repeated_bare_attached_and_inline_values_are_distinct() {
    let b = clean(
        &profile(),
        "attached-tool -p --password=one db -ptwo -p --password",
    );
    assert_eq!(values(&b, "value"), ["one", "two"]);
    assert_eq!(values(&b, "data"), ["db"]);
}
#[test]
fn explicit_empty_long_value_is_not_absence_or_next_argv() {
    let b = clean(&profile(), "attached-tool --password= db -p=fixture");
    assert_eq!(values(&b, "value"), ["", "=fixture"]);
    assert_eq!(values(&b, "data"), ["db"]);
}
#[test]
fn absent_required_parameter_still_has_a_residual() {
    let mut p = profile();
    p.modifiers[1].parameters[0].cardinality = Cardinality::RequiredMany;
    let b = bind(&p, "attached-tool -p db");
    assert!(b.operation_semantics_unresolved && !b.residuals.is_empty());
    assert_eq!(values(&b, "data"), ["db"]);
}
#[test]
fn rejected_attached_or_inline_values_remain_unresolved() {
    let mut p = profile();
    p.modifiers[1].parameters[0]
        .value_constraints
        .push(ValueConstraint::ExcludeLiteral("bad".into()));
    for c in ["attached-tool -pbad", "attached-tool --password=bad"] {
        let b = bind(&p, c);
        assert!(
            b.operation_semantics_unresolved && !b.residuals.is_empty(),
            "{c}: {b:?}"
        );
    }
}
#[test]
fn required_option_can_own_a_terminator_before_optional_options() {
    let b = clean(&profile(), "attached-tool -r -- -pfixture db -- -q");
    assert_eq!(values(&b, "required"), ["--"]);
    assert_eq!(values(&b, "value"), ["fixture"]);
    assert_eq!(values(&b, "data"), ["db", "-q"]);
}
#[test]
fn all_supported_scopes_share_arity_without_changing_their_boundaries() {
    for scope in [
        OptionScopePolicy::LeadingOptions,
        OptionScopePolicy::AllArguments,
        OptionScopePolicy::PermutedOptions,
    ] {
        let mut p = profile();
        p.option_scope = scope;
        let b = clean(&p, "attached-tool -qpfixture -p db");
        assert_eq!(values(&b, "value"), ["fixture"]);
        assert_eq!(values(&b, "data"), ["db"]);
    }
}
#[test]
fn legacy_all_arguments_allows_the_new_mode_after_positional_data() {
    let mut p = profile();
    p.option_scope = OptionScopePolicy::AllArguments;
    let b = clean(&p, "attached-tool db -qpfixture -p other");
    assert_eq!(values(&b, "value"), ["fixture"]);
    assert_eq!(values(&b, "data"), ["db", "other"]);
}
#[test]
fn form_level_binding_uses_the_same_optional_arity() {
    let mut p = profile();
    p.modifiers[1].matcher = ModifierMatcher::AnyFlag(vec![FlagName::new("-p")]);
    p.modifiers[1].parameters.clear();
    p.forms[0].parameters.insert(
        0,
        Parameter::new(
            "value",
            SemanticType::PlainValue,
            BindingSpec::FollowingFlag {
                flag_name: FlagName::new("-p"),
                operand_mode: FlagOperandMode::OptionalInlineOrShortAttached,
            },
        )
        .optional()
        .variadic(),
    );
    for scope in [
        OptionScopePolicy::PermutedOptions,
        OptionScopePolicy::AllArguments,
    ] {
        p.option_scope = scope;
        for (c, expected) in [
            ("attached-tool -pfixture db", vec!["fixture"]),
            ("attached-tool -p db", vec![]),
        ] {
            let b = clean(&p, c);
            assert_eq!(values(&b, "value"), expected);
            assert_eq!(values(&b, "data"), ["db"]);
        }
    }
}

#[test]
fn modifier_following_flag_has_attached_arity_in_legacy_all_arguments() {
    let mut p = profile();
    p.option_scope = OptionScopePolicy::AllArguments;
    p.modifiers[1].parameters[0].binding = BindingSpec::FollowingFlag {
        flag_name: FlagName::new("-p"),
        operand_mode: FlagOperandMode::OptionalInlineOrShortAttached,
    };
    let b = clean(&p, "attached-tool -qpfixture -p db");
    assert_eq!(values(&b, "value"), ["fixture"]);
    assert_eq!(values(&b, "data"), ["db"]);
}
