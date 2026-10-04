//! Synthetic names verify argument ownership without command-specific logic.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile(policy: OptionScopePolicy) -> CommandProfile {
    let mut p = CommandProfile::new("synthetic-transfer").with_option_scope(policy);
    for (id, flag) in [("format", "-f"), ("output", "-o"), ("name", "--name")] {
        p = p.with_modifier(
            Modifier::new(id).with_flag_name(flag).with_parameter(
                Parameter::new(
                    id,
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                )
                .variadic(),
            ),
        );
    }
    p.with_modifier(Modifier::new("quiet").with_flag_name("-q"))
        .with_modifier(Modifier::new("help").with_flag_name("--help"))
        .with_form(
            Form::new("transfer")
                .with_selector(SelectorExpr::Not(Box::new(SelectorExpr::Predicate(
                    SelectorPredicate::HasModifier(ModifierId::new("help")),
                ))))
                .with_parameter(
                    Parameter::new(
                        "files",
                        SemanticType::PlainValue,
                        BindingSpec::RemainingPositionals,
                    )
                    .optional()
                    .variadic(),
                ),
        )
        .with_form(
            Form::new("show_help")
                .with_selector_predicate(SelectorPredicate::HasModifier(ModifierId::new("help"))),
        )
}

fn bind(policy: OptionScopePolicy, command: &str) -> BoundInvocation {
    let p = profile(policy);
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&p, &projection).unwrap_or_else(|e| panic!("{command}: {e}"));
    let b = bind_invocation(&p, &projection, &selection);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
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
fn options_after_files_preserve_operand_order_without_rewriting_argv() {
    for c in [
        "synthetic-transfer -q -o out one two",
        "synthetic-transfer one -q -o out two",
        "synthetic-transfer one two -q -o out",
    ] {
        let b = bind(OptionScopePolicy::PermutedOptions, c);
        assert_eq!(values(&b, "files"), ["one", "two"]);
        assert_eq!(values(&b, "output"), ["out"]);
    }
}
#[test]
fn flag_shaped_option_values_are_never_modifiers() {
    for value in ["--help", "-o", "--", "-q"] {
        let c = format!("synthetic-transfer one -f {value} -o out two");
        let b = bind(OptionScopePolicy::PermutedOptions, &c);
        assert_eq!(b.form_id.as_str(), "transfer");
        assert_eq!(values(&b, "format"), [value]);
        assert_eq!(values(&b, "output"), ["out"]);
        assert_eq!(values(&b, "files"), ["one", "two"]);
        assert!(!b.applied_modifiers.iter().any(|id| id.as_str() == "help"));
    }
}
#[test]
fn real_separator_owns_the_entire_remaining_tail() {
    let b = bind(
        OptionScopePolicy::PermutedOptions,
        "synthetic-transfer one -f -- -- two --help -o out",
    );
    assert_eq!(values(&b, "format"), ["--"]);
    assert_eq!(values(&b, "files"), ["one", "two", "--help", "-o", "out"]);
    assert!(values(&b, "output").is_empty());
}
#[test]
fn inline_attached_and_clustered_values_are_owned_once() {
    let b = bind(
        OptionScopePolicy::PermutedOptions,
        "synthetic-transfer one -qf--help --name=--help -oout two",
    );
    assert_eq!(values(&b, "format"), ["--help"]);
    assert_eq!(values(&b, "name"), ["--help"]);
    assert_eq!(values(&b, "output"), ["out"]);
    assert_eq!(values(&b, "files"), ["one", "two"]);
}
#[test]
fn unknown_arity_or_missing_operands_cannot_certify_a_form() {
    let p = profile(OptionScopePolicy::PermutedOptions);
    for c in [
        "synthetic-transfer one --unknown --help",
        "synthetic-transfer one -o",
        "synthetic-transfer one -qx data",
        "synthetic-transfer --help=value",
    ] {
        let parsed = parse_command(c, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(select_invocation(&p, &projection).is_err(), "{c}");
    }
}
#[test]
fn actual_information_option_still_selects_early_exit() {
    let b = bind(
        OptionScopePolicy::PermutedOptions,
        "synthetic-transfer one -o out --help",
    );
    assert_eq!(b.form_id.as_str(), "show_help");
}

#[test]
fn declared_attached_operand_can_repeat_its_own_option_letter() {
    for (c, output) in [
        ("synthetic-transfer -oout file", "out"),
        ("synthetic-transfer file -qooo", "oo"),
    ] {
        let b = bind(OptionScopePolicy::PermutedOptions, c);
        assert_eq!(values(&b, "output"), [output]);
        assert_eq!(values(&b, "files"), ["file"]);
    }
}

#[test]
fn stdout_declaration_defaults_off_when_omitted_from_yaml() {
    let source = include_str!("../profiles/env.yaml");
    let p =
        load_command_profile_from_str(&source.replace("          stdout_to_parent: true\n", ""))
            .unwrap();
    let targets: Vec<_> = p
        .forms
        .iter()
        .flat_map(|f| &f.effects)
        .filter_map(|e| match &e.target {
            EffectTarget::Dispatch(target) => Some(target),
            _ => None,
        })
        .collect();
    assert!(!targets.is_empty());
    assert!(targets.iter().all(|t| !t.stdout_to_parent));
    let malformed = source.replace("stdout_to_parent: true", "stdout_to_parent: invalid");
    assert!(load_command_profile_from_str(&malformed).is_err());
}
#[test]
fn leading_scope_keeps_child_option_text_as_data() {
    let b = bind(
        OptionScopePolicy::LeadingOptions,
        "synthetic-transfer one --help -o out",
    );
    assert_eq!(b.form_id.as_str(), "transfer");
    assert_eq!(values(&b, "files"), ["one", "--help", "-o", "out"]);
}
#[test]
fn legacy_all_arguments_is_unchanged_until_profile_opts_in() {
    assert_eq!(
        profile(OptionScopePolicy::default()).option_scope,
        OptionScopePolicy::AllArguments
    );
    let b = bind(
        OptionScopePolicy::AllArguments,
        "synthetic-transfer -f --help",
    );
    assert_eq!(b.form_id.as_str(), "show_help");
}
