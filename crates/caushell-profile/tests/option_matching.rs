use caushell_parse::parse_command;
use caushell_profile::{
    BindingSpec, BoundInvocation, BoundValue, CommandProfile, FlagName, FlagOperandMode, Form,
    InvocationRuntimeContext, InvocationShape, Modifier, ModifierConstraint, ModifierId,
    OptionMatchingPolicy, Parameter, ProfileRegistry, ResolveInvocationResult, SelectorPredicate,
    SemanticType, bind_invocation, load_command_profile_from_str, match_modifiers,
    project_invocation, resolve_invocation, select_form, select_invocation,
};
use caushell_types::ShellKind;

fn parameter_modifier(id: &str, names: &[&str]) -> Modifier {
    let mut modifier = Modifier::new(id);
    for name in names {
        modifier = modifier.with_flag_name(name);
    }
    modifier.with_parameter(Parameter::new(
        id,
        SemanticType::PlainValue,
        BindingSpec::FollowingMatchedFlag {
            operand_mode: FlagOperandMode::NextArg,
        },
    ))
}

fn exact_profile() -> CommandProfile {
    CommandProfile::new("arbitrary-option-tool")
        .with_option_matching(OptionMatchingPolicy::ExactNames)
        .with_modifier(parameter_modifier("p", &["-p"]))
        .with_modifier(Modifier::new("l").with_flag_name("-l"))
        .with_modifier(parameter_modifier("pl", &["-pl", "--power-limit"]))
        .with_modifier(Modifier::new("nic").with_flag_name("-nic"))
        .with_modifier(parameter_modifier("n", &["-n"]))
        .with_modifier(parameter_modifier("i", &["-i"]))
        .with_modifier(parameter_modifier("c", &["-c"]))
        .with_form(
            Form::new("run").with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs),
        )
}

fn bound(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(profile, &projection)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    let bound = bind_invocation(profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    bound
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("expected argument: {other:?}"),
        })
        .collect()
}

fn load(body: &str) -> CommandProfile {
    load_command_profile_from_str(&format!("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-option-tool}}\n{body}" )).unwrap()
}

#[test]
fn omitted_matching_keeps_clusters_and_attached_operands() {
    let profile = load(
        "forms: [{id: run}]\nmodifiers:\n  - {id: a, matcher: {kind: any_flag, flags: ['-a']}}\n  - {id: l, matcher: {kind: any_flag, flags: ['-l']}}\n",
    );
    assert_eq!(profile.option_matching, OptionMatchingPolicy::ShortClusters);
    let b = bound(&profile, "arbitrary-option-tool -al");
    assert_eq!(
        b.applied_modifiers,
        [ModifierId::new("a"), ModifierId::new("l")]
    );
    let profile = CommandProfile::new("arbitrary-option-tool")
        .with_modifier(parameter_modifier("p", &["-p"]))
        .with_form(Form::new("run"));
    assert_eq!(
        values(&bound(&profile, "arbitrary-option-tool -pVALUE"), "p"),
        ["VALUE"]
    );
}

#[test]
fn exact_words_never_activate_prefix_or_cluster_modifiers() {
    let profile = exact_profile();
    for command in [
        "arbitrary-option-tool -pl 200",
        "arbitrary-option-tool --power-limit=200",
        "arbitrary-option-tool --power-limit 200",
    ] {
        let b = bound(&profile, command);
        assert_eq!(
            b.applied_modifiers,
            [ModifierId::new("pl")],
            "{command}: {b:?}"
        );
        assert_eq!(values(&b, "pl"), ["200"]);
    }
    let b = bound(&profile, "arbitrary-option-tool -nic");
    assert_eq!(b.applied_modifiers, [ModifierId::new("nic")]);
    for command in [
        "arbitrary-option-tool -pl200",
        "arbitrary-option-tool -i0",
        "arbitrary-option-tool -pl=200",
    ] {
        let b = bound(&profile, command);
        assert!(b.applied_modifiers.is_empty(), "{command}: {b:?}");
    }
    let b = bound(&profile, "arbitrary-option-tool -p 1 -l");
    assert_eq!(
        b.applied_modifiers,
        [ModifierId::new("p"), ModifierId::new("l")]
    );
}

#[test]
fn public_selector_modifier_and_flag_count_apis_obey_profile_policy() {
    let mut profile = exact_profile();
    let shape = InvocationShape::new().with_flag("-pl");
    assert_eq!(
        match_modifiers(&profile, &shape)
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        ["pl"]
    );
    profile.forms = vec![
        Form::new("whole")
            .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-pl"))),
        Form::new("prefix")
            .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-p"))),
    ];
    assert_eq!(select_form(&profile, &shape).unwrap().id.as_str(), "whole");
    let profile = CommandProfile::new("arbitrary-option-tool")
        .with_option_matching(OptionMatchingPolicy::ExactNames)
        .with_form(
            Form::new("twice")
                .with_selector_predicate(SelectorPredicate::HasFlagAtLeast(FlagName::new("-p"), 2)),
        );
    assert!(
        select_form(
            &profile,
            &InvocationShape::new().with_flag("-pl").with_flag("-pl")
        )
        .is_err()
    );
    assert!(
        select_form(
            &profile,
            &InvocationShape::new().with_flag("-p").with_flag("-p")
        )
        .is_ok()
    );
}

#[test]
fn form_flag_binding_does_not_consume_another_full_option_name() {
    let profile = CommandProfile::new("arbitrary-option-tool")
        .with_option_matching(OptionMatchingPolicy::ExactNames)
        .with_form(
            Form::new("run")
                .with_parameter(
                    Parameter::new(
                        "prefix",
                        SemanticType::PlainValue,
                        BindingSpec::FollowingFlag {
                            flag_name: FlagName::new("-p"),
                            operand_mode: FlagOperandMode::NextArg,
                        },
                    )
                    .optional(),
                )
                .with_parameter(Parameter::new(
                    "whole",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingFlag {
                        flag_name: FlagName::new("-pl"),
                        operand_mode: FlagOperandMode::NextArg,
                    },
                ))
                .with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs),
        );
    let b = bound(&profile, "arbitrary-option-tool -pl 200");
    assert!(values(&b, "prefix").is_empty());
    assert_eq!(values(&b, "whole"), ["200"]);
}

#[test]
fn requires_flag_constraints_use_full_names_not_prefixes() {
    let profile = exact_profile().with_modifier(
        Modifier::new("conditional")
            .with_flag_name("--conditional")
            .with_constraint(ModifierConstraint::RequiresFlag(FlagName::new("-p"))),
    );
    let b = bound(&profile, "arbitrary-option-tool -pl 200 --conditional");
    assert!(
        !b.applied_modifiers
            .contains(&ModifierId::new("conditional"))
    );
    let b = bound(&profile, "arbitrary-option-tool -p 1 --conditional");
    assert!(
        b.applied_modifiers
            .contains(&ModifierId::new("conditional"))
    );
    let shape = InvocationShape::new()
        .with_flag("-pl")
        .with_flag("--conditional");
    assert!(
        !match_modifiers(&profile, &shape)
            .iter()
            .any(|m| m.id.as_str() == "conditional")
    );
}

#[test]
fn nodes_inherit_matching_and_can_override_for_their_children() {
    let profile = load(
        r#"
option_matching: exact_names
subcommands:
  roots:
    - name: inherited
      children:
        - name: leaf
          forms: [{id: leaf}]
          modifiers:
            - {id: nic, matcher: {kind: any_flag, flags: ['-nic']}}
            - {id: n, matcher: {kind: any_flag, flags: ['-n']}}
    - name: clustered
      option_matching: short_clusters
      children:
        - name: leaf
          forms: [{id: leaf}]
          modifiers:
            - {id: a, matcher: {kind: any_flag, flags: ['-a']}}
            - {id: l, matcher: {kind: any_flag, flags: ['-l']}}
"#,
    );
    let roots = &profile.subcommands.as_ref().unwrap().roots;
    assert_eq!(roots[0].option_matching, OptionMatchingPolicy::ExactNames);
    assert_eq!(
        roots[0].children[0].option_matching,
        OptionMatchingPolicy::ExactNames
    );
    assert_eq!(
        roots[1].children[0].option_matching,
        OptionMatchingPolicy::ShortClusters
    );
    let b = bound(&profile, "arbitrary-option-tool inherited leaf -nic");
    assert_eq!(b.applied_modifiers, [ModifierId::new("nic")]);
    let b = bound(&profile, "arbitrary-option-tool clustered leaf -al");
    assert_eq!(
        b.applied_modifiers,
        [ModifierId::new("a"), ModifierId::new("l")]
    );
}

fn exact_wrapper() -> CommandProfile {
    load(
        r#"
option_scope: leading_options
option_matching: exact_names
forms:
  - id: dispatch
    parameters:
      - {name: command, semantic: {kind: plain_value}, binding: {kind: next_positional}, cardinality: required_one}
      - {name: argv, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
modifiers:
  - id: output
    matcher: {kind: any_flag, flags: ['-out', '--output']}
    parameters:
      - {name: output, semantic: {kind: path, role: write}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}
    effects: [{kind: write_path, target: {kind: slot, name: output}}]
  - {id: o, matcher: {kind: any_flag, flags: ['-o']}}
  - {id: u, matcher: {kind: any_flag, flags: ['-u']}}
  - {id: t, matcher: {kind: any_flag, flags: ['-t']}}
  - {id: help, matcher: {kind: any_flag, flags: ['--help']}}
"#,
    )
}

#[test]
fn exact_matching_composes_with_leading_ownership_and_long_inline_values() {
    let profile = exact_wrapper();
    for command in [
        "arbitrary-option-tool -out report cmd -out child --help",
        "arbitrary-option-tool --output=report cmd -out child --help",
        "arbitrary-option-tool -out report -- cmd -out child --help",
    ] {
        let b = bound(&profile, command);
        assert_eq!(b.applied_modifiers, [ModifierId::new("output")]);
        assert_eq!(values(&b, "output"), ["report"]);
        assert_eq!(values(&b, "command"), ["cmd"]);
        assert_eq!(values(&b, "argv"), ["-out", "child", "--help"]);
    }
}

#[test]
fn exact_wrapper_option_values_are_not_reinterpreted_as_options() {
    let profile = exact_wrapper();
    for value in ["--help", "--"] {
        let b = bound(
            &profile,
            &format!("arbitrary-option-tool -out {value} cmd -- -out child"),
        );
        assert_eq!(b.applied_modifiers, [ModifierId::new("output")]);
        assert_eq!(values(&b, "output"), [value]);
        assert_eq!(values(&b, "argv"), ["--", "-out", "child"]);
    }
}

#[test]
fn partial_binding_preserves_known_exact_options_without_guessing_unknown_prefixes() {
    let registry = ProfileRegistry::from_profiles(vec![exact_wrapper()]).unwrap();
    for command in [
        "arbitrary-option-tool -out report -unknown cmd",
        "arbitrary-option-tool -out report -outCHILD cmd",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::SelectionError {
                partial_bound: Some(partial),
                ..
            } => {
                assert_eq!(values(&partial, "output"), ["report"]);
                assert_eq!(partial.applied_modifiers, [ModifierId::new("output")]);
                assert_eq!(partial.effects.len(), 1);
            }
            other => panic!("{command}: {other:?}"),
        }
    }
}

#[test]
fn leading_form_flag_bindings_use_exact_names_too() {
    let mut profile = exact_wrapper();
    let operand = profile.modifiers[0].parameters.remove(0);
    let mut operand = operand;
    operand.binding = BindingSpec::FollowingFlag {
        flag_name: FlagName::new("-out"),
        operand_mode: FlagOperandMode::NextArg,
    };
    profile.forms[0].parameters.insert(0, operand);
    let b = bound(&profile, "arbitrary-option-tool -out report cmd");
    assert_eq!(values(&b, "output"), ["report"]);
    assert_eq!(values(&b, "command"), ["cmd"]);
}

#[test]
fn declarations_validate_matching_modes_and_preserve_old_leading_grammar() {
    let base = "option_scope: leading_options\nforms: [{id: run}]\nmodifiers: [{id: word, matcher: {kind: any_flag, flags: ['-word']}}]\n";
    assert!(load_command_profile_from_str(&format!("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-option-tool}}\n{base}")).is_err());
    assert_eq!(
        load(&format!("option_matching: exact_names\n{base}")).option_matching,
        OptionMatchingPolicy::ExactNames
    );
    let invalid = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary-option-tool}\noption_matching: arbitrary_typo\n";
    assert!(load_command_profile_from_str(invalid).is_err());
}
