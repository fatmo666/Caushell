//! Conditional effects use owned option occurrences, never raw argv searches.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const YAML: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: switch-tool}
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - id: mode
    matcher: {kind: any_flag, flags: [-x, --disable, --enable]}
    effects_when:
      unless_modifiers: [info]
      last_option_not_matching: {kind: literal, value: --enable}
    effects:
      - {kind: state_operation, state_operation: {domain: connection_verification, operation: control}, target: {kind: none}}
  - {id: info, matcher: {kind: any_flag, flags: [--info]}}
  - {id: verbose, matcher: {kind: any_flag, flags: [-v]}}
  - id: output
    matcher: {kind: any_flag, flags: [-o]}
    parameters: [{name: output, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#;

fn bind(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(profile, &projection).unwrap();
    let bound = bind_invocation(profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    bound
}

#[test]
fn last_owned_alias_controls_effects_without_changing_modifier_ownership() {
    let profile = load_command_profile_from_str(YAML).unwrap();
    for (command, expected) in [
        ("switch-tool --disable", true),
        ("switch-tool -vx", true),
        ("switch-tool --enable -vx", true),
        ("switch-tool --disable --enable", false),
        ("switch-tool -vx --enable", false),
        ("switch-tool --enable --disable --enable", false),
        ("switch-tool --disable --info", false),
        ("switch-tool --info --disable", false),
        ("switch-tool --disable -o --enable", true),
        ("switch-tool --disable -- --enable", true),
        ("switch-tool --enable -- --disable", false),
        ("switch-tool -o --disable", false),
        ("switch-tool -- --disable", false),
    ] {
        let bound = bind(&profile, command);
        assert_eq!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::StateOperation),
            expected,
            "{command}: {bound:#?}"
        );
    }
    let bound = bind(&profile, "switch-tool --disable --enable");
    assert!(bound.applied_modifiers.contains(&ModifierId::new("mode")));
}

#[test]
fn inline_setting_is_compared_as_a_whole_word_and_regex_is_compiled_once() {
    let yaml = YAML.replace("[-x, --disable, --enable]", "[--setting]")
        .replace("effects_when:", "parameters: [{name: setting, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_inline_only}, cardinality: optional_many}]\n    effects_when:")
        .replace("{kind: literal, value: --enable}", "{kind: regex_pattern, pattern: '^--setting(?:=(?i:on|yes|1))?$'}");
    let profile = load_command_profile_from_str(&yaml).unwrap();
    assert!(
        profile.modifiers[0]
            .effects_when
            .as_ref()
            .unwrap()
            .last_option_not_matching
            .as_ref()
            .unwrap()
            .regex
            .is_some()
    );
    for (args, expected) in [
        ("--setting", false),
        ("--setting=off", true),
        ("--setting=off --setting", false),
        ("--setting --setting=0", true),
        ("--setting=off --setting=YES", false),
        ("--setting=off --setting=unknown", true),
        ("--setting=", true),
        ("--setting=onward", true),
        ("--setting=off -- --setting=on", true),
    ] {
        let command = format!("switch-tool {args}");
        let bound = bind(&profile, &command);
        assert_eq!(!bound.effects.is_empty(), expected, "{command}: {bound:#?}");
    }
}

#[test]
fn invalid_declarations_are_rejected_and_omission_keeps_old_effects() {
    for invalid in [
        YAML.replace(
            "option_scope: permuted_options",
            "option_scope: all_arguments",
        ),
        YAML.replace("unless_modifiers: [info]", "unless_modifiers: [missing]"),
        YAML.replace("unless_modifiers: [info]", "unless_forms: [missing]"),
        YAML.replace(
            "kind: any_flag, flags: [-x, --disable, --enable]",
            "kind: all_flags, flags: [-x, --disable, --enable]",
        ),
        YAML.replace(
            "last_option_not_matching: {kind: literal, value: --enable}",
            "last_option_not_matching: {kind: regex_pattern, pattern: '['}",
        ),
        YAML.replace(
            "unless_modifiers: [info]",
            "unless_modifiers: [info]\n      typo: true",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
    let mut profile = load_command_profile_from_str(YAML).unwrap();
    profile.modifiers[0].effects_when = None;
    assert!(
        !bind(&profile, "switch-tool --disable --enable")
            .effects
            .is_empty()
    );
}

#[test]
fn mixed_arity_aliases_consume_only_their_declared_owned_words() {
    let yaml = YAML.replace("effects_when:", "parameters: [{name: setting, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: --enable, operand_mode: optional_inline_only}, cardinality: optional_many}]\n    effects_when:");
    let profile = load_command_profile_from_str(&yaml).unwrap();
    for command in [
        "switch-tool --disable",
        "switch-tool -vx",
        "switch-tool --disable --enable=on",
        "switch-tool --enable=on --disable",
        "switch-tool --info --disable",
        "switch-tool --disable -o --enable",
    ] {
        bind(&profile, command);
    }
    let required = yaml.replace(
        "operand_mode: optional_inline_only}, cardinality: optional_many",
        "operand_mode: next_arg}, cardinality: required_one",
    );
    let profile = load_command_profile_from_str(&required).unwrap();
    let parsed = parse_command("switch-tool --disable --enable", ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    // The scoped scanner rejects missing operands before binding begins.
    assert!(select_invocation(&profile, &projection).is_err());
}

#[test]
fn informational_forms_can_suppress_effects_without_dropping_parameters() {
    let profile = load_command_profile_from_str(
        &YAML.replace("unless_modifiers: [info]", "unless_forms: [run]"),
    )
    .unwrap();
    let bound = bind(&profile, "switch-tool --disable -o output remaining-data");
    assert!(bound.effects.is_empty());
    assert_eq!(bound.bound_parameters.len(), 2);
    assert!(bound.applied_modifiers.contains(&ModifierId::new("mode")));
}

#[test]
fn ordered_short_aliases_in_one_cluster_use_the_scanner_order() {
    let yaml = YAML
        .replace("[-x, --disable, --enable]", "[-x, -y, --disable, --enable]")
        .replace(
            "{kind: literal, value: --enable}",
            "{kind: regex_pattern, pattern: '^(--enable|-y)$'}",
        );
    let profile = load_command_profile_from_str(&yaml).unwrap();
    for (command, expected) in [("switch-tool -xy", false), ("switch-tool -yx", true)] {
        assert_eq!(
            !bind(&profile, command).effects.is_empty(),
            expected,
            "{command}"
        );
    }
}
