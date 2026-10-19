use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, Effect, EffectKind, InvocationRuntimeContext, Modifier, ProfileRegistry,
    ResolveInvocationResult, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-tool}
option_scope: leading_options
dispatch_overrides:
  - subcommand_depth: 0
    first_arguments: [--inspect]
    forms:
      - id: inspect_root
        parameters: &args [{name: arguments, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
  - subcommand_depth: 1
    first_arguments: [--inspect]
    forms:
      - id: inspect_child
        parameters: *args
  - subcommand_depth: 2
    first_arguments: [--inspect]
    forms:
      - id: inspect_grandchild
        parameters: *args
modifiers:
  - id: tag
    matcher: {kind: any_flag, flags: [--tag]}
    parameters: [{name: tag, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
  - id: directory
    matcher: {kind: any_flag, flags: [--directory]}
    parameters: [{name: directory, semantic: {kind: path, role: cwd_anchor, purpose: working_directory}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
    effects: [{kind: target_path, target: {kind: slot, name: directory}}]
subcommands:
  roots:
    - name: edit
      aliases: [change]
      option_scope: leading_options
      forms:
        - id: edit_file
          parameters: [{name: paths, semantic: {kind: path, role: write}, binding: {kind: remaining_args}, cardinality: optional_many}]
          effects: [{kind: write_path, target: {kind: slot, name: paths}}]
      modifiers:
        - id: log
          matcher: {kind: any_flag, flags: [--log]}
          parameters: [{name: log, semantic: {kind: path, role: write}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
          effects: [{kind: write_path, target: {kind: slot, name: log}}]
      children:
        - name: child
          forms:
            - id: edit_child
              parameters: *args
"#;

fn resolve(command: &str) -> Result<BoundInvocation, String> {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(PROFILE).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => Ok(result.bound),
        other => Err(format!("{other:?}")),
    }
}

#[test]
fn explicit_modes_precede_root_child_and_nested_dispatch() {
    for (command, form, depth) in [
        ("arbitrary-tool --inspect edit", "inspect_root", 0),
        ("arbitrary-tool edit --inspect", "inspect_child", 1),
        ("arbitrary-tool change --inspect", "inspect_child", 1),
        (
            "arbitrary-tool edit child --inspect",
            "inspect_grandchild",
            2,
        ),
        ("arbitrary-tool '--inspect' edit", "inspect_root", 0),
    ] {
        let bound = resolve(command).unwrap();
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:?}");
        assert_eq!(bound.subcommand_path.len(), depth);
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
        assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    }
}

#[test]
fn known_global_options_keep_their_effects_and_own_their_values() {
    let bound = resolve("arbitrary-tool --directory /opt/repo edit --inspect").unwrap();
    assert_eq!(bound.form_id.as_str(), "inspect_child");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TargetPath)
    );
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let bound = resolve("arbitrary-tool edit --log /opt/log child --inspect").unwrap();
    assert_eq!(bound.form_id.as_str(), "inspect_grandchild");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let bound = resolve("arbitrary-tool --tag --inspect edit file").unwrap();
    assert_eq!(bound.form_id.as_str(), "edit_file");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(resolve("arbitrary-tool --unknown --inspect edit").is_err());
    assert!(resolve("arbitrary-tool --tag $values edit --inspect").is_err());
}

#[test]
fn later_words_and_terminators_do_not_redirect_dispatch() {
    for command in [
        "arbitrary-tool edit file --inspect",
        "arbitrary-tool edit -- --inspect",
    ] {
        let bound = resolve(command).unwrap();
        assert_eq!(bound.form_id.as_str(), "edit_file", "{command}: {bound:?}");
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
    assert!(resolve("arbitrary-tool -- --inspect edit").is_err());
    assert!(resolve("arbitrary-tool edit --unmodeled").is_err());
}

#[test]
fn unknown_mode_words_cannot_silently_fall_through_to_a_form() {
    for command in [
        "arbitrary-tool edit \"$mode\"",
        "arbitrary-tool $prefix --inspect edit",
        "arbitrary-tool edit $values --inspect",
    ] {
        let error = resolve(command).unwrap_err();
        assert!(error.contains("OpaqueInvocation"), "{command}: {error}");
    }
}

#[test]
fn invalid_declarations_are_rejected() {
    for source in [
        PROFILE.replace(
            "option_scope: leading_options",
            "option_scope: all_arguments",
        ),
        PROFILE.replacen("first_arguments: [--inspect]", "first_arguments: []", 1),
        PROFILE.replacen(
            "first_arguments: [--inspect]",
            "first_arguments: [--inspect, --inspect]",
            1,
        ),
        PROFILE.replacen("subcommand_depth: 1", "subcommand_depth: 0", 1),
        PROFILE.replacen("first_arguments: [--inspect]", "first_arguments: ['']", 1),
    ] {
        assert!(load_command_profile_from_str(&source).is_err());
    }
}

#[test]
fn override_effects_participate_in_registry_candidate_indexes() {
    let mut profile = load_command_profile_from_str(PROFILE).unwrap();
    profile.dispatch_overrides[0].forms[0]
        .effects
        .push(Effect::new(EffectKind::TerminateCurrentShell));
    profile.dispatch_overrides[0].modifiers.push(
        Modifier::new("bind")
            .with_flag_name("--bind")
            .with_effect(Effect::new(EffectKind::BindVariableFromRuntimeInput)),
    );
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    assert!(registry.may_terminate_shell("arbitrary-tool"));
    assert!(registry.may_write_runtime_variable("arbitrary-tool"));
}

#[test]
fn failed_override_selection_retains_known_local_modifier_effects() {
    let source = PROFILE.replacen(
        "first_arguments: [--inspect]",
        r#"first_arguments: [--inspect]
    option_scope: permuted_options
    modifiers:
      - {id: entry, matcher: {kind: any_flag, flags: [--inspect, --accept]}}
      - id: output
        matcher: {kind: any_flag, flags: [--output]}
        parameters: [{name: output, semantic: {kind: path, role: write}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
        effects: [{kind: write_path, target: {kind: slot, name: output}}]"#,
        1,
    ).replacen("id: inspect_root", "id: inspect_root\n        selector: {kind: has_flag, flag: --accept}", 1);
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
            .unwrap();
    let parsed = parse_command(
        "arbitrary-tool --inspect --output /opt/output",
        ShellKind::Bash,
    )
    .unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::SelectionError {
            gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
            partial_bound: Some(bound),
            ..
        } => {
            assert!(
                bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::WritePath)
            );
        }
        other => panic!("{other:?}"),
    }
}
