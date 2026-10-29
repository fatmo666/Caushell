//! Opt-in native value validation retains original operands and known effects.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: grammar-driver}
option_matching: exact_names
forms: [{id: run}]
modifiers:
  - id: mode
    matcher: {kind: any_flag, flags: [--mode]}
    parameters:
      - name: mode
        semantic: {kind: plain_value}
        binding: {kind: following_matched_flag, operand_mode: inline_only}
        cardinality: required_many
        value_constraints: [{kind: require_match, pattern: 'stable|stable,debug'}]
  - id: loader
    matcher: {kind: any_flag, flags: [--load]}
    parameters:
      - {name: library, semantic: {kind: in_process_code_load, load_kind: library_path}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}
    effects: [{kind: load_in_process_code, target: {kind: slot, name: library}}]
"#;

fn resolve(options: &str) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(PROFILE).unwrap()])
            .unwrap();
    let parsed = parse_command(&format!("grammar-driver {options}"), ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound,
        other => panic!("{options}: {other:#?}"),
    }
}

#[test]
fn complete_decoded_values_are_checked_without_a_second_shell_interpretation() {
    for options in [
        "--mode=stable",
        "--mode=stable,debug",
        "--mode='stable,debug'",
        "--mode=stable --mode=stable,debug",
    ] {
        let r = resolve(options);
        assert!(!r.operation_semantics_unresolved, "{options}: {r:#?}");
    }
}

#[test]
fn every_occurrence_requires_a_whole_value_proof_even_without_opaque_mode() {
    for options in [
        "--mode=stable,surprise",
        "--mode=xstable",
        "--mode=stable,debug/escape",
        "--mode=",
        "--mode",
        "--mode=stable --mode=unknown",
        "--mode=unknown --mode=stable",
        "--mode=\"stable,$UNKNOWN\"",
        "--mode=\"$UNKNOWN\" --mode=stable",
    ] {
        let r = resolve(options);
        assert!(r.operation_semantics_unresolved, "{options}: {r:#?}");
        assert!(!r.residuals.is_empty(), "{options}: {r:#?}");
    }
}

#[test]
fn rejected_values_do_not_remove_their_operands_or_other_code_loading_effects() {
    let r = resolve("--mode=unknown --load /outside/library.so");
    assert!(r.operation_semantics_unresolved);
    assert!(
        r.effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
    let mode = r
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "mode")
        .unwrap();
    assert!(matches!(&mode.values[0], BoundValue::Argument {text, ..} if text == "unknown"));
}

#[test]
fn undeclared_or_invalid_value_grammars_do_not_become_implicit_filters() {
    assert!(
        load_command_profile_from_str(
            &PROFILE.replace("pattern: 'stable|stable,debug'", "pattern: '['")
        )
        .is_err()
    );
    assert!(
        load_command_profile_from_str(
            &PROFILE.replace("pattern: 'stable|stable,debug'", "pattern: ''")
        )
        .is_err()
    );
    let p = load_command_profile_from_str(&PROFILE.replace(
        "        value_constraints: [{kind: require_match, pattern: 'stable|stable,debug'}]\n",
        "",
    ))
    .unwrap();
    let parsed = parse_command("grammar-driver --mode=unknown", ShellKind::Bash).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![p]).unwrap();
    let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!()
    };
    assert!(!r.bound.operation_semantics_unresolved);
}
