//! Complete argv suffixes are data, but their variable origin is not erased.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{RuntimeProducedValueKind, ShellKind};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: fixture}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: execute
    parameters: [{name: args, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - {id: ordinary, matcher: {kind: any_flag, flags: [-a]}}
  - id: program
    matcher: {kind: any_flag, flags: [-e, --program]}
    parameters:
      - {name: program, semantic: {kind: payload, language: bash, source: inline_string, recursive: true}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
    effects: [{kind: execute_payload, target: {kind: slot, name: program}}]
"#;

fn resolve(
    profile: &str,
    command: &str,
    bindings: &SessionBindings,
) -> Result<BoundInvocation, String> {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(profile).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(r) => Ok(r.bound),
        ResolveInvocationResult::SelectionError { error, .. } => Err(format!("{error:#?}")),
        other => panic!("{other:#?}"),
    }
}

fn materialized(
    profile: &str,
    command: &str,
    bindings: &SessionBindings,
) -> MaterializedRecursivePayloadCandidate {
    let r = resolve(profile, command, bindings).unwrap();
    assert!(!r.operation_semantics_unresolved, "{command}: {r:#?}");
    let candidates = collect_recursive_payload_candidates(&r);
    assert_eq!(candidates.len(), 1, "{command}: {r:#?}");
    materialize_recursive_payload_candidate(&candidates[0], bindings)
}

fn text(payload: &MaterializedRecursivePayloadCandidate) -> String {
    match &payload.candidate.input {
        RecursivePayloadInput::ArgumentFragments { fragments } => fragments
            .iter()
            .map(|f| f.text.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        other => panic!("{other:#?}"),
    }
}

#[test]
fn short_cluster_and_long_inline_literals_are_not_expanded_a_second_time() {
    let bindings = SessionBindings::new().with_exact_scalar("INNER", "wrong-second-expansion");
    for profile in [
        PROFILE.to_string(),
        PROFILE.replace("leading_options", "permuted_options"),
    ] {
        for command in [
            r#"fixture -ae'printf "%s\n" "$INNER"'"#,
            r#"fixture --program='printf "%s\n" "$INNER"'"#,
            r#"fixture -eprintf\ \$INNER"#,
        ] {
            let p = materialized(&profile, command, &bindings);
            assert_eq!(p.resolution, ValueMaterialization::Static);
            let expected = if command.contains(r"\ ") {
                "printf $INNER"
            } else {
                r#"printf "%s\n" "$INNER""#
            };
            assert_eq!(text(&p), expected);
        }
    }
}

#[test]
fn unscoped_raw_inline_values_still_receive_their_first_lexical_decode() {
    let profile = PROFILE.replace("option_scope: leading_options\n", "");
    let p = materialized(
        &profile,
        r#"fixture -e'printf "$INNER"'"#,
        &SessionBindings::new(),
    );
    assert_eq!(p.resolution, ValueMaterialization::Static);
    assert_eq!(text(&p), r#"printf "$INNER""#);
}

#[test]
fn exact_and_runtime_variable_origins_survive_suffix_binding() {
    for runtime in [false, true] {
        let mut bindings =
            SessionBindings::new().with_exact_scalar("INNER", "wrong-second-expansion");
        let code = r#"printf "%s" "$INNER""#;
        if runtime {
            bindings.insert_runtime_produced("CODE", code, RuntimeProducedValueKind::Scalar);
        } else {
            bindings.insert_exact_scalar("CODE", code);
        }
        for command in [r#"fixture -ae"$CODE""#, r#"fixture --program="$CODE""#] {
            let p = materialized(PROFILE, command, &bindings);
            assert_eq!(text(&p), code, "{p:#?}");
            if runtime {
                assert!(
                    matches!(p.resolution, ValueMaterialization::ResolvedRuntimeProduced { ref variable_name, .. } if variable_name == "CODE"),
                    "{p:#?}"
                );
            } else {
                assert!(
                    matches!(p.resolution, ValueMaterialization::ResolvedExactScalar { ref variable_name, .. } if variable_name == "CODE"),
                    "{p:#?}"
                );
            }
        }
    }
}

#[test]
fn composite_expansions_keep_splitting_and_runtime_origin_uncertainty() {
    let mut bindings = SessionBindings::new().with_exact_scalar("CODE", "printf x");
    bindings.insert_runtime_produced("LEFT", "printf ", RuntimeProducedValueKind::Scalar);
    bindings.insert_runtime_produced("RIGHT", "x", RuntimeProducedValueKind::Scalar);
    for command in [
        "fixture -e$CODE",
        r#"fixture -e"$LEFT$RIGHT""#,
        r#"fixture -e"$(printf x)""#,
    ] {
        match resolve(PROFILE, command, &bindings) {
            Err(_) => {}
            Ok(r) => {
                let candidates = collect_recursive_payload_candidates(&r);
                assert!(
                    r.operation_semantics_unresolved || !candidates.is_empty(),
                    "{r:#?}"
                );
                for candidate in candidates {
                    let p = materialize_recursive_payload_candidate(&candidate, &bindings);
                    assert!(
                        !matches!(
                            p.resolution,
                            ValueMaterialization::Static
                                | ValueMaterialization::ResolvedExactScalar { .. }
                                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                        ),
                        "{p:#?}"
                    );
                }
            }
        }
    }
}

#[test]
fn unknown_inline_expansions_do_not_acquire_a_literal_proof() {
    for command in [r#"fixture -e"$UNKNOWN""#, r#"fixture --program="$UNKNOWN""#] {
        match resolve(PROFILE, command, &SessionBindings::new()) {
            Ok(r) => {
                let candidates = collect_recursive_payload_candidates(&r);
                assert!(
                    r.operation_semantics_unresolved || !candidates.is_empty(),
                    "{r:#?}"
                );
                for candidate in candidates {
                    let p = materialize_recursive_payload_candidate(
                        &candidate,
                        &SessionBindings::new(),
                    );
                    assert!(
                        !matches!(p.resolution, ValueMaterialization::Static),
                        "{p:#?}"
                    );
                }
            }
            Err(_) => {}
        }
    }
}
