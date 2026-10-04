//! Command-independent contracts for opt-in, incomplete operation semantics.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ResolveGapKind, ShellKind};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: opaque-fixture}
forms:
  - id: run
    selector: {kind: has_positional_at_matching, index: 0, matcher: {kind: literal, value: run}}
    parameters:
      - {name: operation, semantic: {kind: plain_value}, binding: {kind: positional_at, index: 0}, cardinality: required_one}
      - {name: path, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}
      - {name: output, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: '-o', operand_mode: next_arg}, cardinality: optional_many}
      - {name: prefixed_output, semantic: {kind: plain_value}, binding: {kind: args_with_prefix, prefix: '-D', before_dash_dash: true}, cardinality: optional_many}
    effects: [{kind: write_path, target: {kind: slot, name: path}}]
modifiers:
  - {id: flags, matcher: {kind: any_flag, flags: ['-q', '-y']}}
  - id: attached
    matcher: {kind: any_flag, flags: ['-r']}
    parameters:
      - {name: level, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
"#;

fn registry(opt_in: bool) -> ProfileRegistry {
    let mut profile = load_command_profile_from_str(PROFILE).unwrap();
    assert!(!profile.opaque_on_unresolved);
    profile.opaque_on_unresolved = opt_in;
    ProfileRegistry::from_profiles(vec![profile]).unwrap()
}
fn resolved(registry: &ProfileRegistry, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn declaration_is_optional_and_does_not_change_legacy_residual_tolerance() {
    let b = resolved(&registry(false), "opaque-fixture run output --future");
    assert!(!b.operation_semantics_unresolved);
    assert!(b.residuals.is_empty());
    let p =
        load_command_profile_from_str(&format!("{PROFILE}\nopaque_on_unresolved: true\n")).unwrap();
    assert!(p.opaque_on_unresolved);
}

#[test]
fn unknown_options_unbound_operands_and_partial_clusters_are_opaque() {
    let registry = registry(true);
    for c in [
        "opaque-fixture run output --future",
        "opaque-fixture run output extra",
        "opaque-fixture -qZ run output",
        "opaque-fixture -Zq run output",
        "opaque-fixture run",
        "opaque-fixture run output -o",
        "opaque-fixture run output -o result -o",
        "opaque-fixture run output -oresult",
    ] {
        let b = resolved(&registry, c);
        assert!(b.operation_semantics_unresolved, "{c}: {b:?}");
        assert!(!b.residuals.is_empty(), "{c}");
    }
}

#[test]
fn known_clusters_attached_operands_and_dashdash_data_stay_resolved() {
    let registry = registry(true);
    for c in [
        "opaque-fixture -qy run output",
        "opaque-fixture run output -o result",
        "opaque-fixture -r42 run output",
        "opaque-fixture run output -o -qZ",
        "opaque-fixture run output -Ddump",
        "opaque-fixture run -- -qZ",
    ] {
        let b = resolved(&registry, c);
        assert!(!b.operation_semantics_unresolved, "{c}: {b:?}");
        assert!(b.residuals.is_empty(), "{c}: {b:?}");
    }
}

#[test]
fn opacity_keeps_known_effects_and_bound_operands() {
    let b = resolved(&registry(true), "opaque-fixture run /etc/output --future");
    assert!(b.operation_semantics_unresolved);
    assert_eq!(b.effects.len(), 1);
    assert_eq!(b.effects[0].kind, EffectKind::WritePath);
    assert!(b.bound_parameters.iter().any(|p| p.name.as_str() == "path"));
}

#[test]
fn argument_ownership_uses_indices_not_potentially_shared_source_spans() {
    let registry = registry(true);
    let profile = registry.lookup("opaque-fixture").profile.unwrap();
    for (command, opaque) in [
        ("opaque-fixture run output -o -qZ", false),
        ("opaque-fixture run output -o -qZ --future", true),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let mut projection =
            project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        // Derived argv fields can originate at one common parent source span.
        let shared_span = projection.args[0].span.clone();
        for arg in &mut projection.args {
            arg.span = shared_span.clone();
        }
        let selection = select_invocation(profile, &projection).unwrap();
        let bound = bind_invocation(profile, &projection, &selection);
        assert_eq!(
            bound.operation_semantics_unresolved, opaque,
            "{command}: {bound:?}"
        );
    }
}

#[test]
fn failed_and_ambiguous_selection_preserve_a_queryable_partial_invocation() {
    for ambiguous in [false, true] {
        let mut profile = load_command_profile_from_str(PROFILE).unwrap();
        profile.opaque_on_unresolved = true;
        if ambiguous {
            let mut other = profile.forms[0].clone();
            other.id = FormId::new("other");
            profile.forms.push(other);
        }
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let parsed = parse_command(
            if ambiguous {
                "opaque-fixture run output"
            } else {
                "opaque-fixture unknown"
            },
            ShellKind::Bash,
        )
        .unwrap();
        match resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::SelectionError {
                gap_kind,
                partial_bound: Some(bound),
                ..
            } => {
                assert_eq!(gap_kind, ResolveGapKind::OpaqueInvocation);
                assert!(bound.operation_semantics_unresolved);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn nested_subcommand_and_child_flags_obey_declared_option_scope() {
    let p = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: scope-fixture}
opaque_on_unresolved: true
option_scope: leading_options
subcommands:
  roots:
    - name: run
      option_scope: leading_options
      forms:
        - id: child
          selector: {kind: has_positional_at, index: 0}
          parameters:
            - {name: child, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: required_many}
"#).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![p]).unwrap();
    let b = resolved(&registry, "scope-fixture run tool --future -qZ");
    assert!(!b.operation_semantics_unresolved, "{b:?}");
    let parsed = parse_command("scope-fixture unknown", ShellKind::Bash).unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new()
        ),
        ResolveInvocationResult::SelectionError {
            gap_kind: ResolveGapKind::OpaqueInvocation,
            partial_bound: Some(_),
            ..
        }
    ));
}
