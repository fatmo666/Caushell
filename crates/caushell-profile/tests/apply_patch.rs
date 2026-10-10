use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

const PROFILE: &str = include_str!("../profiles/apply_patch.yaml");
fn resolved(command: &str, bindings: &SessionBindings) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    resolve_with(registry, command, bindings)
}
fn resolve_with(
    registry: &ProfileRegistry,
    command: &str,
    bindings: &SessionBindings,
) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{command}: {other:?}"),
    }
}
fn parameter<'a>(bound: &'a BoundInvocation, name: &str) -> &'a BoundParameter {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .unwrap()
}
fn values(bound: &BoundInvocation, name: &str) -> Vec<SemanticValueResolution> {
    parameter(bound, name)
        .semantic_values()
        .map(|value| match value {
            SemanticValueRef::Projected { value, .. } => value.resolution.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}
fn known(s: &str) -> SemanticValueResolution {
    SemanticValueResolution::Known(s.into())
}
fn argv(patch: &str) -> String {
    format!("apply_patch '{}'", patch.replace('\'', "'\\''"))
}

#[test]
fn registers_canonical_name_alias_and_absolute_executable() {
    let r = ProfileRegistry::built_in().unwrap();
    for name in ["apply_patch", "applypatch", "/usr/local/bin/apply_patch"] {
        assert_eq!(
            r.lookup(name).profile.unwrap().primary_name(),
            "apply_patch"
        );
    }
}
#[test]
fn argument_targets_preserve_all_effect_classes_and_moves() {
    let b = resolved(
        &argv(
            "*** Begin Patch\n*** Add File: new\n+x\n*** Delete File: gone\n*** Update File: same\n-old\n+new\n*** Update File: src\n*** Move to: dest\n x\n*** End Patch",
        ),
        &SessionBindings::new(),
    );
    assert_eq!(b.form_id.as_str(), "patch_argument");
    assert!(b.residuals.is_empty(), "{b:?}");
    assert_eq!(values(&b, "patch_reads"), [known("same"), known("src")]);
    assert_eq!(
        values(&b, "patch_writes"),
        [known("new"), known("same"), known("dest")]
    );
    assert_eq!(values(&b, "patch_deletes"), [known("gone"), known("src")]);
    assert_eq!(b.effects.len(), 3);
    assert!(collect_recursive_payload_candidates(&b).is_empty());
}
#[test]
fn materialized_outer_scalar_is_decoded_but_inner_shell_syntax_stays_literal() {
    let mut env = SessionBindings::new();
    env.insert_exact_scalar(
        "PATCH",
        "*** Begin Patch\n*** Add File: $INNER/$(whoami)\n+$(rm -rf /)\n*** End Patch",
    );
    env.insert_exact_scalar("INNER", "/etc");
    let b = resolved("apply_patch \"$PATCH\"", &env);
    assert_eq!(values(&b, "patch_writes"), [known("$INNER/$(whoami)")]);
    assert!(collect_recursive_payload_candidates(&b).is_empty());
}
#[test]
fn original_source_and_span_are_preserved_once_per_effect_not_per_target() {
    let b = resolved(
        &argv("*** Begin Patch\n*** Add File: one\n+x\n*** Add File: two\n+x\n*** End Patch"),
        &SessionBindings::new(),
    );
    let source = &parameter(&b, "patch").values[0];
    for p in b.bound_parameters.iter().filter(|p| p.payload_generated) {
        assert_eq!(p.values, [source.clone()]);
        assert!(
            p.projected_values
                .as_ref()
                .unwrap()
                .iter()
                .all(|v| v.source_index == 0)
        );
    }
}
#[test]
fn malformed_dynamic_and_multiple_arguments_keep_unknown_modifications() {
    for command in [
        argv("*** Begin Patch\n*** Add File: safe\n+x"),
        "apply_patch \"$PATCH\"".into(),
        "apply_patch --help".into(),
        "apply_patch --".into(),
        "apply_patch ''".into(),
        format!("{} extra", argv("*** Begin Patch\n*** End Patch")),
    ] {
        let b = resolved(&command, &SessionBindings::new());
        assert_eq!(b.form_id.as_str(), "patch_argument", "{command}");
        for slot in ["patch_reads", "patch_writes", "patch_deletes"] {
            assert!(
                matches!(
                    values(&b, slot).as_slice(),
                    [SemanticValueResolution::Unknown(_)]
                ),
                "{command}: {b:?}"
            );
        }
    }
}
#[test]
fn proven_absent_effects_are_empty_views_not_missing_or_unknown_slots() {
    for patch in [
        "*** Begin Patch\n*** End Patch",
        "*** Begin Patch\n*** Add File: empty\n*** End Patch",
    ] {
        let b = resolved(&argv(patch), &SessionBindings::new());
        assert!(parameter(&b, "patch_reads").semantic_values_are_inapplicable());
        assert!(parameter(&b, "patch_deletes").semantic_values_are_inapplicable());
    }
}
#[test]
fn stdin_starts_unknown_and_requires_explicit_complete_evidence() {
    let mut b = resolved("apply_patch", &SessionBindings::new());
    assert_eq!(b.form_id.as_str(), "patch_stdin");
    assert_eq!(
        values(&b, "patch_writes"),
        [SemanticValueResolution::Unknown(
            ProjectionUnknownReason::PayloadUnavailable
        )]
    );
    refresh_payload_projections(
        &mut b,
        Some("*** Begin Patch\n*** Add File: stdin-file\n+x\n*** End Patch"),
    );
    assert_eq!(values(&b, "patch_writes"), [known("stdin-file")]);
    assert!(matches!(
        parameter(&b, "patch_writes").values.as_slice(),
        [BoundValue::ImplicitInput {
            source: ImplicitInputSource::StdinData,
            domain: None,
            ..
        }]
    ));
    refresh_payload_projections(&mut b, None);
    assert!(matches!(
        values(&b, "patch_writes").as_slice(),
        [SemanticValueResolution::Unknown(_)]
    ));
    assert_eq!(
        b.bound_parameters
            .iter()
            .filter(|p| p.payload_generated)
            .count(),
        3
    );
}
#[test]
fn opt_in_grammar_is_not_tied_to_apply_patch_command_name() {
    let profile = load_command_profile_from_str(
        &PROFILE
            .replace(
                "canonical_name: apply_patch",
                "canonical_name: arbitrary-editor",
            )
            .replace("aliases: [applypatch]", "aliases: []"),
    )
    .unwrap();
    let r = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let b = resolve_with(
        &r,
        &argv("*** Begin Patch\n*** Delete File: file\n*** End Patch").replacen(
            "apply_patch",
            "arbitrary-editor",
            1,
        ),
        &SessionBindings::new(),
    );
    assert_eq!(values(&b, "patch_deletes"), [known("file")]);
}
#[test]
fn invalid_declarations_cannot_drop_effects_or_collide_slots() {
    load_command_profile_from_str(PROFILE).unwrap();
    for bad in [
        PROFILE.replace("name: patch}", "name: nonexistent}"),
        PROFILE.replace("writes: patch_writes", "writes: patch_reads"),
        PROFILE.replace("writes: patch_writes", "writes: patch"),
        PROFILE.replace("format: codex_apply_patch", "format: bash"),
        PROFILE.replace(
            "format: codex_apply_patch",
            "format: codex_apply_patch\n        max_bytes: 0",
        ),
        PROFILE.replace(
            "format: codex_apply_patch",
            "format: codex_apply_patch\n        max_operations: 0",
        ),
        PROFILE.replace(
            "format: codex_apply_patch",
            "format: codex_apply_patch\n        unknown_field: true",
        ),
        PROFILE.replace("kind: write_path", "kind: read_path"),
        PROFILE.replace("source: stdin_data", "source: stdin_payload"),
    ] {
        assert!(load_command_profile_from_str(&bad).is_err(), "{bad}");
    }
}
#[test]
fn configured_budgets_and_nonlocal_context_keep_unknown_targets() {
    let profile = load_command_profile_from_str(&PROFILE.replace(
        "format: codex_apply_patch",
        "format: codex_apply_patch\n        max_bytes: 90\n        max_operations: 1",
    ))
    .unwrap();
    let r = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for patch in [
        "*** Begin Patch\n*** Delete File: one\n*** Delete File: two\n*** End Patch".into(),
        format!(
            "*** Begin Patch\n*** Add File: x\n+{}\n*** End Patch",
            "x".repeat(100)
        ),
        "*** Begin Patch\n*** Environment ID: remote\n*** Add File: x\n+x\n*** End Patch".into(),
    ] {
        let b = resolve_with(&r, &argv(&patch), &SessionBindings::new());
        assert!(matches!(
            values(&b, "patch_writes").as_slice(),
            [SemanticValueResolution::Unknown(_)]
        ));
    }
}
