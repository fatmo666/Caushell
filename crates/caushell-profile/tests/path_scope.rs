//! Declarative semantics only; no fixture command is executed.
use caushell_profile::{EffectTarget, PathScope, load_command_profile_from_str};

fn profile(effect: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary_tree_tool}}\nforms:\n  - id: tree\n    parameters:\n      - name: roots\n        semantic: {{kind: path, role: read}}\n        binding: {{kind: remaining_positionals}}\n        cardinality: optional_many\n    effects:\n      - {effect}\nmodifiers:\n  - id: follow\n    matcher: {{kind: any_flag, flags: ['-L']}}\n"
    )
}

#[test]
fn traversal_scope_is_opt_in_and_keeps_typed_modifier_references() {
    let old = load_command_profile_from_str(&profile(
        "kind: delete_path\n        target: {kind: slot, name: roots}",
    ))
    .unwrap();
    assert_eq!(old.forms[0].effects[0].path_scope, None);
    let new=load_command_profile_from_str(&profile("kind: delete_path\n        target: {kind: slot, name: roots}\n        path_scope: {kind: subtree, escape_modifiers: [follow]}")).unwrap();
    assert!(matches!(&new.forms[0].effects[0].path_scope,
        Some(PathScope::Subtree {escape_modifiers}) if escape_modifiers[0].as_str()=="follow"));
}

#[test]
fn traversal_declarations_reject_invalid_targets_access_and_references() {
    for declaration in [
        "kind: execute_payload\n        target: {kind: slot, name: roots}",
        "kind: delete_path\n        target: {kind: none}",
        "kind: write_path\n        path_access: content_open\n        target: {kind: slot, name: roots}",
    ] {
        assert!(
            load_command_profile_from_str(&profile(&format!(
                "{declaration}\n        path_scope: {{kind: subtree}}"
            )))
            .is_err()
        );
    }
    for scope in [
        "{kind: subtree, escape_modifiers: [missing]}",
        "{kind: subtree, unknown: true}",
    ] {
        assert!(load_command_profile_from_str(&profile(&format!("kind: delete_path\n        target: {{kind: slot, name: roots}}\n        path_scope: {scope}"))).is_err());
    }
}

#[test]
fn configured_targets_can_declare_the_same_host_risk_as_explicit_targets() {
    let p=load_command_profile_from_str(&profile("kind: delete_path\n        target:\n          kind: configured_path\n          sources: [{slot: roots, projection: {kind: identity}}]\n          default_value: '.'\n        path_scope: {kind: subtree, escape_modifiers: [follow]}\n        catastrophic: {semantic_class: delete_path}")).unwrap();
    let effect = &p.forms[0].effects[0];
    assert!(matches!(effect.target, EffectTarget::ConfiguredPath(_)));
    assert_eq!(
        effect.catastrophic.semantic_class,
        Some(caushell_profile::CatastrophicSemanticClass::DeletePath)
    );
}

#[test]
fn supplemental_default_requires_a_literal_fallback_and_source_slots() {
    let target = "kind: delete_path\n        target:\n          kind: configured_path\n          sources: [{slot: roots, projection: {kind: identity}}]\n          only_when_sources_absent: true\n          default_value: '.'";
    assert!(load_command_profile_from_str(&profile(target)).is_ok());
    for invalid in [
        target.replace("default_value: '.'", "missing: unknown"),
        target.replace("[{slot: roots, projection: {kind: identity}}]", "[]"),
        target.replace(
            "default_value: '.'",
            "default_value: '.'\n          environment: {name: ROOT}",
        ),
    ] {
        assert!(load_command_profile_from_str(&profile(&invalid)).is_err());
    }
}
