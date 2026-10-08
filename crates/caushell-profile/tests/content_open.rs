use caushell_profile::{EffectKind, PathAccessKind, load_command_profile_from_str};

fn profile(effect: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: io-test, aliases: []}}\ntrust: {{tier: tier_a, source: built_in}}\nplatform: {{os_families: [linux], shell_families: [], requires_features: []}}\nforms:\n  - id: default\n    selector: {{kind: all, items: []}}\n    parameters:\n      - name: file\n        semantic: {{kind: path, role: write}}\n        binding: {{kind: positional_at, index: 0}}\n        cardinality: required_one\n    effects:\n      - {effect}\nmodifiers: []\nsubcommands: null\nextensions: {{}}\n"
    )
}

#[test]
fn content_open_is_explicit_and_optional() {
    let old = load_command_profile_from_str(&profile(
        "kind: write_path\n        target: {kind: slot, name: file}",
    ))
    .unwrap();
    assert_eq!(old.forms[0].effects[0].path_access, None);
    for kind in ["read_path", "write_path"] {
        let parsed = load_command_profile_from_str(&profile(&format!("kind: {kind}\n        path_access: content_open\n        target: {{kind: slot, name: file}}"))).unwrap();
        assert_eq!(
            parsed.forms[0].effects[0].path_access,
            Some(PathAccessKind::ContentOpen)
        );
    }
}

#[test]
fn invalid_access_annotations_are_rejected_instead_of_ignored() {
    for effect in [
        "kind: delete_path\n        path_access: content_open\n        target: {kind: slot, name: file}",
        "kind: change_mode\n        path_access: content_open\n        target: {kind: slot, name: file}",
        "kind: write_path\n        path_access: content_open\n        target: {kind: none}",
        "kind: write_path\n        path_access: safe_device\n        target: {kind: slot, name: file}",
    ] {
        assert!(
            load_command_profile_from_str(&profile(effect)).is_err(),
            "{effect}"
        );
    }
}

#[test]
fn reviewed_profiles_annotate_only_actual_content_open_slots() {
    let tee = load_command_profile_from_str(include_str!("../profiles/tee.yaml")).unwrap();
    assert_eq!(
        tee.forms
            .iter()
            .flat_map(|f| &f.effects)
            .find(|e| e.kind == EffectKind::WritePath)
            .unwrap()
            .path_access,
        Some(PathAccessKind::ContentOpen)
    );
    let sed = load_command_profile_from_str(include_str!("../profiles/sed.yaml")).unwrap();
    assert!(
        sed.modifiers
            .iter()
            .flat_map(|m| &m.effects)
            .all(|e| e.path_access.is_none())
    );
    let tar = load_command_profile_from_str(include_str!("../profiles/tar.yaml")).unwrap();
    assert!(
        tar.forms
            .iter()
            .flat_map(|f| &f.effects)
            .filter(|e| matches!(e.target, caushell_profile::EffectTarget::DerivedPath(_)))
            .all(|e| e.path_access.is_none())
    );
}
