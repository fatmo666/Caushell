use caushell_profile::*;
use caushell_types::PathNamespaceEffect;
#[test]
fn removal_contract_cannot_describe_a_write_or_an_implicit_subtree() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: retiring_tool}\nforms:\n - id: run\n   parameters: [{name: source, semantic: {kind: path, role: target}, binding: {kind: next_positional}, cardinality: required_one}]\n   effects: [{kind: move_path, namespace_effect: entry_removal, target: {kind: slot, name: source}}]\n";
    assert_eq!(
        load_command_profile_from_str(source).unwrap().forms[0].effects[0].namespace_effect,
        Some(PathNamespaceEffect::EntryRemoval)
    );
    for invalid in [
        source.replace("kind: move_path", "kind: write_path"),
        source.replace("kind: move_path", "kind: read_path"),
        source.replace(
            "namespace_effect: entry_removal,",
            "namespace_effect: entry_removal, path_scope: {kind: subtree},",
        ),
        source.replace("target: {kind: slot, name: source}", "target: {kind: none}"),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}
#[test]
fn only_reviewed_in_place_conversion_gets_the_regular_file_contract() {
    let registry = ProfileRegistry::built_in().unwrap();
    let profile = registry.lookup("dos2unix").profile.unwrap();
    let form = profile
        .forms
        .iter()
        .find(|f| f.id.as_str() == "convert_in_place")
        .unwrap();
    assert!(
        form.effects
            .iter()
            .filter(|e| e.kind == EffectKind::WritePath)
            .all(|e| e.namespace_effect == Some(PathNamespaceEffect::RegularFileWrite))
    );
    for form in profile
        .forms
        .iter()
        .filter(|f| f.id.as_str() != "convert_in_place")
    {
        assert!(form.effects.iter().all(|e| e.namespace_effect.is_none()));
    }
}
