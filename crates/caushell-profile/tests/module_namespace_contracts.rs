use caushell_profile::*;

#[test]
fn output_family_contracts_do_not_become_input_or_scalar_namespace_proofs() {
    let base = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: producer}
forms:
  - id: run
    parameters:
      - {name: inputs, semantic: {kind: path, role: read, purpose: generic_operand}, binding: {kind: remaining_positionals}, cardinality: required_many}
    effects:
      - kind: write_path
        namespace_effect: directory_tree_write
        target: {kind: configured_path, sources: [], fallback_parent_slots: [inputs], fallback_parent_suffix: __cache__, missing: unknown}
"#;
    assert!(load_command_profile_from_str(base).is_ok());
    for invalid in [
        base.replace("kind: write_path", "kind: read_path"),
        base.replace(
            "fallback_parent_suffix: __cache__",
            "fallback_parent_suffix: ../escape",
        ),
        base.replace(
            "fallback_parent_suffix: __cache__",
            "fallback_parent_suffix: /absolute",
        ),
        base.replace(
            "fallback_parent_suffix: __cache__",
            "fallback_parent_suffix: ''",
        ),
        base.replace(
            "fallback_parent_slots: [inputs]",
            "fallback_parent_slots: []",
        ),
        base.replace(
            "namespace_effect: directory_tree_write",
            "namespace_effect: regular_file_write",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
    let invalid=base.replace("target: {kind: configured_path, sources: [], fallback_parent_slots: [inputs], fallback_parent_suffix: __cache__, missing: unknown}","target: {kind: slot, name: inputs}");
    assert!(load_command_profile_from_str(&invalid).is_err());
}

#[test]
fn compilation_cli_profiles_declare_facts_without_issuing_module_permission() {
    let registry = ProfileRegistry::built_in().unwrap();
    let profile = registry
        .lookup_module("python", "py_compile")
        .profile
        .unwrap();
    assert!(profile.identity.module_only);
    let files = profile
        .forms
        .iter()
        .find(|f| f.id.as_str() == "files")
        .unwrap();
    assert!(files.effects.iter().any(|effect| effect.namespace_effect
        == Some(caushell_types::PathNamespaceEffect::DirectoryTreeWrite)));
    let stdin = profile
        .forms
        .iter()
        .find(|f| f.id.as_str() == "stdin_list")
        .unwrap();
    assert!(stdin.operation_semantics_unresolved);
}
