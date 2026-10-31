use caushell_profile::load_command_profile_from_str;

#[test]
fn directory_creation_is_an_explicit_write_contract() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_directory_producer}
forms:
  - id: run
    parameters:
      - {name: output, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}
    effects:
      - {kind: write_path, namespace_effect: directory_create, target: {kind: slot, name: output}}
"#;
    assert!(load_command_profile_from_str(source).is_ok());
    for invalid in [
        source.replace("kind: write_path", "kind: read_path"),
        source.replace("kind: write_path", "kind: delete_path"),
        source.replace("target: {kind: slot, name: output}", "target: {kind: none}"),
        source.replace(
            "target: {kind: slot, name: output}",
            "target: {kind: configured_path, sources: [{slot: output, projection: {kind: identity}}], missing: unknown}",
        ),
        source.replace(
            "namespace_effect: directory_create,",
            "namespace_effect: directory_create, path_scope: {kind: subtree},",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn family_namespace_contract_requires_an_explicit_bounded_family_rule() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_file_family_producer}
forms:
  - id: run
    parameters:
      - {name: output, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}
    effects:
      - kind: write_path
        namespace_effect: directory_tree_write
        target: {kind: derived_path, source: {kind: slot, name: output}, rule: {kind: sibling_files}}
"#;
    assert!(load_command_profile_from_str(source).is_ok());
    for invalid in [
        source.replace("kind: write_path", "kind: read_path"),
        source.replace("kind: sibling_files", "kind: archive_members"),
        source.replace("kind: sibling_files", "kind: append_suffix, suffix: '.bak'"),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}
