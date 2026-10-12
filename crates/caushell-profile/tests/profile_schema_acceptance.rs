use caushell_profile::{ProfileRegistry, load_command_profile_from_path};

#[test]
fn all_builtin_documents_are_individually_valid_and_form_a_registry() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    paths.sort();
    let mut errors = Vec::new();
    let mut profiles = Vec::new();
    for path in paths {
        match load_command_profile_from_path(&path) {
            Ok(profile) => profiles.push(profile),
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    ProfileRegistry::from_profiles(profiles).unwrap();
    ProfileRegistry::built_in().unwrap();
}

#[test]
fn endpoint_input_scope_is_validated_without_any_command_name_dependency() {
    let template = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-uploader}
forms:
  - id: upload
    parameters:
      - {name: endpoint, semantic: {kind: endpoint, endpoint_kind: url, usage: upload_target}, binding: {kind: next_positional}, cardinality: required_one}
      - {name: body, semantic: {kind: path, role: read, purpose: generic_operand}, binding: {kind: next_positional}, cardinality: required_one}
    effects:
      - {kind: network_endpoint, target: {kind: slot, name: endpoint}, input_scope: {slots: [BODY_SLOT], stdin: true}}
"#;
    assert!(
        caushell_profile::load_command_profile_from_str(&template.replace("BODY_SLOT", "body"))
            .is_ok()
    );
    for name in ["typo", "body, body", "''"] {
        let err =
            caushell_profile::load_command_profile_from_str(&template.replace("BODY_SLOT", name))
                .unwrap_err();
        assert!(
            format!("{err}").contains("InvalidEndpointInputScope"),
            "{err}"
        );
    }
}
