use caushell_profile::*;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_eraser}
forms:
  - id: erase
    parameters:
      - {name: files, semantic: {kind: path, role: write}, binding: {kind: remaining_positionals}, cardinality: required_many}
    effects:
      - kind: write_path
        target: {kind: slot, name: files}
        host_risk: {semantic_class: file_content_erasure_target}
"#;

#[test]
fn erasure_is_optional_metadata_not_a_command_name() {
    let profile = load_command_profile_from_str(PROFILE).unwrap();
    let effect = &profile.forms[0].effects[0];
    assert_eq!(effect.kind, EffectKind::WritePath);
    assert_eq!(
        effect.host_risk.semantic_class,
        Some(HostRiskSemanticClass::FileContentErasureTarget)
    );
    let plain = load_command_profile_from_str(&PROFILE.replace(
        "        host_risk: {semantic_class: file_content_erasure_target}\n",
        "",
    ))
    .unwrap();
    assert_eq!(plain.forms[0].effects[0].host_risk.semantic_class, None);
}

#[test]
fn erasure_metadata_rejects_non_filesystem_writes() {
    for source in [
        PROFILE.replace("kind: write_path", "kind: read_path"),
        PROFILE.replace("{kind: slot, name: files}", "{kind: none}"),
    ] {
        assert!(load_command_profile_from_str(&source).is_err(), "{source}");
    }
}
