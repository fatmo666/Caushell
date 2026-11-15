use caushell_profile::*;
fn cat() -> RawCommandProfile {
    load_raw_command_profile_from_str(include_str!("../profiles/cat.yaml")).unwrap()
}
#[test]
fn total_contract_requires_explicit_review_and_no_writable_mode() {
    let mut p = cat();
    p.read_only_control_surface = false;
    assert!(normalize_command_profile(p).is_err());
    let mut p = cat();
    p.forms[1].effects[0].kind = RawEffectKind::WritePath;
    assert!(normalize_command_profile(p).is_err());
    let mut p = cat();
    p.forms[1].operation_semantics_unresolved = true;
    assert!(normalize_command_profile(p).is_err());
}
#[test]
fn indirect_configuration_and_non_data_implicit_input_cannot_opt_in() {
    let mut p = cat();
    p.native_configuration = Some(NativeConfigurationSyntax::Pip25_3Linux);
    assert!(normalize_command_profile(p).is_err());
    let mut p = cat();
    p.forms[1].implicit_inputs.push(RawImplicitInput {
        source: RawImplicitInputSource::InheritedEnvironment,
        semantic: RawSemanticType::PlainValue,
        extensions: Default::default(),
    });
    assert!(normalize_command_profile(p).is_err());
}
#[test]
fn only_reviewed_profile_opts_in_and_legacy_defaults_are_conservative() {
    let registry = ProfileRegistry::built_in().unwrap();
    assert!(
        registry
            .lookup("cat")
            .profile
            .unwrap()
            .native_argv_read_envelope
    );
    assert!(
        !registry
            .lookup("wc")
            .profile
            .unwrap()
            .native_argv_read_envelope
    );
    let mut p = cat();
    p.native_argv_read_envelope = false;
    assert!(
        !normalize_command_profile(p)
            .unwrap()
            .native_argv_read_envelope
    );
}
