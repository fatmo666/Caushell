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
    assert_eq!(
        registry
            .lookup("cat")
            .profile
            .unwrap()
            .native_argv_effect_envelope,
        Some(NativeArgvEffectEnvelope::ContentRead)
    );
    assert_eq!(
        registry
            .lookup("wc")
            .profile
            .unwrap()
            .native_argv_effect_envelope,
        Some(NativeArgvEffectEnvelope::ContentRead)
    );
    let mut p = cat();
    p.native_argv_read_envelope = false;
    assert!(
        normalize_command_profile(p)
            .unwrap()
            .native_argv_effect_envelope
            .is_none()
    );
}

#[test]
fn metadata_query_and_content_read_are_distinct_total_contracts() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["ls", "stat"] {
        assert_eq!(
            registry
                .lookup(name)
                .profile
                .unwrap()
                .native_argv_effect_envelope,
            Some(NativeArgvEffectEnvelope::MetadataQuery)
        );
    }
    assert_eq!(
        registry
            .lookup("du")
            .profile
            .unwrap()
            .native_argv_effect_envelope,
        Some(NativeArgvEffectEnvelope::ContentRead.union(NativeArgvEffectEnvelope::MetadataQuery))
    );
    let target = Effect::new(EffectKind::TargetPath).for_slot("objects");
    let read = Effect::new(EffectKind::ReadPath).for_slot("contents");
    assert!(native_effect_contract_allows_effect(
        NativeArgvEffectEnvelope::MetadataQuery,
        &target
    ));
    assert!(!native_effect_contract_allows_effect(
        NativeArgvEffectEnvelope::MetadataQuery,
        &read
    ));
    assert!(!native_effect_contract_allows_effect(
        NativeArgvEffectEnvelope::ContentRead,
        &target
    ));
    assert!(native_effect_contract_allows_effect(
        NativeArgvEffectEnvelope::ContentRead,
        &read
    ));
}

#[test]
fn explicit_empty_and_combined_contracts_do_not_erase_access_kinds() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["echo", "basename", "dirname"] {
        assert_eq!(
            registry
                .lookup(name)
                .profile
                .unwrap()
                .native_argv_effect_envelope,
            Some(NativeArgvEffectEnvelope::DataOnly)
        );
    }
    let data = NativeArgvEffectEnvelope::DataOnly;
    for effect in [
        EffectKind::ReadPath,
        EffectKind::TargetPath,
        EffectKind::WritePath,
        EffectKind::ExecutePayload,
    ] {
        assert!(!native_effect_contract_allows_effect(
            data,
            &Effect::new(effect)
        ));
    }
    let mixed =
        NativeArgvEffectEnvelope::ContentRead.union(NativeArgvEffectEnvelope::MetadataQuery);
    assert!(native_effect_contract_allows_effect(
        mixed,
        &Effect::new(EffectKind::ReadPath)
    ));
    assert!(native_effect_contract_allows_effect(
        mixed,
        &Effect::new(EffectKind::TargetPath)
    ));
    assert!(!native_effect_contract_allows_effect(
        mixed,
        &Effect::new(EffectKind::WritePath)
    ));
    let text = include_str!("../profiles/du.yaml");
    for declaration in ["[]", "content_read", "metadata_query"] {
        let text = text.replace("[content_read, metadata_query]", declaration);
        assert!(
            normalize_command_profile(load_raw_command_profile_from_str(&text).unwrap()).is_err(),
            "{declaration}"
        );
    }
    let text = include_str!("../profiles/echo.yaml");
    let mut raw = load_raw_command_profile_from_str(text).unwrap();
    let mut read = raw.forms[0].effects[0].clone();
    read.kind = RawEffectKind::ReadPath;
    raw.forms[0].effects.push(read);
    assert!(normalize_command_profile(raw).is_err());
}

#[test]
fn metadata_contract_cannot_hide_file_read_mutation_execution_or_unknown_annotations() {
    let text = include_str!("../profiles/ls.yaml");
    for kind in [
        RawEffectKind::ReadPath,
        RawEffectKind::WritePath,
        RawEffectKind::ExecutePayload,
    ] {
        let mut raw = load_raw_command_profile_from_str(text).unwrap();
        raw.forms[1].effects[0].kind = kind;
        assert!(normalize_command_profile(raw).is_err());
    }
    let mut raw = load_raw_command_profile_from_str(text).unwrap();
    raw.forms[1].effects[0]
        .extensions
        .insert("unknown_operation".into(), serde_json::json!(true));
    assert!(normalize_command_profile(raw).is_err());
    let mut raw = load_raw_command_profile_from_str(text).unwrap();
    raw.native_configuration = Some(NativeConfigurationSyntax::Pip25_3Linux);
    assert!(normalize_command_profile(raw).is_err());
    let mut raw = cat();
    raw.native_argv_effect_envelope = Some(NativeArgvEffectEnvelope::MetadataQuery);
    assert!(normalize_command_profile(raw).is_err());
}

#[test]
fn regex_search_can_opt_into_content_read_but_executable_languages_cannot() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["grep", "egrep", "fgrep"] {
        assert_eq!(
            registry
                .lookup(name)
                .profile
                .unwrap()
                .native_argv_effect_envelope,
            Some(NativeArgvEffectEnvelope::ContentRead)
        );
    }
    let text = include_str!("../profiles/grep.yaml");
    for language in [
        "sed_script",
        "awk_program",
        "path_expression",
        "env_assignment",
    ] {
        let modified = text.replace("context: regex", &format!("context: {language}"));
        let normalized =
            normalize_command_profile(load_raw_command_profile_from_str(&modified).unwrap());
        assert!(normalized.is_err(), "{language}");
    }
}
