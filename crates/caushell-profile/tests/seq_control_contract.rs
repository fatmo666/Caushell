use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
fn resolve(registry: &ProfileRegistry, text: &str) -> ResolvedInvocationArtifact {
    let p = parse_command(text, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &p.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{text}: {other:#?}"),
    }
}
#[test]
fn separators_padding_and_native_negative_operands_are_completely_owned() {
    let registry = ProfileRegistry::built_in().unwrap();
    for text in [
        "seq -s= 4",
        "seq -s+ -5 2",
        "seq --separator=' ' 1 3",
        "seq -w 3",
        "seq --equal-width 1 3",
        "seq -.5 .5",
        "seq -2e1 1",
        "seq -0x2 1",
    ] {
        let r = resolve(&registry, text);
        assert!(
            !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty(),
            "{text}: {r:#?}"
        );
    }
}
#[test]
fn numeric_output_proof_is_separate_from_read_only_operation_completeness() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (text, numeric) in [
        ("seq 2 4", true),
        ("seq -s '$(payload)' 2 4", false),
        ("seq -s '\n' 2 4", false),
        ("seq -w 3", false),
        ("seq -f 'x%g' 2 4", false),
        ("seq --help 3", false),
        ("seq --version 3", false),
        ("seq -5 1", false),
        ("seq 2.5 3.5", false),
        ("seq $start $end", false),
    ] {
        let r = resolve(&registry, text);
        assert_eq!(r.proven_arithmetic_stdout(), numeric, "{text}: {r:#?}");
    }
}
#[test]
fn dynamic_native_values_gain_only_a_data_effect_proof_not_numeric_or_record_facts() {
    let registry = ProfileRegistry::built_in().unwrap();
    for text in ["seq $OPTIONS", "seq -s' ' $start $end", "seq -f '%g' $end"] {
        let r = resolve(&registry, text);
        assert_eq!(
            r.bound.native_argv_effect_envelope,
            Some(NativeArgvEffectEnvelope::DataOnly),
            "{text}: {r:#?}"
        );
        assert!(!r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty());
        assert!(
            r.bound.stdout_scalar.is_none()
                && r.bound.stdout_records.is_none()
                && r.bound.stdout_growth.is_none()
        );
        assert!(
            r.bound
                .effects
                .iter()
                .all(|e| native_effect_contract_allows_effect(
                    NativeArgvEffectEnvelope::DataOnly,
                    e
                ))
        );
    }
}
#[test]
fn selected_control_operands_keep_data_dependency_and_exact_bytes() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (text, slot, value) in [
        ("seq -s= 3", "separator", "="),
        ("seq -s+ 3", "separator", "+"),
        ("seq -f 'x%g' 3", "format_string", "x%g"),
    ] {
        let r = resolve(&registry, text);
        assert!(
            r.bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == slot
                    && p.values
                        .iter()
                        .any(|v| matches!(v,BoundValue::Argument{text,..} if text==value))),
            "{text}: {r:#?}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            caushell_types::StreamDataDependency::Inputs
        );
    }
}
#[test]
fn effect_admission_remains_capability_based_and_rejects_writes_or_execution() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut seq = registry.lookup("seq").profile.unwrap().clone();
    seq.identity.canonical_name = CommandName::new("fixture_sequence");
    seq.identity.aliases.clear();
    for edit in 0..4 {
        let mut changed = seq.clone();
        match edit {
            1 => changed.native_argv_effect_envelope = None,
            2 => changed.forms[0]
                .effects
                .push(Effect::new(EffectKind::WritePath)),
            3 => changed.forms[0]
                .effects
                .push(Effect::new(EffectKind::ExecutePayload)),
            _ => (),
        }
        let mut profiles = registry.profiles().to_vec();
        profiles.push(changed);
        let registry = ProfileRegistry::from_profiles(profiles).unwrap();
        let r = resolve(&registry, "fixture_sequence $end");
        assert_eq!(
            r.bound.native_argv_effect_envelope.is_some(),
            edit == 0,
            "edit {edit}: {r:#?}"
        );
    }
}

#[test]
fn parameter_dependency_identity_does_not_require_an_exact_word_value() {
    let mut bindings = SessionBindings::new();
    bindings.insert_opaque_dynamic("secret", "unknown file contents");
    bindings.insert_exact_scalar("public", "ok");
    for (text, expected) in [
        ("echo \"prefix${secret}%g\"", vec!["secret"]),
        ("echo \"${public}:${secret}\"", vec!["public", "secret"]),
        ("echo '${secret}suffix'", vec![]),
        ("echo \"\\${secret}suffix\"", vec![]),
    ] {
        let parsed = parse_command(text, ShellKind::Bash).unwrap();
        let projection = project_invocation(
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        );
        assert_eq!(
            shell_parameter_dependencies(&projection.args[0], &bindings),
            expected,
            "{text}"
        );
        if !expected.is_empty() {
            let value = materialize_projected_invocation(&projection, &bindings);
            assert!(
                matches!(
                    value.arg_resolutions[0],
                    ValueMaterialization::UnsupportedDynamicText { .. }
                ),
                "{text}: {value:#?}"
            );
        }
    }
}
