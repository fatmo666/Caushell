use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve_with(registry: &ProfileRegistry, text: &str) -> ResolvedInvocationArtifact {
    let parsed = parse_command(text, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{text}: {other:#?}"),
    }
}
fn resolve(text: &str) -> ResolvedInvocationArtifact {
    resolve_with(&ProfileRegistry::built_in().unwrap(), text)
}

#[test]
fn budget_limited_data_suffix_does_not_require_exact_argv_enumeration() {
    for text in [
        "printf '%.0sa' {1..10000}",
        "printf '%s' {1..20}{1..20}",
        "printf '%s' {1..200} {1..200}",
        "printf '%s' {1..10000} ~{unknown,user}",
    ] {
        let r = resolve(text);
        assert!(
            !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty(),
            "{text}: {r:#?}"
        );
        assert!(r.materialized_projection.shell_expansion_unresolved);
        assert!(r.materialized_projection.invocation.args.len() < 260);
        assert!(
            r.materialized_projection
                .arg_resolutions
                .iter()
                .any(|r| matches!(r, ValueMaterialization::UnsupportedDynamicText { .. })),
            "{text}: {r:#?}"
        );
    }
}

#[test]
fn effect_completeness_is_not_a_scalar_record_or_output_bound() {
    let r = resolve("printf '%d\\n' {1..10000}");
    assert!(!r.bound.operation_semantics_unresolved);
    assert_eq!(
        r.bound.native_argv_effect_envelope,
        Some(NativeArgvEffectEnvelope::DataOnly)
    );
    assert!(!r.proven_arithmetic_stdout());
    assert!(r.proven_stdout_records().is_none() && r.bound.stdout_growth.is_none());
    assert_eq!(
        r.proven_stream_contract().unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
}

#[test]
fn unknown_controls_writes_paths_and_unsupported_syntax_keep_their_gaps() {
    for text in [
        "printf {1..10000} value",
        "printf '%n' {1..10000}",
        "printf -v result '%s' {1..10000}",
        "printf \"$FORMAT\" {1..10000}",
        "printf '%s' {a..Z}",
        "printf '%s' {--,-v,target}{1..10000}",
        "touch /opt/out{1..10000}",
        "printf '%s' {1..10000} {a..Z}",
    ] {
        let r = resolve(text);
        assert!(
            r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(),
            "{text}: {r:#?}"
        );
    }
}

#[test]
fn recovery_uses_declared_capabilities_and_operand_slots_not_the_command_name() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut profile = registry.lookup("printf").profile.unwrap().clone();
    profile.identity.canonical_name = CommandName::new("fixture_format_data");
    profile.identity.aliases.clear();
    for write in [false, true] {
        let mut changed = profile.clone();
        if write {
            for form in &mut changed.forms {
                form.effects.push(Effect::new(EffectKind::WritePath));
            }
        }
        let mut profiles = registry.profiles().to_vec();
        profiles.push(changed);
        let custom = ProfileRegistry::from_profiles(profiles).unwrap();
        let r = resolve_with(&custom, "fixture_format_data '%s' {1..10000}");
        assert_eq!(
            r.bound.operation_semantics_unresolved, write,
            "write={write}: {r:#?}"
        );
    }
}

#[test]
fn symbolic_recovery_keeps_the_original_byte_resource_budget() {
    for text in [
        "printf '%s' {1..20000}",
        "printf '%s' {1..10000}{1..10000}",
        "printf '%s' {-9223372036854775808..9223372036854775807}",
    ] {
        let r = resolve(text);
        assert!(r.bound.operation_semantics_unresolved, "{text}: {r:#?}");
        assert!(r.materialized_projection.invocation.args.len() < 260);
        assert!(
            r.materialized_projection
                .shell_expansion_gaps
                .iter()
                .all(|g| g.bounded_literal_bytes.is_none())
        );
    }
    let r = resolve("printf '%s' {1..10000}");
    assert!(
        r.materialized_projection
            .shell_expansion_gaps
            .iter()
            .all(|g| g.bounded_literal_bytes.is_some_and(|bytes| bytes <= 65536))
    );
}
