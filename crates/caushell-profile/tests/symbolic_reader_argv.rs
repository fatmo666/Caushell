use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn attempt(registry: &ProfileRegistry, command: &str) -> ResolveInvocationArtifactResult {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        registry, &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &SessionBindings::new(),
    )
}
fn resolve(registry: &ProfileRegistry, command: &str) -> ResolvedInvocationArtifact {
    match attempt(registry, command) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn dynamic_option_spellings_use_a_total_effect_proof_without_inventing_count_or_width() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["head -$N file", "head -\"$N\" file", "head -${N:-10}",
                    "head $options public-a public-b", "head $options"] {
        let r = resolve(&registry, command);
        assert_eq!(r.bound.native_argv_effect_envelope, Some(NativeArgvEffectEnvelope::ContentRead), "{command}: {r:#?}");
        assert!(!r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty());
        assert!(r.bound.stdout_scalar.is_none() && r.bound.stdout_records.is_none() && r.bound.stdout_growth.is_none());
        let streams = r.bound.stream_contract.as_ref().unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::DataOptional);
        assert_eq!(streams.stdout_mode, StreamOutputMode::Data);
        assert_eq!(streams.stderr_mode, StreamOutputMode::Data);
        assert_eq!(streams.stdout_dependency, caushell_types::StreamDataDependency::Inputs);
        assert_eq!(streams.stderr_dependency, caushell_types::StreamDataDependency::Inputs);
        assert!(r.materialized_projection.invocation.args.iter().any(|a| argument_structure(a).exact_value().is_none()));
    }
}

#[test]
fn all_possible_suffix_paths_keep_content_open_access_and_original_origins() {
    let registry = ProfileRegistry::built_in().unwrap();
    for path in [".env", "/dev/fd/3", "/proc/self/fd/3", "public"] {
        let r = resolve(&registry, &format!("head -$N {path}"));
        let parameter = r.bound.bound_parameters.iter().find(|p| p.name.as_str() == "__symbolic_argv_reads__").unwrap();
        assert_eq!(parameter.values.len(), 2);
        assert!(parameter.values.iter().any(|v| matches!(v, BoundValue::Argument { text, .. } if text == path)));
        assert!(parameter.values.iter().any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "-$N")));
        assert!(r.bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath
            && e.target == EffectTarget::Slot(SlotName::new("__symbolic_argv_reads__"))
            && e.path_access == Some(PathAccessKind::ContentOpen)), "{r:#?}");
    }
}

#[test]
fn exact_unsupported_controls_and_incomplete_prefixes_do_not_gain_a_certificate() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["head --unreviewed file", "head --unreviewed $files", "head $options -n 2 file", "head -n $N file", "head $options +2"] {
        if let ResolveInvocationArtifactResult::Resolved(r) = attempt(&registry, command) {
            assert!(r.bound.native_argv_effect_envelope.is_none(), "{command}: {r:#?}");
        }
    }
}

#[test]
fn selection_recovery_is_capability_based_and_rejects_effectful_contracts() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut reader = registry.lookup("head").profile.unwrap().clone();
    reader.identity.canonical_name = CommandName::new("fixture_reader");
    reader.identity.aliases.clear();
    for edit in 0..5 {
        let mut changed = reader.clone();
        match edit {
            1 => changed.native_argv_effect_envelope = None,
            2 => changed.read_only_control_surface = false,
            3 => changed.forms[0].effects.push(Effect::new(EffectKind::WritePath)),
            4 => changed.forms[0].effects.push(Effect::new(EffectKind::ExecutePayload)),
            _ => (),
        }
        let mut profiles = registry.profiles().to_vec();
        profiles.push(changed);
        let registry = ProfileRegistry::from_profiles(profiles).unwrap();
        match attempt(&registry, "fixture_reader -$N file") {
            ResolveInvocationArtifactResult::Resolved(r) if edit == 0 => assert!(r.bound.native_argv_effect_envelope.is_some()),
            ResolveInvocationArtifactResult::Resolved(r) => assert!(r.bound.native_argv_effect_envelope.is_none()),
            other if edit == 0 => panic!("{other:#?}"),
            _ => (),
        }
    }
}
