use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
fn resolve(registry: &ProfileRegistry, command: &str) -> ResolvedInvocationArtifact {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
#[test]
fn total_contract_covers_symbolic_shell_argv_without_inventing_fields_or_shapes() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (command, contract) in [
        ("ls *.txt", NativeArgvEffectEnvelope::MetadataQuery),
        (
            "du -sh *",
            NativeArgvEffectEnvelope::ContentRead.union(NativeArgvEffectEnvelope::MetadataQuery),
        ),
        ("md5sum *.txt", NativeArgvEffectEnvelope::ContentRead),
        ("grep -n fixed *.log", NativeArgvEffectEnvelope::ContentRead),
        ("echo $words", NativeArgvEffectEnvelope::DataOnly),
    ] {
        let r = resolve(&registry, command);
        if ["ls *.txt", "du -sh *", "md5sum *.txt"].contains(&command) {
            assert_eq!(
                r.bound.native_argv_effect_envelope,
                Some(contract),
                "{command}: {r:#?}"
            );
        }
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
                .all(|e| native_effect_contract_allows_effect(contract, e))
        );
        if !contract.reads_content() {
            assert!(
                !r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::ReadPath)
            );
        }
        assert!(
            r.materialized_projection
                .invocation
                .args
                .iter()
                .any(|a| argument_structure(a).exact_value().is_none())
        );
        assert!(r.proven_stream_contract().is_some());
    }
}
#[test]
fn declaration_and_effect_closure_are_name_independent_and_fail_closed() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut reader = registry.lookup("ls").profile.unwrap().clone();
    reader.identity.canonical_name = CommandName::new("fixture_reader");
    reader.identity.aliases.clear();
    let mut profiles = registry.profiles().to_vec();
    profiles.push(reader.clone());
    let r = resolve(
        &ProfileRegistry::from_profiles(profiles).unwrap(),
        "fixture_reader *.txt",
    );
    assert!(r.bound.native_argv_effect_envelope.is_some());
    for edit in 0..3 {
        let mut changed = reader.clone();
        match edit {
            0 => {
                changed.native_argv_effect_envelope = None;
            }
            1 => {
                changed.forms[0]
                    .effects
                    .push(Effect::new(EffectKind::WritePath));
            }
            _ => {
                changed.forms[0]
                    .effects
                    .push(Effect::new(EffectKind::ExecutePayload));
            }
        }
        let mut profiles = registry.profiles().to_vec();
        profiles.push(changed);
        let r = resolve(
            &ProfileRegistry::from_profiles(profiles).unwrap(),
            "fixture_reader *.txt",
        );
        assert!(r.bound.native_argv_effect_envelope.is_none());
    }
}
#[test]
fn fixed_unknown_controls_and_controls_after_unknown_fields_keep_ownership_gaps() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "cat --unreviewed $files",
        "grep *.log -f .env",
        "file *",
        "sed -i s/A/B/ $files",
        "printf $format",
    ] {
        let r = resolve(&registry, command);
        assert!(r.bound.native_argv_effect_envelope.is_none(), "{command}");
    }
}
