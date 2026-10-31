use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

#[test]
fn compiler_effects_and_required_observations_are_declarative() {
    let yaml = include_str!("../profiles/cobc.yaml").replace(
        "canonical_name: cobc",
        "canonical_name: another-native-compiler",
    );
    let profile = load_command_profile_from_str(&yaml).unwrap();
    let requirements = execution_frame_requirements([&profile]);
    assert!(requirements.environment_names.contains("COB_CC"));
    assert!(requirements.environment_names.contains("COB_CONFIG_DIR"));
    let mut snapshot = ShellStateSnapshot::new("/workspace");
    for name in &requirements.environment_names {
        snapshot = snapshot.with_environment_observation(name, ShellEnvironmentValue::Absent);
    }
    let bindings =
        SessionBindings::from_summary_and_shell_state(&SessionSummary::default(), &snapshot);
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for command in [
        "another-native-compiler -x -o output one.cbl two.cbl",
        "another-native-compiler -x -ofirst -osecond one.cbl",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(r) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &bindings,
            )
        else {
            panic!("resolution failed")
        };
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:#?}",
            r.bound.residuals
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
        assert!(
            r.bound
                .effects
                .iter()
                .all(|e| e.kind != EffectKind::ExecutePayload)
        );
    }
}
