use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

fn resolve(
    name: &str,
    required: bool,
    command: &str,
    snapshot: ShellStateSnapshot,
) -> BoundInvocation {
    let profile = load_command_profile_from_str(&format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
environment_inputs:
  - name: native_control
    environment: {{name: DECLARED_CONTROL, empty_is_unset: true}}
    require_observation: {required}
    semantic: {{kind: payload, language: opaque, source: dynamic_reference, recursive: true}}
    unless_modifiers: [information]
forms: [{{id: run}}]
modifiers: [{{id: information, matcher: {{kind: any_flag, flags: ['--version']}}}}]
"#
    ))
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let bindings =
        SessionBindings::from_summary_and_shell_state(&SessionSummary::default(), &snapshot);
    let ResolveInvocationArtifactResult::Resolved(result) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &bindings,
        )
    else {
        panic!("resolution failed")
    };
    result.bound
}

#[test]
fn observation_is_opt_in_and_independent_of_command_identity() {
    for name in ["first-native-driver", "unrelated-native-driver"] {
        let missing = resolve(name, true, name, ShellStateSnapshot::new("/work"));
        assert!(missing.operation_semantics_unresolved);
        assert!(!missing.residuals.is_empty());
        let legacy = resolve(name, false, name, ShellStateSnapshot::new("/work"));
        assert!(!legacy.operation_semantics_unresolved);
        let info = resolve(
            name,
            true,
            &format!("{name} --version"),
            ShellStateSnapshot::new("/work"),
        );
        assert!(!info.operation_semantics_unresolved);
    }
}

#[test]
fn observed_absence_empty_and_prefix_data_have_distinct_meanings() {
    let name = "native-driver";
    for value in [
        ShellEnvironmentValue::Absent,
        ShellEnvironmentValue::Present { value: "".into() },
    ] {
        let snapshot = ShellStateSnapshot::new("/work")
            .with_environment_observation("DECLARED_CONTROL", value);
        let result = resolve(name, true, name, snapshot);
        assert!(!result.operation_semantics_unresolved);
        assert!(collect_recursive_payload_candidates(&result).is_empty());
    }
    let result = resolve(
        name,
        true,
        "DECLARED_CONTROL='$(not_shell)' native-driver",
        ShellStateSnapshot::new("/work"),
    );
    assert!(!result.operation_semantics_unresolved);
    assert_eq!(collect_recursive_payload_candidates(&result).len(), 1);
    assert!(
        result
            .bound_parameters
            .iter()
            .flat_map(|p| &p.values)
            .any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "$(not_shell)"))
    );
}
