//! Profile contracts and argv proofs, never captured runtime output.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const SOURCE: &str = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_absolute_producer}\noption_scope: all_arguments\nopaque_on_unresolved: true\nforms:\n  - id: path\n    stdout_scalar: absolute_path\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n";

#[test]
fn only_a_complete_selected_contract_proves_stdout_shape() {
    let profile = load_command_profile_from_str(SOURCE).unwrap();
    assert_eq!(
        profile.forms[0].stdout_scalar,
        Some(StdoutScalarShape::AbsolutePath)
    );
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for (command, expected) in [
        ("arbitrary_absolute_producer", true),
        ("arbitrary_absolute_producer --unknown", false),
        ("arbitrary_absolute_producer unexpected", false),
        ("arbitrary_absolute_producer $unknown", false),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation_artifact(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        );
        let shape = match result {
            ResolveInvocationArtifactResult::Resolved(r) => r.proven_stdout_scalar(),
            _ => None,
        };
        assert_eq!(shape.is_some(), expected, "{command}");
    }
}

#[test]
fn incompatible_or_unknown_declarations_are_rejected() {
    for source in [
        SOURCE.replace("stdout_mode: path_list", "stdout_mode: opaque"),
        SOURCE.replace("stdout_scalar: absolute_path", "stdout_scalar: anything"),
        SOURCE.replace("    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n", ""),
    ] {
        assert!(load_command_profile_from_str(&source).is_err());
    }
}

#[test]
fn a_shape_proof_is_not_a_concrete_value_or_path_root() {
    let parsed = parse_command(
        "consumer \"$(arbitrary_absolute_producer)\"",
        ShellKind::Bash,
    )
    .unwrap();
    let mut projection =
        project_invocation(&parsed.commands[0], InvocationRuntimeContext::default());
    projection.args[0].substitution_shape = Some(StdoutScalarShape::AbsolutePath);
    let original = projection.args[0].text.clone();
    let materialized = materialize_projected_invocation(&projection, &SessionBindings::new());
    let arg = &materialized.invocation.args[0];
    let shape = argument_structure(arg);
    assert_eq!(shape.fields, ArgumentFieldCount::ExactlyOne);
    assert!(shape.exact_value().is_none());
    assert!(!shape.may_start_with("-"));
    assert!(!shape.may_equal("-delete"));
    assert!(shape.may_equal(""));
    assert!(shape.may_equal("/opt/unknown/$data"));
    assert!(shape.may_start_with("/"));
    assert_eq!(arg.text, original);
    assert!(!arg.runtime_data);
    assert!(matches!(
        &materialized.arg_resolutions[0],
        ValueMaterialization::UnsupportedDynamicText { .. }
    ));
}
