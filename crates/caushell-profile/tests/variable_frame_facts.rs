use caushell_profile::{
    SessionBindings, SessionValue, ShellArrayKind, ShellVariableFacts, StdoutScalarShape,
};

#[test]
fn numeric_argv_proof_is_width_and_affixes_not_an_invented_value() {
    use caushell_profile::*;
    let parsed = caushell_parse::parse_command(
        "arbitrary_consumer R=$number",
        caushell_types::ShellKind::Bash,
    )
    .unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let mut bindings = SessionBindings::new().with_opaque_dynamic("number", "dynamic integer");
    bindings.set_variable_facts(
        "number",
        ShellVariableFacts {
            integer_scalar: true,
            scalar_shape: Some(StdoutScalarShape::ArithmeticText),
            ..Default::default()
        },
    );
    // No observation does not mean default IFS.
    let unresolved = materialize_projected_invocation(&projection, &bindings);
    assert_ne!(
        argument_structure(&unresolved.invocation.args[0]).fields,
        ArgumentFieldCount::ExactlyOne
    );
    bindings.remove("IFS");
    let materialized = materialize_projected_invocation(&projection, &bindings);
    let arg = &materialized.invocation.args[0];
    let structure = argument_structure(arg);
    assert_eq!(structure.fields, ArgumentFieldCount::ExactlyOne);
    assert!(structure.exact_value().is_none());
    assert!(!structure.may_start_with("-"));
    assert_eq!(arg.text, "R=$number");
    assert!(
        matches!(&arg.runtime_argument_domain, Some(caushell_types::RuntimeArgumentDomain::TextTemplate {prefix, suffix}) if prefix == "R=" && suffix.is_empty())
    );
    assert!(matches!(
        bindings.get("number").unwrap().value,
        SessionValue::OpaqueDynamic { .. }
    ));
    bindings.insert_exact_scalar("IFS", "0123456789");
    let unresolved = materialize_projected_invocation(&projection, &bindings);
    assert_ne!(
        argument_structure(&unresolved.invocation.args[0]).fields,
        ArgumentFieldCount::ExactlyOne
    );
}

#[test]
fn shell_attributes_and_unexported_proofs_do_not_leak_to_new_interpreters() {
    let mut bindings = SessionBindings::new().with_opaque_dynamic("number", "dynamic integer");
    bindings.set_variable_facts(
        "number",
        ShellVariableFacts {
            integer_scalar: true,
            ..Default::default()
        },
    );
    bindings.enter_child_shell_environment();
    assert!(!bindings.variable_facts("number").integer_scalar);
}

#[test]
fn frame_proofs_are_not_concrete_values_and_writes_invalidate_them() {
    let mut bindings = SessionBindings::new().with_opaque_dynamic("n", "unknown numeric bytes");
    let proof = ShellVariableFacts {
        scalar_shape: Some(StdoutScalarShape::ArithmeticText),
        ..Default::default()
    };
    bindings.set_variable_facts("n", proof);
    assert!(matches!(
        bindings.get("n").unwrap().value,
        SessionValue::OpaqueDynamic { .. }
    ));
    let mut child = bindings.clone();
    child.insert_exact_scalar("n", "script text");
    assert_eq!(child.variable_facts("n"), ShellVariableFacts::default());
    assert_eq!(bindings.variable_facts("n"), proof);
    for action in 0..4 {
        let mut frame = bindings.clone();
        match action {
            0 => frame.remove("n"),
            1 => frame.insert_opaque_dynamic("n", "unknown writer"),
            2 => frame.mark_unresolved_runtime_variable_target("n"),
            _ => frame.forget_variable_presence(),
        }
        assert_eq!(frame.variable_facts("n"), ShellVariableFacts::default());
    }
}

#[test]
fn type_only_facts_are_visible_to_namespace_invalidation() {
    let mut bindings = SessionBindings::new();
    bindings.set_variable_facts(
        "map",
        ShellVariableFacts {
            array_kind: Some(ShellArrayKind::Associative),
            ..Default::default()
        },
    );
    assert!(bindings.variable_names().any(|name| name == "map"));
    assert!(bindings.get("map").is_none());
    bindings.forget_variable_presence();
    assert!(!bindings.has_variable_facts());
}
