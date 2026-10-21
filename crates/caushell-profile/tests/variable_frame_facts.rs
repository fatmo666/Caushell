use caushell_profile::{
    SessionBindings, SessionValue, ShellArrayKind, ShellVariableFacts, StdoutScalarShape,
};

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
