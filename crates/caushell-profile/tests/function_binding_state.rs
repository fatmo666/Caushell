use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

#[test]
fn scalar_presence_is_independent_of_export_and_value_certainty() {
    let summary = SessionSummary::new();
    let shell = ShellStateSnapshot::new("/tmp/project")
        .with_variable_knowledge(ShellStateKnowledge::Complete);
    let mut bindings = SessionBindings::from_summary_and_shell_state(&summary, &shell);
    assert_eq!(bindings.variable_presence("f"), VariablePresence::Absent);
    bindings.insert_exact_scalar("f", "");
    assert_eq!(bindings.variable_presence("f"), VariablePresence::Present);
    assert_eq!(bindings.environment_value("f"), EnvironmentValueRef::Absent);
    bindings.insert_opaque_dynamic("f", "possibly unset");
    assert_eq!(bindings.variable_presence("f"), VariablePresence::Unknown);
    bindings.remove("f");
    assert_eq!(bindings.variable_presence("f"), VariablePresence::Absent);
    let partial = SessionBindings::from_summary_and_shell_state(
        &summary,
        &ShellStateSnapshot::new("/tmp/project")
            .with_variable_knowledge(ShellStateKnowledge::ExportedOnly),
    );
    assert_eq!(partial.variable_presence("f"), VariablePresence::Unknown);
}

#[test]
fn uncertain_function_resolution_has_a_real_gap_not_a_fake_profile() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut bindings = SessionBindings::new();
    bindings.upsert_function_binding(SessionFunctionBinding::uncertain(
        "printf",
        "conditional unset",
        CommandSequenceNo::new(1),
    ));
    let parsed = parse_command("printf LAB", ShellKind::Bash).unwrap();
    let result = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &bindings,
    );
    assert!(matches!(
        result,
        ResolveInvocationArtifactResult::SelectionError {
            gap_kind: ResolveGapKind::OpaqueInvocation,
            error: BindError::UncertainFunctionBinding { .. },
            partial_bound: None,
            ..
        }
    ));
    bindings.enter_child_shell_environment();
    assert!(bindings.function_binding("printf").is_none());
    assert!(matches!(
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &bindings
        ),
        ResolveInvocationArtifactResult::Resolved(_)
    ));
}

#[test]
fn old_exact_binding_wire_format_and_new_uncertainty_roundtrip() {
    let old = serde_json::json!({"name": "f", "body": "printf LAB;", "observed_at": 1});
    let binding: SessionFunctionBinding = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(binding.uncertainty, None);
    assert_eq!(serde_json::to_value(&binding).unwrap(), old);
    let uncertain =
        SessionFunctionBinding::uncertain("f", "conditional unset", CommandSequenceNo::new(2));
    let roundtrip: SessionFunctionBinding =
        serde_json::from_str(&serde_json::to_string(&uncertain).unwrap()).unwrap();
    assert_eq!(roundtrip, uncertain);
    assert!(roundtrip.body.is_empty());
}

#[test]
fn authoritative_function_snapshot_clears_or_replaces_summary_uncertainty() {
    let mut summary = SessionSummary::new();
    summary.upsert_function_binding(SessionFunctionBinding::uncertain(
        "f",
        "conditional unset",
        CommandSequenceNo::new(2),
    ));
    let unknown = ShellStateSnapshot::new("/tmp/project");
    assert!(
        SessionBindings::from_summary_and_shell_state(&summary, &unknown)
            .function_binding("f")
            .unwrap()
            .uncertainty
            .is_some()
    );
    let complete = unknown.with_function_knowledge(ShellStateKnowledge::Complete);
    assert!(
        SessionBindings::from_summary_and_shell_state(&summary, &complete)
            .function_binding("f")
            .is_none()
    );
    let exact = complete.with_function("f", "printf FACT;");
    assert_eq!(
        SessionBindings::from_summary_and_shell_state(&summary, &exact)
            .function_binding("f")
            .unwrap()
            .uncertainty,
        None
    );
}
