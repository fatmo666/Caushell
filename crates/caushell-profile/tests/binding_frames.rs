use caushell_profile::{BindingOrigin, EnvironmentValueRef as E, SessionBindings, SessionValue};
use caushell_types::{CommandSequenceNo, SessionSummary};

fn summary(sequence: u64) -> SessionSummary {
    let mut summary = SessionSummary::new();
    summary.set_exact_scalar_variable("EXPORTED", "outside", true, CommandSequenceNo(sequence));
    summary.set_exact_scalar_variable("LOCAL", "local", false, CommandSequenceNo(sequence));
    summary
}

#[test]
fn entry_snapshot_is_shared_but_writes_unsets_and_exports_are_local() {
    let summary = summary(1);
    let entry = SessionBindings::from_session_summary(&summary);
    assert!(std::ptr::eq(
        entry.get("EXPORTED").unwrap().value,
        &summary.variable_binding("EXPORTED").unwrap().value
    ));
    let mut fork = entry.clone();
    fork.insert_exact_scalar("EXPORTED", "inside");
    assert_eq!(
        fork.environment_value("EXPORTED"),
        E::Present(&SessionValue::exact_scalar("inside"))
    );
    assert_eq!(
        entry.environment_value("EXPORTED"),
        E::Present(&SessionValue::exact_scalar("outside"))
    );
    fork.remove("LOCAL");
    assert!(fork.get("LOCAL").is_none());
    assert_eq!(fork.environment_value("LOCAL"), E::Absent);
    assert!(!fork.variable_names().any(|name| name == "LOCAL"));
    fork.insert_exact_scalar("LOCAL", "changed");
    assert_eq!(fork.environment_value("LOCAL"), E::Absent);
    fork.export("LOCAL");
    assert_eq!(
        fork.environment_value("LOCAL"),
        E::Present(&SessionValue::exact_scalar("changed"))
    );
    assert_eq!(
        entry.get("LOCAL").unwrap().value,
        &SessionValue::exact_scalar("local")
    );
}

#[test]
fn child_frames_keep_only_exports_and_preserve_session_provenance() {
    let mut bindings = SessionBindings::from_session_summary(&summary(1));
    bindings.enter_child_shell_environment();
    assert!(bindings.get("LOCAL").is_none());
    assert_eq!(
        bindings.get("EXPORTED").unwrap().origin,
        BindingOrigin::SessionBinding
    );
    bindings.unexport("EXPORTED");
    bindings.enter_child_shell_environment();
    assert!(bindings.get("EXPORTED").is_none());
    bindings.reset_child_environment(false);
    assert_eq!(bindings.environment_value("EXPORTED"), E::Unknown);
    assert!(bindings.variable_names().next().is_none());
}

#[test]
fn frame_equality_uses_values_not_entry_timestamps_or_overlay_layout() {
    let first = SessionBindings::from_session_summary(&summary(1));
    let mut later = SessionBindings::from_session_summary(&summary(99));
    assert_eq!(first, later);
    later.set_child_environment_value("EXPORTED", SessionValue::exact_scalar("changed"));
    assert_ne!(first, later);
    let mut fork = first.clone();
    fork.insert_exact_scalar("NEW", "value");
    fork.remove("NEW");
    assert!(fork.get("NEW").is_none());
    assert!(first.get("NEW").is_none());
    let mut observed = first.clone();
    observed.forget_environment();
    assert_eq!(observed.environment_value("EXPORTED"), E::Unknown);
    assert!(observed.get("EXPORTED").is_some());
}
