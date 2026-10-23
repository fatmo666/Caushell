use caushell_profile::{EnvironmentValueRef as E, SessionBindings, SessionValue};
use caushell_types::{
    CommandSequenceNo, SessionSummary, SessionVariableBinding, ShellEnvironmentValue as V,
    ShellStateKnowledge, ShellStateSnapshot,
};

fn bindings(snapshot: &ShellStateSnapshot) -> SessionBindings {
    SessionBindings::from_summary_and_shell_state(&SessionSummary::default(), snapshot)
}

#[test]
fn observed_absence_is_per_name_and_not_shell_variable_absence() {
    let mut summary = SessionSummary::default();
    summary.upsert_variable_binding(SessionVariableBinding::new(
        "FLAGS",
        SessionValue::exact_scalar("local"),
        false,
        CommandSequenceNo(1),
    ));
    let snapshot =
        ShellStateSnapshot::new("/work").with_environment_observation("FLAGS", V::Absent);
    let b = SessionBindings::from_summary_and_shell_state(&summary, &snapshot);
    assert_eq!(b.environment_value("FLAGS"), E::Absent);
    assert_eq!(b.environment_value("OTHER"), E::Unknown);
    assert!(
        matches!(b.get("FLAGS").unwrap().value, SessionValue::ExactScalar(value) if value == "local")
    );
}

#[test]
fn present_empty_and_unknown_are_distinct_and_do_not_inject_shell_locals() {
    let snapshot = ShellStateSnapshot::new("/work")
        .with_environment_observation("EMPTY", V::Present { value: "".into() })
        .with_environment_observation("SECRET", V::Unknown);
    let b = bindings(&snapshot);
    assert!(
        matches!(b.environment_value("EMPTY"), E::Present(SessionValue::ExactScalar(v)) if v.is_empty())
    );
    assert!(matches!(
        b.environment_value("SECRET"),
        E::Present(SessionValue::OpaqueDynamic { .. })
    ));
    assert!(b.get("EMPTY").is_none());
    assert_eq!(b.environment_value("OTHER"), E::Unknown);
}

#[test]
fn conflicting_duplicate_observations_never_select_a_known_value() {
    for (a, b) in [
        (
            V::Absent,
            V::Present {
                value: "value".into(),
            },
        ),
        (
            V::Present {
                value: "one".into(),
            },
            V::Present {
                value: "two".into(),
            },
        ),
        (V::Absent, V::Unknown),
    ] {
        for values in [[a.clone(), b.clone()], [b, a]] {
            let snapshot = ShellStateSnapshot::new("/work")
                .with_environment_observation("FLAGS", values[0].clone())
                .with_environment_observation("FLAGS", values[1].clone());
            assert!(matches!(
                bindings(&snapshot).environment_value("FLAGS"),
                E::Present(SessionValue::OpaqueDynamic { .. })
            ));
        }
    }
    let snapshot = ShellStateSnapshot::new("/work")
        .with_environment_observation("FLAGS", V::Absent)
        .with_environment_observation("FLAGS", V::Absent);
    assert_eq!(bindings(&snapshot).environment_value("FLAGS"), E::Absent);
}

#[test]
fn contradictory_variable_snapshots_and_invalid_values_remain_unknown() {
    for snapshot in [
        ShellStateSnapshot::new("/work")
            .with_exact_scalar_variable("FLAGS", "one", true)
            .with_environment_observation("FLAGS", V::Absent),
        ShellStateSnapshot::new("/work")
            .with_exact_scalar_variable("FLAGS", "one", true)
            .with_environment_observation(
                "FLAGS",
                V::Present {
                    value: "two".into(),
                },
            ),
        ShellStateSnapshot::new("/work")
            .with_exact_scalar_variable("FLAGS", "one", false)
            .with_environment_observation(
                "FLAGS",
                V::Present {
                    value: "one".into(),
                },
            ),
        ShellStateSnapshot::new("/work")
            .with_variable_knowledge(ShellStateKnowledge::ExportedOnly)
            .with_environment_observation(
                "FLAGS",
                V::Present {
                    value: "one".into(),
                },
            ),
        ShellStateSnapshot::new("/work").with_environment_observation(
            "FLAGS",
            V::Present {
                value: "bad\0value".into(),
            },
        ),
    ] {
        assert!(matches!(
            bindings(&snapshot).environment_value("FLAGS"),
            E::Present(SessionValue::OpaqueDynamic { .. })
        ));
    }
}

#[test]
fn current_environment_facts_override_history_without_modifying_it() {
    let mut summary = SessionSummary::default();
    summary.upsert_variable_binding(SessionVariableBinding::new(
        "FLAGS",
        SessionValue::exact_scalar("old"),
        true,
        CommandSequenceNo(1),
    ));
    let snapshot =
        ShellStateSnapshot::new("/work").with_environment_observation("FLAGS", V::Absent);
    let b = SessionBindings::from_summary_and_shell_state(&summary, &snapshot);
    assert_eq!(b.environment_value("FLAGS"), E::Absent);
    assert!(
        matches!(SessionBindings::from_session_summary(&summary).environment_value("FLAGS"), E::Present(SessionValue::ExactScalar(v)) if v == "old")
    );
    let mut b = b.clone();
    b.set_child_environment_value("FLAGS", SessionValue::exact_scalar("new"));
    assert!(
        matches!(b.environment_value("FLAGS"), E::Present(SessionValue::ExactScalar(v)) if v == "new")
    );
    b.remove("FLAGS");
    assert_eq!(b.environment_value("FLAGS"), E::Absent);
}

#[test]
fn every_current_variable_observation_participates_in_conflict_detection() {
    let snapshot = ShellStateSnapshot::new("/work")
        .with_exact_scalar_variable("FLAGS", "one", true)
        .with_exact_scalar_variable("FLAGS", "two", true)
        .with_environment_observation(
            "FLAGS",
            V::Present {
                value: "one".into(),
            },
        );
    assert!(matches!(
        bindings(&snapshot).environment_value("FLAGS"),
        E::Present(SessionValue::OpaqueDynamic { .. })
    ));
}

#[test]
fn invalid_names_cannot_change_other_environment_facts() {
    let snapshot = ShellStateSnapshot::new("/work")
        .with_environment_observation("", V::Absent)
        .with_environment_observation("BAD=NAME", V::Absent)
        .with_environment_observation("BAD\0NAME", V::Absent);
    let b = bindings(&snapshot);
    for name in ["", "BAD=NAME", "BAD\0NAME", "OTHER"] {
        assert_eq!(b.environment_value(name), E::Unknown);
    }
}
