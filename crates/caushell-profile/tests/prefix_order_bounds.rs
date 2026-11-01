use caushell_profile::*;
use caushell_types::ShellKind;

fn values(source: &str, bindings: &SessionBindings) -> Vec<(String, SessionValue)> {
    let parsed = caushell_parse::parse_command(source, ShellKind::Bash).unwrap();
    materialize_prefix_environment(&parsed.commands[0], bindings)
}

#[test]
fn only_order_independent_prefix_values_are_concrete() {
    let base = SessionBindings::new().with_exact_scalar("value", "old");
    let result = values("value=new NEXT=$value value=last command", &base);
    assert_eq!(result[0].1, SessionValue::exact_scalar("new"));
    assert!(matches!(result[1].1, SessionValue::OpaqueDynamic { .. }));
    assert_eq!(result[2].1, SessionValue::exact_scalar("last"));
    assert_eq!(
        base.get("value").unwrap().value,
        &SessionValue::exact_scalar("old")
    );
    let same = values("value=old NEXT=$value command", &base);
    assert_eq!(same[1].1, SessionValue::exact_scalar("old"));
    let literal = values("A=left B=right command", &base);
    assert_eq!(literal[1].1, SessionValue::exact_scalar("right"));
}

#[test]
fn unknowns_and_source_order_are_not_guessed_from_variable_names() {
    let base = SessionBindings::new().with_exact_scalar("destination", "/outside");
    for source in [
        "destination=/workspace OUT=$destination command",
        "destination=/workspace OUT=${destination}/data command",
        "destination=$unknown OUT=$destination command",
    ] {
        assert!(
            matches!(
                values(source, &base)[1].1,
                SessionValue::OpaqueDynamic { .. }
            ),
            "{source}"
        );
    }
    assert!(
        matches!(values("OUT=$destination destination=/workspace command", &base)[0].1,
        SessionValue::ExactScalar(ref s) if s == "/outside")
    );
}
