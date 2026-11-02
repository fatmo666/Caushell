use caushell_parse::{observed_shell_variables, referenced_shell_variables};
use caushell_types::ShellKind;

#[test]
fn attribute_roots_include_writes_without_treating_quoted_text_as_shell() {
    let source = "TARGET=literal; printf '%s' \"$READ\" 'IGNORED=literal $HIDDEN'";
    assert_eq!(
        referenced_shell_variables(source, ShellKind::Bash).unwrap(),
        ["READ".into()].into()
    );
    assert_eq!(
        observed_shell_variables(source, ShellKind::Bash).unwrap(),
        ["TARGET".into(), "READ".into()].into()
    );
}

#[test]
fn array_write_and_reference_declaration_names_are_observed_as_attributes() {
    let source = "items[2]=data; declare -n link=other; printf '%s' \"${items[@]}\"";
    let names = observed_shell_variables(source, ShellKind::Bash).unwrap();
    assert!(names.contains("items") && names.contains("link"));
    assert!(!names.contains("other")); // Follow only the actual owning declaration, not pending code.
}

#[test]
fn parameter_reads_have_evaluation_sites_but_literal_text_does_not() {
    use caushell_parse::{ShellEvaluationKind, parse_command};
    let parsed = parse_command(
        "printf '%s' \"$READ\" \"${OTHER:-fallback}\" '$LITERAL'",
        ShellKind::Bash,
    )
    .unwrap();
    let names: Vec<_> = parsed
        .shell_evaluations
        .iter()
        .filter_map(|s| match &s.kind {
            ShellEvaluationKind::ParameterReference { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["READ", "OTHER"]);
}
