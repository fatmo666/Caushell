use caushell_parse::referenced_shell_variables;
use caushell_types::ShellKind;
#[test]
fn plans_grammar_references_without_reading_embedded_strings_or_commands() {
    let names = referenced_shell_variables(
        r#"printf '%s' "$DEST" "${PWD}/out" "${EMPTY:-$FALLBACK}" "$(printf '%s' "$INNER")"; awk '{print "$NOT_SHELL"}' file # $COMMENT"#, ShellKind::Bash).unwrap();
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        ["DEST", "EMPTY", "FALLBACK", "INNER", "PWD"]
    );
}
#[test]
fn plans_are_partial_and_bounded_and_never_execute_substitutions() {
    let command = (0..300)
        .map(|n| format!("\"$VALUE_{n}\" "))
        .collect::<String>();
    let names = referenced_shell_variables(&format!("printf {command}"), ShellKind::Bash).unwrap();
    assert_eq!(names.len(), 128);
    let names = referenced_shell_variables(
        "printf '%s' '${INDIRECT}' \\$ESCAPED ${!REF} ${ARRAY[index]}",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(!names.contains("INDIRECT") && !names.contains("ESCAPED"));
    assert!(names.contains("REF") && names.contains("ARRAY"));
}
