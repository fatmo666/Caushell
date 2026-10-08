use caushell_parse::parse_command;
use caushell_types::ShellKind;

#[test]
fn generic_frame_metadata_distinguishes_isolation_and_condition() {
    for (source, isolated, conditional) in [
        ("exit", false, false),
        ("(exit; printf done)", true, false),
        ("{ exit; printf done; } | cat", true, false),
        ("{ exit; printf done; } & wait", true, false),
        ("false && exit", false, true),
        ("if false; then exit; fi", false, true),
        ("(false && exit)", true, true),
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        let c = p
            .commands
            .iter()
            .find(|c| c.command_name.as_deref() == Some("exit"))
            .unwrap();
        assert_eq!(c.shell_scope_span.is_some(), isolated, "{source}");
        assert_eq!(c.conditional_execution, conditional, "{source}");
    }
}

#[test]
fn function_definitions_have_the_same_frame_metadata_as_commands() {
    for (source, isolated, conditional) in [
        ("f() { printf LAB; }", false, false),
        ("(f() { printf LAB; })", true, false),
        ("{ f() { printf LAB; }; } | cat", true, false),
        ("{ f() { printf LAB; }; } & wait", true, false),
        (
            "if test -n \"$flag\"; then f() { printf LAB; }; fi",
            false,
            true,
        ),
        (
            "(if test -n \"$flag\"; then f() { printf LAB; }; fi)",
            true,
            true,
        ),
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        let definition = &parsed.function_definitions[0];
        assert_eq!(definition.shell_scope_span.is_some(), isolated, "{source}");
        assert_eq!(definition.conditional_execution, conditional, "{source}");
    }
}
