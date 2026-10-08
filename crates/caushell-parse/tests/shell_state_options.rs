use caushell_parse::parse_command;
use caushell_types::ShellKind;

#[test]
fn export_options_stop_at_the_first_operand() {
    for (source, options, names) in [
        ("export -n target", vec!["-n"], vec!["target"]),
        ("export target -n", vec![], vec!["target", "-n"]),
        ("export -- target", vec!["--"], vec!["target"]),
        ("export -- -n target", vec!["--"], vec!["-n", "target"]),
        ("export \"-np\" target", vec!["-np"], vec!["target"]),
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        let d = &p.declaration_commands[0];
        assert_eq!(d.options, options, "{source}");
        assert_eq!(d.names, names, "{source}");
    }
    let p = parse_command("export target=LAB -n", ShellKind::Bash).unwrap();
    assert!(p.declaration_commands[0].options.is_empty());
    assert_eq!(p.declaration_commands[0].names, ["-n"]);
}

#[test]
fn unset_options_stop_at_the_first_operand() {
    for (source, options, names) in [
        ("unset -v -- target", vec!["-v", "--"], vec!["target"]),
        ("unset target -f", vec![], vec!["target", "-f"]),
        ("unset -- -f target", vec!["--"], vec!["-f", "target"]),
        ("unset \"-fn\" target", vec!["-fn"], vec!["target"]),
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(p.unset_commands[0].options, options, "{source}");
        assert_eq!(p.unset_commands[0].names, names, "{source}");
    }
}

#[test]
fn variable_state_facts_distinguish_isolated_and_conditional_frames() {
    for (source, isolated, conditional) in [
        ("export -n target; unset -v target; x=LAB", false, false),
        ("(export -n target; unset -v target; x=LAB)", true, false),
        (
            "{ export -n target; unset -v target; x=LAB; } | cat",
            true,
            false,
        ),
        (
            "{ export -n target; unset -v target; x=LAB; } &",
            true,
            false,
        ),
        (
            "if true; then export -n target; unset -v target; x=LAB; fi",
            false,
            true,
        ),
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            p.declaration_commands[0].shell_scope_span.is_some(),
            isolated,
            "{source}"
        );
        assert_eq!(
            p.declaration_commands[0].conditional_execution, conditional,
            "{source}"
        );
        assert_eq!(
            p.unset_commands[0].shell_scope_span.is_some(),
            isolated,
            "{source}"
        );
        assert_eq!(
            p.unset_commands[0].conditional_execution, conditional,
            "{source}"
        );
        assert_eq!(
            p.assignment_commands[0].shell_scope_span.is_some(),
            isolated,
            "{source}"
        );
        assert_eq!(
            p.assignment_commands[0].conditional_execution, conditional,
            "{source}"
        );
    }
}
