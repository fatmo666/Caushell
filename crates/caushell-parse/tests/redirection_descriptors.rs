use caushell_parse::{ParseStatus, parse_command};
use caushell_types::ShellKind;

fn syntax(source: &str) -> String {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .unwrap();
    parser.parse(source, None).unwrap().root_node().to_sexp()
}

#[test]
fn mixed_stdin_redirections_keep_their_individual_fd_ownership() {
    for (source, expected) in [
        ("sh 000<<<'rm /opt/shared/file'", vec![Some("000")]),
        ("sh 0<&3 3<<<'printf SAFE'", vec![Some("0"), Some("3")]),
        ("sh 0<&2 <<< 'rm /opt/shared/file'", vec![Some("0"), None]),
        ("sh 3<&- 0<&3", vec![Some("3"), Some("0")]),
        ("sh <input <<< 'printf SAFE'", vec![None, None]),
        ("sh 0<&2 000<<<'printf SAFE'", vec![Some("0"), Some("000")]),
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {} {parsed:#?}",
            syntax(source)
        );
        assert_eq!(
            parsed
                .redirections
                .iter()
                .map(|r| r.file_descriptor.as_deref())
                .collect::<Vec<_>>(),
            expected,
            "{source}: {} {parsed:#?}",
            syntax(source)
        );
        assert!(
            parsed.commands[0].tokens.is_empty(),
            "{source}: {parsed:#?}"
        );
        for redirect in &parsed.redirections {
            assert_eq!(
                &source[redirect.span.start_byte..redirect.span.end_byte],
                redirect.text
            );
        }
    }
}

#[test]
fn here_string_repair_does_not_accept_unrelated_broken_syntax() {
    for source in ["sh 0<&2 <<<<DATA", "sh 0<&2 <<< 'unterminated"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
    }
    let source = "printf '%s' '<<<rm /opt/shared/file'";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    assert!(parsed.redirections.is_empty());
    assert_eq!(parsed.commands[0].tokens[1].text, "<<<rm /opt/shared/file");
}

#[test]
fn adjacent_numeric_descriptors_belong_to_redirections_not_argv() {
    for source in ["sh 0<&2 1>&2", "cat 12<input 34>output", "printf SAFE 2>&1"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        let argv: Vec<_> = parsed.commands[0]
            .tokens
            .iter()
            .map(|token| token.text.as_str())
            .collect();
        let expected = if source.starts_with("printf") {
            vec!["SAFE"]
        } else {
            vec![]
        };
        assert_eq!(argv, expected, "{source}: {} {parsed:#?}", syntax(source));
        for redirect in &parsed.redirections {
            assert!(redirect.file_descriptor.is_some(), "{source}: {parsed:#?}");
            assert_eq!(
                &source[redirect.span.start_byte..redirect.span.end_byte],
                redirect.text
            );
            assert!(redirect.parent_command_span.is_some());
        }
    }
}

#[test]
fn spaced_quoted_and_escaped_numbers_remain_arguments() {
    for source in [
        "cat 0 <input",
        "cat '0'<input",
        "cat \"0\"<input",
        "cat \\0<input",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert_eq!(parsed.commands[0].tokens.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(parsed.redirections.len(), 1);
        assert_eq!(
            parsed.redirections[0].file_descriptor, None,
            "{source}: {parsed:#?}"
        );
    }
}

#[test]
fn operators_and_descriptor_spelling_are_preserved_from_original_source() {
    for (source, fd, operator, target) in [
        ("cat 0<input", "0", "<", Some("input")),
        ("cat 0>output", "0", ">", Some("output")),
        ("cat 0>>output", "0", ">>", Some("output")),
        ("cat 0>|output", "0", ">|", Some("output")),
        ("cat 0<&2", "0", "<&", Some("2")),
        ("cat 0>&2", "0", ">&", Some("2")),
        ("cat 0<&-", "0", "<&-", None),
        ("cat 0>&-", "0", ">&-", None),
        ("cat 0<&3-", "0", "<&", Some("3-")),
        ("cat 0>&3-", "0", ">&", Some("3-")),
        ("cat 000<input", "000", "<", Some("input")),
        ("cat 012<input", "012", "<", Some("input")),
        ("cat 0<>file", "0", "<>", Some("file")),
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert!(
            parsed.commands[0].tokens.is_empty(),
            "{source}: {parsed:#?}"
        );
        let redirect = &parsed.redirections[0];
        assert_eq!(
            redirect.file_descriptor.as_deref(),
            Some(fd),
            "{source}: {parsed:#?}"
        );
        assert_eq!(
            redirect.operator.as_deref(),
            Some(operator),
            "{source}: {parsed:#?}"
        );
        assert_eq!(redirect.target.as_ref().map(|x| x.text.as_str()), target);
        assert_eq!(
            &source[redirect.span.start_byte..redirect.span.end_byte],
            redirect.text
        );
        assert_eq!(
            redirect.parent_command_span.as_ref(),
            Some(&parsed.commands[0].span)
        );
        assert_eq!(
            &source[parsed.commands[0].span.start_byte..parsed.commands[0].span.end_byte],
            parsed.commands[0].text
        );
    }
}

#[test]
fn numeric_redirect_destinations_and_combined_output_do_not_become_descriptors() {
    for source in [
        "cat >'0'<input",
        "cat <'0'>output",
        "cat >\"0\">&1",
        "cat >012 <input",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert!(parsed.commands[0].tokens.is_empty());
        assert!(
            parsed
                .redirections
                .iter()
                .all(|r| r.file_descriptor.is_none()),
            "{source}: {parsed:#?}"
        );
        assert!(
            parsed.redirections[0]
                .target
                .as_ref()
                .unwrap()
                .text
                .starts_with('0')
        );
    }
    for source in ["cat 0&>output", "cat 0&>>output", "cat 2&>output"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete);
        assert_eq!(parsed.commands[0].tokens.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(parsed.redirections[0].file_descriptor, None);
    }
}

#[test]
fn here_inputs_and_unquoted_line_continuations_have_descriptor_ownership() {
    for source in [
        "cat 0<<<DATA",
        "cat 0<<EOF\nDATA\nEOF\n",
        "cat 0<<-EOF\n\tDATA\nEOF\n",
        "cat 0\\\n<input",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {} {parsed:#?}",
            syntax(source)
        );
        assert!(
            parsed.commands[0].tokens.is_empty(),
            "{source}: {parsed:#?}"
        );
        assert_eq!(parsed.redirections[0].file_descriptor.as_deref(), Some("0"));
        assert_eq!(
            parsed.redirections[0].parent_command_span.as_ref(),
            Some(&parsed.commands[0].span)
        );
    }
    for source in ["cat 0 <<EOF\nDATA\nEOF\n", "cat 0\\\n <input"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete);
        assert_eq!(parsed.commands[0].tokens.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(parsed.redirections[0].file_descriptor, None);
    }
}

#[test]
fn leading_descriptors_and_bare_redirections_do_not_invent_a_program() {
    for source in ["0<input cat", "0<&2 cat"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert_eq!(parsed.commands[0].command_name.as_deref(), Some("cat"));
        assert!(parsed.commands[0].tokens.is_empty());
        assert_eq!(parsed.redirections[0].file_descriptor.as_deref(), Some("0"));
        assert_eq!(
            parsed.redirections[0].parent_command_span.as_ref(),
            Some(&parsed.commands[0].span)
        );
    }
    let parsed = parse_command("0<input", ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    assert!(parsed.commands.is_empty(), "{parsed:#?}");
    assert_eq!(parsed.redirections[0].file_descriptor.as_deref(), Some("0"));
    assert_eq!(parsed.redirections[0].parent_command_span, None);
}

#[test]
fn descriptor_restoration_keeps_unicode_rows_scopes_and_nested_source() {
    for source in [
        "printf 文件;\ncat 0<input | cat",
        "(cat 0<input) &",
        "VALUE=DATA cat 0<input",
        "cat 0<$(printf input)",
        "cat 0< <(printf DATA)",
        "cat 0<<<'0<&2'",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        let cat = parsed
            .commands
            .iter()
            .find(|c| c.command_name.as_deref() == Some("cat"))
            .unwrap();
        assert!(cat.tokens.is_empty(), "{source}: {parsed:#?}");
        let redirect = parsed
            .redirections
            .iter()
            .find(|r| r.file_descriptor.as_deref() == Some("0"))
            .unwrap();
        assert_eq!(
            redirect.parent_command_span.as_ref(),
            Some(&cat.span),
            "{source}: {parsed:#?}"
        );
        assert_eq!(
            &source[redirect.span.start_byte..redirect.span.end_byte],
            redirect.text
        );
        for (span, text) in [
            (&cat.span, cat.text.as_str()),
            (&redirect.span, redirect.text.as_str()),
        ] {
            assert_eq!(&source[span.start_byte..span.end_byte], text);
            let prefix = &source[..span.start_byte];
            assert_eq!(
                span.start_row,
                prefix.bytes().filter(|b| *b == b'\n').count()
            );
            assert_eq!(span.start_column, prefix.rsplit('\n').next().unwrap().len());
        }
    }
}

#[test]
fn quoted_expanded_and_invalid_syntax_is_not_repaired_as_a_descriptor() {
    for source in [
        "cat $ZERO<input",
        "cat prefix0<input",
        "cat $'0'<input",
        "cat 0\"\"<input",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert_eq!(parsed.commands[0].tokens.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(parsed.redirections[0].file_descriptor, None);
    }
    for source in ["cat 0<\"unterminated", "cat 0<<EOF\nDATA", "cat 0<"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
    }
    let parsed = parse_command("{cat,0}<input", ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete, "{parsed:#?}");
    assert_eq!(parsed.commands[0].command_name.as_deref(), Some("cat"));
    assert_eq!(parsed.commands[0].tokens[0].text, "0");
    assert_eq!(parsed.redirections[0].file_descriptor, None);
}

#[test]
fn redirected_state_builtins_and_assignments_keep_their_real_operands() {
    for source in ["export VALUE 0>output", "unset VALUE 0>output"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        assert!(parsed.commands.is_empty(), "{source}: {parsed:#?}");
        assert_eq!(
            parsed.redirections[0].file_descriptor.as_deref(),
            Some("0"),
            "{source}: {parsed:#?}"
        );
        if let Some(declaration) = parsed.declaration_commands.first() {
            assert_eq!(declaration.names, vec!["VALUE"]);
        } else if let Some(unset) = parsed.unset_commands.first() {
            assert_eq!(unset.names, vec!["VALUE"]);
        }
    }
    // This grammar does not yet model assignment-only redirected statements.
    // Keep that explicit gap rather than inventing an executable named "0".
    for source in ["VALUE=DATA 0>output", "0>output VALUE=DATA"] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
        assert!(
            parsed
                .commands
                .iter()
                .all(|command| command.command_name.as_deref() != Some("0")),
            "{source}: {parsed:#?}"
        );
    }
}
