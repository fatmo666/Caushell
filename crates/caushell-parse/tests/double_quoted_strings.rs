use caushell_parse::{ParseStatus, decode_static_shell_argument, parse_command};
use caushell_types::ShellKind;

#[test]
fn double_quoted_arguments_preserve_all_interior_source_bytes() {
    for inner in ["", "one line", "\n", "first\n\n\t文件\r\nlast\n"] {
        let source = format!("printf '%s' \"{inner}\"");
        let parsed = parse_command(&source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source:?}");
        let token = &parsed.commands[0].tokens[1];
        assert_eq!(token.text, inner, "{source:?}");
        assert!(token.quoted);
        assert_eq!(token.node_kind, "string");
        assert_eq!(
            &source[token.span.start_byte..token.span.end_byte],
            format!("\"{inner}\"")
        );
        assert_eq!(
            decode_static_shell_argument(&token.text, token.quoted, &token.node_kind),
            Some(inner.to_string())
        );
    }
}

#[test]
fn expansions_keep_source_spelling_and_independent_substitution_spans() {
    let inner = "head\n$VAR\n${VAR:-default}\n$(printf ok)\n$((1 + 2))\n`printf fine`\ntail";
    let source = format!("printf '%s' \"{inner}\"");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    let token = &parsed.commands[0].tokens[1];
    assert_eq!(token.text, inner);
    assert_eq!(token.command_substitutions.len(), 2);
    assert_eq!(token.command_substitutions[0].body_text, "printf ok");
    assert_eq!(token.command_substitutions[1].body_text, "printf fine");
    for fact in &token.command_substitutions {
        assert_eq!(&source[fact.span.start_byte..fact.span.end_byte], fact.text);
    }
    assert_eq!(
        decode_static_shell_argument(&token.text, token.quoted, &token.node_kind),
        None
    );
}

#[test]
fn double_quoted_escapes_are_preserved_then_decoded_exactly_once() {
    let inner = r#"first
\$VAR \`literal\` \"quoted\" \\ \q\
last"#;
    let source = format!("printf '%s' \"{inner}\"");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    let token = &parsed.commands[0].tokens[1];
    assert_eq!(token.text, inner);
    assert!(token.command_substitutions.is_empty());
    assert_eq!(
        decode_static_shell_argument(&token.text, token.quoted, &token.node_kind),
        Some("first\n$VAR `literal` \"quoted\" \\ \\qlast".into())
    );
}

#[test]
fn assignment_value_keeps_multiline_text_and_quote_metadata() {
    let inner = "first\n\n$VAR\n$(printf ok)\nlast";
    for source in [
        format!("VALUE=\"{inner}\""),
        format!("export VALUE=\"{inner}\""),
        format!("VALUE=\"{inner}\" printf ok"),
    ] {
        let parsed = parse_command(&source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete);
        let assignment = if let Some(command) = parsed.assignment_commands.first() {
            &command.assignments[0]
        } else if let Some(command) = parsed.declaration_commands.first() {
            &command.assignments[0]
        } else {
            &parsed.commands[0].prefix_assignments[0]
        };
        assert_eq!(assignment.value.text, inner);
        assert!(assignment.value.quoted);
        assert_eq!(assignment.value.node_kind, "string");
        assert_eq!(
            assignment.value.command_substitutions[0].body_text,
            "printf ok"
        );
        assert_eq!(
            &source[assignment.value.span.start_byte..assignment.value.span.end_byte],
            format!("\"{inner}\"")
        );
    }
}

#[test]
fn here_string_preserves_multiline_source_including_escapes() {
    let inner = "first\n\\$VALUE\\\nlast\n";
    let source = format!("cat <<< \"{inner}\"");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    let content = parsed.redirections[0].content.as_ref().unwrap();
    assert_eq!(content.text, inner);
    assert!(content.quoted);
    assert_eq!(content.node_kind, "string");
    assert_eq!(
        &source[content.span.start_byte..content.span.end_byte],
        format!("\"{inner}\"")
    );
}

#[test]
fn quoted_redirection_target_keeps_embedded_newlines() {
    let inner = "dir/first\n\n文件";
    let source = format!("printf ok > \"{inner}\"");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    let target = parsed.redirections[0].target.as_ref().unwrap();
    assert_eq!(target.text, inner);
    assert!(target.quoted);
    assert_eq!(target.node_kind, "string");
    assert_eq!(
        &source[target.span.start_byte..target.span.end_byte],
        format!("\"{inner}\"")
    );
}

#[test]
fn adjacent_quoted_and_unquoted_segments_remain_concatenation_source() {
    let token_source = "prefix\"first\nlast\"'tail'";
    let source = format!("printf '%s' {token_source}");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    let token = &parsed.commands[0].tokens[1];
    assert_eq!(token.node_kind, "concatenation");
    assert!(!token.quoted);
    assert_eq!(token.text, token_source);
}

#[test]
fn incomplete_double_quotes_remain_partial_not_repaired_strings() {
    for source in ["printf \"first\nlast", "printf \"first\nlast\\\""] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial);
        assert!(!parsed.diagnostics.is_empty());
        for token in parsed.commands.iter().flat_map(|command| &command.tokens) {
            if token.node_kind == "string" {
                assert_eq!(
                    token.text,
                    source[token.span.start_byte..token.span.end_byte]
                );
            }
        }
    }
}
