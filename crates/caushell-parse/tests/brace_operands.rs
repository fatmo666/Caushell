use caushell_parse::parse_command;
use caushell_types::ShellKind;

#[test]
fn numeric_brace_operands_keep_their_ast_kind_source_and_order() {
    let source = "touch {1..3} cache/{4..6} {7..9}";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    let tokens = &parsed.commands[0].tokens;
    assert_eq!(
        tokens.iter().map(|t| t.text.as_str()).collect::<Vec<_>>(),
        ["{1..3}", "cache/{4..6}", "{7..9}"]
    );
    assert_eq!(tokens[0].node_kind, "brace_expression");
    for token in tokens {
        assert_eq!(
            &source[token.span.start_byte..token.span.end_byte],
            token.text
        );
    }
}

#[test]
fn quoted_numeric_braces_are_literal_not_range_nodes() {
    let parsed = parse_command("echo '{1..3}' \"{4..6}\"", ShellKind::Bash).unwrap();
    let tokens = &parsed.commands[0].tokens;
    assert_eq!(tokens.len(), 2);
    assert!(
        tokens
            .iter()
            .all(|t| t.quoted && t.node_kind != "brace_expression")
    );
}
