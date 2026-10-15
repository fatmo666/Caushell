use caushell_parse::parse_command;
use caushell_types::ShellKind;
#[test]
fn compound_redirects_record_the_opening_statement_not_the_last_command() {
    let p = parse_command(
        "cd /outside; { cd /inside; printf DATA; } > out 2> log",
        ShellKind::Bash,
    )
    .unwrap();
    assert_eq!(p.redirections.len(), 2);
    for r in &p.redirections {
        assert!(r.parent_command_span.is_none());
        let s = r.opening_statement.as_ref().unwrap();
        assert!(s.text.starts_with("{ cd /inside;"), "{s:#?}");
        assert!(s.command_name.is_none() && s.tokens.is_empty());
        assert_eq!(s.span.start_byte, 13);
        assert!(s.subshell_span.is_none());
    }
}
#[test]
fn inner_scope_and_standalone_redirect_context_are_preserved() {
    for c in ["( { :; } > out )", "if true; then > out; fi", "{ > out; }"] {
        let p = parse_command(c, ShellKind::Bash).unwrap();
        let r = p.redirections.first().unwrap();
        assert!(r.opening_statement.is_some(), "{c}: {p:#?}");
    }
    let p = parse_command("printf DATA > out", ShellKind::Bash).unwrap();
    assert!(p.redirections[0].opening_statement.is_none());
}

#[test]
fn descriptor_prefix_restoration_keeps_opening_spans_and_text() {
    for command in ["3> out", "(3> out)", "{ :; } 3> out 2>&3"] {
        let p = parse_command(command, ShellKind::Bash).unwrap();
        for r in &p.redirections {
            let s = r.opening_statement.as_ref().unwrap();
            assert_eq!(s.text, command[s.span.start_byte..s.span.end_byte]);
            assert!(s.span.start_byte <= r.span.start_byte);
            assert!(r.span.end_byte <= s.span.end_byte);
        }
    }
}
