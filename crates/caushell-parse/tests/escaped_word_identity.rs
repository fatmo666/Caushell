//! Original source bytes, argv boundaries and source coordinates are the contract.
use caushell_parse::*;
use caushell_types::ShellKind;
fn parse(source: &str) -> ParsedCommandArtifact {
    let p = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(
        p.status,
        ParseStatus::Complete,
        "{source:?}: {:?}",
        p.diagnostics
    );
    p
}
#[test]
fn ignored_escaped_prefixes_are_part_of_the_complete_command_word() {
    for blank in [' ', '\t', '\u{b}', '\u{c}'] {
        let name = format!("\\{blank}egrep");
        let source = format!("{name} abc");
        let p = parse(&source);
        assert_eq!(p.commands[0].command_name.as_deref(), Some(name.as_str()));
        assert_eq!(p.commands[0].text, source);
        assert_eq!(p.commands[0].span.start_byte, 0);
        assert_eq!(p.commands[0].tokens.len(), 1);
        assert_eq!(p.commands[0].tokens[0].text, "abc");
    }
}
#[test]
fn argv_and_concatenated_scalar_queries_share_the_same_word_boundary() {
    let p = parse(r"printf '%s' \ hello");
    let arg = p.commands[0].tokens.last().unwrap();
    assert_eq!(arg.text, r"\ hello");
    assert_eq!(
        decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind).as_deref(),
        Some(" hello")
    );
    let p = parse(r"\ 'egrep' abc");
    assert_eq!(p.commands[0].command_name.as_deref(), Some(r"\ 'egrep'"));
    assert_eq!(
        decode_static_shell_argument(r"\ 'egrep'", false, "concatenation").as_deref(),
        Some(" egrep")
    );
    let p = parse(r"\ # abc");
    assert_eq!(p.commands[0].command_name.as_deref(), Some(r"\ #"));
    assert_eq!(p.commands[0].tokens[0].text, "abc");
}
#[test]
fn escape_parity_and_actual_line_continuations_remain_distinct() {
    let p = parse(r"\\ egrep abc");
    assert_eq!(p.commands[0].command_name.as_deref(), Some(r"\\"));
    assert_eq!(p.commands[0].tokens[0].text, "egrep");
    let p = parse("\\\negrep abc");
    assert!(
        p.commands[0]
            .command_name
            .as_ref()
            .unwrap()
            .ends_with("egrep")
    );
    let p = parse("\\\r\nprintf SAFE");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.commands[0].command_name.as_deref(), Some("\\\r"));
    assert_eq!(p.commands[1].span.start_byte, 3);
    assert_eq!(p.commands[1].span.start_row, 1);
}
#[test]
fn quotes_comments_and_heredoc_delimiters_keep_their_original_bytes() {
    let p = parse("printf '%s' '\\ egrep' \"\\ egrep\" # \\ egrep\n");
    assert_eq!(p.commands[0].tokens.len(), 3);
    for arg in &p.commands[0].tokens[1..] {
        assert_eq!(arg.text, r"\ egrep");
    }
    let source = "cat <<\\ EOF\nx\n EOF\n";
    let p = parse(source);
    let r = &p.redirections[0];
    assert_eq!(r.heredoc_start.as_ref().unwrap().text, r"\ EOF");
    assert!(r.heredoc_start.as_ref().unwrap().quoted);
    assert_eq!(r.content.as_ref().unwrap().text, "x\n");
    let p = parse("cat <<'EOF'\n\\ egrep abc\nEOF\n");
    assert!(
        p.redirections[0]
            .content
            .as_ref()
            .unwrap()
            .command_substitutions
            .is_empty()
    );
}
#[test]
fn substitutions_reopen_shell_words_inside_expandable_heredocs() {
    let p = parse("cat <<EOF\n$(\\ egrep abc)\nEOF\n");
    let c = &p.redirections[0]
        .content
        .as_ref()
        .unwrap()
        .command_substitutions[0];
    assert_eq!(c.text, "$(\\ egrep abc)");
    let body = parse(&c.body_text);
    assert_eq!(body.commands[0].command_name.as_deref(), Some(r"\ egrep"));
}
#[test]
fn a_newly_exposed_heredoc_retains_literal_data() {
    let source = "\\ # <<'EOF'\n\\ egrep abc\nEOF\n";
    let p = parse(source);
    assert_eq!(p.commands[0].command_name.as_deref(), Some(r"\ #"));
    assert_eq!(
        p.redirections[0].content.as_ref().unwrap().text,
        "\\ egrep abc\n"
    );
}
#[test]
fn unsupported_backslash_heredoc_delimiters_keep_their_parse_gap() {
    // Fixed-grammar AST controls independently reproduce this error even
    // without the escaped command prefix. It must not become Complete.
    let source = "\\ # <<'\\_EOF'\n\\ EOF\n\\_EOF\n";
    let p = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(p.status, ParseStatus::Partial);
    assert!(!p.diagnostics.is_empty());
    assert_eq!(p.commands[0].command_name.as_deref(), Some(r"\ #"));
}
#[test]
fn all_grammar_calls_use_the_shared_word_boundary_entry() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fn visit(path: &std::path::Path) {
        for e in std::fs::read_dir(path).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                visit(&p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs")
                || p.file_name().unwrap() == "word_boundary.rs"
            {
                continue;
            }
            let s = std::fs::read_to_string(&p).unwrap();
            let compact: String = s
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            assert!(
                !compact.contains(".parse("),
                "{} bypasses lexical boundary validation",
                p.display()
            );
        }
    }
    visit(&src);
}

#[test]
fn deferred_body_bounds_follow_quotes_comments_and_child_shell_scopes() {
    for source in [
        "cat <<EOF 'a\nb'\n\\ value\nEOF\n",
        "cat <<EOF # trailing\\\n\\ value\nEOF\n",
        "cat <<OUT $(cat <<IN\ninside\nIN\n)\n\\ value\nOUT\n",
    ] {
        let p = parse(source);
        assert_eq!(
            p.redirections[0].content.as_ref().unwrap().text,
            "\\ value\n",
            "{source:?}"
        );
    }
}
#[test]
fn multiple_deferred_inputs_and_tab_stripped_end_markers_keep_separate_data() {
    let p = parse("cat <<A\n\\ first\nA\ncat <<B\n\\ second\nB\n");
    assert_eq!(p.redirections.len(), 2);
    assert_eq!(
        p.redirections[0].content.as_ref().unwrap().text,
        "\\ first\n"
    );
    assert_eq!(
        p.redirections[1].content.as_ref().unwrap().text,
        "\\ second\n"
    );
    let p = parse("cat <<-EOF\n\t\\ value\n\tEOF\n");
    assert_eq!(
        p.redirections[0].content.as_ref().unwrap().text,
        "\t\\ value\n"
    );
}

#[test]
fn unsupported_multiple_headers_do_not_lose_the_existing_syntax_error() {
    let p = parse_command("cat <<A <<B\n\\ first\nA\n\\ second\nB\n", ShellKind::Bash).unwrap();
    assert_eq!(p.status, ParseStatus::Partial);
    assert!(!p.diagnostics.is_empty());
}
