use caushell_parse::{ParseStatus, parse_command};
use caushell_types::ShellKind;

#[test]
fn word_lists_keep_scope_quoting_and_nested_order() {
    let p = parse_command(
        "for f in ./*.jpg '/opt/a b' \"$ROOT\"; do for g in \"$f\"; do cp \"$g\" ./out; done; done",
        ShellKind::Bash,
    )
    .unwrap();
    assert_eq!(p.status, ParseStatus::Complete);
    assert_eq!(p.for_loops.len(), 2);
    let outer = &p.for_loops[0];
    assert_eq!(outer.variable, "f");
    let items = outer.items.as_ref().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0].text, "./*.jpg");
    assert!(!items[0].quoted);
    assert_eq!(items[1].text, "/opt/a b");
    assert_eq!(items[1].node_kind, "raw_string");
    assert_eq!(items[2].text, "$ROOT");
    assert!(items[2].quoted);
    assert!(outer.body_span.start_byte < p.commands[0].span.start_byte);
    assert!(outer.span.end_byte > p.for_loops[1].span.end_byte);
}

#[test]
fn implicit_lists_and_nested_shells_are_distinct() {
    let p = parse_command("for f; do echo \"$f\"; done; x=$(for h in a; do echo h; done); fn() { for z in b; do echo z; done; }", ShellKind::Bash).unwrap();
    assert_eq!(p.status, ParseStatus::Complete);
    assert_eq!(p.for_loops.len(), 1);
    assert_eq!(p.for_loops[0].items, None);
}

#[test]
fn executable_header_words_retain_syntax_and_owner_spans() {
    use caushell_parse::ShellEvaluationKind::ForListExpansion;

    let command = r#"for x in "$(find . -print)" "`find . -type f -print`" '$(find .)'; do :; done"#;
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let sites: Vec<_> = parsed.shell_evaluations.iter()
        .filter(|site| site.kind == ForListExpansion)
        .collect();
    assert_eq!(sites.len(), 2);
    for (site, expected) in sites.iter().zip(["find . -print", "find . -type f -print"]) {
        assert_eq!(site.top_level_span, parsed.for_loops[0].top_level_span);
        assert!(site.input.span.end_byte < parsed.for_loops[0].body_span.start_byte);
        let [substitution] = site.input.command_substitutions.as_slice() else {
            panic!("one substitution must belong to the loop word");
        };
        assert_eq!(substitution.body_text, expected);
    }
}
