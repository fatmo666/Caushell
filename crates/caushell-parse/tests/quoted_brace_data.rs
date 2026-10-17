use caushell_parse::decode_static_shell_argument;
use caushell_parse::parse_command;
use caushell_types::ShellKind;

#[test]
fn lexical_continuation_does_not_create_a_new_argument() {
    let parsed = parse_command("bash -c r\\\nm' /opt/file'", ShellKind::Bash).unwrap();
    assert_eq!(parsed.commands[0].tokens.len(), 2, "{:#?}", parsed.commands);
    assert_eq!(parsed.commands[0].tokens[1].text, "r\\\nm' /opt/file'");
    assert_eq!(parsed.commands[0].tokens[1].span.start_byte, 8);
    for (source, count) in [
        ("echo a\\\n\\\nb", 1),
        ("echo a \\\nb", 2),
        ("echo a\\\n b", 2),
        ("echo a\\\n>out b", 2),
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(p.commands[0].tokens.len(), count, "{source}: {p:?}");
    }
    let p = parse_command("p\\\nrintf '%s' value", ShellKind::Bash).unwrap();
    assert_eq!(p.commands[0].command_name.as_deref(), Some("p\\\nrintf"));
    assert_eq!(p.commands[0].tokens.len(), 2);
    let p = parse_command("bash -\\\nc 'rm /opt/file'", ShellKind::Bash).unwrap();
    assert_eq!(
        p.commands[0].tokens[0].kind,
        caushell_parse::CommandTokenKind::Flag
    );
}

#[test]
fn quote_removal_keeps_literal_program_braces_without_inventing_brace_vectors() {
    for (text, expected) in [
        ("{'print $4'}", "{print $4}"),
        (
            "{'print substr($5, 1, length($5)-1)'}",
            "{print substr($5, 1, length($5)-1)}",
        ),
        ("{'print \"a..b\"'}", "{print \"a..b\"}"),
        ("'{a,b}'suffix", "{a,b}suffix"),
        ("!#$", "!#$"),
        ("'quoted$'$", "quoted$$"),
        ("r\\\nm' /opt/file'", "rm /opt/file"),
    ] {
        assert_eq!(
            decode_static_shell_argument(text, false, "concatenation").as_deref(),
            Some(expected),
            "{text}"
        );
    }
    for text in [
        "{'a','b'}",
        "{a,'b'}",
        "{'a',b}",
        "{1..'3'}",
        "{a,{b,'c'}}",
        "{a,b}'suffix'",
    ] {
        assert_eq!(
            decode_static_shell_argument(text, false, "concatenation"),
            None,
            "{text}"
        );
    }
    for text in [
        "{}.tmp$$",
        "word$?",
        "word$!",
        "'prefix'$UNKNOWN",
        "{\"$UNKNOWN\"}",
        "'prefix'$(rm /opt/file)",
    ] {
        assert_eq!(
            decode_static_shell_argument(text, false, "concatenation"),
            None,
            "{text}"
        );
    }
}

#[test]
fn unquoted_line_continuations_are_removed_not_inserted_into_native_argv() {
    assert_eq!(
        decode_static_shell_argument("r\\\nm", false, "word").as_deref(),
        Some("rm")
    );
}
