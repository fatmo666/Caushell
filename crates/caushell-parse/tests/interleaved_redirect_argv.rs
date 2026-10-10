//! Static AST extraction only; these commands are never executed.
use caushell_parse::{ParseStatus, PipelinePosition, parse_command};
use caushell_types::ShellKind;

#[test]
fn redirects_own_only_their_first_destination_and_keep_all_later_argv() {
    for source in [
        "probe one >out two three",
        "probe >out one two three",
        "probe one >out two 2>err three",
        "probe one >out two <input three",
        "probe one >&- two three",
        "probe one 2>&1 two three",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source}");
        assert_eq!(parsed.commands.len(), 1, "{source}");
        let command = &parsed.commands[0];
        assert_eq!(
            command
                .tokens
                .iter()
                .map(|t| t.text.as_str())
                .collect::<Vec<_>>(),
            ["one", "two", "three"],
            "{source}"
        );
        assert_eq!(
            &source[command.span.start_byte..command.span.end_byte],
            command.text
        );
        for redirection in &parsed.redirections {
            assert_eq!(
                redirection.parent_command_span.as_ref(),
                Some(&command.span),
                "{source}"
            );
            assert_eq!(
                &source[redirection.span.start_byte..redirection.span.end_byte],
                redirection.text
            );
            assert!(!redirection.text.contains("two") && !redirection.text.contains("three"));
        }
        if source.contains(">&-") {
            assert_eq!(parsed.redirections[0].target, None);
        } else {
            assert_eq!(
                parsed.redirections[0].target.as_ref().unwrap().text,
                if source.contains("2>&1") { "1" } else { "out" }
            );
        }
    }
}

#[test]
fn trailing_expansions_stay_whole_and_dont_promote_their_nested_commands() {
    let source = r"probe >'out file' $(echo alpha) <input >(cat) \; | tail -n 1";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    assert_eq!(parsed.commands.len(), 2);
    let command = &parsed.commands[0];
    assert_eq!(
        command
            .tokens
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>(),
        ["$(echo alpha)", ">(cat)", r"\;"]
    );
    assert_eq!(command.tokens[0].command_substitutions.len(), 1);
    assert_eq!(command.pipeline_position, Some(PipelinePosition::First));
    assert_eq!(
        parsed.commands[1].pipeline_position,
        Some(PipelinePosition::Last)
    );
    assert_eq!(
        parsed.redirections[0].target.as_ref().unwrap().text,
        "out file"
    );
    assert_eq!(
        parsed.redirections[1].target.as_ref().unwrap().text,
        "input"
    );
    for redirect in &parsed.redirections {
        assert_eq!(redirect.parent_command_span.as_ref(), Some(&command.span));
    }
}

#[test]
fn compound_statement_redirect_does_not_merge_distinct_commands() {
    let parsed = parse_command("{ probe one; probe two; } >out", ShellKind::Bash).unwrap();
    assert_eq!(parsed.commands.len(), 2);
    assert_eq!(parsed.commands[0].tokens[0].text, "one");
    assert_eq!(parsed.commands[1].tokens[0].text, "two");
    assert_eq!(parsed.redirections[0].target.as_ref().unwrap().text, "out");
    assert_eq!(parsed.redirections[0].parent_command_span, None);
}

#[test]
fn adjacent_destination_fragments_are_one_complete_shell_word_not_trailing_argv() {
    for source in [
        "probe >$f-$g.md5 argument",
        "probe >$f-$(echo suffix).md5 argument",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source}");
        assert_eq!(parsed.commands[0].tokens.len(), 1, "{source}: {parsed:?}");
        assert_eq!(parsed.commands[0].tokens[0].text, "argument");
        let target = parsed.redirections[0].target.as_ref().unwrap();
        assert_eq!(
            target.text,
            source
                .strip_prefix("probe >")
                .unwrap()
                .strip_suffix(" argument")
                .unwrap()
        );
        assert_eq!(
            &source[target.span.start_byte..target.span.end_byte],
            target.text
        );
    }
}
