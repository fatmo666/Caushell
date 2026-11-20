//! Parse shell source only; none of the submitted commands is executed.
use caushell_parse::{ParseStatus, SourceSpan, parse_command};
use caushell_types::ShellKind;

fn coordinates(source: &str, span: &SourceSpan) {
    let point = |offset| {
        let prefix = &source.as_bytes()[..offset];
        (
            prefix.iter().filter(|&&b| b == b'\n').count(),
            prefix
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(offset, |i| offset - i - 1),
        )
    };
    assert_eq!((span.start_row, span.start_column), point(span.start_byte));
    assert_eq!((span.end_row, span.end_column), point(span.end_byte));
}

#[test]
fn later_redirect_cannot_swallow_commands_after_a_pipeline() {
    for stages in [2, 3, 4, 6] {
        for redirect in [">out", "2>err", "0<input", "2>&1", ">&-"] {
            for separator in ["\n", "\n\n", " \n\t", ";\n"] {
                let pipeline = std::iter::repeat_n("cat", stages)
                    .collect::<Vec<_>>()
                    .join(" | ");
                let source = format!(
                    "{pipeline}{separator}rm -f victim{separator}printf ok {redirect}\necho done"
                );
                let parsed = parse_command(&source, ShellKind::Bash).unwrap();
                assert_eq!(parsed.status, ParseStatus::Complete, "{source}: {parsed:?}");
                assert_eq!(parsed.commands.len(), stages + 3, "{source}: {parsed:?}");
                assert!(parsed.commands[..stages].iter().all(|c| c.in_pipeline));
                assert!(parsed.commands[stages..].iter().all(|c| !c.in_pipeline));
                let deletion = &parsed.commands[stages];
                assert_eq!(deletion.command_name.as_deref(), Some("rm"));
                assert_eq!(deletion.text, "rm -f victim");
                assert_eq!(
                    parsed.commands[stages + 1].command_name.as_deref(),
                    Some("printf")
                );
                for command in &parsed.commands {
                    coordinates(&source, &command.span);
                    coordinates(&source, &command.top_level_span);
                    assert_eq!(
                        &source[command.span.start_byte..command.span.end_byte],
                        command.text
                    );
                    for token in &command.tokens {
                        coordinates(&source, &token.span);
                    }
                }
                for redirection in &parsed.redirections {
                    coordinates(&source, &redirection.span);
                    coordinates(&source, &redirection.top_level_span);
                    if let Some(parent) = &redirection.parent_command_span {
                        assert_eq!(parent, &parsed.commands[stages + 1].span, "{source}");
                    }
                }
            }
        }
    }
}

#[test]
fn quoted_newlines_continuations_and_heredoc_data_are_not_command_boundaries() {
    for tail in [
        "printf '%s' 'line one\nrm -f literal'",
        "printf '%s' \"line one\nrm -f literal\"",
        "printf '%s' $'line one\nrm -f literal'",
        "printf '%s' line\\\ncontinued",
        "printf '%s' \\\n+            continued",
        "cat <<'EOF'\nrm -f literal\nEOF",
    ] {
        let source = format!("printf x | cat | cat\n{tail}\nprintf done >out");
        let parsed = parse_command(&source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source}: {parsed:?}");
        assert_eq!(parsed.commands.len(), 5, "{source}: {parsed:?}");
        assert!(
            !parsed
                .commands
                .iter()
                .any(|c| c.command_name.as_deref() == Some("rm"))
        );
        assert!(
            parsed.commands[3]
                .text
                .contains(tail.split('\n').next().unwrap())
        );
        for command in &parsed.commands {
            coordinates(&source, &command.span);
        }
    }
    let source = "printf x |\ncat |\ncat >out";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete);
    assert_eq!(parsed.commands.len(), 3);
    assert!(parsed.commands.iter().all(|c| c.in_pipeline));
}

#[test]
fn scopes_and_nested_evaluation_retain_original_source_positions() {
    for source in [
        "{ printf x | cat | cat\nrm victim\nprintf done >out; }",
        "(printf x | cat | cat\nrm victim\nprintf done >out)",
        "if true; then printf x | cat | cat\nrm victim\nprintf done >out; fi",
        "printf x | cat | cat\nrm victim\nprintf '%s' \"$(wc -c < input)\" >out",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source}: {parsed:?}");
        assert!(
            parsed.commands.iter().any(|c| c.text == "rm victim"),
            "{source}"
        );
        for command in &parsed.commands {
            coordinates(source, &command.span);
            if let Some(scope) = &command.shell_scope_span {
                coordinates(source, scope);
            }
            for token in &command.tokens {
                coordinates(source, &token.span);
                for substitution in &token.command_substitutions {
                    coordinates(source, &substitution.span);
                }
            }
        }
    }
}

#[test]
fn boundary_budget_retains_partial_analysis_and_known_commands() {
    let source = format!(
        "rm -rf /;\n{}",
        "printf x | cat | cat\nprintf done >out;\n".repeat(300)
    );
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial);
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.node_kind == "unprojected_command_boundary")
    );
    assert_eq!(parsed.commands[0].text, "rm -rf /");
}

#[test]
fn comments_and_stderr_pipes_keep_newline_separators() {
    for source in [
        "printf x |& cat | cat\nrm victim\nprintf ok >out",
        "printf x | cat | cat # trailing comment\nrm victim\nprintf ok >out",
        "printf x | cat | cat\n# separate comment\nrm victim\nprintf ok >out",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{source}: {parsed:?}");
        assert_eq!(parsed.commands.len(), 5, "{source}: {parsed:?}");
        assert_eq!(parsed.commands[3].text, "rm victim");
        assert!(!parsed.commands[3].in_pipeline);
    }
}

#[test]
fn a_swallowed_boundary_does_not_consume_the_next_functions_header() {
    let source = "function makeFixture {\n local data=$1\n printf '%s' fixture | tr -d '\\n' | xargs -I {} echo -n \"$data\"\n}\n\nfunction writeFixture {\n local data=$1\n echo -n \"$data\" >./output.txt\n}\n";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(
        parsed.status,
        ParseStatus::Complete,
        "{:?}",
        parsed.diagnostics
    );
    assert_eq!(parsed.function_definitions.len(), 2);
    assert_eq!(parsed.function_definitions[0].name, "makeFixture");
    let write = &parsed.function_definitions[1];
    assert_eq!(write.name, "writeFixture");
    assert_eq!(
        write.body_text,
        "local data=$1\n echo -n \"$data\" >./output.txt"
    );
    coordinates(source, &write.span);
    let body = parse_command(&write.body_text, ShellKind::Bash).unwrap();
    assert_eq!(body.status, ParseStatus::Complete);
    assert_eq!(body.redirections.len(), 1);
    assert_eq!(body.redirections[0].operator.as_deref(), Some(">"));
    assert_eq!(
        body.redirections[0]
            .target
            .as_ref()
            .map(|target| target.text.as_str()),
        Some("./output.txt")
    );
}

#[test]
fn a_missing_redirect_operand_stays_incomplete_after_an_earlier_separator() {
    let source = "function makeFixture {\n local data=$1\n printf '%s' fixture | tr -d '\\n' | xargs -I {} echo -n \"$data\"\n}\n\nfunction writeFixture {\n local data=$1\n echo -n \"$data\" >\n}\n";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial, "{parsed:?}");
}
