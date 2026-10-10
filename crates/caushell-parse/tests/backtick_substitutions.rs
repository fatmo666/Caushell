//! Parse-only regressions; shell fragments are never executed.
use caushell_parse::{ParseStatus, parse_command, parse_command_substitutions};
use caushell_types::ShellKind;

#[test]
fn sibling_backticks_are_distinct_substitutions() {
    for source in [
        "echo `date` `hostname`",
        "echo `date``hostname`",
        "echo \"`date` `hostname`\"",
        "value=\"`date` `hostname`\"",
        "echo $(true) `date` `hostname`",
    ] {
        let facts = parse_command_substitutions(source, ShellKind::Bash).unwrap();
        let expected = if source.contains("$(true)") {
            vec!["true", "date", "hostname"]
        } else {
            vec!["date", "hostname"]
        };
        assert_eq!(
            facts
                .iter()
                .map(|f| f.body_text.as_str())
                .collect::<Vec<_>>(),
            expected,
            "{source}: {facts:#?}"
        );
        for fact in &facts {
            assert_eq!(&source[fact.span.start_byte..fact.span.end_byte], fact.text);
        }
        let artifact = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(artifact.status, ParseStatus::Complete, "{artifact:#?}");
        let facts: Vec<_> = artifact
            .commands
            .iter()
            .flat_map(|c| &c.tokens)
            .flat_map(|t| &t.command_substitutions)
            .chain(
                artifact
                    .assignment_commands
                    .iter()
                    .flat_map(|c| &c.assignments)
                    .flat_map(|a| &a.value.command_substitutions),
            )
            .collect();
        assert_eq!(
            facts
                .iter()
                .map(|f| f.body_text.as_str())
                .collect::<Vec<_>>(),
            expected,
            "{source}: {artifact:#?}"
        );
    }
}

#[test]
fn argv_width_and_quotes_are_restored_not_placeholder_values() {
    let separate = parse_command("echo `date` `hostname` -- suffix", ShellKind::Bash).unwrap();
    let tokens = &separate.commands[0].tokens;
    assert_eq!(tokens.len(), 4);
    for token in &tokens[..2] {
        assert_eq!(token.node_kind, "command_substitution");
        assert!(!token.quoted);
        assert!(token.text.starts_with('`'));
    }
    let adjacent = parse_command("echo pre`date``hostname`post", ShellKind::Bash).unwrap();
    assert_eq!(adjacent.commands[0].tokens.len(), 1);
    assert_eq!(
        adjacent.commands[0].tokens[0].text,
        "pre`date``hostname`post"
    );
    assert!(!adjacent.commands[0].tokens[0].quoted);
    let quoted = parse_command("echo \"`date` `hostname`\"", ShellKind::Bash).unwrap();
    assert_eq!(quoted.commands[0].tokens.len(), 1);
    assert!(quoted.commands[0].tokens[0].quoted);
    assert_eq!(quoted.commands[0].tokens[0].node_kind, "string");
    assert_eq!(quoted.commands[0].tokens[0].text, "`date` `hostname`");
}

#[test]
fn old_style_body_loses_exactly_one_escape_layer() {
    let source = r"echo `printf '%s' \`id\` \$name \\x \q`";
    let facts = parse_command_substitutions(source, ShellKind::Bash).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].body_text, r"printf '%s' `id` $name \x \q");
    let nested = parse_command(&facts[0].body_text, ShellKind::Bash).unwrap();
    assert_eq!(
        nested.commands[0].tokens[1].command_substitutions[0].body_text,
        "id"
    );
    let modern =
        parse_command_substitutions(r"echo $(printf '%s' \`id\` \$name \\x)", ShellKind::Bash)
            .unwrap();
    assert_eq!(modern[0].body_text, r"printf '%s' \`id\` \$name \\x");
}

#[test]
fn literal_ticks_comments_and_quoted_heredocs_do_not_become_code() {
    for source in [
        "echo '`touch /opt/shared/marker`'",
        r"echo \`touch /opt/shared/marker\`",
        "echo $'`touch /opt/shared/marker`'",
        "echo okay # `touch /opt/shared/marker`",
        "cat <<'EOF'\n`touch /opt/shared/marker`\nEOF\n",
        "echo `true` '`touch /opt/shared/marker`' `false`",
    ] {
        let artifact = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(artifact.status, ParseStatus::Complete, "{artifact:#?}");
        let facts: Vec<_> = artifact
            .commands
            .iter()
            .flat_map(|c| &c.tokens)
            .flat_map(|t| &t.command_substitutions)
            .collect();
        assert!(
            facts.iter().all(|f| !f.body_text.contains("touch")),
            "{source}: {facts:#?}"
        );
    }
}

#[test]
fn multiline_and_utf8_source_coordinates_survive_projection() {
    let source = "echo 中文\nvalue=\"`printf '甲\\n'\ntrue` `hostname`\"\n";
    let artifact = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(artifact.status, ParseStatus::Complete, "{artifact:#?}");
    let value = &artifact.assignment_commands[0].assignments[0].value;
    assert!(value.quoted);
    assert_eq!(value.command_substitutions.len(), 2);
    for fact in &value.command_substitutions {
        assert_eq!(&source[fact.span.start_byte..fact.span.end_byte], fact.text);
    }
    assert_eq!(value.command_substitutions[0].span.start_row, 1);
    assert_eq!(value.command_substitutions[0].span.end_row, 2);
    assert_eq!(value.command_substitutions[1].span.start_row, 2);
}

#[test]
fn outer_control_flow_and_redirections_are_not_swallowed() {
    let source = "echo `true`; touch marker; echo `false` 2>error.log 3<&0";
    let artifact = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(artifact.status, ParseStatus::Complete, "{artifact:#?}");
    assert_eq!(
        artifact
            .commands
            .iter()
            .map(|c| c.command_name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["echo", "touch", "echo"]
    );
    assert_eq!(artifact.redirections.len(), 2);
    assert_eq!(
        artifact.redirections[0].file_descriptor.as_deref(),
        Some("2")
    );
    assert_eq!(
        artifact.redirections[1].file_descriptor.as_deref(),
        Some("3")
    );
    let redirect = parse_command("echo hi >`printf path`", ShellKind::Bash).unwrap();
    let target = redirect.redirections[0].target.as_ref().unwrap();
    assert_eq!(target.node_kind, "command_substitution");
    assert!(!target.quoted);
    assert_eq!(target.text, "`printf path`");
}

#[test]
fn excessive_greedy_boundaries_fail_instead_of_partial_success() {
    let source = format!("echo {}", vec!["`true`"; 40].join(" "));
    assert_eq!(
        parse_command(&source, ShellKind::Bash).unwrap_err(),
        caushell_parse::ParseError::BacktickBoundaryLimit
    );
}
