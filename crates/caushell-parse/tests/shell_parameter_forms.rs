use caushell_parse::{ParseStatus, parse_command, parse_command_substitutions};
use caushell_types::ShellKind;

fn complete(source: &str) -> caushell_parse::ParsedCommandArtifact {
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(
        parsed.status,
        ParseStatus::Complete,
        "{source}: {parsed:#?}"
    );
    parsed
}

#[test]
fn substring_expansions_are_not_commands_or_broken_quotes() {
    for source in [
        "char=${data:$i:1}",
        "char=${data:$i:1}; echo \"$char\"",
        "printf \"%d\" \"'${data:$i:1}\"",
        "echo \"${data:$i:1}\"",
        "echo ${data:$i:1}",
        "echo \"${data: $i:1}\"",
        "echo \"${data:$i + 1:$length}\"",
        "echo \"${data: -1:1}\"",
        "echo \"${data:$((i + 1)):1}\"",
    ] {
        let parsed = complete(source);
        assert!(
            parsed
                .commands
                .iter()
                .all(|c| matches!(c.command_name.as_deref(), Some("echo" | "printf"))),
            "{source}: {parsed:#?}"
        );
    }
}

#[test]
fn projection_preserves_original_values_quotes_and_coordinates() {
    let source =
        "echo 中文\nchar=${data:$i:1}\necho \"'${data:$i:1}\"\nfor f\t do echo \"$f\"; done";
    let parsed = complete(source);
    let value = &parsed.assignment_commands[0].assignments[0].value;
    assert_eq!(value.text, "${data:$i:1}");
    assert_eq!(value.node_kind, "expansion");
    assert_eq!(
        &source[value.span.start_byte..value.span.end_byte],
        value.text
    );
    assert_eq!(value.span.start_row, 1);
    let quoted = &parsed.commands[1].tokens[0];
    assert!(quoted.quoted);
    assert_eq!(quoted.node_kind, "string");
    assert_eq!(quoted.text, "'${data:$i:1}");
    assert!(parsed.commands[2].conditional_execution);
    for command in &parsed.commands {
        assert_eq!(
            &source[command.span.start_byte..command.span.end_byte],
            command.text
        );
    }
}

#[test]
fn substring_offsets_keep_embedded_command_effects() {
    for source in [
        "echo \"${data:$(touch /opt/shared/marker):1}\"",
        "echo \"${data:$i:$(touch /opt/shared/marker)}\"",
        "char=${data:$i:$(touch /opt/shared/marker)}",
    ] {
        let parsed = complete(source);
        let facts = parse_command_substitutions(source, ShellKind::Bash).unwrap();
        assert_eq!(facts.len(), 1, "{source}: {facts:#?}");
        assert_eq!(facts[0].body_text, "touch /opt/shared/marker");
        let owned: Vec<_> = parsed
            .commands
            .iter()
            .flat_map(|c| &c.tokens)
            .flat_map(|t| &t.command_substitutions)
            .chain(
                parsed
                    .assignment_commands
                    .iter()
                    .flat_map(|c| &c.assignments)
                    .flat_map(|a| &a.value.command_substitutions),
            )
            .collect();
        assert_eq!(owned.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(owned[0].body_text, facts[0].body_text);
    }
    // More complex arithmetic is not blindly projected as known syntax; its
    // diagnostic remains, but a known embedded command must still be retained.
    let source = "echo \"${data:$i + $(touch /opt/shared/marker):1}\"";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial);
    assert_eq!(
        parsed.commands[0].tokens[0].command_substitutions[0].body_text,
        "touch /opt/shared/marker"
    );
}

#[test]
fn literals_are_not_rewritten_and_invalid_syntax_remains_partial() {
    for source in [
        "echo '${data:$i:1} for f do touch /opt/shared/marker; done'",
        "echo okay # ${data:$i:1} for f do touch /opt/shared/marker; done",
        "cat <<'EOF'\n${data:$i:1}\nfor f do touch /opt/shared/marker; done\nEOF\n",
    ] {
        let parsed = complete(source);
        assert_eq!(parsed.commands.len(), 1, "{source}: {parsed:#?}");
        assert!(
            parse_command_substitutions(source, ShellKind::Bash)
                .unwrap()
                .is_empty()
        );
    }
    for source in [
        "char=${data:$i:1",
        "char=${data:$i:1}; echo \"unfinished",
        "for f do echo hi",
        "for f 123 do echo hi; done",
        "for f doo echo hi; done",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
    }
}

#[test]
fn implicit_positional_for_has_no_missing_separator() {
    for source in [
        "for f do echo \"$f\"; done",
        "for f; do echo \"$f\"; done",
        "for f\ndo echo \"$f\"; done",
        "for f do for g do echo \"$f $g\"; done; done",
    ] {
        let parsed = complete(source);
        assert_eq!(parsed.commands.len(), 1, "{source}: {parsed:#?}");
        assert_eq!(parsed.commands[0].command_name.as_deref(), Some("echo"));
    }
}
