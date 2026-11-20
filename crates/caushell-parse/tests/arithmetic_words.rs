use caushell_parse::{
    ParseStatus, ShellEvaluationKind, constant_arithmetic_word, parse_command,
    parse_command_substitutions,
};
use caushell_types::ShellKind;

#[test]
fn folds_only_bounded_decimal_arithmetic_with_no_shell_inputs() {
    for (word, value) in [
        ("$((1024*1024))", 1048576),
        ("$((10-2*3))", 4),
        ("$(((10 - 2) * 3))", 24),
        ("$((-7 / 2))", -3),
        ("$((-7 % 2))", -1),
    ] {
        assert_eq!(constant_arithmetic_word(word), Some(value), "{word}");
    }
    for word in [
        "$((016))",
        "$((1/0))",
        "$((2147483647*2))",
        "$((n+1))",
        "$((n=1))",
        "$((1<<2))",
        "$((1))suffix",
        "$((1+))",
    ] {
        assert_eq!(constant_arithmetic_word(word), None, "{word}");
    }
}

#[test]
fn complete_arithmetic_words_keep_original_bytes_and_substitution_boundaries() {
    for body in [
        "$(printf '%d' 1)0",
        "0$(printf '%d' 1)",
        "$(printf '%d' 1)$(printf '%d' 2)",
        " $(printf '%d' 1)0 ",
        "$(date -f - +%s- <<< $'tomorrow 21:30\\nnow')0",
    ] {
        for source in [format!("echo $(({body}))"), format!("(({body}))")] {
            let parsed = parse_command(&source, ShellKind::Bash).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {:?}",
                parsed.diagnostics
            );
            assert!(parsed.diagnostics.is_empty());
            assert!(
                parsed.shell_evaluations.iter().any(|site| {
                    site.kind == ShellEvaluationKind::Arithmetic && site.input.text == body
                }),
                "{source}: {:?}",
                parsed.shell_evaluations
            );
            for command in &parsed.commands {
                assert_eq!(
                    &source[command.span.start_byte..command.span.end_byte],
                    command.text
                );
            }
            let substitutions = parse_command_substitutions(&source, ShellKind::Bash).unwrap();
            assert!(!substitutions.is_empty());
            for substitution in substitutions {
                assert_eq!(
                    &source[substitution.span.start_byte..substitution.span.end_byte],
                    substitution.text
                );
            }
        }
    }
}

#[test]
fn adjacent_substitutions_remain_separate_executable_inputs() {
    let source = "printf 中文; echo $(($(printf 1)$(touch /opt/out)))";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(
        parsed.status,
        ParseStatus::Complete,
        "{:?}",
        parsed.diagnostics
    );
    let substitutions = parse_command_substitutions(source, ShellKind::Bash).unwrap();
    assert_eq!(
        substitutions
            .iter()
            .map(|s| s.body_text.as_str())
            .collect::<Vec<_>>(),
        ["printf 1", "touch /opt/out"]
    );
    assert_eq!(parsed.commands.len(), 2);
    assert!(
        parsed
            .commands
            .iter()
            .all(|command| !command.text.starts_with("touch"))
    );
    for substitution in substitutions {
        assert_eq!(
            &source[substitution.span.start_byte..substitution.span.end_byte],
            substitution.text
        );
    }
}

#[test]
fn a_word_without_complete_enclosing_boundaries_remains_partial() {
    let source = "echo $(($(printf 1)$(touch /opt/out)0))";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial);
    assert!(!parsed.diagnostics.is_empty());
    assert_eq!(
        parse_command_substitutions(source, ShellKind::Bash)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn malformed_incomplete_or_non_word_fields_are_not_certified() {
    for source in [
        "echo $(( $(printf 1) 0 ))",
        "echo $(( $(printf 1)0 + ))",
        "echo $(($(printf 1)0)",
        "echo $(($(printf 'unfinished)0))",
        "echo $(($(printf 1)0)); echo 'unfinished",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
    }
}

#[test]
fn quoted_words_comments_and_heredocs_do_not_acquire_arithmetic_effects() {
    for source in [
        "echo '$(( $(touch /opt/out)0 ))'",
        "echo ok # $(( $(touch /opt/out)0 ))",
        "cat <<'EOF'\n$(( $(touch /opt/out)0 ))\nEOF\n",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete);
        assert!(parsed.shell_evaluations.is_empty());
        assert!(
            parse_command_substitutions(source, ShellKind::Bash)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn arithmetic_word_completeness_proofs_are_bounded() {
    for source in [
        format!("echo $(({}$(printf 1)0))", " ".repeat(8200)),
        format!("echo $(({}0))", "$(true)".repeat(300)),
        "echo $(($(printf 1)0)); ".repeat(257),
    ] {
        let parsed = parse_command(&source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial);
        assert!(!parsed.diagnostics.is_empty());
    }
}

#[test]
fn shells_without_the_bash_arithmetic_model_keep_the_parse_gap() {
    let parsed = parse_command("echo $(($(printf 1)0))", ShellKind::Sh).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial);
    assert!(!parsed.diagnostics.is_empty());
}
