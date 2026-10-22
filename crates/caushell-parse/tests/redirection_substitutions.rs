//! Parse-only: no shell fragments are executed.
use caushell_parse::{ParseStatus, ShellEvaluationKind, parse_command};
use caushell_types::ShellKind;

#[test]
fn executable_redirect_operands_preserve_substitution_source_and_sites() {
    for source in [
        "cat <\"$(touch /opt/shared/marker; printf /etc/hosts)\"",
        "printf safe 3<\"$(rm -rf /; printf /etc/hosts)\"",
        "cat <<<\"$(rm -rf /; printf safe)\"",
        "cat <<EOF\n'$(rm -rf /)'\nEOF\n",
        "cat <<-EOF\n\t$(rm -rf /)\nEOF\n",
        "cat <`printf /etc/hosts``true`",
        "cat <<EOF\n`true` `false`\nEOF\n",
        "printf x >prefix\"$(true)\"suffix",
        "cat <<EOF\n  $(printf '%s' \"(literal)\"; true)\nEOF\n",
        "cat <<EOF\n  $(printf '%s' \"`true`\")\nEOF\n",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{source}: {parsed:#?}"
        );
        let sites: Vec<_> = parsed
            .shell_evaluations
            .iter()
            .filter(|site| matches!(site.kind, ShellEvaluationKind::RedirectionExpansion { .. }))
            .collect();
        assert_eq!(sites.len(), 1, "{source}: {parsed:#?}");
        assert!(!sites[0].input.command_substitutions.is_empty(), "{source}");
        assert!(
            !matches!(
                sites[0].kind,
                ShellEvaluationKind::RedirectionExpansion {
                    unresolved: true,
                    ..
                }
            ),
            "{source}: {parsed:#?}"
        );
        for substitution in &sites[0].input.command_substitutions {
            assert_eq!(
                &source[substitution.span.start_byte..substitution.span.end_byte],
                substitution.text
            );
        }
    }
}

#[test]
fn process_substitution_owns_its_inner_expansions() {
    for source in [
        "cat < <(printf '%s' \"$(true)\")",
        "cat < <(printf '%s' `true`)",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Complete, "{parsed:#?}");
        assert!(
            parsed.redirections[0]
                .target
                .as_ref()
                .unwrap()
                .command_substitutions
                .is_empty(),
            "{parsed:#?}"
        );
        assert!(parsed.shell_evaluations.is_empty(), "{parsed:#?}");
    }
}

#[test]
fn tab_stripping_precedes_expansion_without_changing_source_coordinates() {
    let source = "cat <<-EOF\n$(printf '%s' '\n\tVALUE')\nEOF\n";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    let substitution = &parsed.redirections[0]
        .content
        .as_ref()
        .unwrap()
        .command_substitutions[0];
    assert_eq!(substitution.body_text, "printf '%s' '\nVALUE'");
    assert_eq!(
        &source[substitution.span.start_byte..substitution.span.end_byte],
        substitution.text
    );
    assert!(substitution.text.contains("\tVALUE"));
}

#[test]
fn literal_redirect_operands_never_become_executable_sites() {
    for source in [
        "cat <'$(rm -rf /)'",
        "cat <<<'$(rm -rf /)'",
        "cat <<'EOF'\n$(rm -rf /)\nEOF\n",
        "cat <<\"EOF\"\n$(rm -rf /)\nEOF\n",
        "cat <<\\EOF\n$(rm -rf /)\nEOF\n",
        "cat <<E'OF'\n$(rm -rf /)\nEOF\n",
        "cat <<EOF\n\\$(rm -rf /)\nEOF\n",
        "cat <<EOF\n\\`rm -rf /\\`\nEOF\n",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        if !source.contains("\\$(") && !source.contains("\\`") {
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {parsed:#?}"
            );
        }
        assert!(
            parsed
                .shell_evaluations
                .iter()
                .all(|site| !matches!(site.kind, ShellEvaluationKind::RedirectionExpansion { .. })),
            "{source}: {parsed:#?}"
        );
    }
}
