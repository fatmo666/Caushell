use caushell_parse::{ParseStatus, parse_command, parse_command_substitutions};
use caushell_types::ShellKind;

fn complete(command: &str) {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    if parsed.status != ParseStatus::Complete {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .unwrap();
        eprintln!(
            "pinned grammar: {}",
            parser.parse(command, None).unwrap().root_node().to_sexp()
        );
        let tree = parser.parse(command, None).unwrap();
        let root = tree.root_node();
        for i in 0..root.child_count() {
            let n = root.child(i as u32).unwrap();
            eprintln!(
                "child {:?} {}..{} {:?}",
                n.kind(),
                n.start_byte(),
                n.end_byte(),
                &command[n.start_byte()..n.end_byte()]
            );
        }
    }
    assert_eq!(
        parsed.status,
        ParseStatus::Complete,
        "{command}: {:?}",
        parsed.diagnostics
    );
}

#[test]
fn arithmetic_substring_offsets_are_native_shell_syntax() {
    for command in [
        "printf '%s' \"${digits:length-1-index:1}\"",
        "printf '%s' \"${digits:(length-1-index):1}\"",
        "printf '%s' \"${digits:(length>1?length-1:0):1}\"",
    ] {
        complete(command);
    }
}

#[test]
fn substring_values_can_occur_inside_arithmetic_expansions() {
    complete("value=$((carry + ${digits:length-1-index:1}))");
}

#[test]
fn arithmetic_for_comparisons_and_ternary_expressions_remain_scoped() {
    complete(
        "for ((index=0; index<(left>right?left:right)||carry; index++)); do printf '%s' \"$index\"; done",
    );
}

#[test]
fn function_bodies_with_arithmetic_slices_keep_their_identity() {
    let source = "digit(){ local digits=$1; local length=${#digits}; for ((index=0; index<(length>width?length:width)||carry; index++)); do value=$((carry + ${digits:length-1-index:1})); printf '%s' \"$value\"; done; }; digit 456";
    complete(source);
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.function_definitions.len(), 1);
    assert_eq!(parsed.function_definitions[0].name, "digit");
}

#[test]
fn all_three_fields_nested_ternaries_and_source_coordinates_are_preserved() {
    let source = "printf 中文; for ((index=(flag?0:1); index<(flag?(other?2:3):4); index=(flag?index+1:index+2))); do echo ok; done";
    complete(source);
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert!(
        parsed
            .shell_evaluations
            .iter()
            .any(|s| s.input.text.contains("flag?"))
    );
    for command in &parsed.commands {
        assert_eq!(
            &source[command.span.start_byte..command.span.end_byte],
            command.text
        );
    }
}

#[test]
fn ternary_projection_retains_substitutions_in_each_branch_and_body() {
    let source = "probe(){ for ((index=0; index<(flag ? $(printf 1; printf 2) : $(printf 3)); index++)); do touch /opt/shared/marker; done; }; probe";
    complete(source);
    let substitutions = parse_command_substitutions(source, ShellKind::Bash).unwrap();
    assert_eq!(substitutions.len(), 2);
    assert_eq!(substitutions[0].body_text, "printf 1; printf 2");
    assert_eq!(substitutions[1].body_text, "printf 3");
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert!(
        parsed.function_definitions[0]
            .body_text
            .contains("touch /opt/shared/marker")
    );
}

#[test]
fn malformed_headers_and_bodies_still_have_diagnostics() {
    for source in [
        "for ((index=0; index<(flag ? : 3); index++)); do echo ok; done",
        "for ((index=0; index<(flag ? 2 :); index++)); do echo ok; done",
        "for ((index=0; index<(flag ? 2 : 3); index++)); do echo \"unfinished; done",
        "for ((index=0; index<(flag ? 2 : 3); index++)); do echo ok",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{source}: {parsed:#?}");
        assert!(!parsed.diagnostics.is_empty());
    }
}

#[test]
fn oversized_compatibility_fields_remain_partial() {
    let source = format!(
        "for ((i=0; i<({}flag?1:2); i++)); do echo ok; done",
        " ".repeat(8200)
    );
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Partial);
}

#[test]
fn words_comments_and_quoted_heredocs_do_not_create_for_headers() {
    for source in [
        "echo 'for ((i=0; i<(flag?1:2); i++)); do rm /opt/marker; done'",
        "echo ok # for ((i=0; i<(flag?1:2); i++)); do rm /opt/marker; done",
        "cat <<'EOF'\nfor ((i=0; i<(flag?1:2); i++)); do rm /opt/marker; done\nEOF\n",
    ] {
        complete(source);
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert!(parsed.shell_evaluations.is_empty(), "{source}: {parsed:#?}");
        assert!(
            parse_command_substitutions(source, ShellKind::Bash)
                .unwrap()
                .is_empty()
        );
    }
}
