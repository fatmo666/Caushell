//! Lexical facts only: none of the supplied shell commands are executed.
use caushell_parse::{ParseStatus, parse_command};
use caushell_types::ShellKind;

#[test]
fn standalone_parameter_expansions_keep_their_argv_position_and_source() {
    for shell in [ShellKind::Bash, ShellKind::Sh] {
        for word in [
            "${DIRECTORY}",
            "${1}",
            "${@}",
            "${value:-fallback}",
            "${value#prefix}",
        ] {
            let source = format!("probe before {word} after");
            let parsed = parse_command(&source, shell).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {parsed:#?}"
            );
            let tokens = &parsed.commands[0].tokens;
            assert_eq!(tokens.len(), 3, "{source}: {tokens:#?}");
            assert_eq!(tokens[1].text, word);
            assert_eq!(tokens[1].node_kind, "expansion");
            assert!(!tokens[1].quoted);
            assert_eq!(
                &source[tokens[1].span.start_byte..tokens[1].span.end_byte],
                word
            );
        }
    }
}

#[test]
fn standalone_expansions_own_their_embedded_substitutions() {
    let parsed = parse_command(
        "probe ${value:-$(touch /opt/shared/marker)} tail",
        ShellKind::Bash,
    )
    .unwrap();
    let tokens = &parsed.commands[0].tokens;
    assert_eq!(tokens.len(), 2, "{parsed:#?}");
    assert_eq!(tokens[0].command_substitutions.len(), 1);
    assert_eq!(
        tokens[0].command_substitutions[0].body_text,
        "touch /opt/shared/marker"
    );
    assert_eq!(tokens[1].text, "tail");
}

#[test]
fn quoting_and_concatenation_keep_original_parameter_meaning() {
    let parsed = parse_command(
        r#"probe '${value}' "${value}" pre${value}/post"#,
        ShellKind::Bash,
    )
    .unwrap();
    let tokens = &parsed.commands[0].tokens;
    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[0].node_kind, "raw_string");
    assert_eq!(tokens[1].node_kind, "string");
    assert_eq!(tokens[2].node_kind, "concatenation");
    assert_eq!(tokens[2].text, "pre${value}/post");
}

#[test]
fn braced_redirection_operands_do_not_swallow_the_following_argv() {
    let source = "probe > ${OUTPUT} ${INPUT} tail";
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    assert_eq!(parsed.status, ParseStatus::Complete, "{parsed:#?}");
    let tokens = &parsed.commands[0].tokens;
    assert_eq!(tokens.len(), 2, "{parsed:#?}");
    assert_eq!(tokens[0].text, "${INPUT}");
    assert_eq!(tokens[1].text, "tail");
    let target = parsed.redirections[0].target.as_ref().unwrap();
    assert_eq!(target.text, "${OUTPUT}");
    assert_eq!(target.node_kind, "expansion");
}
