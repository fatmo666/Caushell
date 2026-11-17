use caushell_parse::parse_argument_process_substitutions;
use caushell_types::ShellKind;
#[test]
fn attached_and_concatenated_words_keep_immediate_shell_expansions() {
    for word in [
        "--input=<(printf marker)",
        "prefix<(printf marker)suffix",
        "\"--input=\"<(printf marker)",
    ] {
        let s = parse_argument_process_substitutions(word, ShellKind::Bash).unwrap();
        assert_eq!(s.len(), 1, "{word}: {s:#?}");
        assert_eq!(s[0].body_text, "printf marker");
    }
}
#[test]
fn quotes_and_escapes_do_not_manufacture_process_expansion() {
    for word in [
        "'<(printf marker)'",
        "\"<(printf marker)\"",
        r"\<\(printf\ marker\)",
        "'--input=<(printf marker)'",
    ] {
        assert!(
            parse_argument_process_substitutions(word, ShellKind::Bash)
                .unwrap()
                .is_empty(),
            "{word}"
        );
    }
}
#[test]
fn child_shell_expansions_belong_to_their_own_scope() {
    let s =
        parse_argument_process_substitutions("--input=<(cat <(printf nested))", ShellKind::Bash)
            .unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].body_text, "cat <(printf nested)");
    assert!(
        parse_argument_process_substitutions("\"$(cat <(printf child))\"", ShellKind::Bash)
            .unwrap()
            .is_empty()
    );
}
