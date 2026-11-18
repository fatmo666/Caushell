use caushell_parse::{ScalarArgumentPart as P, scalar_argument_parts as parts};

#[test]
fn scalar_parts_keep_literals_parameters_and_quoted_producers_separate() {
    let p = parts(r#"prefix/${HOST}/$(printf '%s' data)/tail"#, true, "string").unwrap();
    let nonempty = p
        .into_iter()
        .filter(|p| !matches!(p,P::Literal(s) if s.is_empty()))
        .collect::<Vec<_>>();
    assert_eq!(
        nonempty,
        [
            P::Literal("prefix/".into()),
            P::Parameter("${HOST}".into()),
            P::Literal("/".into()),
            P::CommandSubstitution("$(printf '%s' data)".into()),
            P::Literal("/tail".into())
        ]
    );
    let p = parts(r#"'literal$'"$(printf x)"suffix"#, false, "concatenation").unwrap();
    assert_eq!(
        p.into_iter()
            .filter(|p| !matches!(p,P::Literal(s) if s.is_empty()))
            .collect::<Vec<_>>(),
        [
            P::Literal("literal$".into()),
            P::CommandSubstitution("$(printf x)".into()),
            P::Literal("suffix".into())
        ]
    );
    assert_eq!(
        parts(r#"\$HOME\`literal\`\\end"#, true, "string")
            .unwrap()
            .into_iter()
            .filter_map(|p| match p {
                P::Literal(s) => Some(s),
                _ => None,
            })
            .collect::<String>(),
        "$HOME`literal`\\end"
    );
}

#[test]
fn vectors_operators_unquoted_producers_and_unaccounted_syntax_have_no_scalar_proof() {
    for (word, quoted, kind) in [
        ("$(printf x)", false, "word"),
        (r#""$@""#, false, "concatenation"),
        ("${X:=value}", true, "string"),
        ("${X:-$(side_effect)}", true, "string"),
        ("$((x++))", true, "string"),
        ("$$", true, "string"),
        (r#""$(printf x)"*"#, false, "concatenation"),
        (r#"{a,b}"$(printf x)""#, false, "concatenation"),
    ] {
        assert!(parts(word, quoted, kind).is_none(), "{word}");
    }
    assert!(parts(&"${NAME}".repeat(257), true, "string").is_none());
    assert!(parts(&"a".repeat(65_537), false, "word").is_none());
}

#[test]
fn scalar_parts_match_native_bash_quote_removal_without_reexpanding_values() {
    for word in [
        r#""pre-${NAME}-$(printf '%s\n\n' 'a b')-post""#,
        r#"literal"$(printf '%s\n\n' 'a b')"' suffix'"#,
        r#""\$HOME-$(printf '%s\n\n' 'a b')-\\end""#,
    ] {
        let p = parts(word, false, "concatenation").unwrap();
        let mut value = String::new();
        for part in p {
            value.push_str(match &part {
                P::Literal(s) => s,
                P::Parameter(s) if s == "${NAME}" => "$(not_code) spaced",
                P::CommandSubstitution(s) if s == "$(printf '%s\\n\\n' 'a b')" => "a b",
                other => panic!("unexpected {other:?}"),
            });
        }
        let native = std::process::Command::new("/bin/bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                &format!("printf '%s\\0' {word}"),
            ])
            .env_clear()
            .env("NAME", "$(not_code) spaced")
            .output()
            .unwrap();
        assert!(native.status.success(), "{:?}", native.stderr);
        assert_eq!(native.stdout, [value.as_bytes(), &[0]].concat(), "{word}");
    }
}

#[test]
fn expansion_parts_keep_splittable_and_quoted_fragments_separate() {
    use caushell_parse::scalar_word_parts;
    assert_eq!(
        scalar_word_parts(
            r#"head${PWD}/$(printf data)"$NAME"tail"#,
            false,
            "concatenation",
            true
        ),
        Some(vec![
            P::Literal("head".into()),
            P::UnquotedParameter("${PWD}".into()),
            P::Literal("/".into()),
            P::UnquotedCommandSubstitution("$(printf data)".into()),
            P::Parameter("$NAME".into()),
            P::Literal("tail".into()),
        ])
    );
    for word in [r#""$PWD"/$(printf data)*"#, r#"$(printf data)"$@""#] {
        assert!(
            scalar_word_parts(word, false, "concatenation", true).is_none(),
            "{word}"
        );
    }
}

#[test]
fn frame_planning_requests_ifs_for_unquoted_substitution_without_explicit_variables() {
    for raw in ["find $(pwd)/ -type f", "find `pwd` -type f"] {
        let names =
            caushell_parse::observed_shell_variables(raw, caushell_types::ShellKind::Bash).unwrap();
        assert!(names.contains("IFS"), "{raw}: {names:?}");
    }
    for raw in [r#"find "$(pwd)" -type f"#, r#"find '$(pwd)' -type f"#] {
        let names =
            caushell_parse::observed_shell_variables(raw, caushell_types::ShellKind::Bash).unwrap();
        assert!(!names.contains("IFS"), "{raw}: {names:?}");
    }
}
