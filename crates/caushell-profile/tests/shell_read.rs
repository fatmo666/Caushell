use caushell_profile::*;
use caushell_types::{ShellKind, ShellScalarValue, StructuredShellValue};

fn read(command: &str, ifs: Option<&str>, input: &[u8]) -> Option<ShellReadResult> {
    let mut bindings = SessionBindings::new();
    if let Some(ifs) = ifs {
        bindings.insert_exact_scalar("IFS", ifs);
    }
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &ProfileRegistry::built_in().unwrap(),
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &bindings,
        )
    else {
        panic!("{command}")
    };
    let args = resolved
        .materialized_projection
        .invocation
        .args
        .iter()
        .map(|a| a.text.clone())
        .collect::<Vec<_>>();
    decode_shell_read(&resolved.bound, &args, &bindings, input)
}

fn values(result: ShellReadResult) -> Vec<(String, String)> {
    result
        .assignments
        .into_iter()
        .map(|(name, value)| {
            let SessionValue::RuntimeProduced { value, .. } = value else {
                panic!("{value:?}")
            };
            (name, value)
        })
        .collect()
}

#[test]
fn nul_records_preserve_whitespace_and_stop_at_the_first_delimiter() {
    let result = read(
        "read -r -d '' slot",
        Some(""),
        b" /workspace/a b \0ignored\0",
    )
    .unwrap();
    assert!(result.terminated);
    assert_eq!(values(result), [("slot".into(), " /workspace/a b ".into())]);
    assert_eq!(
        values(read("read -r -d '' slot", Some(""), b"\0").unwrap()),
        [("slot".into(), "".into())]
    );
    let eof = read("read -r -d '' slot", Some(""), b"partial").unwrap();
    assert!(!eof.terminated);
    assert_eq!(values(eof), [("slot".into(), "partial".into())]);
}

#[test]
fn default_delimiter_nul_skipping_reply_and_backslashes_are_distinct() {
    assert_eq!(
        values(read("read -r line", Some(""), b"a\0b\nrest").unwrap()),
        [("line".into(), "ab".into())]
    );
    assert_eq!(
        values(read("read -r", None, b"  a b  \n").unwrap()),
        [("REPLY".into(), "  a b  ".into())]
    );
    assert_eq!(
        values(read("read first second", Some(" \t\n"), b"a\\ b c\\\nd\n").unwrap()),
        [
            ("first".into(), "a b".into()),
            ("second".into(), "cd".into())
        ]
    );
    assert_eq!(
        values(read("read -r first second", Some(" "), b"a\\ b c\n").unwrap()),
        [
            ("first".into(), "a\\".into()),
            ("second".into(), "b c".into())
        ]
    );
}

#[test]
fn ifs_nonwhitespace_empty_fields_and_last_variable_remainder_follow_read() {
    for (input, first, second) in [
        ("x:y:\n", "x", "y"),
        (":x:y::\n", "", "x:y::"),
        ("x::y\n", "x", ":y"),
        (":\n", "", ""),
    ] {
        assert_eq!(
            values(read("read -r a b", Some(":"), input.as_bytes()).unwrap()),
            [("a".into(), first.into()), ("b".into(), second.into())]
        );
    }
    assert_eq!(
        values(read("read -r a", Some(":"), b"::x::\n").unwrap()),
        [("a".into(), "::x::".into())]
    );
    assert_eq!(
        values(read("read -r a b c", Some(" \t"), b"  one\t two three four  \n").unwrap()),
        [
            ("a".into(), "one".into()),
            ("b".into(), "two".into()),
            ("c".into(), "three four".into())
        ]
    );
}

#[test]
fn array_destination_uses_the_same_split_and_replaces_the_list() {
    let value = read("read -ra items", Some(":"), b":x::y:\n").unwrap();
    let SessionValue::Structured(StructuredShellValue::IndexedArray { elements, complete }) =
        &value.assignments[0].1
    else {
        panic!("{value:?}")
    };
    assert!(*complete);
    assert_eq!(
        elements
            .values()
            .map(|v| match v {
                ShellScalarValue::RuntimeProduced { value, .. } => value.as_str(),
                _ => panic!("{v:?}"),
            })
            .collect::<Vec<_>>(),
        ["", "x", "", "y"]
    );
}

#[test]
fn unknown_ifs_unmodeled_modes_and_budgets_do_not_produce_values() {
    assert!(read("read line", None, b"x\n").is_none());
    for command in [
        "read -t1 line",
        "read -u3 line",
        "read -n1 line",
        "read -N2 line",
        "read -e line",
    ] {
        assert!(read(command, Some(""), b"ab\n").is_none(), "{command}");
    }
    assert!(read("read -r line", Some(""), &vec![b'x'; 8193]).is_none());
}

#[test]
fn input_binding_metadata_requires_a_variable_binding_effect() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: fixture}\nforms:\n  - id: main\n    effects:\n      - kind: write_path\n        target: {kind: none}\n        runtime_input_binding: shell_read\n";
    assert!(load_command_profile_from_str(source).is_err());
}
