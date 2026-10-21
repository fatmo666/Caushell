use caushell_parse::*;
use caushell_types::ShellKind;

#[test]
fn executable_positions_belong_to_the_enclosing_statement() {
    let parsed = parse_command("a=(1 2); echo $((a[0]+1)) ${a[x]}", ShellKind::Bash).unwrap();
    assert_eq!(parsed.shell_evaluations.len(), 2);
    for site in &parsed.shell_evaluations {
        assert_eq!(site.top_level_span, parsed.commands[0].top_level_span);
    }
    let parsed = parse_command(
        "echo 'a[$(touch /opt/out)]'; f() { echo $((x)); }",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(parsed.shell_evaluations.is_empty());
}

#[test]
fn arithmetic_assignment_keeps_its_lvalue_semantics() {
    let refs = parse_arithmetic_references("x=2").unwrap();
    assert!(
        matches!(&refs[..], [ArithmeticReference::Assignment { name, reads_previous: false, value }] if name == "x" && value.is_empty())
    );
    let refs = parse_arithmetic_references("a[0]=2").unwrap();
    assert!(
        matches!(&refs[..], [ArithmeticReference::Array { name, index, read_value: false }] if name == "a" && index == "0")
    );
    assert!(parse_arithmetic_references(&"1".repeat(8193)).is_none());
    assert!(parse_arithmetic_references("1)); touch /opt/out; ((1").is_none());
    let incomplete = parse_command("echo $((x$(printf 1)y))", ShellKind::Bash).unwrap();
    assert!(
        incomplete
            .shell_evaluations
            .iter()
            .any(|s| s.kind == ShellEvaluationKind::UnresolvedArithmetic)
    );
}

#[test]
fn array_literal_query_does_not_expand_elements() {
    assert_eq!(
        static_array_entry_values("([x]=1 ['y']=-2 [\"z\"]=0)").unwrap(),
        vec!["1", "-2", "0"]
    );
    assert!(static_array_entry_values("([x]=$unknown)").is_none());
    assert!(static_array_entry_values("([x]=$(printf 1))").is_none());
    assert!(static_array_entry_values("([$(printf x)]=1)").is_none());
    assert!(static_array_entry_values("([x]=1); echo nope").is_none());
    assert_eq!(
        static_array_values("(1 'b[$(touch /opt/out)]')").unwrap(),
        vec!["1", "b[$(touch /opt/out)]"]
    );
    assert!(static_array_values("($unknown)").is_none());
    assert!(static_array_values("(1); echo nope").is_none());
}

#[test]
fn builtin_words_and_nested_arithmetic_keep_their_grammar() {
    let parsed = parse_command("unset array[2] array[$RANDOM%4]", ShellKind::Bash).unwrap();
    assert_eq!(parsed.shell_evaluations.len(), 2);
    assert_eq!(parsed.shell_evaluations[0].input.text, "array[2]");
    assert_eq!(parsed.shell_evaluations[1].input.text, "array[$RANDOM%4]");
    assert!(
        matches!(parse_arithmetic_references("$((i+1))").unwrap().as_slice(), [ArithmeticReference::ArithmeticExpansion(s)] if s == "i+1")
    );
    assert!(matches!(
        parse_arithmetic_references("$(printf 1)")
            .unwrap()
            .as_slice(),
        [ArithmeticReference::CommandSubstitution(_)]
    ));
    assert!(
        exhaustive_case_assignment_values("case x in x) n=1;; *) n=2;; esac; echo end", "n", 40)
            .is_some()
    );
    assert!(
        exhaustive_case_assignment_values("case x in x) n=1;; esac; echo end", "n", 40).is_none()
    );
}

#[test]
fn assignment_dominance_is_local_to_the_statement_list() {
    for (source, expected) in [
        ("for x in a; do local n=1; echo $((n)); done", true),
        (
            "for x in a; do if test x; then local n=1; fi; echo $((n)); done",
            false,
        ),
        ("for x in a; do local n=1; done; echo $((n))", false),
        (
            "for x in a; do test x && local n=1; echo $((n)); done",
            false,
        ),
        ("for x in a; do local n=1; local result=$((n)); done", true),
    ] {
        assert_eq!(
            assignment_dominates_use(
                source,
                source.find("local n=").unwrap(),
                source.find("$((n))").unwrap()
            ),
            expected,
            "{source}"
        );
    }
}

#[test]
fn arithmetic_word_fallback_and_loop_initializers_do_not_invent_commands() {
    assert!(matches!(
        parse_arithmetic_references("$(printf 1)0")
            .unwrap()
            .as_slice(),
        [ArithmeticReference::ExpandedWord { .. }]
    ));
    assert!(parse_arithmetic_references("1)); touch /opt/out; ((1").is_none());
    let p = parse_command(
        "for ((i=${#a}-2;i>=0;i--)); do echo ${a[i]}; done",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(p.shell_evaluations[0].numeric_locals.is_empty());
    assert!(
        p.shell_evaluations[1]
            .numeric_locals
            .iter()
            .any(|n| n == "i")
    );
    let p = parse_command("[[ foo =~ ^(f)(oo)$ ]]", ShellKind::Bash).unwrap();
    assert_eq!(
        p.commands[0]
            .tokens
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>(),
        ["foo", "=~", "^(f)(oo)$", "]]"]
    );
}
