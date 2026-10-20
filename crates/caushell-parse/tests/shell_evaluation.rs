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
}

#[test]
fn array_literal_query_does_not_expand_elements() {
    assert_eq!(
        static_array_values("(1 'b[$(touch /opt/out)]')").unwrap(),
        vec!["1", "b[$(touch /opt/out)]"]
    );
    assert!(static_array_values("($unknown)").is_none());
    assert!(static_array_values("(1); echo nope").is_none());
}
