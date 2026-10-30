use caushell_parse::{ParsedCommandArtifact, parse_command};
use caushell_types::ShellKind;
fn conditions(source: &str, producer: &str, consumer: &str) -> Vec<bool> {
    let p = parse_command(source, ShellKind::Bash).unwrap();
    at(
        &p,
        source.find(producer).unwrap(),
        source.find(consumer).unwrap(),
    )
}
fn at(p: &ParsedCommandArtifact, producer: usize, consumer: usize) -> Vec<bool> {
    p.status_conditions
        .iter()
        .filter(|c| {
            c.command_span.start_byte == producer
                && c.guarded_region.start_byte <= consumer
                && consumer < c.guarded_region.end_byte
        })
        .map(|c| c.success)
        .collect()
}
#[test]
fn compound_guards_cover_every_body_position_but_not_the_following_statement() {
    for compound in [
        "for n in 1 2; do first=$(printf a); second=$(printf b); done",
        "{ first=$(printf a); second=$(printf b); }",
    ] {
        let source = format!("cd work && printf start && {compound}; final=$(printf z)");
        assert!(conditions(&source, "cd work", "first=").contains(&true));
        assert!(conditions(&source, "cd work", "second=").contains(&true));
        assert!(conditions(&source, "cd work", "final=").is_empty());
    }
}
#[test]
fn failure_regions_and_condition_arms_keep_their_status() {
    assert_eq!(
        conditions("cd work || { first=x; second=y; }", "cd work", "second="),
        vec![false]
    );
    let s = "if cd work; then first=x; second=y; else third=z; fi; last=q";
    assert_eq!(conditions(s, "cd work", "second="), vec![true]);
    assert_eq!(conditions(s, "cd work", "third="), vec![false]);
    assert!(conditions(s, "cd work", "last=").is_empty());
    assert!(conditions("cd work; second=y", "cd work", "second=").is_empty());
    assert!(conditions("cd work && printf x || second=y", "cd work", "second=").is_empty());
}
#[test]
fn nested_frames_partial_syntax_and_unknown_negation_do_not_fabricate_status() {
    for s in [
        "value=$(cd work && printf x)",
        "f(){ cd work && printf x; }",
        "cd work && printf 'unterminated",
        "! cd work || printf x",
    ] {
        assert!(conditions(s, "cd work", "printf").is_empty(), "{s}");
    }
    let s = "(cd work && { first=x; second=y; })";
    let p = parse_command(s, ShellKind::Bash).unwrap();
    assert!(
        p.status_conditions
            .iter()
            .any(|c| c.shell_scope_span.is_some())
    );
}
