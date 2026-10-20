//! Declarative option ownership; no commands are executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn yaml(trailing: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-tool}}
option_scope: leading_options
trailing_option_words: {trailing}
opaque_on_unresolved: true
forms:
  - id: action
    parameters:
      - {{name: data, semantic: {{kind: plain_value}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}
modifiers:
  - {{id: mode, matcher: {{kind: any_flag, flags: [-p]}}}}
  - {{id: tail_switch, matcher: {{kind: any_flag, flags: [-x]}}}}
  - id: destination
    matcher: {{kind: any_flag, flags: [-d, --destination]}}
    parameters:
      - {{name: destination, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_one}}
"#
    )
}
fn bind(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(profile, &projection).unwrap();
    let bound = bind_invocation(profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    bound
}
fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}
#[test]
fn only_declared_trailing_words_can_be_controls() {
    let p = load_command_profile_from_str(&yaml("[-d, --destination, -x]")).unwrap();
    for command in [
        "arbitrary-tool item -p -d /opt/out -x member",
        "arbitrary-tool item -p -d/opt/out -x member",
        "arbitrary-tool item -p --destination=/opt/out -x member",
    ] {
        let b = bind(&p, command);
        assert_eq!(values(&b, "destination"), ["/opt/out"], "{command}");
        assert_eq!(values(&b, "data"), ["item", "-p", "member"], "{command}");
        assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "mode"));
        assert!(
            b.applied_modifiers
                .iter()
                .any(|m| m.as_str() == "tail_switch")
        );
    }
    let b = bind(&p, "arbitrary-tool item -pd/opt/out -xp");
    assert!(b.applied_modifiers.is_empty());
    assert_eq!(values(&b, "data"), ["item", "-pd/opt/out", "-xp"]);
}
#[test]
fn leading_clusters_operands_and_real_terminator_keep_their_ownership() {
    let p = load_command_profile_from_str(&yaml("[-d, --destination, -x]")).unwrap();
    let b = bind(&p, "arbitrary-tool -pd/opt/out item -p");
    assert_eq!(values(&b, "destination"), ["/opt/out"]);
    assert_eq!(values(&b, "data"), ["item", "-p"]);
    assert!(b.applied_modifiers.iter().any(|m| m.as_str() == "mode"));
    let b = bind(&p, "arbitrary-tool item -- -d /opt/out");
    assert!(b.applied_modifiers.is_empty());
    assert_eq!(values(&b, "data"), ["item", "-d", "/opt/out"]);
    let b = bind(&p, "arbitrary-tool item -d -p");
    assert_eq!(values(&b, "destination"), ["-p"]);
    assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "mode"));
}
#[test]
fn absent_declaration_preserves_existing_leading_grammar() {
    let p = load_command_profile_from_str(&yaml("[]")).unwrap();
    let b = bind(&p, "arbitrary-tool -p item -d out");
    assert_eq!(values(&b, "data"), ["item", "-d", "out"]);
    assert_eq!(values(&b, "destination"), Vec::<String>::new());
    assert_eq!(b.applied_modifiers.len(), 1);
}
#[test]
fn exact_word_precedence_cannot_expand_the_trailing_vocabulary() {
    let body = yaml("[-d]")
        .replace(
            "opaque_on_unresolved: true",
            "opaque_on_unresolved: true\nexact_option_words: [-dump]",
        )
        .replace(
            "  - {id: mode,",
            "  - {id: dumping, matcher: {kind: any_flag, flags: [-dump]}}\n  - {id: mode,",
        );
    let p = load_command_profile_from_str(&body).unwrap();
    let b = bind(&p, "arbitrary-tool item -dump");
    assert!(b.applied_modifiers.is_empty());
    assert_eq!(values(&b, "data"), ["item", "-dump"]);
}
#[test]
fn malformed_declarations_and_missing_operands_are_not_accepted() {
    for body in [
        yaml("[-missing]"),
        yaml("[-d, -d]"),
        yaml("[-d]").replace("leading_options", "permuted_options"),
        yaml("[-d]").replace("leading_options", "all_arguments"),
    ] {
        assert!(load_command_profile_from_str(&body).is_err());
    }
    let p = load_command_profile_from_str(&yaml("[-d]")).unwrap();
    for command in ["arbitrary-tool -unknown item", "arbitrary-tool item -d"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            select_invocation(
                &p,
                &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
            )
            .is_err()
        );
    }
}
