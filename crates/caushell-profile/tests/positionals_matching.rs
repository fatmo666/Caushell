//! Opt-in filtering preserves argv; no command name is privileged.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile() -> CommandProfile {
    load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-filter-tool}
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters:
      - {name: files, semantic: {kind: path, role: write}, binding: {kind: positionals_matching, matcher: {kind: regex_pattern, pattern: '^[/.]'}}, cardinality: optional_many}
      - {name: rest, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}
modifiers:
  - {id: flag, matcher: {kind: any_flag, flags: [-x]}}
  - id: value
    matcher: {kind: any_flag, flags: [-v, --value]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#).unwrap()
}
fn bind(p: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(p, &projected).unwrap();
    bind_invocation(p, &projected, &selected)
}
fn clean(p: &CommandProfile, command: &str) -> BoundInvocation {
    let b = bind(p, command);
    assert!(!b.operation_semantics_unresolved, "{command}: {b:?}");
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    b
}
fn slot<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a BoundValue> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .collect()
}
fn values(b: &BoundInvocation, name: &str) -> Vec<String> {
    slot(b, name)
        .into_iter()
        .map(|v| match project_value(&ValueProjection::Identity, v) {
            Some(SemanticValueResolution::Known(s)) => s,
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn normalization_retains_the_declared_matcher() {
    assert_eq!(
        profile().forms[0].parameters[0].binding,
        BindingSpec::PositionalsMatching(ValueMatcher::RegexPattern("^[/.]".into()))
    );
}
#[test]
fn interleaved_matches_keep_full_paths_and_unmatched_order() {
    let b = clean(
        &profile(),
        "arbitrary-filter-tool one /etc/out two ./local ../sibling three",
    );
    assert_eq!(values(&b, "files"), ["/etc/out", "./local", "../sibling"]);
    assert_eq!(values(&b, "rest"), ["one", "two", "three"]);
}
#[test]
fn quoted_and_escaped_paths_match_without_rewriting_the_source() {
    let command = "arbitrary-filter-tool '/etc/out one' \"./local two\" ./escaped\\ space other";
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let b = clean(&profile(), command);
    assert_eq!(
        values(&b, "files"),
        ["/etc/out one", "./local two", "./escaped space"]
    );
    let source = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    for (value, original) in slot(&b, "files").into_iter().zip(&source.args) {
        assert!(
            matches!(value, BoundValue::Argument {text, quoted, node_kind, span, binding_source: ArgumentBindingSource::Positional {kind: PositionalBindingSource::MatchingPositionals}, ..}
            if text == &original.text && quoted == &original.quoted && node_kind == &original.node_kind && span == &original.span)
        );
    }
}
#[test]
fn declared_option_values_are_never_reclassified_as_positionals() {
    let b = clean(
        &profile(),
        "arbitrary-filter-tool one -v /etc/not-output ./output --value=./metadata -x other",
    );
    assert_eq!(values(&b, "files"), ["./output"]);
    assert_eq!(values(&b, "value"), ["/etc/not-output", "./metadata"]);
    assert_eq!(values(&b, "rest"), ["one", "other"]);
}
#[test]
fn delimiter_and_post_delimiter_data_keep_their_cli_roles() {
    let b = clean(
        &profile(),
        "arbitrary-filter-tool ./first -- /etc/last --value=./data -x",
    );
    assert_eq!(values(&b, "files"), ["./first", "/etc/last"]);
    assert_eq!(values(&b, "rest"), ["--value=./data", "-x"]);
    assert!(slot(&b, "value").is_empty());
    assert!(!b.applied_modifiers.contains(&ModifierId::new("flag")));
}
#[test]
fn previously_owned_delimiter_does_not_hide_the_actual_boundary() {
    let b = clean(
        &profile(),
        "arbitrary-filter-tool -v -- ./first -- /etc/last -x",
    );
    assert_eq!(values(&b, "value"), ["--"]);
    assert_eq!(values(&b, "files"), ["./first", "/etc/last"]);
    assert_eq!(values(&b, "rest"), ["-x"]);
}
#[test]
fn empty_optional_matches_and_no_match_are_not_failures() {
    for c in ["arbitrary-filter-tool", "arbitrary-filter-tool one two"] {
        assert!(slot(&clean(&profile(), c), "files").is_empty());
    }
}
#[test]
fn dynamic_arguments_are_not_guessed_from_their_visible_prefix() {
    let b = clean(&profile(), "arbitrary-filter-tool \"./$UNKNOWN\" /known");
    assert_eq!(values(&b, "files"), ["/known"]);
    assert_eq!(slot(&b, "rest").len(), 1);
}
#[test]
fn literal_and_case_insensitive_matchers_share_the_preserving_binding() {
    for matcher in [
        ValueMatcher::Literal("literal".into()),
        ValueMatcher::AsciiCaseInsensitiveLiterals(vec!["LITERAL".into()]),
    ] {
        let mut p = profile();
        p.forms[0].parameters[0].binding = BindingSpec::PositionalsMatching(matcher);
        let b = clean(&p, "arbitrary-filter-tool before 'literal' after");
        assert_eq!(values(&b, "files"), ["literal"]);
        assert_eq!(values(&b, "rest"), ["before", "after"]);
    }
}
#[test]
fn already_decoded_runtime_argv_is_not_expanded_a_second_time() {
    let p = profile();
    let parsed = parse_command("arbitrary-filter-tool placeholder", ShellKind::Bash).unwrap();
    let mut projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    projected.args[0].text = "/literal/$NOT_CODE".into();
    projected.args[0].runtime_data = true;
    let selected = select_invocation(&p, &projected).unwrap();
    let b = bind_invocation(&p, &projected, &selected);
    assert_eq!(values(&b, "files"), ["/literal/$NOT_CODE"]);
    assert!(matches!(
        slot(&b, "files")[0],
        BoundValue::Argument {
            materialization: BoundArgumentMaterialization::RuntimeData,
            ..
        }
    ));
}
#[test]
fn required_cardinality_and_rejected_unconsumed_values_remain_visible() {
    let mut p = profile();
    p.forms[0].parameters.truncate(1);
    p.forms[0].parameters[0].cardinality = Cardinality::RequiredMany;
    p.forms[0].parameters[0]
        .value_constraints
        .push(ValueConstraint::ExcludeLiteral("./reject".into()));
    for c in ["arbitrary-filter-tool", "arbitrary-filter-tool './reject'"] {
        let b = bind(&p, c);
        assert!(b.operation_semantics_unresolved);
        assert!(!b.residuals.is_empty());
    }
}
#[test]
fn malformed_patterns_are_rejected_during_profile_loading() {
    assert!(load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-filter-tool}
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: positionals_matching, matcher: {kind: regex_pattern, pattern: '['}}}]
"#).is_err());
}
#[test]
fn old_prefix_payload_extraction_is_unchanged() {
    let mut p = profile();
    p.forms[0].parameters[0].binding = BindingSpec::ArgsWithPrefix("/".into());
    let b = clean(&p, "arbitrary-filter-tool /etc/out");
    assert_eq!(values(&b, "files"), ["etc/out"]);
}
