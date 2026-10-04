//! Index matching sees original argv, not consumed/filtered positionals.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile(index: usize, matcher: ValueMatcher) -> CommandProfile {
    let mut p = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: indexed-tool}
option_scope: permuted_options
forms:
  - id: matched
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
  - id: fallback
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - {id: flag, matcher: {kind: any_flag, flags: [--first, --second]}}
  - id: value
    matcher: {kind: any_flag, flags: [--value]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#).unwrap();
    let predicate =
        SelectorExpr::Predicate(SelectorPredicate::HasArgumentAtMatching(index, matcher));
    p.forms[0].selector = predicate.clone();
    p.forms[1].selector = SelectorExpr::Not(Box::new(predicate));
    p
}
fn projection(c: &str) -> ProjectedInvocation {
    let parsed = parse_command(c, ShellKind::Bash).unwrap();
    project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
}
fn selected(p: &CommandProfile, c: &str) -> String {
    select_invocation(p, &projection(c))
        .unwrap()
        .form
        .id
        .as_str()
        .into()
}
#[test]
fn raw_normalization_uses_existing_value_matcher_validation() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary}
forms:
  - id: match
    selector: {kind: has_argument_at_matching, index: 2, matcher: {kind: literal, value: known}}
"#;
    assert_eq!(
        load_command_profile_from_str(yaml).unwrap().forms[0].selector,
        SelectorExpr::Predicate(SelectorPredicate::HasArgumentAtMatching(
            2,
            ValueMatcher::Literal("known".into())
        ))
    );
    assert!(
        load_command_profile_from_str(&yaml.replace(
            "kind: literal, value: known",
            "kind: regex_pattern, pattern: '['"
        ))
        .is_err()
    );
}
#[test]
fn original_option_indices_exclude_executable_and_survive_consumption() {
    let p = profile(1, ValueMatcher::Literal("--second".into()));
    assert_eq!(
        selected(&p, "indexed-tool --first --second value"),
        "matched"
    );
    assert_eq!(
        selected(&p, "indexed-tool --second --first value"),
        "fallback"
    );
}
#[test]
fn required_operands_are_not_reindexed_or_mistaken_for_flags() {
    let p = profile(1, ValueMatcher::Literal("--second".into()));
    assert_eq!(
        selected(&p, "indexed-tool --value --second --first"),
        "matched"
    );
    let p = profile(2, ValueMatcher::Literal("--first".into()));
    assert_eq!(
        selected(&p, "indexed-tool --value --second --first"),
        "matched"
    );
}
#[test]
fn quoted_escaped_and_concatenated_known_words_share_semantic_value() {
    let p = profile(0, ValueMatcher::Literal("known".into()));
    for c in [
        "indexed-tool 'known'",
        "indexed-tool \"known\"",
        "indexed-tool kn'own'",
        "indexed-tool k\\nown",
    ] {
        assert_eq!(selected(&p, c), "matched", "{c}");
    }
}
#[test]
fn terminator_is_an_original_argument_and_later_data_keeps_its_index() {
    let p = profile(0, ValueMatcher::Literal("--".into()));
    assert_eq!(selected(&p, "indexed-tool -- --first"), "matched");
    let p = profile(1, ValueMatcher::Literal("--first".into()));
    assert_eq!(selected(&p, "indexed-tool -- --first"), "matched");
}
#[test]
fn absent_or_out_of_range_indices_do_not_match_or_allocate_to_index() {
    for index in [0, 1, usize::MAX] {
        let p = profile(index, ValueMatcher::RegexPattern("(?s).*".into()));
        assert_eq!(selected(&p, "indexed-tool"), "fallback");
    }
}
#[test]
fn empty_literal_is_known_data_not_absence() {
    let p = profile(0, ValueMatcher::Literal(String::new()));
    assert_eq!(selected(&p, "indexed-tool ''"), "matched");
    assert_eq!(selected(&p, "indexed-tool"), "fallback");
}
#[test]
fn dynamic_word_is_not_guessed_from_its_static_prefix() {
    let p = profile(0, ValueMatcher::RegexPattern("^known".into()));
    assert_eq!(selected(&p, "indexed-tool \"known$UNKNOWN\""), "fallback");
    assert_eq!(selected(&p, "indexed-tool known$UNKNOWN"), "fallback");
}
#[test]
fn runtime_argv_data_is_not_reexpanded_or_unquoted() {
    for text in ["$UNKNOWN", "'literal'", "a\\b"] {
        let p = profile(0, ValueMatcher::Literal(text.into()));
        let mut projected = projection("indexed-tool value");
        projected.args[0].text = text.into();
        projected.args[0].runtime_data = true;
        assert_eq!(
            select_invocation(&p, &projected).unwrap().form.id.as_str(),
            "matched"
        );
    }
}
#[test]
fn unknown_runtime_source_is_not_a_literal_placeholder() {
    let p = profile(0, ValueMatcher::Literal("value".into()));
    let mut projected = projection("indexed-tool value");
    projected.args[0].implicit_input_source =
        Some(caushell_types::ImplicitInputSource::StdinPayload);
    assert_eq!(
        select_invocation(&p, &projected).unwrap().form.id.as_str(),
        "fallback"
    );
}
#[test]
fn remaining_selector_still_refers_to_original_consumed_argument() {
    let mut p = profile(0, ValueMatcher::Literal("--first".into()));
    p.forms.remove(1);
    p.forms[0].selector = SelectorExpr::new();
    p.forms[0].remaining_selector = SelectorExpr::Predicate(
        SelectorPredicate::HasArgumentAtMatching(1, ValueMatcher::Literal("data".into())),
    );
    assert_eq!(selected(&p, "indexed-tool --first data"), "matched");
}
#[test]
fn direct_shape_api_explicitly_accepts_known_indexed_values() {
    let p = profile(
        0,
        ValueMatcher::AsciiCaseInsensitiveLiterals(vec!["FIRST".into()]),
    );
    assert_eq!(
        select_form(&p, &InvocationShape::new().with_argument_at(0, "first"))
            .unwrap()
            .id
            .as_str(),
        "matched"
    );
    assert_eq!(
        select_form(&p, &InvocationShape::new().with_positional_arg("first"))
            .unwrap()
            .id
            .as_str(),
        "fallback"
    );
}

#[test]
fn subcommand_selectors_keep_absolute_original_tool_argv_indices() {
    let mut p = profile(1, ValueMatcher::Literal("run".into()));
    p.option_scope = OptionScopePolicy::LeadingOptions;
    p.subcommands = Some(SubcommandTree {
        roots: vec![SubcommandNode {
            name: "run".into(),
            aliases: vec![],
            forms: p.forms.clone(),
            modifiers: p.modifiers.clone(),
            option_scope: OptionScopePolicy::PermutedOptions,
            option_matching: Default::default(),
            children: vec![],
            default_behavior: None,
            extensions: Default::default(),
        }],
    });
    p.forms.clear();
    assert_eq!(selected(&p, "indexed-tool --first run data"), "matched");
    assert_eq!(selected(&p, "indexed-tool run --first data"), "fallback");
}

#[test]
fn selecting_does_not_rewrite_argv_or_source_metadata() {
    let p = profile(1, ValueMatcher::Literal("known".into()));
    let projected = projection("indexed-tool --first 'known'");
    let original = projected.clone();
    assert_eq!(
        select_invocation(&p, &projected).unwrap().form.id.as_str(),
        "matched"
    );
    assert_eq!(projected, original);
}
