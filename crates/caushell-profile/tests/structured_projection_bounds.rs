use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(grammar: &str, operands: &str) -> BoundInvocation {
    let yaml = format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: projection-demo}}\nforms:\n  - id: run\n    parameters:\n      - name: source\n        semantic: {{kind: plain_value}}\n        binding: {{kind: remaining_args}}\n        cardinality: required_many\n        structured_projection: {grammar}\n"
    );
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&yaml).unwrap()])
            .unwrap();
    let parsed = parse_command(&format!("projection-demo {operands}"), ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{operands}: {other:?}"),
    }
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<SemanticValueResolution> {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .unwrap()
        .semantic_values()
        .map(|v| match v {
            SemanticValueRef::Projected { value, .. } => value.resolution.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}

const GRAMMAR: &str = "{branches: [{matcher: {kind: regex_capture, pattern: '(?i)^gophers?://(.+)$', group: 1}, target: {name: upload, semantic: {kind: plain_value}}}, {matcher: {kind: prefix, value: 'exec:'}, target: {name: code, semantic: {kind: plain_value}}}, {matcher: {kind: literal, value: delete}, target: {name: removal, semantic: {kind: plain_value}}}], fallback: {name: other, semantic: {kind: plain_value}}}";

#[test]
fn whole_operand_bounds_exclude_impossible_semantics_without_resolving_the_value() {
    for operand in [
        "\"https://example.test/$UNKNOWN\"",
        "https://example.test/query?q=literal",
        "https://example.test/'fixed'\"$UNKNOWN\"",
    ] {
        let bound = resolve(GRAMMAR, operand);
        for name in ["upload", "code", "removal"] {
            assert!(values(&bound, name).is_empty(), "{operand}: {bound:#?}");
        }
        assert!(
            matches!(
                values(&bound, "other").as_slice(),
                [SemanticValueResolution::Unknown(_)]
            ),
            "{operand}: {bound:#?}"
        );
        let source = &bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "source")
            .unwrap()
            .values;
        let other = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "other")
            .unwrap();
        assert_eq!(&other.values, source);
    }
}

#[test]
fn unquoted_field_splitting_and_quoted_vectors_do_not_inherit_a_first_field_prefix() {
    for operand in [
        "https://example.test/$UNKNOWN",
        "\"https://example.test/$@\"",
        "\"$UNKNOWN\"",
        "",
    ] {
        let bound = resolve(GRAMMAR, operand);
        for name in ["upload", "code", "removal", "other"] {
            assert!(
                matches!(
                    values(&bound, name).as_slice(),
                    [SemanticValueResolution::Unknown(_)]
                ),
                "{operand} {name}: {bound:#?}"
            );
        }
    }
}

#[test]
fn possible_captures_and_stripped_prefixes_remain_unknown() {
    for (operand, name) in [
        ("\"gopher://example.test/$UNKNOWN\"", "upload"),
        ("\"exec:$UNKNOWN\"", "code"),
        ("delet?", "removal"),
    ] {
        let bound = resolve(GRAMMAR, operand);
        assert!(
            matches!(
                values(&bound, name).as_slice(),
                [SemanticValueResolution::Unknown(_)]
            ),
            "{operand}: {bound:#?}"
        );
    }
}

#[test]
fn original_prefix_does_not_constrain_separated_or_native_decoded_items() {
    let separated = GRAMMAR.replacen("{branches:", "{separator: ';', branches:", 1);
    let native = GRAMMAR.replacen("{branches:", "{native_syntax: curl_multipart, branches:", 1);
    for grammar in [&separated, &native] {
        let bound = resolve(grammar, "\"https://example.test/$UNKNOWN\"");
        for name in ["upload", "code", "removal", "other"] {
            assert!(
                matches!(
                    values(&bound, name).as_slice(),
                    [SemanticValueResolution::Unknown(_)]
                ),
                "{name}: {bound:#?}"
            );
        }
    }
}

#[test]
fn uncertain_first_match_does_not_hide_a_later_concrete_match() {
    let grammar = GRAMMAR
        .replacen("{branches:", "{first_match_only: true, branches:", 1)
        .replace(
            ", fallback: {name: other, semantic: {kind: plain_value}}",
            "",
        );
    for first in ["\"$UNKNOWN\"", "\"https://example.test/$UNKNOWN\""] {
        let bound = resolve(&grammar, &format!("{first} exec:danger gopher://later"));
        assert!(
            values(&bound, "code").contains(&SemanticValueResolution::Known("danger".into())),
            "{bound:#?}"
        );
        assert!(
            !values(&bound, "upload")
                .iter()
                .any(|v| matches!(v, SemanticValueResolution::Known(_))),
            "known match must still stop later operands: {bound:#?}"
        );
    }
}

#[test]
fn scalar_fallback_stops_but_a_possibly_absent_field_does_not() {
    let grammar = GRAMMAR.replacen("{branches:", "{first_match_only: true, branches:", 1);
    let bound = resolve(&grammar, "\"https://example.test/$UNKNOWN\" exec:danger");
    assert!(values(&bound, "code").is_empty(), "{bound:#?}");
    for first in ["$UNKNOWN", "https://example.test/?"] {
        let bound = resolve(&grammar, &format!("{first} exec:danger"));
        assert!(
            values(&bound, "code").contains(&SemanticValueResolution::Known("danger".into())),
            "{bound:#?}"
        );
    }
}

#[test]
fn case_uncertain_globs_do_not_rule_out_case_sensitive_regex_branches() {
    let grammar = GRAMMAR.replace("(?i)^gophers?://(.+)$", "^GoPhEr://(.+)$");
    let bound = resolve(&grammar, "gopher://example.test/?");
    assert!(
        matches!(
            values(&bound, "upload").as_slice(),
            [SemanticValueResolution::Unknown(_)]
        ),
        "{bound:#?}"
    );
    let bound = resolve(&grammar, "https://example.test/?");
    assert!(values(&bound, "upload").is_empty(), "{bound:#?}");
    let unicode = GRAMMAR.replace("(?i)^gophers?://(.+)$", "^Kelvin://(.+)$");
    let bound = resolve(&unicode, "kelvin://example.test/?");
    assert!(
        matches!(
            values(&bound, "upload").as_slice(),
            [SemanticValueResolution::Unknown(_)]
        ),
        "{bound:#?}"
    );
}

#[test]
fn unanchored_regexes_are_not_rejected_using_only_a_prefix() {
    for pattern in ["gopher(.+)$", "(?m)^gopher(.+)$", "^(gopher)|https"] {
        let grammar = GRAMMAR.replace("(?i)^gophers?://(.+)$", pattern);
        let bound = resolve(&grammar, "\"https://example.test/$UNKNOWN\"");
        assert!(
            matches!(
                values(&bound, "upload").as_slice(),
                [SemanticValueResolution::Unknown(_)]
            ),
            "{pattern}: {bound:#?}"
        );
    }
}

#[test]
fn concrete_brace_alternatives_keep_their_exact_values() {
    let bound = resolve(GRAMMAR, "https://example.test/{first,second}");
    for name in ["upload", "code", "removal"] {
        assert!(values(&bound, name).is_empty(), "{bound:#?}");
    }
    assert_eq!(
        values(&bound, "other"),
        [
            SemanticValueResolution::Known("https://example.test/first".into()),
            SemanticValueResolution::Known("https://example.test/second".into()),
        ]
    );
}

#[test]
fn impossible_no_effect_branch_does_not_erase_a_possible_fallback() {
    let grammar = "{branches: [{matcher: {kind: prefix, value: 'console:'}, target: null}], fallback: {name: other, semantic: {kind: plain_value}}}";
    let bound = resolve(grammar, "\"write:$UNKNOWN\"");
    assert!(matches!(
        values(&bound, "other").as_slice(),
        [SemanticValueResolution::Unknown(_)]
    ));
}
