//! Opt-in tool grammar contracts. All programs below are static input only.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const KEYWORDS: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: keyword-fixture}
option_scope: leading_options
forms:
  - id: command
modifiers:
  - id: option
    matcher: {kind: any_flag, flags: [-o]}
    parameters:
      - name: options
        semantic: {kind: plain_value}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        cardinality: optional_many
        structured_projection:
          first_match_only: true
          branches:
            - matcher: {kind: keyword_value, keyword: Runner, case_insensitive: true, disabled_values: [none], unresolved_markers: ['%']}
              target: {name: program, semantic: {kind: plain_value}}
    effects:
      - {kind: dispatch_command, target: {kind: dispatch, command_string: {slot: program, syntax: posix_shell}}}
"#;

const OPAQUE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: opaque-fixture}
forms:
  - id: executable_input
    parameters:
      - name: program
        semantic: {kind: payload, language: opaque, source: inline_string, recursive: true}
        binding: {kind: remaining_args}
        cardinality: required_many
    effects:
      - {kind: execute_payload, target: {kind: slot, name: program}}
"#;

fn bind(yaml: &str, command: &str, bindings: &SessionBindings) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()]).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{other:?}"),
    }
}

fn projection(yaml: &str, command: &str) -> DispatchCommandProjection {
    collect_dispatch_command_projection(&bind(yaml, command, &SessionBindings::new()))
}

#[test]
fn keyword_boundaries_case_separators_and_shell_body_are_exact() {
    for value in [
        "Runner=printf 'a=b'; rm /opt/file",
        "runner printf 'a=b'; rm /opt/file",
        "  RUNNER \t= = printf 'a=b'; rm /opt/file",
    ] {
        let command = format!("keyword-fixture -o \"{}\"", value.replace('"', "\\\""));
        let p = projection(KEYWORDS, &command);
        assert!(p.unresolved.is_empty(), "{command}: {p:?}");
        assert_eq!(p.resolved.len(), 1, "{command}");
        assert_eq!(p.resolved[0].command.text, "/bin/sh");
        assert_eq!(p.resolved[0].argv[1].text, "printf 'a=b'; rm /opt/file");
        assert!(!p.resolved[0].stdout_to_parent);
    }
    for value in [
        "RunnerExtra=rm /opt/file",
        "Other=Runner rm /opt/file",
        "éRunner=rm /opt/file",
    ] {
        let p = projection(KEYWORDS, &format!("keyword-fixture -o '{value}'"));
        assert!(
            p.resolved.is_empty() && p.unresolved.is_empty(),
            "{value}: {p:?}"
        );
    }
}

#[test]
fn disabled_and_unknown_first_matches_do_not_fall_through_to_later_values() {
    for c in [
        "keyword-fixture -o 'Runner=none' -o 'Runner=rm /opt/file'",
        "keyword-fixture -o 'Other=on' -o 'Runner NONE' -o 'Runner=rm /opt/file'",
    ] {
        let p = projection(KEYWORDS, c);
        assert!(
            p.resolved.is_empty() && p.unresolved.is_empty(),
            "{c}: {p:?}"
        );
    }
    for c in [
        "keyword-fixture -o 'Runner' -o 'Runner=rm /opt/file'",
        "keyword-fixture -o 'Runner=echo %h' -o 'Runner=rm /opt/file'",
        "keyword-fixture -o \"$OPTIONS\" -o 'Runner=rm /opt/file'",
        "keyword-fixture -o 'Runner='",
        "keyword-fixture -o",
    ] {
        let p = projection(KEYWORDS, c);
        assert!(p.resolved.is_empty(), "{c}: {p:?}");
        assert_eq!(p.unresolved.len(), 1, "{c}: {p:?}");
    }
}

#[test]
fn first_match_stops_only_after_matching_and_default_keeps_all_values() {
    let c = "keyword-fixture -o 'Other=on' -o 'Runner=printf FIRST' -o 'Runner=printf SECOND'";
    let p = projection(KEYWORDS, c);
    assert_eq!(p.resolved.len(), 1);
    assert_eq!(p.resolved[0].argv[1].text, "printf FIRST");
    let p = projection(
        &KEYWORDS.replace("first_match_only: true", "first_match_only: false"),
        c,
    );
    assert_eq!(p.resolved.len(), 2);
    assert_eq!(p.resolved[1].argv[1].text, "printf SECOND");
}

#[test]
fn case_sensitive_declarations_and_disabled_values_do_not_fold() {
    let yaml = KEYWORDS.replace("case_insensitive: true", "case_insensitive: false");
    assert!(
        projection(&yaml, "keyword-fixture -o 'runner=echo SAFE'")
            .resolved
            .is_empty()
    );
    assert!(
        projection(&yaml, "keyword-fixture -o 'Runner=none'")
            .resolved
            .is_empty()
    );
    assert_eq!(
        projection(&yaml, "keyword-fixture -o 'Runner=NONE'").resolved[0].argv[1].text,
        "NONE"
    );
    // Trailing spaces are part of the tool's command, not a disabled sentinel.
    assert_eq!(
        projection(KEYWORDS, "keyword-fixture -o 'Runner=none '")
            .resolved
            .len(),
        1
    );
}

#[test]
fn quoted_keyword_is_opt_in_and_does_not_decode_the_shell_body() {
    let yaml = KEYWORDS.replace(
        "case_insensitive: true",
        "case_insensitive: true, allow_quoted_keyword: true",
    );
    for value in ["\"Runner\"=printf 'a b'", "Ru\"nner\" printf 'a b'"] {
        let c = format!("keyword-fixture -o '{}'", value.replace("'a b'", "\"a b\""));
        let p = projection(&yaml, &c);
        assert_eq!(p.resolved[0].argv[1].text, "printf \"a b\"");
        assert!(projection(KEYWORDS, &c).resolved.is_empty());
    }
    assert!(
        projection(&yaml, "keyword-fixture -o '\"Runner\"=none'")
            .resolved
            .is_empty()
    );
    assert!(
        projection(&yaml, "keyword-fixture -o '\"Other\"=rm /opt/file'")
            .resolved
            .is_empty()
    );
}

#[test]
fn original_option_and_span_are_retained_and_outer_materialization_is_not_repeated() {
    let c = "keyword-fixture -o 'Runner=echo $INNER'";
    let b = bind(
        KEYWORDS,
        c,
        &SessionBindings::new().with_exact_scalar("INNER", "/opt/outer"),
    );
    let before = b.clone();
    let p = collect_dispatch_command_projection(&b);
    assert_eq!(b, before);
    let source = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "options")
        .unwrap();
    let generated = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "program")
        .unwrap();
    assert_eq!(source.values, generated.values);
    assert_eq!(p.resolved[0].argv[1].text, "echo $INNER");
    let c = "keyword-fixture -o \"$OPTION\"";
    let b = bind(
        KEYWORDS,
        c,
        &SessionBindings::new().with_exact_scalar("OPTION", "Runner=printf DATA"),
    );
    assert_eq!(
        collect_dispatch_command_projection(&b).resolved[0].argv[1].text,
        "printf DATA"
    );
}

#[test]
fn first_match_also_applies_to_declared_item_separators() {
    let yaml = KEYWORDS.replace(
        "first_match_only: true",
        "separator: ';'\n          first_match_only: true",
    );
    let p = projection(
        &yaml,
        "keyword-fixture -o 'Other=on;Runner=echo FIRST;Runner=echo SECOND'",
    );
    assert_eq!(p.resolved.len(), 1);
    assert_eq!(p.resolved[0].argv[1].text, "echo FIRST");
}

#[test]
fn malformed_new_declarations_are_rejected_at_load_time() {
    for yaml in [
        KEYWORDS.replace("keyword: Runner", "keyword: ''"),
        KEYWORDS.replace("keyword: Runner", "keyword: 'Bad Key'"),
        KEYWORDS.replace("keyword: Runner", "keyword: 'Bad=Key'"),
        KEYWORDS.replace("unresolved_markers: ['%']", "unresolved_markers: ['']"),
        KEYWORDS.replace("disabled_values: [none]", "disabled_values: ['']"),
        KEYWORDS.replace("first_match_only: true", "first_match_only: invalid"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
    let duplicated = KEYWORDS.replace("              target: {name: program", "            - matcher: {kind: keyword_value, keyword: RUNNER, case_insensitive: true}\n              target: {name: program");
    assert!(load_command_profile_from_str(&duplicated).is_err());
}

#[test]
fn opaque_inline_code_is_not_parsed_as_shell_even_if_it_looks_like_shell() {
    for c in [
        "opaque-fixture 'rm /opt/file'",
        "opaque-fixture 'system(\"/bin/sh\")'",
        "opaque-fixture ''",
        "opaque-fixture \"$CODE\"",
    ] {
        let b = bind(OPAQUE, c, &SessionBindings::new());
        let candidates = collect_recursive_payload_candidates(&b);
        assert_eq!(candidates.len(), 1, "{c}: {b:?}");
        assert_eq!(candidates[0].language, PayloadLanguage::Opaque);
        assert!(matches!(
            parse_recursive_payload_candidate(&candidates[0]),
            RecursivePayloadParseResult::UnsupportedLanguage { .. }
        ));
    }
}

#[test]
fn opaque_stdin_is_unsupported_code_not_a_provenance_only_runtime_gap() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: opaque-fixture}
forms:
  - id: run
    implicit_inputs:
      - {source: stdin_payload, semantic: {kind: payload, language: opaque, source: stdin, recursive: true}}
    effects:
      - {kind: execute_payload, target: {kind: implicit_input, source: stdin_payload}}
"#;
    let b = bind(yaml, "opaque-fixture", &SessionBindings::new());
    let c = collect_recursive_payload_candidates(&b);
    assert_eq!(c.len(), 1);
    assert!(matches!(
        parse_recursive_payload_candidate(&c[0]),
        RecursivePayloadParseResult::UnsupportedLanguage { .. }
    ));
    let ordinary = yaml.replace("language: opaque", "language: sh");
    let b = bind(&ordinary, "opaque-fixture", &SessionBindings::new());
    assert!(matches!(
        parse_recursive_payload_candidate(&collect_recursive_payload_candidates(&b)[0]),
        RecursivePayloadParseResult::RequiresRuntimeInput { .. }
    ));
}

#[test]
fn script_reference_binds_once_and_retains_a_separate_declared_path_view() {
    let yaml = OPAQUE.replace("source: inline_string", "source: script_file_ref").replace("        cardinality: required_many", "        cardinality: required_many\n        structured_projection:\n          branches: [{matcher: {kind: literal, value: '-'}}]\n          fallback: {name: files, semantic: {kind: path, role: read, purpose: script_source}}");
    for path in ["/opt/code", "./code", "-"] {
        let b = bind(
            &yaml,
            &format!("opaque-fixture '{path}'"),
            &SessionBindings::new(),
        );
        assert!(b.residuals.is_empty(), "{b:?}");
        let c = collect_recursive_payload_candidates(&b);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].source, PayloadSource::ScriptFileRef);
        assert!(matches!(
            parse_recursive_payload_candidate(&c[0]),
            RecursivePayloadParseResult::UnsupportedLanguage { .. }
        ));
        assert_eq!(
            b.bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "files"),
            path != "-"
        );
    }
    // Arbitrary executable text must not be projected into paths by this extension.
    assert!(
        load_command_profile_from_str(
            &yaml.replace("source: script_file_ref", "source: inline_string")
        )
        .is_err()
    );
}

#[test]
fn existing_shell_languages_and_undeclared_projection_behavior_are_unchanged() {
    let yaml = OPAQUE.replace("language: opaque", "language: sh");
    let b = bind(&yaml, "opaque-fixture 'echo SAFE'", &SessionBindings::new());
    assert!(matches!(
        parse_recursive_payload_candidate(&collect_recursive_payload_candidates(&b).remove(0)),
        RecursivePayloadParseResult::Parsed(_)
    ));
    let yaml = KEYWORDS.replace("kind: keyword_value, keyword: Runner, case_insensitive: true, disabled_values: [none], unresolved_markers: ['%']", "kind: prefix, value: 'Runner='");
    assert_eq!(
        projection(&yaml, "keyword-fixture -o 'Runner=echo SAFE'").resolved[0].argv[1].text,
        "echo SAFE"
    );
}
