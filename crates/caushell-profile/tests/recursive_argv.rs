//! Shell strings are analysed, never executed by these tests.
use std::sync::OnceLock;

use caushell_parse::{SourceSpan, parse_command};
use caushell_profile::{
    InvocationRuntimeContext, MaterializedRecursivePayloadCandidate, PayloadLanguage,
    PayloadSource, ProfileRegistry, RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
    RecursivePayloadFragmentMaterialization, RecursivePayloadInput, RecursivePayloadOrigin,
    ResolveInvocationResult, SessionBindings, ValueMaterialization,
    collect_recursive_payload_candidates, joined_recursive_payload_text,
    materialize_recursive_payload_candidate, resolve_invocation_with_bindings,
};
use caushell_types::{RuntimeProducedValueKind, ShellKind};

fn candidate(argument: &str, bindings: &SessionBindings) -> RecursivePayloadCandidate {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let source = format!("bash -c {argument}");
    let parsed = parse_command(&source, ShellKind::Bash).unwrap();
    let bound = match resolve_invocation_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        other => panic!("{source}: {other:?}"),
    };
    collect_recursive_payload_candidates(&bound).remove(0)
}

fn fragments(candidate: &RecursivePayloadCandidate) -> &[RecursivePayloadArgumentFragment] {
    match &candidate.input {
        RecursivePayloadInput::ArgumentFragments { fragments } => fragments,
        other => panic!("{other:?}"),
    }
}

fn text(materialized: &MaterializedRecursivePayloadCandidate) -> String {
    joined_recursive_payload_text(fragments(&materialized.candidate))
}

#[test]
fn double_quoted_script_becomes_true_argv_with_original_source_metadata() {
    let bindings = SessionBindings::new();
    let raw = candidate(r#""TARGET=/etc/outside; rm -f \"\$TARGET\"""#, &bindings);
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), r#"TARGET=/etc/outside; rm -f "$TARGET""#);
    assert_eq!(decoded.resolution, ValueMaterialization::Static);
    assert_eq!(
        fragments(&decoded.candidate)[0].span,
        fragments(&raw)[0].span
    );
    assert_eq!(fragments(&decoded.candidate)[0].node_kind, "string");
    assert!(fragments(&decoded.candidate)[0].quoted);
    assert_eq!(
        fragments(&decoded.candidate)[0].materialization,
        RecursivePayloadFragmentMaterialization::DecodedLiteral
    );
    // The collected source candidate is not rewritten in place.
    assert!(fragments(&raw)[0].text.contains(r#"\"\$TARGET\""#));
}

#[test]
fn decoded_literal_is_idempotent_even_if_outer_binding_now_exists() {
    let bindings = SessionBindings::new().with_exact_scalar("TARGET", "incorrect outer value");
    let raw = candidate(r#""rm -f \"\$TARGET\"""#, &bindings);
    let first = materialize_recursive_payload_candidate(&raw, &bindings);
    let second = materialize_recursive_payload_candidate(&first.candidate, &bindings);
    assert_eq!(first, second);
    assert_eq!(text(&second), r#"rm -f "$TARGET""#);
}

#[test]
fn two_escape_layers_are_not_collapsed_into_one() {
    let bindings = SessionBindings::new();
    let raw = candidate(r#""rm -f \"\\\$TARGET\"""#, &bindings);
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), r#"rm -f "\$TARGET""#);
    assert_eq!(
        decoded,
        materialize_recursive_payload_candidate(&decoded.candidate, &bindings)
    );
}

#[test]
fn static_quote_concatenation_decodes_shell_segments_not_the_child_program() {
    let bindings = SessionBindings::new();
    let raw = candidate(r#"'printf '\''%s'\'' "$TARGET"'"#, &bindings);
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), r#"printf '%s' "$TARGET""#);
    assert_eq!(decoded.resolution, ValueMaterialization::Static);
}

#[test]
fn known_scalar_payload_is_not_expanded_or_unescaped_twice() {
    let script = r#"printf '%s' '\$OTHER'; rm -f "$INNER""#;
    let bindings = SessionBindings::new()
        .with_exact_scalar("SCRIPT", script)
        .with_exact_scalar("OTHER", "bad outer replacement");
    let raw = candidate(r#""$SCRIPT""#, &bindings);
    let first = materialize_recursive_payload_candidate(&raw, &bindings);
    let second = materialize_recursive_payload_candidate(&first.candidate, &bindings);
    assert_eq!(text(&first), script);
    assert_eq!(first, second);
    assert!(matches!(
        first.resolution,
        ValueMaterialization::ResolvedExactScalar { .. }
    ));
}

#[test]
fn single_and_ansi_c_quoted_values_are_already_decoded() {
    let bindings = SessionBindings::new().with_exact_scalar("OTHER", "incorrect outer value");
    for argument in [r#"'printf "$OTHER" \q'"#, r#"$'printf "$OTHER" \\q'"#] {
        let raw = candidate(argument, &bindings);
        let value = fragments(&raw)[0].text.clone();
        let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
        assert_eq!(text(&decoded), value);
        assert_eq!(decoded.resolution, ValueMaterialization::Static);
        assert_eq!(
            decoded,
            materialize_recursive_payload_candidate(&decoded.candidate, &bindings)
        );
    }
}

#[test]
fn line_continuation_is_removed_but_other_quoted_backslashes_are_preserved() {
    let bindings = SessionBindings::new();
    let raw = candidate("\"printf '%s' \\q\\\nend\"", &bindings);
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), "printf '%s' \\qend");
}

#[test]
fn dynamic_or_uncompleted_argv_does_not_accept_a_static_prefix() {
    let bindings = SessionBindings::new().with_exact_scalar("KNOWN", "suffix");
    for argument in [
        r#""echo $UNKNOWN""#,
        r#""echo $KNOWN""#,
        "prefix*.sh",
        "~user/script",
    ] {
        let raw = candidate(argument, &bindings);
        let value = fragments(&raw)[0].text.clone();
        let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
        assert!(matches!(
            decoded.resolution,
            ValueMaterialization::UnsupportedDynamicText { .. }
                | ValueMaterialization::MissingBinding { .. }
        ));
        assert_eq!(text(&decoded), value);
        assert_eq!(
            fragments(&decoded.candidate)[0].materialization,
            RecursivePayloadFragmentMaterialization::Literal
        );
    }
}

#[test]
fn runtime_argv_data_is_not_treated_as_outer_shell_source() {
    let bindings = SessionBindings::new().with_exact_scalar("OTHER", "incorrect outer value");
    let mut raw = candidate("'literal'", &bindings);
    if let RecursivePayloadInput::ArgumentFragments { fragments } = &mut raw.input {
        fragments[0].text = r#"printf '%s' '\$OTHER'"#.into();
        fragments[0].materialization = RecursivePayloadFragmentMaterialization::RuntimeData;
        fragments[0].node_kind = "string".into();
    }
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(decoded.candidate, raw);
    assert_eq!(decoded.resolution, ValueMaterialization::Static);
}

#[test]
fn lost_runtime_origin_stays_unknown_without_reinterpreting_argv_data() {
    let mut raw = candidate("'literal'", &SessionBindings::new());
    if let RecursivePayloadInput::ArgumentFragments { fragments } = &mut raw.input {
        fragments[0].text = "$OTHER".into();
        fragments[0].materialization =
            RecursivePayloadFragmentMaterialization::ResolvedRuntimeProduced {
                variable_name: "SCRIPT".into(),
            };
    }
    let bindings = SessionBindings::new().with_exact_scalar("OTHER", "wrong script");
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), "$OTHER");
    assert!(matches!(
        decoded.resolution,
        ValueMaterialization::UnsupportedDynamicBinding { .. }
    ));
    let mut known = bindings;
    known.insert_runtime_produced(
        "SCRIPT",
        "unrelated latest value",
        RuntimeProducedValueKind::Path,
    );
    let decoded = materialize_recursive_payload_candidate(&raw, &known);
    assert_eq!(text(&decoded), "$OTHER");
    assert!(matches!(
        decoded.resolution,
        ValueMaterialization::ResolvedRuntimeProduced { .. }
    ));
}

#[test]
fn literal_script_and_implicit_stdin_keep_their_existing_distinct_contracts() {
    let literal = RecursivePayloadCandidate {
        language: PayloadLanguage::Bash,
        source: PayloadSource::Stdin,
        origin: RecursivePayloadOrigin::FormImplicitInput,
        input: RecursivePayloadInput::LiteralText {
            text: r#"rm -f "\$TARGET""#.into(),
        },
    };
    let decoded = materialize_recursive_payload_candidate(&literal, &SessionBindings::new());
    assert_eq!(decoded.candidate, literal);
    assert_eq!(decoded.resolution, ValueMaterialization::Static);
    let implicit = RecursivePayloadCandidate {
        input: RecursivePayloadInput::ImplicitInput {
            source: caushell_profile::ImplicitInputSource::StdinPayload,
            domain: None,
        },
        ..literal
    };
    let decoded = materialize_recursive_payload_candidate(&implicit, &SessionBindings::new());
    assert_eq!(decoded.candidate, implicit);
    assert!(matches!(
        decoded.resolution,
        ValueMaterialization::RequiresRuntimeInput { .. }
    ));
}

#[test]
fn joined_argument_fragments_decode_each_outer_operand_once() {
    let bindings = SessionBindings::new();
    let mut raw = candidate("'first'", &bindings);
    if let RecursivePayloadInput::ArgumentFragments { fragments } = &mut raw.input {
        fragments[0] = RecursivePayloadArgumentFragment {
            text: r#"echo \"one\""#.into(),
            quoted: true,
            node_kind: "string".into(),
            span: SourceSpan {
                start_byte: 1,
                end_byte: 12,
                start_row: 0,
                start_column: 1,
                end_row: 0,
                end_column: 12,
            },
            materialization: RecursivePayloadFragmentMaterialization::Literal,
        };
        fragments.push(RecursivePayloadArgumentFragment {
            text: "&& pwd".into(),
            ..fragments[0].clone()
        });
    }
    let decoded = materialize_recursive_payload_candidate(&raw, &bindings);
    assert_eq!(text(&decoded), "echo \"one\" && pwd");
    assert_eq!(
        decoded,
        materialize_recursive_payload_candidate(&decoded.candidate, &bindings)
    );
}
