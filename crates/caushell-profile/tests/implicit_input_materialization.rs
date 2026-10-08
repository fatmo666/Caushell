//! Source classification only; no sample program is executed.
use caushell_parse::{SourceSpan, parse_command};
use caushell_profile::*;
use caushell_types::{RuntimeArgumentDomain, RuntimeInputSource, ShellKind};

fn sources() -> [ImplicitInputSource; 5] {
    [
        ImplicitInputSource::StdinPayload,
        ImplicitInputSource::StdinData,
        ImplicitInputSource::InteractiveSession,
        ImplicitInputSource::DispatchOutput,
        ImplicitInputSource::InheritedEnvironment,
    ]
}

fn candidate(source: ImplicitInputSource) -> RecursivePayloadCandidate {
    RecursivePayloadCandidate {
        language: PayloadLanguage::Sh,
        source: PayloadSource::InlineString,
        origin: RecursivePayloadOrigin::Parameter {
            slot: SlotName::new("program"),
        },
        input: RecursivePayloadInput::ImplicitInput {
            source,
            domain: Some(RuntimeArgumentDomain::PathSet {
                roots: vec!["/workspace".into()],
                may_escape: false,
            }),
        },
    }
}

#[test]
fn all_implicit_sources_keep_their_identity_and_domain() {
    for source in sources() {
        let input = candidate(source);
        let value = materialize_recursive_payload_candidate(&input, &SessionBindings::new());
        assert_eq!(value.candidate, input);
        match (value.resolution, source.to_runtime_input_source()) {
            (ValueMaterialization::RequiresRuntimeInput { source: actual, .. }, Some(expected)) => {
                assert_eq!(actual, expected);
            }
            (ValueMaterialization::RequiresImplicitInput { source: actual }, None) => {
                assert_eq!(actual, source);
            }
            other => panic!("source {source:?}: {other:?}"),
        }
    }
}

#[test]
fn parse_results_carry_typed_sources_without_trying_to_parse_unknown_bytes() {
    for source in sources() {
        let input = candidate(source);
        match (
            parse_recursive_payload_candidate(&input),
            source.to_runtime_input_source(),
        ) {
            (
                RecursivePayloadParseResult::RequiresRuntimeInput {
                    candidate,
                    source: actual,
                },
                Some(expected),
            ) => {
                assert_eq!(actual, expected);
                assert_eq!(candidate, input);
            }
            (
                RecursivePayloadParseResult::RequiresImplicitInput {
                    candidate,
                    source: actual,
                },
                None,
            ) => {
                assert_eq!(actual, source);
                assert_eq!(candidate, input);
            }
            other => panic!("source {source:?}: {other:?}"),
        }
    }
}

#[test]
fn projected_unknown_arguments_are_not_misrepresented_as_static_empty_strings() {
    let parsed = parse_command("fixture argument", ShellKind::Bash).unwrap();
    for source in sources() {
        let mut projection =
            project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let domain = Some(RuntimeArgumentDomain::PathSet {
            roots: vec!["/workspace".into()],
            may_escape: false,
        });
        projection.args[0].text.clear();
        projection.args[0].implicit_input_source =
            Some(source.to_caushell_types_implicit_input_source());
        projection.args[0].runtime_argument_domain = domain.clone();
        let value = materialize_projected_invocation(&projection, &SessionBindings::new());
        assert_eq!(
            value.invocation.args[0].implicit_input_source,
            projection.args[0].implicit_input_source
        );
        assert_eq!(value.invocation.args[0].runtime_argument_domain, domain);
        assert_eq!(
            value.arg_resolutions,
            vec![ValueMaterialization::requires_implicit_input(source)]
        );
        assert!(!value.invocation.args[0].runtime_data);
    }
}

#[test]
fn opaque_program_boundary_is_preserved_for_every_input_source() {
    for source in sources() {
        let mut input = candidate(source);
        input.language = PayloadLanguage::Opaque;
        assert!(matches!(
            parse_recursive_payload_candidate(&input),
            RecursivePayloadParseResult::UnsupportedLanguage { .. }
        ));
    }
}

#[test]
fn runtime_binding_keeps_capture_and_origin_with_narrow_source_type() {
    let mut bindings = SessionBindings::new();
    bindings.insert_runtime_input(
        "PROGRAM",
        RuntimeInputSource::StdinData,
        caushell_types::RuntimeInputCapture::NotCaptured,
    );
    let input = RecursivePayloadCandidate {
        input: RecursivePayloadInput::ArgumentFragments {
            fragments: vec![RecursivePayloadArgumentFragment {
                text: "$PROGRAM".into(),
                quoted: true,
                node_kind: "string".into(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: 8,
                    start_row: 0,
                    start_column: 0,
                    end_row: 0,
                    end_column: 8,
                },
                materialization: RecursivePayloadFragmentMaterialization::Literal,
            }],
        },
        ..candidate(ImplicitInputSource::StdinData)
    };
    let value = materialize_recursive_payload_candidate(&input, &bindings);
    assert!(matches!(
        value.resolution,
        ValueMaterialization::RequiresRuntimeInput {
            source: RuntimeInputSource::StdinData,
            variable_name: Some(_),
            origin: Some(_),
            capture: Some(_)
        }
    ));
}
