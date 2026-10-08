use caushell_profile::{
    ImplicitInputSource, PayloadLanguage, PayloadSource, RecursivePayloadCandidate,
    RecursivePayloadInput, RecursivePayloadOrigin, SessionBindings,
    materialize_recursive_payload_candidate, parse_recursive_payload_candidate,
};
use caushell_runner::{
    NestedPayloadParentRef, NestedPayloadRecord, NestedPayloadRecordId, NestedPayloadResolution,
};

#[test]
fn normal_constructor_and_unresolved_constructor_agree_for_all_sources() {
    for source in [
        ImplicitInputSource::StdinPayload,
        ImplicitInputSource::StdinData,
        ImplicitInputSource::InteractiveSession,
        ImplicitInputSource::DispatchOutput,
        ImplicitInputSource::InheritedEnvironment,
    ] {
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Sh,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ImplicitInput {
                source,
                domain: None,
            },
        };
        let materialized =
            materialize_recursive_payload_candidate(&candidate, &SessionBindings::new());
        let unresolved = NestedPayloadResolution::from_unresolved_materialization(
            materialized.resolution.clone(),
        );
        let record = NestedPayloadRecord::from_parse_result(
            NestedPayloadRecordId(0),
            NestedPayloadParentRef::RootCommand { command_index: 0 },
            0,
            1,
            SessionBindings::new(),
            materialized,
            parse_recursive_payload_candidate(&candidate),
        );
        assert_eq!(record.resolution, unresolved);
        match (record.resolution, source.to_runtime_input_source()) {
            (NestedPayloadResolution::RequiresRuntimeInput { source: actual }, Some(expected)) => {
                assert_eq!(actual, expected)
            }
            (NestedPayloadResolution::RequiresImplicitInput { source: actual }, None) => {
                assert_eq!(actual, source.to_caushell_types_implicit_input_source())
            }
            other => panic!("{source:?}: {other:?}"),
        }
    }
}
