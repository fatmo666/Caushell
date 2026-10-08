use caushell_types::{
    ImplicitInputSource, NestedPayloadResolutionKind, ProvenanceMaterializedValueState,
};

#[test]
fn deferred_source_survives_json_round_trip_without_becoming_stdin() {
    for source in [
        ImplicitInputSource::DispatchOutput,
        ImplicitInputSource::InheritedEnvironment,
    ] {
        let state = ProvenanceMaterializedValueState::RequiresImplicitInput { source };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["kind"], "requires_implicit_input");
        assert_eq!(
            serde_json::from_value::<ProvenanceMaterializedValueState>(json).unwrap(),
            state
        );
    }
}

#[test]
fn deferred_nested_resolution_has_a_typed_storage_contract() {
    assert_eq!(
        NestedPayloadResolutionKind::from_storage("requires_implicit_input").unwrap(),
        NestedPayloadResolutionKind::RequiresImplicitInput
    );
    assert_eq!(
        serde_json::to_value(NestedPayloadResolutionKind::RequiresImplicitInput).unwrap(),
        "requires_implicit_input"
    );
    assert_eq!(
        NestedPayloadResolutionKind::from_storage("requires_runtime_input").unwrap(),
        NestedPayloadResolutionKind::RequiresRuntimeInput
    );
}
