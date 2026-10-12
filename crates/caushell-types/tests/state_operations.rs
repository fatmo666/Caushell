use caushell_types::{
    ExecutionSemantics, StateOperation, StateOperationDomain, StateOperationKind,
};

#[test]
fn old_semantics_decode_without_new_metadata_and_empty_metadata_is_omitted() {
    let old = ExecutionSemantics::new("read-tool", "run");
    let json = serde_json::to_value(&old).unwrap();
    assert!(json.get("state_operations").is_none());
    let decoded: ExecutionSemantics = serde_json::from_value(json).unwrap();
    assert!(decoded.state_operations.is_empty());
}

#[test]
fn state_metadata_roundtrips_and_rejects_misspelled_fields() {
    let mut semantics = ExecutionSemantics::new("state-tool", "run");
    semantics.state_operations.push(StateOperation {
        domain: StateOperationDomain::CloudResource,
        operation: StateOperationKind::Mutate,
    });
    let json = serde_json::to_value(&semantics).unwrap();
    assert_eq!(json["state_operations"][0]["domain"], "cloud_resource");
    assert_eq!(
        serde_json::from_value::<ExecutionSemantics>(json).unwrap(),
        semantics
    );
    assert!(
        serde_json::from_str::<StateOperation>(
            r#"{"domain":"cloud_resource","operation":"mutate","target":"/workspace"}"#
        )
        .is_err()
    );
}
