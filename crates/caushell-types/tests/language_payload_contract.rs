use caushell_types::{NestedPayloadResolutionKind, PythonPayloadEvidence};

#[test]
fn modeled_language_is_distinct_from_a_shell_parse_and_roundtrips() {
    let kind = NestedPayloadResolutionKind::from_storage("modeled_language").unwrap();
    assert_eq!(kind, NestedPayloadResolutionKind::ModeledLanguage);
    assert_eq!(
        serde_json::to_string(&kind).unwrap(),
        "\"modeled_language\""
    );
    assert_eq!(
        serde_json::from_str::<NestedPayloadResolutionKind>("\"parsed\"").unwrap(),
        NestedPayloadResolutionKind::Parsed
    );
    assert!(NestedPayloadResolutionKind::from_storage("invented").is_err());
}
#[test]
fn python_empty_stdout_is_distinct_from_unknown_child_output() {
    let value = PythonPayloadEvidence {
        node_id: "node".into(),
        source: Some("pass".into()),
        cwd: Some("/work".into()),
        complete: false,
        isolated_startup: true,
        imports: vec![],
        inputs: vec![],
        native_argv: vec![],
        shell_commands: vec![],
        stdout: vec![],
        stdout_complete: false,
        gap: Some("unsupported statement".into()),
    };
    let serialized = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        serde_json::from_slice::<PythonPayloadEvidence>(&serialized).unwrap(),
        value
    );
}

#[test]
fn stdout_fields_and_listener_response_routes_roundtrip_without_claiming_a_peer() {
    use caushell_types::{ProvenanceEndpointKind, PythonStdoutFieldEvidence};
    let field = PythonStdoutFieldEvidence {
        node_id: "consumer".into(),
        argument_index: 1,
        expression: "$(producer)".into(),
        stdout: b"$NAME\n\n".to_vec(),
        value: "$NAME".into(),
        inputs: vec![],
    };
    assert_eq!(
        serde_json::from_str::<PythonStdoutFieldEvidence>(&serde_json::to_string(&field).unwrap())
            .unwrap(),
        field
    );
    assert_eq!(
        serde_json::to_string(&ProvenanceEndpointKind::ListenerResponse).unwrap(),
        "\"listener_response\""
    );
    assert_eq!(
        serde_json::from_str::<ProvenanceEndpointKind>("\"host_port\"").unwrap(),
        ProvenanceEndpointKind::HostPort
    );
}
