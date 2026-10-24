use caushell_profile::{
    ProfileRegistry, execution_frame_requirements, load_command_profile_from_str,
};

fn profile(resource: &str, extra: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-state-client}}
forms:
  - id: change
    parameters:
      - {{name: destination, semantic: {{kind: endpoint, endpoint_kind: url, usage: upload_target}}, binding: {{kind: next_positional}}, cardinality: required_many}}
    effects:
      - {{kind: network_endpoint, target: {{kind: slot, name: destination}}}}
      - kind: state_operation
        state_operation: {{domain: remote_resource, operation: mutate, resource: {resource}}}
        target: {{kind: none}}
        {extra}
"#
    )
}

#[test]
fn resource_binding_is_a_declaration_not_an_authorization() {
    let p = load_command_profile_from_str(&profile(
        "{kind: endpoint, usage: upload_target}",
        "resource_environment_absent: [TRANSFER_PROXY]",
    ))
    .unwrap();
    let requirements = execution_frame_requirements([&p]);
    assert!(requirements.environment_names.contains("TRANSFER_PROXY"));
    assert!(
        p.forms[0].effects[1]
            .state_operation
            .unwrap()
            .resource
            .is_some()
    );
    for extra in [
        "grant: allow",
        "resource_namespace: same_executor",
        "resource_environment_absent: ['BAD-NAME']",
        "resource_unless_modifiers: [undeclared]",
    ] {
        assert!(
            load_command_profile_from_str(&profile(
                "{kind: endpoint, usage: upload_target}",
                extra
            ))
            .is_err()
        );
    }
    for selector in [
        "{kind: endpoint, usage: transport_target}",
        "{kind: endpoint, usage: upload_target, trusted: true}",
    ] {
        assert!(load_command_profile_from_str(&profile(selector, "")).is_err());
    }
}

#[test]
fn builtin_resource_route_inputs_are_part_of_the_executor_plan() {
    let registry = ProfileRegistry::built_in().unwrap();
    let requirements = execution_frame_requirements(registry.profiles());
    for name in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        assert!(requirements.environment_names.contains(name));
    }
}
