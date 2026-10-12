//! Command-independent compiler/binder checks for opt-in native semantics.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const CONDITIONAL: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: archive-demo}
forms:
  - id: run
    parameters:
      - name: archive
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          branches:
            - {unless_modifier: local, matcher: {kind: regex_capture, pattern: '^.*:.*$', group: 0}, target: {name: remote, semantic: {kind: endpoint, endpoint_kind: remote_spec, usage: generic_endpoint}}}
          fallback: {name: file, semantic: {kind: path, role: read, purpose: generic_operand}}
modifiers: [{id: local, matcher: {kind: any_flag, flags: [--local]}}]
"#;

fn bind(yaml: &str, command: &str) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()]).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) else {
        panic!("{command}");
    };
    r.bound
}

#[test]
fn conditional_projection_respects_override_even_for_unknown_input() {
    for (command, remote) in [
        ("archive-demo host:file", true),
        ("archive-demo --local host:file", false),
        ("archive-demo --local \"$ARCHIVE\"", false),
    ] {
        let b = bind(CONDITIONAL, command);
        assert_eq!(
            b.bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "remote"),
            remote,
            "{b:#?}"
        );
        assert_eq!(
            b.bound_parameters.iter().any(|p| p.name.as_str() == "file"),
            !remote,
            "{b:#?}"
        );
    }
    assert!(
        load_command_profile_from_str(
            &CONDITIONAL.replace("unless_modifier: local", "unless_modifier: typo")
        )
        .is_err()
    );
}

#[test]
fn multipart_declaration_is_opt_in_and_keeps_malformed_input_unresolved() {
    let yaml = CONDITIONAL.replace("identity: {canonical_name: archive-demo}", "identity: {canonical_name: form-demo}")
        .replace("branches:\n            - {unless_modifier: local, matcher: {kind: regex_capture, pattern: '^.*:.*$', group: 0}, target: {name: remote, semantic: {kind: endpoint, endpoint_kind: remote_spec, usage: generic_endpoint}}}\n          fallback: {name: file, semantic: {kind: path, role: read, purpose: generic_operand}}",
            "native_syntax: curl_multipart\n          branches:\n            - {matcher: {kind: prefix, value: 'file:'}, target: {name: file, semantic: {kind: path, role: read, purpose: generic_operand}}}");
    let b = bind(&yaml, "form-demo 'f=@a,b;filename=not-a-file'");
    let file = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "file")
        .unwrap();
    assert_eq!(
        file.semantic_values()
            .filter_map(|v| match v {
                SemanticValueRef::Projected { value, .. } => Some(value.resolution.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![
            SemanticValueResolution::Known("a".into()),
            SemanticValueResolution::Known("b".into())
        ]
    );
    let b = bind(&yaml, "form-demo 'f=@\"unfinished'");
    assert!(b.operation_semantics_unresolved);
    for extra in ["separator: ','", "first_match_only: true"] {
        assert!(
            load_command_profile_from_str(&yaml.replace(
                "native_syntax: curl_multipart",
                &format!("native_syntax: curl_multipart\n          {extra}")
            ))
            .is_err()
        );
    }
}

#[test]
fn directory_prefix_requires_declared_source_and_root() {
    let base = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: writer-demo}
forms:
  - id: run
    parameters:
      - {name: name, semantic: {kind: plain_value}, binding: {kind: next_positional}, cardinality: required_one}
      - {name: directory, semantic: {kind: path, role: target}, binding: {kind: next_positional}, cardinality: required_one}
    effects: [{kind: write_path, path_access: content_open, target: {kind: derived_path, source: {kind: slot, name: name}, root: {kind: slot, name: directory}, rule: {kind: prefix_directory}}}]
"#;
    load_command_profile_from_str(base).unwrap();
    assert!(
        load_command_profile_from_str(&base.replace("root: {kind: slot, name: directory}, ", ""))
            .is_err()
    );
    assert!(
        load_command_profile_from_str(&base.replace(
            "root: {kind: slot, name: directory}",
            "root: {kind: slot, name: absent}"
        ))
        .is_err()
    );
}
