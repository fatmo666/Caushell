use caushell_profile::load_command_profile_from_str;

#[test]
fn namespace_contract_is_opt_in_and_exclusive_to_single_file_writes() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: materializer}\nforms:\n  - id: emit\n    parameters:\n      - {name: destination, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}\n    effects:\n      - {kind: write_path, namespace_effect: regular_file_write, target: {kind: slot, name: destination}}\n";
    let p = load_command_profile_from_str(source).unwrap();
    assert!(p.forms[0].effects[0].namespace_effect.is_some());
    let old = load_command_profile_from_str(
        &source.replace("namespace_effect: regular_file_write, ", ""),
    )
    .unwrap();
    assert!(old.forms[0].effects[0].namespace_effect.is_none());
    for invalid in [
        source.replace(
            "kind: write_path, namespace_effect:",
            "kind: read_path, namespace_effect:",
        ),
        source.replace(
            "kind: write_path, namespace_effect:",
            "kind: delete_path, namespace_effect:",
        ),
        source.replace("regular_file_write", "arbitrary_write"),
        source.replace(
            "target: {kind: slot, name: destination}",
            "target: {kind: none}",
        ),
        source.replace(
            "namespace_effect: regular_file_write,",
            "namespace_effect: regular_file_write, path_scope: {kind: subtree},",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn exact_option_words_own_declared_equals_operands_without_short_flag_confusion() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: driver}\noption_scope: permuted_options\noption_matching: exact_names\nopaque_on_unresolved: true\nforms: [{id: run}]\nmodifiers:\n  - {id: diagnostics, matcher: {kind: any_flag, flags: [-Warnings]}}\n  - id: loader\n    matcher: {kind: any_flag, flags: [-loader]}\n    parameters: [{name: library, semantic: {kind: in_process_code_load, load_kind: library_path}, binding: {kind: following_matched_flag, operand_mode: inline_or_short_attached}, cardinality: required_one}]\n    effects: [{kind: load_in_process_code, target: {kind: slot, name: library}}]\n";
    let registry = caushell_profile::ProfileRegistry::from_profiles(vec![
        load_command_profile_from_str(source).unwrap(),
    ])
    .unwrap();
    let parsed = caushell_parse::parse_command(
        "driver -Warnings -loader=/outside/lib.so",
        caushell_types::ShellKind::Bash,
    )
    .unwrap();
    let caushell_profile::ResolveInvocationArtifactResult::Resolved(r) =
        caushell_profile::resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            caushell_profile::InvocationRuntimeContext::new(),
            &caushell_profile::SessionBindings::new(),
        )
    else {
        panic!("exact word projection failed")
    };
    assert!(!r.bound.operation_semantics_unresolved, "{r:#?}");
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == caushell_profile::EffectKind::LoadInProcessCode)
    );
    let parameter = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "library")
        .unwrap();
    assert!(
        matches!(&parameter.values[0], caushell_profile::BoundValue::Argument { text, .. } if text == "/outside/lib.so")
    );
}
