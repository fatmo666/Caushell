use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn bound(text: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(text, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!("unresolved {text}")
    };
    r.bound
}

#[test]
fn native_file_list_option_owns_joined_and_separate_values() {
    for text in ["wc -l --files0-from=list0", "wc --files0-from list0 -l"] {
        let b = bound(text);
        assert_eq!(b.form_id.as_str(), "count_list_file");
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{b:#?}"
        );
        let reads = b
            .effects
            .iter()
            .filter(|e| e.kind == EffectKind::ReadPath)
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 2);
        assert!(reads.iter().any(|e| e.path_list.is_some()));
        assert!(reads.iter().any(|e| e.path_list.is_none()));
        assert!(b.stdout_scalar.is_none());
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataOptional
        );
    }
}
#[test]
fn list_stdin_and_numeric_stdin_have_distinct_output_proofs() {
    let list = bound("wc -l --files0-from=-");
    assert_eq!(list.form_id.as_str(), "count_list_stdin");
    assert!(list.stdout_scalar.is_none());
    assert!(list.effects.iter().any(|e| {
        e.path_list
            .as_ref()
            .is_some_and(|p| p.separator == PathListSeparator::Nul)
            && e.target == EffectTarget::ImplicitInput(ImplicitInputSource::StdinData)
    }));
    assert_eq!(
        bound("wc -l").stdout_scalar,
        Some(StdoutScalarShape::ArithmeticText)
    );
    assert!(
        bound("wc -l -- --files0-from=-")
            .effects
            .iter()
            .all(|e| e.path_list.is_none())
    );
}
#[test]
fn missing_values_mixed_operands_and_unknown_options_do_not_bind_as_counts() {
    let registry = ProfileRegistry::built_in().unwrap();
    for text in [
        "wc --files0-from",
        "wc --files0-from=list0 extra",
        "wc --unknown-control=list0",
    ] {
        let p = parse_command(text, ShellKind::Bash).unwrap();
        let r = resolve_invocation(&registry, &p.commands[0], InvocationRuntimeContext::new());
        assert!(
            !matches!(r, ResolveInvocationResult::Resolved(ref r) if !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty()),
            "{text}: {r:#?}"
        );
    }
}
#[test]
fn file_list_source_must_be_a_read_and_declared_slot() {
    let raw = include_str!("../profiles/wc.yaml");
    let valid = load_raw_command_profile_from_str(raw).unwrap();
    assert!(normalize_command_profile(valid).is_ok());
    for changed in [
        raw.replace("      - {kind: read_path, path_access: content_open, target: {kind: slot, name: list_path}}\n", ""),
        raw.replace("target: {kind: slot, name: list_path}, path_list", "target: {kind: slot, name: undeclared_list}, path_list"),
        raw.replace("kind: read_path, path_access: content_open, target: {kind: slot, name: list_path}, path_list", "kind: write_path, path_access: content_open, target: {kind: slot, name: list_path}, path_list"),
    ] {
        assert!(normalize_command_profile(load_raw_command_profile_from_str(&changed).unwrap()).is_err());
    }
}

#[test]
fn information_mode_does_not_open_operational_list_source() {
    let help = bound("wc --help --files0-from=.env");
    assert!(help.effects.is_empty());
    assert!(
        help.bound_parameters
            .iter()
            .all(|p| p.semantic == SemanticType::PlainValue)
    );
}
