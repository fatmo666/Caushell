use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn wget_list_paths_are_separate_from_unknown_download_addresses() {
    for command in [
        "wget -i urls.txt -O out",
        "wget -iurls.txt -O -",
        "wget --input-file=urls.txt --spider",
        "wget -i urls.txt -O out https://example.test/x",
        "wget -i urls.txt",
        "wget -i urls.txt -P cache",
    ] {
        let bound = resolve(command);
        assert!(
            !bound.operation_semantics_unresolved && bound.residuals.is_empty(),
            "{command}: {bound:#?}"
        );
        let endpoint = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "input_file")
            .unwrap();
        assert!(matches!(endpoint.semantic, SemanticType::Endpoint(_)));
        assert!(endpoint.semantic_values().all(|value| matches!(
            value,
            SemanticValueRef::Projected {
                value: ProjectedSemanticValue {
                    resolution: SemanticValueResolution::Unknown(_),
                    ..
                },
                ..
            }
        )));
        let path = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "input_list_path")
            .unwrap();
        assert!(path.semantic_values().any(|value| matches!(value,
            SemanticValueRef::Projected {value: ProjectedSemanticValue {resolution: SemanticValueResolution::Known(path), ..}, ..} if path == "urls.txt")));
    }
}

#[test]
fn wget_list_stdin_is_not_a_file_named_dash() {
    let bound = resolve("wget -i - -O -");
    assert!(
        bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "input_list_path")
            .unwrap()
            .semantic_values_are_inapplicable()
    );
    assert!(
        !bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "input_list_stdin")
            .unwrap()
            .semantic_values_are_inapplicable()
    );
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
}

#[test]
fn unknown_projection_preserves_raw_source_but_never_its_value() {
    let bound = resolve("wget -i 'http://127.0.0.1/list' -O out");
    let parameter = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "input_file")
        .unwrap();
    let source = &parameter.values[0];
    assert!(matches!(
        project_value(&ValueProjection::Unknown, source),
        Some(SemanticValueResolution::Unknown(_))
    ));
    assert!(
        matches!(project_value(&ValueProjection::Identity, source), Some(SemanticValueResolution::Known(value)) if value == "http://127.0.0.1/list")
    );
}
