use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

fn known(command: &str) -> BoundInvocation {
    let bound = resolve(command);
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    bound
}

fn parameter<'a>(bound: &'a BoundInvocation, name: &str) -> &'a BoundParameter {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .unwrap()
}

fn unknown_endpoint(parameter: &BoundParameter) {
    assert!(matches!(parameter.semantic, SemanticType::Endpoint(_)));
    assert!(!parameter.values.is_empty());
    assert!(
        parameter.semantic_values().all(|v| matches!(
            v,
            SemanticValueRef::Projected {
                value: ProjectedSemanticValue {
                    resolution: SemanticValueResolution::Unknown(_),
                    ..
                },
                ..
            }
        )),
        "{parameter:#?}"
    );
}

#[test]
fn dns_query_words_and_resolver_addresses_have_distinct_roles() {
    let bound = known("dig @127.0.0.1 -p 5353 example.test TXT +short");
    let resolver = parameter(&bound, "resolver_servers");
    assert!(resolver.semantic_values().any(|v| matches!(v,
        SemanticValueRef::Projected { value: ProjectedSemanticValue { resolution: SemanticValueResolution::Known(value), .. }, .. } if value == "127.0.0.1"
    )));
    unknown_endpoint(parameter(&bound, "query_names"));
    unknown_endpoint(parameter(&bound, "query_options"));
    assert!(parameter(&bound, "query_names").values.iter().all(|value|
        matches!(project_value(&ValueProjection::Identity, value), Some(SemanticValueResolution::Known(text)) if text == "example.test" || text == "TXT")
    ));
    assert!(matches!(
        bound.stream_contract.unwrap().stdin_mode,
        StreamInputMode::DeclaredEffects
    ));
}

#[test]
fn batch_files_keep_real_reads_and_unknown_query_destinations() {
    for command in [
        "dig -f queries.txt",
        "dig -fqueries.txt +short",
        "dig TXT -f queries.txt @127.0.0.1",
    ] {
        let bound = known(command);
        unknown_endpoint(parameter(&bound, "batch_source"));
        let files = parameter(&bound, "batch_files");
        assert!(files.semantic_values().any(|v| matches!(v,
            SemanticValueRef::Projected { value: ProjectedSemanticValue { resolution: SemanticValueResolution::Known(path), .. }, .. } if path == "queries.txt"
        )));
        assert!(parameter(&bound, "batch_stdin").semantic_values_are_inapplicable());
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    }
}

#[test]
fn batch_dash_is_stdin_not_a_file_or_address() {
    let bound = known("dig +short -f -");
    assert!(parameter(&bound, "batch_files").semantic_values_are_inapplicable());
    assert!(!parameter(&bound, "batch_stdin").semantic_values_are_inapplicable());
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
    unknown_endpoint(parameter(&bound, "batch_source"));
}

#[test]
fn repeated_batch_and_key_options_only_open_the_last_file() {
    let bound = known("dig -f ignored-list -f queries.txt -k ignored-key -k key.conf");
    for (slot, expected) in [
        ("batch_files", "queries.txt"),
        ("signing_key_file", "key.conf"),
    ] {
        let values: Vec<_> = parameter(&bound, slot).semantic_values().collect();
        assert_eq!(values.len(), 1, "{bound:#?}");
        assert!(
            matches!(&values[0], SemanticValueRef::Projected { value: ProjectedSemanticValue { resolution: SemanticValueResolution::Known(value), .. }, .. } if value == expected)
        );
    }
}

#[test]
fn explicit_queries_and_reverse_addresses_are_request_data() {
    for (command, slot) in [
        ("dig -qexample.test -tA", "explicit_query"),
        ("dig -x127.0.0.1", "reverse_query"),
    ] {
        unknown_endpoint(parameter(&known(command), slot));
    }
}

#[test]
fn signing_and_tls_files_are_auxiliary_not_query_inputs() {
    let bound = known(
        "dig -k key.conf +tls-ca=ca.pem +tls-certfile=cert.pem +tls-keyfile=key.pem example.test",
    );
    assert!(bound.is_auxiliary_input_slot("signing_key_file"));
    assert!(bound.is_auxiliary_input_slot("tls_files"));
    assert_eq!(parameter(&bound, "tls_files").values.len(), 3);
    for effect in &bound.effects {
        if let Some(scope) = &effect.input_scope {
            assert!(
                !scope
                    .slots
                    .iter()
                    .any(|s| s == "signing_key_file" || s == "tls_files")
            );
        }
    }
}

#[test]
fn help_and_version_do_not_read_or_send_batch_data() {
    for command in [
        "dig -h",
        "dig -v",
        "dig -h -f .env -k .env +tls-keyfile=.env",
    ] {
        let bound = known(command);
        assert_eq!(bound.form_id.as_str(), "information");
        assert!(bound.effects.is_empty(), "{command}: {bound:#?}");
    }
    let bound = known("dig -f -h");
    assert_eq!(bound.form_id.as_str(), "dns_query");
}
