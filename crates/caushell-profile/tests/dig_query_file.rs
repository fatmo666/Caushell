use caushell_parse::parse_command;
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, EndpointUsage, InvocationRuntimeContext, ProfileRegistry,
    ProjectedSemanticValue, ResolveInvocationResult, SemanticType, SemanticValueRef,
    SemanticValueResolution, resolve_invocation,
};
use caushell_types::ShellKind;

#[test]
fn dig_file_queries_read_file_and_bind_server_port_and_output_option_separately() {
    let resolved = resolve("dig @127.0.0.1 -p 5353 -f cache/queries +short");

    let query_file = parameter_values(&resolved, "batch_files");
    assert_eq!(query_file, vec!["cache/queries"]);
    assert_eq!(parameter_values(&resolved, "settings"), vec!["5353"]);
    assert_eq!(
        parameter_values(&resolved, "resolver_servers"),
        vec!["127.0.0.1"]
    );
    assert_eq!(
        parameter_values(&resolved, "query_names"),
        Vec::<&str>::new()
    );
    assert_eq!(parameter_values(&resolved, "query_options"), vec!["+short"]);
    assert_eq!(
        endpoint_usage(&resolved, "resolver_servers"),
        Some(EndpointUsage::TransportTarget)
    );
    assert!(has_effect(&resolved, EffectKind::ReadPath, "batch_files"));
    assert!(has_effect(
        &resolved,
        EffectKind::NetworkEndpoint,
        "resolver_servers"
    ));
}

#[test]
fn dig_explicit_resolver_query_name_options_and_port_bind_separately() {
    let resolved = resolve("dig @resolver.test example.test +short +dnssec -p 5353");

    assert!(parameter_values(&resolved, "batch_files").is_empty());
    assert_eq!(parameter_values(&resolved, "settings"), vec!["5353"]);
    assert_eq!(
        parameter_values(&resolved, "resolver_servers"),
        vec!["resolver.test"]
    );
    assert_eq!(
        parameter_values(&resolved, "query_names"),
        vec!["example.test"]
    );
    assert_eq!(
        parameter_values(&resolved, "query_options"),
        vec!["+short", "+dnssec"]
    );
    assert!(has_effect(
        &resolved,
        EffectKind::NetworkEndpoint,
        "resolver_servers"
    ));
    assert!(
        !resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
}

#[test]
fn dig_default_resolver_keeps_query_destination_unknown() {
    let resolved = resolve("dig example.test +short");

    assert_eq!(
        parameter_values(&resolved, "query_names"),
        vec!["example.test"]
    );
    assert!(parameter_values(&resolved, "resolver_servers").is_empty());
    assert!(
        !resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint
                && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == "resolver_servers"))
    );
    assert!(has_effect(
        &resolved,
        EffectKind::NetworkEndpoint,
        "query_names"
    ));
    let query = resolved
        .bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == "query_names")
        .unwrap();
    assert!(query.semantic_values().all(|value| matches!(
        value,
        SemanticValueRef::Projected {
            value: ProjectedSemanticValue {
                resolution: SemanticValueResolution::Unknown(_),
                ..
            },
            ..
        }
    )));
    assert!(
        !resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
}

struct Resolved {
    bound: caushell_profile::BoundInvocation,
}

fn resolve(command_line: &str) -> Resolved {
    let registry = ProfileRegistry::built_in().expect("built-in profiles load");
    let artifact = parse_command(command_line, ShellKind::Bash).expect("command parses");
    let command = artifact.commands.first().expect("one command");
    let ResolveInvocationResult::Resolved(resolved) =
        resolve_invocation(&registry, command, InvocationRuntimeContext::new())
    else {
        panic!("{command_line:?} did not resolve");
    };
    Resolved {
        bound: resolved.bound,
    }
}

fn parameter_values<'a>(resolved: &'a Resolved, name: &str) -> Vec<&'a str> {
    resolved
        .bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == name)
        .into_iter()
        .flat_map(|parameter| parameter.semantic_values())
        .filter_map(|value| match value {
            SemanticValueRef::Projected {
                value:
                    ProjectedSemanticValue {
                        resolution: SemanticValueResolution::Known(text),
                        ..
                    },
                ..
            } => Some(text.as_str()),
            SemanticValueRef::Original(BoundValue::Argument { text, .. })
            | SemanticValueRef::Projected {
                source: BoundValue::Argument { text, .. },
                ..
            } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn endpoint_usage(resolved: &Resolved, name: &str) -> Option<EndpointUsage> {
    resolved
        .bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == name)
        .and_then(|parameter| match &parameter.semantic {
            SemanticType::Endpoint(endpoint) => Some(endpoint.usage),
            _ => None,
        })
}

fn has_effect(resolved: &Resolved, kind: EffectKind, slot: &str) -> bool {
    resolved.bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}
