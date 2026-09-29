use caushell_parse::parse_command;
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, EndpointUsage, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, SemanticType, resolve_invocation,
};
use caushell_types::ShellKind;

#[test]
fn dig_file_queries_read_file_and_bind_server_port_and_output_option_separately() {
    let resolved = resolve("dig @127.0.0.1 -p 5353 -f cache/queries +short");

    let query_file = parameter_values(&resolved, "query_file");
    assert_eq!(query_file, vec!["cache/queries"]);
    assert_eq!(parameter_values(&resolved, "port"), vec!["5353"]);
    assert_eq!(
        parameter_values(&resolved, "query_target"),
        vec!["127.0.0.1"]
    );
    assert_eq!(
        parameter_values(&resolved, "query_names"),
        Vec::<&str>::new()
    );
    assert_eq!(parameter_values(&resolved, "dig_options"), vec!["short"]);
    assert_eq!(
        endpoint_usage(&resolved, "query_target"),
        Some(EndpointUsage::UploadTarget)
    );
    assert!(has_effect(&resolved, EffectKind::ReadPath, "query_file"));
    assert!(has_effect(
        &resolved,
        EffectKind::NetworkEndpoint,
        "query_target"
    ));
}

#[test]
fn dig_explicit_resolver_query_name_options_and_port_bind_separately() {
    let resolved = resolve("dig @resolver.test example.test +short +dnssec -p 5353");

    assert!(parameter_values(&resolved, "query_file").is_empty());
    assert_eq!(parameter_values(&resolved, "port"), vec!["5353"]);
    assert_eq!(
        parameter_values(&resolved, "query_target"),
        vec!["resolver.test"]
    );
    assert_eq!(
        parameter_values(&resolved, "query_names"),
        vec!["example.test"]
    );
    assert_eq!(
        parameter_values(&resolved, "dig_options"),
        vec!["short", "dnssec"]
    );
    assert!(has_effect(
        &resolved,
        EffectKind::NetworkEndpoint,
        "query_target"
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
fn dig_default_resolver_does_not_mislabel_query_name_as_endpoint() {
    let resolved = resolve("dig example.test +short");

    assert_eq!(
        parameter_values(&resolved, "query_names"),
        vec!["example.test"]
    );
    assert!(parameter_values(&resolved, "query_target").is_empty());
    assert!(
        !resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint)
    );
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
        .flat_map(|parameter| parameter.values.iter())
        .filter_map(|value| match value {
            BoundValue::Argument { text, .. } => Some(text.as_str()),
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
