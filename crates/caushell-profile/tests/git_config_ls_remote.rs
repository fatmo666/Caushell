use caushell_parse::parse_command;
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, EndpointUsage, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, SemanticType, resolve_invocation,
};
use caushell_types::ShellKind;

#[test]
fn local_config_write_has_config_file_effect() {
    let resolved = resolve("git config --local http.extraHeader 'X-Trace-ID: value'");
    assert_eq!(resolved.form_id, "write_local_config_value");
    assert_eq!(resolved.value.as_deref(), Some("X-Trace-ID: value"));
    assert!(resolved.effects.iter().any(|(kind, target)| {
        *kind == EffectKind::WritePath
            && matches!(target, EffectTarget::ToolConventionPath(path) if path.path == ".git/config")
    }));
}

#[test]
fn local_config_read_does_not_write_config_file() {
    let resolved = resolve("git config --local --get http.extraHeader");
    assert_eq!(resolved.form_id, "inspect_local_config");
    assert!(
        resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::LoadConfig)
    );
    assert!(
        !resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::WritePath)
    );
}

#[test]
fn ls_remote_loads_config_and_fetches_from_explicit_endpoint() {
    let resolved = resolve("git ls-remote http://127.0.0.1:8766/repo.git");
    assert_eq!(resolved.form_id, "inspect_remote_refs");
    assert_eq!(resolved.endpoint_usage, Some(EndpointUsage::FetchSource));
    assert!(
        resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::LoadConfig)
    );
    assert!(
        resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::NetworkEndpoint)
    );
}

#[test]
fn ls_remote_get_url_does_not_create_network_effect() {
    let resolved = resolve("git ls-remote --get-url origin");
    assert_eq!(resolved.form_id, "resolve_remote_url");
    assert!(
        resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::LoadConfig)
    );
    assert!(
        !resolved
            .effects
            .iter()
            .any(|(kind, _)| *kind == EffectKind::NetworkEndpoint)
    );
}

struct ResolvedShape {
    form_id: String,
    value: Option<String>,
    endpoint_usage: Option<EndpointUsage>,
    effects: Vec<(EffectKind, EffectTarget)>,
}

fn resolve(command_line: &str) -> ResolvedShape {
    let registry = ProfileRegistry::built_in().expect("built-in profiles load");
    let artifact = parse_command(command_line, ShellKind::Bash).expect("command parses");
    let command = artifact.commands.first().expect("one command");
    let ResolveInvocationResult::Resolved(resolved) =
        resolve_invocation(&registry, command, InvocationRuntimeContext::new())
    else {
        panic!("{command_line:?} did not resolve");
    };

    let value = resolved
        .bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == "value")
        .and_then(|parameter| parameter.values.first())
        .and_then(|value| match value {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        });
    let endpoint_usage = resolved
        .bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == "repository")
        .and_then(|parameter| match &parameter.semantic {
            SemanticType::Endpoint(semantic) => Some(semantic.usage),
            _ => None,
        });

    ResolvedShape {
        form_id: resolved.selection.form.id.as_str().to_string(),
        value,
        endpoint_usage,
        effects: resolved
            .bound
            .effects
            .iter()
            .map(|effect| (effect.kind, effect.target.clone()))
            .collect(),
    }
}
