use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(
    registry: &ProfileRegistry,
    command: &str,
    domain: CommandLookupDomain,
) -> ResolvedInvocationArtifact {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let mut bindings = SessionBindings::new();
    bindings.set_command_lookup_domain(domain);
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &bindings,
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
#[test]
fn native_destinations_share_existing_scalar_target_validation() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (command, names, unresolved) in [
        ("printf -v target '%s' x", vec!["target"], false),
        ("printf -vtarget '%s' x", vec!["target"], false),
        ("printf -v old -v target '%s' x", vec!["target"], false),
        ("printf -v 'a[$(printf MARKER)]' '%s' x", vec![], true),
        ("printf -v \"$target\" '%s' x", vec![], true),
        ("printf \"$format\" x", vec![], true),
        ("printf '%*s%n' 2 x count", vec!["count"], false),
        ("printf '%s%n' a one bb two", vec!["one", "two"], false),
        ("printf '%n' \"$@\"", vec![], true),
        ("printf '%n'", vec![], false),
        ("printf 'operator: $data'", vec![], false),
        ("printf \"operator: $data\"", vec![], false),
        ("printf -- \"$format\"", vec![], false),
        ("printf \"operator: $data\" target", vec![], true),
        ("printf -- '-v %s' x", vec![], false),
        ("printf '%s' -v target", vec![], false),
        ("printf '%%n%s' target", vec![], false),
        ("printf '%(%n)T' 0", vec![], false),
        ("printf '%s' \"$@\"", vec![], false),
    ] {
        let r = resolve(&registry, command, CommandLookupDomain::Shell);
        let writes = runtime_variable_writes(&r.bound);
        assert_eq!(writes.names, names, "{command}: {r:#?}");
        assert_eq!(writes.unresolved, unresolved, "{command}: {r:#?}");
        assert_eq!(
            r.bound.operation_semantics_unresolved, unresolved,
            "{command}: {r:#?}"
        );
        assert!(
            r.bound.bound_implicit_inputs.is_empty(),
            "printf does not read stdin"
        );
    }
}
#[test]
fn declaration_is_name_independent_and_external_calls_never_write_the_shell() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mut profile = registry.lookup("printf").profile.unwrap().clone();
    profile.identity.canonical_name = CommandName::new("fixture_formatter");
    profile.identity.aliases.clear();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    assert!(registry.may_write_runtime_variable("fixture_formatter"));
    for domain in [
        CommandLookupDomain::Shell,
        CommandLookupDomain::Builtin,
        CommandLookupDomain::External,
    ] {
        let r = resolve(&registry, "fixture_formatter -v x '%s' y", domain.clone());
        assert_eq!(
            runtime_variable_writes(&r.bound).names,
            if domain == CommandLookupDomain::External {
                vec![]
            } else {
                vec!["x"]
            }
        );
    }
    let r = resolve(
        &ProfileRegistry::built_in().unwrap(),
        "/usr/bin/printf -v x '%s' y",
        CommandLookupDomain::Shell,
    );
    assert_eq!(
        runtime_variable_writes(&r.bound),
        RuntimeVariableWrites::default()
    );
}

#[test]
fn writer_cannot_claim_a_readonly_contract() {
    let mut raw =
        load_raw_command_profile_from_str(include_str!("../profiles/printf.yaml")).unwrap();
    raw.read_only_control_surface = true;
    assert!(normalize_command_profile(raw).is_err());
}
