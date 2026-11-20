//! Static binding tests. No ping process is created by these tests.
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    resolve_invocation,
};
use caushell_types::ShellKind;

#[test]
fn proven_absence_of_destination_has_no_probe_effect() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["ping", "ping -c 7"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        );
        let ResolveInvocationResult::Resolved(resolved) = result else {
            panic!("{command}: {result:?}");
        };
        assert_eq!(resolved.bound.form_id.as_str(), "missing_destination");
        assert!(!resolved.bound.operation_semantics_unresolved);
        assert!(resolved.bound.effects.is_empty());
    }
}

#[test]
fn known_destination_still_binds_a_network_endpoint() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("ping -c 7 fixture.invalid", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!("known destination did not resolve");
    };
    assert_eq!(resolved.bound.form_id.as_str(), "probe_host");
    assert!(
        resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint)
    );
}

#[test]
fn incomplete_or_symbolic_argv_does_not_certify_absence() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "ping -c",
        "ping -c -7",
        "ping --unmodeled",
        "ping -c \"$COUNT\"",
        "ping -c 7 $DESTINATION",
        "ping -c 7 \"$DESTINATION\"",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        );
        if let ResolveInvocationResult::Resolved(resolved) = result {
            assert_ne!(
                resolved.bound.form_id.as_str(),
                "missing_destination",
                "{command}"
            );
        }
    }
}
