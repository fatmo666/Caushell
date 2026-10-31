use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(source: &str, command: &str) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{command}: {other:#?}"),
    }
}
const SOURCE: &str = include_str!("../profiles/pypi-server.yaml");

#[test]
fn renamed_frontends_use_existing_typed_listener_effects_without_core_name_checks() {
    let source = SOURCE.replace(
        "canonical_name: pypi-server",
        "canonical_name: arbitrary_package_frontend",
    );
    for command in [
        "arbitrary_package_frontend",
        "arbitrary_package_frontend run --port 9123 /workspace/packages",
        "arbitrary_package_frontend -H127.0.0.1 /workspace/packages",
    ] {
        let b = resolve(&source, command);
        assert!(!b.operation_semantics_unresolved, "{command}: {b:#?}");
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ListenNetwork && matches!(&e.target,
            EffectTarget::NetworkListener(n) if n.host.slot.as_str() == "host" && n.host.default_value.as_deref() == Some("0.0.0.0") && n.port.as_ref().and_then(|p| p.default_value.as_deref()) == Some("8080"))));
        assert!(
            b.effects
                .iter()
                .all(|e| e.kind != EffectKind::StateOperation)
        );
    }
}

#[test]
fn host_port_and_option_looking_values_keep_native_ownership() {
    for (command, slot, expected) in [
        (
            "pypi-server run -i 127.0.0.1 --port 9123 /workspace/packages",
            "host",
            "127.0.0.1",
        ),
        (
            "pypi-server run -H127.0.0.1 /workspace/packages",
            "host",
            "127.0.0.1",
        ),
        (
            "pypi-server run --interface=::1 /workspace/packages",
            "host",
            "::1",
        ),
        (
            "pypi-server run --host=0.0.0.0 --host=127.0.0.1 /workspace/packages",
            "host",
            "127.0.0.1",
        ),
        (
            "pypi-server run --host=--help /workspace/packages",
            "host",
            "--help",
        ),
        (
            "pypi-server run --log-file=--version /workspace/packages",
            "log_file",
            "--version",
        ),
        ("pypi-server run -p9123 /workspace/packages", "port", "9123"),
    ] {
        let b = resolve(SOURCE, command);
        assert!(!b.operation_semantics_unresolved, "{command}: {b:#?}");
        let p = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == slot)
            .unwrap();
        assert!(
            matches!(p.values.last().unwrap(), BoundValue::Argument { text, .. } if text == expected),
            "{command}: {p:#?}"
        );
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ListenNetwork)
        );
    }
}

#[test]
fn complete_information_suppresses_startup_effects_and_unmodeled_adapters_do_not() {
    for command in [
        "pypi-server --help",
        "pypi-server run --version",
        "pypi-server run --log-file /outside/log --help",
    ] {
        let b = resolve(SOURCE, command);
        assert!(!b.operation_semantics_unresolved, "{command}: {b:#?}");
        assert!(b.effects.is_empty(), "{command}: {:?}", b.effects);
    }
    for command in [
        "pypi-server run --server gunicorn /workspace/packages",
        "pypi-server run --port 65536 /workspace/packages",
        "pypi-server run -a . -P . /workspace/packages",
        "pypi-server -P /workspace/credentials /workspace/packages",
    ] {
        let b = resolve(SOURCE, command);
        assert!(b.operation_semantics_unresolved, "{command}: {b:#?}");
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ListenNetwork),
            "{command}"
        );
    }
}

#[test]
fn module_identity_is_declared_and_invalid_listener_sources_are_rejected() {
    let profile = load_command_profile_from_str(SOURCE).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    assert!(
        registry
            .lookup_module("python", "pypiserver")
            .profile
            .is_some()
    );
    assert!(
        load_command_profile_from_str(
            &SOURCE.replace("host: {slot: host,", "host: {slot: absent_source,")
        )
        .is_err()
    );
    assert!(
        load_command_profile_from_str(
            &SOURCE.replace("kind: listen_network", "kind: network_endpoint")
        )
        .is_err()
    );
}
