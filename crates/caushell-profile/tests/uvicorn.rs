use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => {
            assert!(
                resolved.bound.residuals.is_empty(),
                "{command}: {:?}",
                resolved.bound.residuals
            );
            resolved.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn common_cli_options_have_correct_arity_without_stealing_app() {
    let bound = resolve(
        "uvicorn --host 0.0.0.0 --port 8000 --reload --reload-dir src --reload-include '*.py' --reload-exclude cache --reload-delay 0.25 --workers 2 --loop asyncio --http h11 --ws auto --lifespan auto --interface asgi3 --env-file .env --log-config log.yaml --log-level info --no-access-log --no-use-colors --proxy-headers --forwarded-allow-ips '*' --root-path /api --limit-concurrency 32 --backlog 128 --limit-max-requests 100 --timeout-keep-alive 5 --timeout-graceful-shutdown 10 --timeout-worker-healthcheck 5 --ssl-keyfile key.pem --ssl-certfile cert.pem --ssl-ca-certs ca.pem --ssl-keyfile-password secret --ssl-version 17 --ssl-cert-reqs 0 --ssl-ciphers TLSv1 --header X-Test:yes --app-dir src --h11-max-incomplete-event-size 1000 --factory app:create_app",
    );
    let app = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "app")
        .unwrap();
    assert!(
        matches!(&app.values[0], BoundValue::Argument { text, .. } if text == "app:create_app")
    );
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ListenNetwork)
    );
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
}

#[test]
fn websocket_and_paired_boolean_options_are_bound() {
    resolve(
        "uvicorn app:app --http2 --ws-max-size 100 --ws-max-queue 10 --ws-ping-interval 20 --ws-ping-timeout 20 --ws-per-message-deflate true --access-log --use-colors --no-proxy-headers --server-header --no-server-header --date-header --no-date-header --limit-max-requests-jitter 10 --reset-contextvars",
    );
}

#[test]
fn uds_and_fd_do_not_drop_cleanup_effects() {
    let bound = resolve("uvicorn app:app --uds=/etc/app.sock --fd=3 --workers=2");
    for kind in [
        EffectKind::ListenNetwork,
        EffectKind::WritePath,
        EffectKind::DeletePath,
    ] {
        assert!(bound.effects.iter().any(|e| e.kind == kind));
    }
}

#[test]
fn help_and_version_do_not_start_servers() {
    for command in [
        "uvicorn --help",
        "uvicorn --version",
        "/usr/bin/uvicorn --help",
    ] {
        assert!(resolve(command).effects.is_empty());
    }
}

#[test]
fn python_module_dispatch_is_declarative_and_keeps_child_arguments() {
    let bound = resolve("python3 -m uvicorn app:app --host=0.0.0.0");
    let candidates = collect_dispatch_command_candidates(&bound);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].command.text, "uvicorn");
    assert_eq!(candidates[0].argv.len(), 2);
}

#[test]
fn listener_schema_rejects_wrong_kind_and_undeclared_sources() {
    let profile = include_str!("../profiles/uvicorn.yaml");
    assert!(
        load_command_profile_from_str(
            &profile.replace("kind: listen_network", "kind: network_endpoint")
        )
        .is_err()
    );
    assert!(
        load_command_profile_from_str(
            &profile.replace("slot: host, environment", "slot: missing, environment")
        )
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&profile.replace("name: UVICORN_HOST", "name: 'BAD-NAME'"))
            .is_err()
    );
}

#[test]
fn module_load_from_environment_is_not_silently_lost() {
    let bound = resolve("uvicorn");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}

#[test]
fn dispatch_environment_declarations_are_validated_at_load_time() {
    let profile = include_str!("../profiles/env.yaml");
    assert!(
        load_command_profile_from_str(&profile.replace(
            "clear_environment_when: [ignore_environment]",
            "clear_environment_when: [typo]"
        ))
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&profile.replace(
            "unset_environment: [unset_names]",
            "unset_environment: [typo]"
        ))
        .is_err()
    );
}
