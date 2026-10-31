//! Static checks only: never launch a server or open a socket.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/workspace");
    shell.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("pypiserver-listener"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: shell,
        home: Some("/home/tester".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}
fn listener(r: &CheckResponse) -> &NetworkListener {
    r.decision_trace
        .execution_semantics
        .iter()
        .flat_map(|s| &s.network_listeners)
        .next()
        .expect("typed listener must be retained")
}
fn exposure(r: &CheckResponse) -> bool {
    r.decision_trace
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
}

#[test]
fn native_default_and_explicit_run_share_existing_listener_policy() {
    for command in [
        "pypi-server",
        "pypi-server run",
        "pypi-server /workspace/packages",
        "pypi-server run --port 9091 /workspace/packages",
        "/usr/local/bin/pypi-server run /tmp/packages -p9091",
        "env pypi-server run --port 9091 /workspace/packages",
        "time pypi-server run --port 9091 /workspace/packages",
        "python3 -m pypiserver run --port 9091 /workspace/packages",
        "pypi-server run --port 9091 /workspace/packages &",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(exposure(&r), "{command}: {:?}", r.reasons);
        assert!(
            matches!(listener(&r), NetworkListener::Internet { host: Some(host), scope: NetworkListenScope::NonLoopback, .. } if host == "0.0.0.0"),
            "{command}: {:?}",
            listener(&r)
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::NoProfile | RuleId::SelectionError)),
            "{command}: {:?}",
            r.reasons
        );
    }
}

#[test]
fn explicit_loopback_and_native_host_aliases_do_not_gain_other_authority() {
    for command in [
        "pypi-server run -i 127.0.0.1 /workspace/packages",
        "pypi-server run -H127.2.3.4 /workspace/packages",
        "pypi-server run --interface=::1 /workspace/packages",
        "pypi-server run /workspace/packages --host 127.0.0.1 --port 0",
        "pypi-server -i127.0.0.1 /workspace/packages",
        "pypi-server run --host 0.0.0.0 --host 127.0.0.1 /workspace/packages",
        "pypi-server run --host 127.0.0.1 --server wsgiref /workspace/packages",
        "pypi-server run --host 127.0.0.1 --welcome /outside/welcome.html /workspace/packages",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            matches!(
                listener(&r),
                NetworkListener::Internet {
                    scope: NetworkListenScope::Loopback,
                    ..
                }
            ),
            "{command}"
        );
        assert!(!exposure(&r));
    }
    let r = check(
        "pypi-server run --host 127.0.0.1 --log-file /outside/listener.log /workspace/packages",
        Decision::NeedApproval,
    );
    assert!(!exposure(&r));
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Write)
    );
}

#[test]
fn external_unknown_and_dynamic_hosts_retain_approval_without_dns_or_env_probes() {
    for host in [
        "0.0.0.0",
        "::",
        "10.1.2.3",
        "localhost",
        "listener.test",
        "127.0.0.1.evil.test",
        "$UNKNOWN",
        "",
    ] {
        let r = check(
            &format!("pypi-server run --host \"{host}\" /workspace/packages"),
            Decision::NeedApproval,
        );
        assert!(exposure(&r), "{host}: {:?}", r.reasons);
    }
    let r = check(
        "pypi-server run --host 127.0.0.1 --host \"$UNKNOWN\" /workspace/packages",
        Decision::NeedApproval,
    );
    assert!(exposure(&r));
    let mut req = request("pypi-server run --host 127.0.0.1 /workspace/packages");
    req.shell_state_before = req.shell_state_before.with_environment_observation(
        "PYPI_SERVER_HOST",
        ShellEnvironmentValue::Present {
            value: "0.0.0.0".into(),
        },
    );
    assert_eq!(ShellQueryCore::new().check(req).decision, Decision::Allow);
}

#[test]
fn operand_ownership_cannot_turn_a_host_or_log_value_into_help() {
    for command in [
        "pypi-server run --host=--help /workspace/packages",
        "pypi-server run -i--help /workspace/packages",
        "pypi-server run --log-file=--help /workspace/packages",
        "pypi-server run --log-frmt=--version /workspace/packages",
        "pypi-server run --fallback-url=--help /workspace/packages",
        "pypi-server run --host \"$UNKNOWN\" --port 9091 /workspace/packages",
    ] {
        let r = check(command, Decision::NeedApproval);
        listener(&r);
    }
}

#[test]
fn incomplete_or_unmodeled_native_modes_never_become_local_listener_exemptions() {
    for command in [
        "pypi-server run --host 127.0.0.1 --unknown",
        "pypi-server run --host 127.0.0.1 --port",
        "pypi-server run --host 127.0.0.1 --port invalid",
        "pypi-server run --host 127.0.0.1 --port 65536",
        "pypi-server run --host 127.0.0.1 --server gunicorn",
        "pypi-server run --host 127.0.0.1 --server \"$UNKNOWN\"",
        "pypi-server run --host 127.0.0.1 -a . -P . /workspace/packages",
        "pypi-server run --host 127.0.0.1 --passwords /workspace/credentials",
        "pypi-server --verbose run --host 127.0.0.1 /workspace/packages",
        "pypi-server update -x /workspace/packages",
        "pypi-server -U -x /workspace/packages",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn help_and_version_do_not_claim_a_listener_or_startup_log_write() {
    for command in [
        "pypi-server --help",
        "pypi-server --version",
        "pypi-server run --help",
        "pypi-server run /workspace/packages -h",
        "pypi-server run --log-file /outside/listener.log --version",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.network_listeners.is_empty())
        );
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .all(|p| p.operation != PathTargetOperation::Write)
        );
    }
}

#[test]
fn listener_overrides_and_partial_analysis_preserve_independent_denies() {
    for command in [
        "pypi-server run --host 127.0.0.1; rm -rf /",
        "pypi-server run --unknown; rm -rf /",
        "pypi-server run --host \"$(rm -rf /)\"",
        "pypi-server run --host 127.0.0.1 --welcome \"$(rm -rf /)\"",
    ] {
        check(command, Decision::Deny);
    }
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::NetworkListenerExposure,
            RulePolicyEntry::new(action),
        );
        let r = ShellQueryCore::with_policy(policy)
            .check(request("pypi-server run --port 9091 /workspace/packages"));
        assert_eq!(r.decision, expected);
        assert!(exposure(&r));
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::NetworkListenerExposure,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    let r = ShellQueryCore::with_policy(policy).check(request(
        "pypi-server run --server gunicorn /workspace/packages",
    ));
    assert_eq!(
        r.decision,
        Decision::Deny,
        "{:?}; semantics: {:?}",
        r.reasons,
        r.decision_trace.execution_semantics
    );
    assert!(exposure(&r));
}
