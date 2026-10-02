//! Static guard checks, never launches an application or opens a socket.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/tmp/project");
    shell.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("listener-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn check(req: CheckRequest, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(req.clone());
    assert_eq!(
        response.decision, expected,
        "{}: {:?}",
        req.command, response.decision_trace
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::NoProfile | RuleId::SelectionError)),
        "{}: {:?}",
        req.command,
        response.decision_trace.findings
    );
    response
}

fn env(req: &mut CheckRequest, name: &str, value: &str, exported: bool) {
    req.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            name,
            ShellValueSnapshot::exact_scalar(value),
            exported,
        ));
}

fn listener(response: &CheckResponse) -> &NetworkListener {
    response
        .decision_trace
        .execution_semantics
        .iter()
        .flat_map(|s| &s.network_listeners)
        .next()
        .expect("listener fact must be retained")
}

#[test]
fn numeric_loopback_only_is_exempt() {
    for host in [
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "0:0:0:0:0:0:0:1",
        "::ffff:127.0.0.1",
    ] {
        let r = check(
            request(&format!("uvicorn app:app --host '{host}'")),
            Decision::Allow,
        );
        assert!(matches!(
            listener(&r),
            NetworkListener::Internet {
                scope: NetworkListenScope::Loopback,
                ..
            }
        ));
    }
}

#[test]
fn external_wildcard_lan_and_unknown_names_need_approval() {
    for host in [
        "0.0.0.0",
        "::",
        "192.168.1.2",
        "10.0.0.1",
        "8.8.8.8",
        "2001:db8::1",
        "localhost",
        "service.local",
        "$UNKNOWN",
        "",
        "127.0.0.1.evil.test",
    ] {
        let r = check(
            request(&format!("uvicorn app:app --host '{host}'")),
            Decision::NeedApproval,
        );
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
        );
    }
}

#[test]
fn default_host_requires_known_environment_absence() {
    check(request("uvicorn app:app"), Decision::Allow);
    let mut req = request("uvicorn app:app");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    check(req, Decision::NeedApproval);
}

#[test]
fn env_cli_priority_and_export_attributes() {
    let mut req = request("uvicorn app:app");
    env(&mut req, "UVICORN_HOST", "0.0.0.0", true);
    check(req.clone(), Decision::NeedApproval);
    req.command += " --host=127.0.0.1";
    check(req, Decision::Allow);
    let mut req = request("uvicorn app:app");
    env(&mut req, "UVICORN_HOST", "0.0.0.0", false);
    check(req, Decision::Allow);
}

#[test]
fn empty_click_environment_values_use_defaults() {
    let mut req = request("uvicorn app:app");
    for name in ["UVICORN_HOST", "UVICORN_PORT", "UVICORN_FD", "UVICORN_UDS"] {
        env(&mut req, name, "", true);
    }
    check(req, Decision::Allow);
}

#[test]
fn exported_only_is_complete_for_child_environment() {
    let mut req = request("uvicorn app:app");
    req.shell_state_before.observability.variables = ShellStateKnowledge::ExportedOnly;
    check(req.clone(), Decision::Allow);
    env(&mut req, "UVICORN_HOST", "::", true);
    check(req, Decision::NeedApproval);
}

#[test]
fn dynamic_environment_does_not_use_loopback_default() {
    let mut req = request("uvicorn app:app");
    req.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "UVICORN_HOST",
            ShellValueSnapshot::opaque_dynamic("$HOST"),
            true,
        ));
    check(req.clone(), Decision::NeedApproval);
    req.command += " --host=127.0.0.1";
    check(req, Decision::Allow);
}

#[test]
fn same_action_export_prefix_and_plain_local_are_distinct() {
    for command in [
        "UVICORN_HOST=0.0.0.0 uvicorn app:app",
        "export UVICORN_HOST=0.0.0.0; uvicorn app:app",
        "UVICORN_HOST=0.0.0.0; export UVICORN_HOST; uvicorn app:app",
        "export UVICORN_HOST=127.0.0.1; UVICORN_HOST=0.0.0.0; uvicorn app:app",
    ] {
        check(request(command), Decision::NeedApproval);
    }
    check(
        request("UVICORN_HOST=0.0.0.0; uvicorn app:app"),
        Decision::Allow,
    );
    check(
        request("export UVICORN_HOST=0.0.0.0; unset UVICORN_HOST; uvicorn app:app"),
        Decision::Allow,
    );
}

#[test]
fn prefix_and_nested_dispatch_keep_environment() {
    for command in [
        "python3 -m uvicorn app:app --host=0.0.0.0",
        "UVICORN_HOST=0.0.0.0 python3 -m uvicorn app:app",
        "env UVICORN_HOST=0.0.0.0 python3 -m uvicorn app:app",
        "env UVICORN_HOST=$UNKNOWN uvicorn app:app",
    ] {
        check(request(command), Decision::NeedApproval);
    }
    check(
        request("python3 -m uvicorn app:app --host=127.0.0.1"),
        Decision::Allow,
    );
}

#[test]
fn repeated_host_last_wins_and_dynamic_is_not_dropped() {
    check(
        request("uvicorn app:app --host=0.0.0.0 --host=127.0.0.1"),
        Decision::Allow,
    );
    check(
        request("uvicorn app:app --host=127.0.0.1 --host=0.0.0.0"),
        Decision::NeedApproval,
    );
    check(
        request("uvicorn app:app --host=127.0.0.1 --host=\"$UNKNOWN\""),
        Decision::NeedApproval,
    );
}

#[test]
fn filesystem_sockets_use_path_guard_not_listener_guard() {
    for (path, expected) in [
        ("service.sock", Decision::Allow),
        ("/tmp/project/service.sock", Decision::Allow),
        ("/etc/service.sock", Decision::NeedApproval),
        ("../service.sock", Decision::NeedApproval),
    ] {
        let r = check(
            request(&format!("uvicorn app:app --uds '{path}' --host=0.0.0.0")),
            expected,
        );
        assert!(matches!(listener(&r), NetworkListener::Unix { .. }));
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
        );
        if expected == Decision::NeedApproval {
            assert!(
                r.decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
            );
        }
    }
}

#[test]
fn env_socket_paths_and_cli_override_are_checked() {
    let mut req = request("uvicorn app:app");
    env(&mut req, "UVICORN_UDS", "/etc/server.sock", true);
    check(req.clone(), Decision::NeedApproval);
    req.command += " --uds=server.sock";
    check(req, Decision::Allow);
}

#[test]
fn inherited_fd_is_unknown_even_with_local_host_or_uds() {
    for command in [
        "uvicorn app:app --fd=3",
        "uvicorn app:app --fd=3 --host=127.0.0.1",
        "uvicorn app:app --fd=3 --uds=server.sock",
        "uvicorn app:app --fd=3 --uds=/etc/server.sock --workers=2",
    ] {
        let r = check(request(command), Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
        );
    }
    let mut req = request("uvicorn app:app --host=127.0.0.1");
    env(&mut req, "UVICORN_FD", "3", true);
    check(req, Decision::NeedApproval);
}

#[test]
fn env_file_is_not_misinterpreted_as_listener_configuration() {
    let r = check(
        request(
            "uvicorn app:app --env-file=.env --log-config=log.yaml --app-dir=src --reload --reload-dir=src --port=0 --root-path=/etc/not-a-file",
        ),
        Decision::Allow,
    );
    assert!(
        matches!(listener(&r), NetworkListener::Internet { host: Some(host), port: Some(port), .. } if host == "127.0.0.1" && port == "0")
    );
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.loads_in_process_code)
    );
}

#[test]
fn information_and_unrelated_commands_have_no_listener() {
    for command in [
        "uvicorn --help",
        "uvicorn --version",
        "echo hello",
        "curl https://example.com",
    ] {
        let r = check(request(command), Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.network_listeners.is_empty())
        );
    }
}

#[test]
fn local_listener_does_not_exempt_other_mutations() {
    check(
        request("uvicorn app:app --host=127.0.0.1 > /etc/log"),
        Decision::NeedApproval,
    );
    check(
        request("uvicorn app:app --host=127.0.0.1; rm -rf /"),
        Decision::Deny,
    );
}

#[test]
fn rule_supports_explicit_observe_and_deny_overrides() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::NetworkListenerExposure,
            RulePolicyEntry::new(action),
        );
        let r =
            ShellQueryCore::with_policy(policy).check(request("uvicorn app:app --host=0.0.0.0"));
        assert_eq!(r.decision, expected);
        assert!(matches!(
            listener(&r),
            NetworkListener::Internet {
                scope: NetworkListenScope::NonLoopback,
                ..
            }
        ));
    }
}

#[test]
fn scoped_or_conditional_exports_cannot_prove_loopback() {
    for command in [
        "export UVICORN_HOST=0.0.0.0; (export UVICORN_HOST=127.0.0.1); uvicorn app:app",
        "export UVICORN_HOST=0.0.0.0; if false; then export UVICORN_HOST=127.0.0.1; fi; uvicorn app:app",
        "false && export UVICORN_HOST=127.0.0.1; uvicorn app:app",
    ] {
        let mut req = request(command);
        env(&mut req, "UVICORN_HOST", "0.0.0.0", true);
        check(req, Decision::NeedApproval);
    }
}

#[test]
fn declare_export_and_auto_export_are_not_silently_ignored() {
    for command in [
        "declare -x UVICORN_HOST=0.0.0.0; uvicorn app:app",
        "typeset -x UVICORN_HOST=0.0.0.0; uvicorn app:app",
        "set -a; UVICORN_HOST=0.0.0.0; uvicorn app:app",
    ] {
        check(request(command), Decision::NeedApproval);
    }
}

#[test]
fn environment_wrappers_cannot_leave_a_phantom_local_socket() {
    for command in [
        "env -i uvicorn app:app --host=0.0.0.0",
        "env -u UVICORN_UDS uvicorn app:app --host=0.0.0.0",
        "env --unset=UVICORN_UDS python3 -m uvicorn app:app --host=0.0.0.0",
    ] {
        let mut req = request(command);
        env(&mut req, "UVICORN_UDS", "/tmp/project/service.sock", true);
        check(req, Decision::NeedApproval);
    }
    let mut req = request("env -i uvicorn app:app");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    check(req, Decision::Allow);
    check(
        request("env -i UVICORN_HOST=0.0.0.0 uvicorn app:app"),
        Decision::NeedApproval,
    );
}

#[test]
fn shell_payloads_inherit_prefix_environment() {
    for command in [
        "UVICORN_HOST=0.0.0.0 bash -c 'uvicorn app:app'",
        "UVICORN_HOST=0.0.0.0 sh -c 'python3 -m uvicorn app:app'",
        "env -i UVICORN_HOST=0.0.0.0 sh -c 'uvicorn app:app'",
    ] {
        check(request(command), Decision::NeedApproval);
    }
}

#[test]
fn child_shell_does_not_expand_stale_locals_or_pre_prefix_values() {
    let mut req =
        request("UVICORN_HOST=0.0.0.0 bash -c 'uvicorn app:app --host \"$UVICORN_HOST\"'");
    env(&mut req, "UVICORN_HOST", "127.0.0.1", true);
    check(req, Decision::NeedApproval);
    let mut req = request("sh -c 'uvicorn app:app --host \"$LOCAL\"'");
    env(&mut req, "LOCAL", "127.0.0.1", false);
    check(req, Decision::NeedApproval);
}

#[test]
fn facts_roundtrip_and_old_listeners_do_not_retrigger_new_actions() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::NetworkListenerExposure,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    let mut core = ShellQueryCore::with_policy(policy);
    let req = request("uvicorn app:app --host=0.0.0.0");
    let r = core.check(req.clone());
    assert_eq!(r.decision, Decision::Allow);
    let snapshot = core.session_snapshot(&req.session_id, 1).unwrap();
    assert!(snapshot.graph.nodes.iter().any(|node| matches!(&node.kind,
        SessionGraphNodeKindSnapshot::ExecutionSemantics { semantics }
            if !semantics.network_listeners.is_empty())));
    core.replace_policy(PolicyConfig::default());
    let mut next = request("echo done");
    next.sequence_no = CommandSequenceNo::new(2);
    let r = core.check(next);
    assert_eq!(r.decision, Decision::Allow);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
    );
}
