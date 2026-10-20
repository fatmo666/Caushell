use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("npm-config-tasks"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command, 1))
}

#[test]
fn npm_known_tasks_enter_the_graph_and_existing_guards() {
    for (body, expected, child) in [
        ("rm -rf /", Decision::Deny, "rm"),
        ("touch /opt/output", Decision::NeedApproval, "touch"),
        ("/bin/sh", Decision::NeedApproval, "/bin/sh"),
        ("printf SAFE", Decision::Allow, "printf"),
    ] {
        let command =
            format!("printf '%s' '{{\"scripts\":{{\"x\":\"{body}\"}}}}' >package.json; npm run x");
        let response = check(&command);
        assert_eq!(response.decision, expected, "{command}: {response:#?}");
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|i| i.command_name.as_deref() == Some(child)),
            "{response:#?}"
        );
    }
}

#[test]
fn npm_selects_only_the_requested_task_and_its_lifecycle() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf /","y":"printf SAFE"}}' >package.json; npm run y"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run missing"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"prex":"rm -rf /","x":"printf SAFE"}}' >package.json; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"postx":"rm -rf /","x":"printf SAFE"}}' >package.json; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"pretest":"rm -rf /","test":"printf SAFE"}}' >package.json; npm test"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"prex":"rm -rf /"}}' >package.json; npm run x"#,
            Decision::Allow,
        ),
    ] {
        assert_eq!(check(command).decision, expected, "{command}");
    }
}

#[test]
fn npm_arguments_are_appended_as_argv_not_shell_code() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf"}}' >package.json; npm run x -- /"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf %s"}}' >package.json; npm run x -- 'x; rm -rf /'"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"printf %s"}}' >package.json; npm run x -- \"x'\""#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"prex":"printf PRE","x":"printf %s"}}' >package.json; npm run x -- /"#,
            Decision::Allow,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {r:#?}");
    }
}

#[test]
fn npm_graph_retains_lifecycle_order_and_literal_separator_argument() {
    let response = check(
        r#"echo '{"scripts":{"prex":"printf PRE","x":"printf %s","postx":"printf POST"}}' >package.json; npm run x -- -- /"#,
    );
    assert_eq!(response.decision, Decision::Allow);
    let events = response
        .decision_trace
        .nested_payloads
        .iter()
        .filter_map(|p| match &p.origin {
            NestedPayloadOrigin::ConfigDefinedTask { task_name, .. } => Some(task_name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(events, ["prex", "x", "postx"]);
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|i| i.raw_text == "printf %s '--' '/'"),
        "{:?}",
        response.decision_trace.derived_invocations
    );
}

#[test]
fn npm_latest_content_and_unknown_overwrites_do_not_restore_old_bytes() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; echo '{"scripts":{"x":"printf SAFE"}}' >package.json; npm run x"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; cat /opt/input >package.json; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; cp /opt/input package.json; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json >other.json; npm run x"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' 2>package.json; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"printf '%s' '{"scripts":{' >package.json; printf '%s' '"x":"rm -rf /"}}' >>package.json; npm run x"#,
            Decision::Deny,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {r:#?}");
    }
}

#[test]
fn npm_task_directory_follows_shell_and_process_local_cwd() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >/tmp/package.json; npm -C /tmp run x"#,
            Decision::Deny,
        ),
        (
            r#"cd /tmp; echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"cd /tmp && echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"touch ../../opt/output"}}' >/tmp/package.json; npm -C /tmp run x"#,
            Decision::NeedApproval,
        ),
        (r#"cd "$unknown"; npm run x"#, Decision::NeedApproval),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {r:#?}");
    }
}

#[test]
fn npm_wrapped_and_nested_tasks_are_not_skipped() {
    for command in [
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; env npm run x"#,
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; sh -c 'npm run x'"#,
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; env sh -c 'npm run x'"#,
        r#"sh -c 'echo '\''{"scripts":{"x":"rm -rf /"}}'\'' >package.json; npm run x'"#,
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; f() { npm run x; }; f"#,
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Deny, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn npm_nested_scope_writes_override_ancestor_content() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; sh -c 'echo '\''{"scripts":{"x":"printf SAFE"}}'\'' >package.json; npm run x'"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; sh -c 'cat /opt/input >package.json; npm run x'"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; sh -c 'echo '\''{"scripts":{"x":"rm -rf /"}}'\'' >package.json; npm run x'"#,
            Decision::Deny,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn npm_static_content_handles_heredocs_and_keeps_unknown_sources_unknown() {
    for (command, expected) in [
        (
            "cat >package.json <<'JSON'\n{\"scripts\":{\"x\":\"rm -rf /\"}}\nJSON\nnpm run x",
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >seed.json; cat /opt/input >seed.json; cat seed.json >package.json; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; chmod 600 package.json; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; npm run x -- *"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; npm run x -- '*'"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >/tmp/package.json; alias go='cd /tmp'; go; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x --script-shell /bin/bash"#,
            Decision::Deny,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn npm_prior_action_content_and_invalidation_are_ordered() {
    let mut core = ShellQueryCore::new();
    let first = core.check(request(
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json"#,
        1,
    ));
    assert_eq!(first.decision, Decision::Allow);
    let next = core.check(request("npm run x", 2));
    assert_eq!(next.decision, Decision::Deny, "{next:#?}");

    let mut core = ShellQueryCore::new();
    core.check(request(
        r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json"#,
        1,
    ));
    core.check(request("cat /opt/input >package.json", 2));
    let next = core.check(request("npm run x", 3));
    assert_eq!(next.decision, Decision::NeedApproval, "{next:#?}");
}

#[test]
fn npm_native_controls_are_not_script_arguments() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run-script x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"prex":"rm -rf /","x":"printf SAFE"}}' >package.json; npm run x --ignore-scripts"#,
            Decision::Allow,
        ),
        (
            r#"echo '{"scripts":{"prex":"rm -rf /","x":"printf SAFE"}}' >package.json; npm run x --ignore-scripts=false"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x --ignore-scripts"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; npm run x --script-shell /opt/custom-shell"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; npm run x --script-shell /bin/sh"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; npm_config_script_shell=/opt/custom-shell npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf /"}}' >/tmp/package.json; npm --prefix /tmp run x"#,
            Decision::Deny,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn npm_child_environment_does_not_inherit_unexported_shell_locals() {
    for (command, expected) in [
        (
            r#"echo '{"scripts":{"x":"rm -rf \"$TARGET\""}}' >package.json; TARGET=/; npm run x"#,
            Decision::NeedApproval,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf \"$TARGET\""}}' >package.json; export TARGET=/; npm run x"#,
            Decision::Deny,
        ),
        (
            r#"echo '{"scripts":{"x":"rm -rf \"$TARGET\""}}' >package.json; TARGET=/ npm run x"#,
            Decision::Deny,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}
