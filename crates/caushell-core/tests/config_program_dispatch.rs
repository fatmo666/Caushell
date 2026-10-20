use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, persistent: bool) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("config-program-dispatch"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: if persistent {
                ShellRuntimeCapabilities::persistent_shell()
            } else {
                ShellRuntimeCapabilities::request_only()
            },
        },
    }
}

fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command, true));
    assert_eq!(r.decision, expected, "{command}: {:#?}", r.reasons);
    r
}

fn setup(file: &str, body: &str) -> String {
    format!("echo '{{\"scripts\":{{\"x\":\"{body}\"}}}}' >{file}")
}

#[test]
fn configured_tasks_and_hooks_share_dispatch_expansion() {
    for (file, call) in [
        ("package.json", "npm run x"),
        ("package.json", "yarn run x"),
        ("composer.json", "composer run-script x"),
        ("hook", "git commit --allow-empty -m x"),
    ] {
        for (body, expected, program) in [
            ("rm -rf /", Decision::Deny, "rm"),
            ("touch /opt/output", Decision::NeedApproval, "touch"),
            ("printf SAFE", Decision::Allow, "printf"),
        ] {
            let prefix = if file == "hook" {
                format!(
                    "git init .; echo '{body}' >.git/hooks/pre-commit; chmod +x .git/hooks/pre-commit"
                )
            } else {
                setup(file, body)
            };
            for invocation in [
                call.into(),
                format!("printf '%s\\n' one | xargs -I{{}} {call}"),
                format!("printf '%s\\n' one | xargs -I{{}} env {call}"),
                format!("printf '%s\\n' one | xargs -I{{}} sh -c '{call}'"),
                format!("find . -maxdepth 0 -exec {call} \\;"),
            ] {
                let command = format!("{prefix}; {invocation}");
                for persistent in [false, true] {
                    let r = ShellQueryCore::new().check(request(&command, persistent));
                    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
                    let payloads: Vec<_> = r
                        .decision_trace
                        .nested_payloads
                        .iter()
                        .filter(|p| {
                            matches!(p.origin, NestedPayloadOrigin::ConfigDefinedTask { .. })
                        })
                        .collect();
                    assert_eq!(payloads.len(), 1, "{command}: {payloads:#?}");
                    assert!(
                        r.decision_trace
                            .derived_invocations
                            .iter()
                            .any(|d| d.command_name.as_deref() == Some(program)),
                        "{command}: {r:#?}"
                    );
                }
            }
        }
    }
}

#[test]
fn native_arguments_select_tasks_and_remain_data() {
    for (call, argument) in [
        ("npm run", "x"),
        ("yarn run", "x"),
        ("composer run-script", "x"),
    ] {
        let file = if call.starts_with("composer") {
            "composer.json"
        } else {
            "package.json"
        };
        check(
            &format!(
                "{}; printf '%s\\n' {argument} | xargs {call}",
                setup(file, "rm -rf /")
            ),
            Decision::Deny,
        );
        check(
            &format!(
                "{}; printf '%s\\n' missing | xargs {call}",
                setup(file, "rm -rf /")
            ),
            Decision::Allow,
        );
    }
    check(
        &format!(
            "{}; printf '%s\\n' 'x; rm -rf /' | xargs -0 npm run x --",
            setup("package.json", "printf %s")
        ),
        Decision::Allow,
    );
    check(
        &format!(
            "{}; printf '%s\\n' / | xargs npm run x --",
            setup("package.json", "rm -rf")
        ),
        Decision::Deny,
    );
}

#[test]
fn nested_configuration_writes_and_wrappers_preserve_visibility() {
    for command in [
        r#"sh -c 'echo "{\"scripts\":{\"x\":\"rm -rf /\"}}" >package.json; printf one | xargs -I{} npm run x'"#,
        r#"f() { echo '{"scripts":{"x":"rm -rf /"}}' >package.json; printf one | xargs -I{} npm run x; }; f"#,
        r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; printf one | xargs -I{} sh -c 'echo "{\"scripts\":{\"x\":\"rm -rf /\"}}" >package.json; npm run x'"#,
        r#"echo '{"scripts":{"x":"npm run y","y":"rm -rf /"}}' >package.json; printf one | xargs -I{} npm run x"#,
        r#"echo '{"scripts":{"x":"sh -c \"rm -rf /\""}}' >package.json; printf one | xargs -I{} npm run x"#,
        r#"echo '{"scripts":{"x":"bash ./task"}}' >package.json; echo 'rm -rf /' >task; printf one | xargs -I{} npm run x"#,
        r#"echo '{"scripts":{"x":"env bash ./task"}}' >package.json; echo 'rm -rf /' >task; printf one | xargs -I{} npm run x"#,
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; find . -maxdepth 0 -exec printf SAFE \; -exec npm run x \;"#,
    ] {
        check(command, Decision::Deny);
    }
    check(
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; printf one | xargs -I{} sh -c 'echo "{\"scripts\":{\"x\":\"printf SAFE\"}}" >package.json; npm run x'"#,
        Decision::Allow,
    );
}

#[test]
fn configured_dispatch_uses_the_invocation_directory() {
    for call in [
        "npm -C sub run x",
        "env -C sub npm run x",
        "sh -c 'cd sub && npm run x'",
    ] {
        let command = format!(
            "mkdir -p sub; {}; echo '{{\"scripts\":{{\"x\":\"rm -rf /\"}}}}' >sub/package.json; printf one | xargs -I{{}} {call}",
            setup("package.json", "printf SAFE")
        );
        check(&command, Decision::Deny);
    }
    let command = format!(
        "mkdir -p sub; {}; echo '{{\"scripts\":{{\"x\":\"printf SAFE\"}}}}' >sub/package.json; printf one | xargs -I{{}} env -C sub npm run x",
        setup("package.json", "rm -rf /")
    );
    check(&command, Decision::Allow);
    let r = check(
        &format!(
            "{}; printf one | xargs -I{{}} env -C \"$UNKNOWN\" npm run x",
            setup("package.json", "printf SAFE")
        ),
        Decision::NeedApproval,
    );
    assert!(!r.decision_trace.nested_payloads.is_empty());
}

#[test]
fn config_task_recursion_stops_at_the_shared_budget() {
    let r = check(
        r#"echo '{"scripts":{"x":"npm run x"}}' >package.json; printf one | xargs -I{} npm run x"#,
        Decision::NeedApproval,
    );
    assert!(r.decision_trace.nested_payloads.len() < 16, "{r:#?}");
    for depth in [0, 1, 2] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = depth;
        let r = ShellQueryCore::try_with_policy(policy)
            .unwrap()
            .check(request(
                &format!(
                    "{}; printf one | xargs -I{{}} npm run x",
                    setup("package.json", "printf SAFE")
                ),
                true,
            ));
        assert_eq!(
            r.decision,
            if depth < 2 {
                Decision::NeedApproval
            } else {
                Decision::Allow
            },
            "{depth}: {r:#?}"
        );
        assert!(
            r.decision_trace
                .derived_invocations
                .iter()
                .all(|d| d.depth <= depth),
            "{r:#?}"
        );
    }
}

#[test]
fn hook_dispatch_preserves_stage_and_executable_controls() {
    for (stage, tail, expected) in [
        (
            "pre-commit",
            "git commit --no-verify --allow-empty -m x",
            Decision::Allow,
        ),
        (
            "prepare-commit-msg",
            "git commit --no-verify --allow-empty -m x",
            Decision::Deny,
        ),
        ("pre-commit", "git status", Decision::Allow),
    ] {
        check(
            &format!(
                "git init .; echo 'rm -rf /' >.git/hooks/{stage}; chmod +x .git/hooks/{stage}; printf one | xargs -I{{}} {tail}"
            ),
            expected,
        );
    }
    check(
        "git init .; echo 'rm -rf /' >.git/hooks/pre-commit; chmod a-x .git/hooks/pre-commit; printf one | xargs -I{} git commit --allow-empty -m x",
        Decision::Allow,
    );
}
