use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("manifest-config-tasks"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
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
fn yarn_and_composer_known_tasks_enter_the_graph_and_existing_guards() {
    for (file, invocation) in [
        ("package.json", "yarn --cwd . x"),
        ("package.json", "yarn run x"),
        ("composer.json", "composer run-script x"),
        ("composer.json", "composer run x"),
    ] {
        for (body, expected, child) in [
            ("rm -rf /", Decision::Deny, "rm"),
            ("touch /opt/out", Decision::NeedApproval, "touch"),
            ("/bin/sh", Decision::NeedApproval, "/bin/sh"),
            ("printf SAFE", Decision::Allow, "printf"),
        ] {
            let command =
                format!("echo '{{\"scripts\":{{\"x\":\"{body}\"}}}}' >{file}; {invocation}");
            let r = check(&command);
            assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
            assert!(
                r.decision_trace
                    .derived_invocations
                    .iter()
                    .any(|i| i.command_name.as_deref() == Some(child)),
                "{command}: {:?}",
                r.decision_trace.derived_invocations
            );
        }
    }
}

#[test]
fn yarn_install_events_are_distinct_from_named_tasks() {
    for (tail, expected) in [
        ("yarn", Decision::Deny),
        ("yarn --cwd .", Decision::Deny),
        ("yarn install", Decision::Deny),
        ("yarn --ignore-scripts", Decision::Allow),
        ("yarn install --ignore-scripts", Decision::Allow),
        ("yarn run x", Decision::Allow),
        ("yarn x", Decision::Allow),
    ] {
        let command = format!(
            "echo '{{\"scripts\":{{\"preinstall\":\"rm -rf /\",\"x\":\"printf SAFE\"}}}}' >package.json; {tail}"
        );
        let r = check(&command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
    for event in ["install", "postinstall"] {
        let command =
            format!("echo '{{\"scripts\":{{\"{event}\":\"rm -rf /\"}}}}' >package.json; yarn");
        assert_eq!(check(&command).decision, Decision::Deny, "{command}");
    }
}

#[test]
fn yarn_hooks_respect_known_version_and_keep_unknown_versions_unknown() {
    for (manifest, expected) in [
        (
            r#"{"packageManager":"yarn@1.22.22","scripts":{"prex":"rm -rf /","x":"printf SAFE"}}"#,
            Decision::Deny,
        ),
        (
            r#"{"packageManager":"yarn@4.0.0","scripts":{"prex":"rm -rf /","x":"printf SAFE"}}"#,
            Decision::Allow,
        ),
        (
            r#"{"scripts":{"prex":"rm -rf /","x":"printf SAFE"}}"#,
            Decision::NeedApproval,
        ),
        (
            r#"{"packageManager":"yarn@1.22.22","scripts":{"postx":"rm -rf /","x":"printf SAFE"}}"#,
            Decision::Deny,
        ),
    ] {
        let command = format!("echo '{manifest}' >package.json; yarn x");
        let r = check(&command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
    let r = check(
        r#"echo '{"packageManager":"yarn@1.22.22","scripts":{"prex":"printf PRE","x":"printf MAIN","postx":"printf POST"}}' >package.json; yarn x"#,
    );
    let names: Vec<_> = r
        .decision_trace
        .nested_payloads
        .iter()
        .filter_map(|p| match &p.origin {
            NestedPayloadOrigin::ConfigDefinedTask { task_name, .. } => Some(task_name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["prex", "x", "postx"]);
}

#[test]
fn manifest_tasks_pass_arguments_as_literal_argv() {
    for (file, call) in [
        ("package.json", "yarn run x"),
        ("composer.json", "composer run-script x --"),
    ] {
        for (body, args, expected) in [
            ("rm -rf", "/", Decision::Deny),
            ("printf %s", "'x; rm -rf /'", Decision::Allow),
            ("printf %s", "\"a'b\"", Decision::Allow),
        ] {
            let command =
                format!("echo '{{\"scripts\":{{\"x\":\"{body}\"}}}}' >{file}; {call} {args}");
            let r = check(&command);
            assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
        }
    }
}

#[test]
fn composer_arrays_references_and_non_shell_handlers_preserve_the_boundary() {
    for (manifest, expected) in [
        (
            r#"{"scripts":{"x":["printf SAFE","rm -rf /"]}}"#,
            Decision::Deny,
        ),
        (
            r#"{"scripts":{"x":"@other","other":"rm -rf /"}}"#,
            Decision::Deny,
        ),
        (
            r#"{"scripts":{"x":"@other /","other":"rm -rf"}}"#,
            Decision::Deny,
        ),
        (
            r#"{"scripts":{"x":"Handler::run"}}"#,
            Decision::NeedApproval,
        ),
        (
            r#"{"scripts":{"x":"@php -r \"echo 1;\""}}"#,
            Decision::NeedApproval,
        ),
        (
            r#"{"scripts":{"x":"@putenv TARGET=/opt/out"}}"#,
            Decision::NeedApproval,
        ),
        (r#"{"scripts":{"x":"@x"}}"#, Decision::NeedApproval),
        (
            r#"{"scripts":{"x":"printf SAFE","unrelated":"rm -rf /","prex":"rm -rf /"}}"#,
            Decision::Allow,
        ),
    ] {
        let command = format!("echo '{manifest}' >composer.json; composer run-script x");
        let r = check(&command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
    let r = check(
        r#"echo '{"scripts":{"x":["printf ONE","printf TWO"]}}' >composer.json; composer run-script x"#,
    );
    let children: Vec<_> = r
        .decision_trace
        .derived_invocations
        .iter()
        .map(|i| i.raw_text.as_str())
        .collect();
    assert_eq!(children, ["printf ONE", "printf TWO"]);
}

#[test]
fn observed_content_overwrites_and_cwd_are_shared_with_npm() {
    for (file, call, cd_call) in [
        ("package.json", "yarn x", "yarn --cwd /tmp x"),
        (
            "composer.json",
            "composer run-script x",
            "composer -d /tmp run-script x",
        ),
    ] {
        let danger = r#"{"scripts":{"x":"rm -rf /"}}"#;
        let safe = r#"{"scripts":{"x":"printf SAFE"}}"#;
        for (command, expected) in [
            (
                format!("echo '{danger}' >{file}; echo '{safe}' >{file}; {call}"),
                Decision::Allow,
            ),
            (
                format!("echo '{safe}' >{file}; echo '{danger}' >{file}; {call}"),
                Decision::Deny,
            ),
            (
                format!("echo '{safe}' >{file}; cat /opt/input >{file}; {call}"),
                Decision::NeedApproval,
            ),
            (
                format!("echo '{danger}' >/tmp/{file}; {cd_call}"),
                Decision::Deny,
            ),
            (
                format!("echo '{danger}' >{file}; sh -c '{call}'"),
                Decision::Deny,
            ),
            (
                format!("echo '{danger}' >{file}; env {call}"),
                Decision::Deny,
            ),
        ] {
            let r = check(&command);
            assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
        }
    }
}

#[test]
fn unobserved_normal_project_tasks_and_information_are_not_blanket_approvals() {
    for command in [
        "yarn x",
        "yarn",
        "composer run-script x",
        "yarn --help",
        "composer run-script --list",
        "composer --help",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
    }
    assert_eq!(
        check(r#"echo '{"scripts":{"x":"rm -rf /"}}' >package.json; yarn --help"#).decision,
        Decision::Allow
    );
    assert_eq!(
        check(r#"echo '{"scripts":{"x":"rm -rf /"}}' >composer.json; composer run-script --list"#)
            .decision,
        Decision::Allow
    );
}

#[test]
fn explicit_task_configuration_overrides_cannot_certify_the_wrong_manifest() {
    for command in [
        r#"echo '{"scripts":{"x":"rm -rf /"}}' >composer.json; COMPOSER=other.json composer run-script x"#,
        r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; yarn --script-shell /opt/custom-shell x"#,
        r#"echo '{"scripts":{"x":"printf SAFE"}}' >package.json; yarn "$task""#,
        r#"yarn install --cwd /tmp"#,
        r#"npm run "$task""#,
        r#"echo '{"scripts":{"":"rm -rf /"}}' >composer.json; composer run-script ''"#,
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
    }
    assert_eq!(check(r#"echo '{"scripts":{"x":"rm -rf /"}}' >composer.json; COMPOSER_SKIP_SCRIPTS=x composer run-script x"#).decision, Decision::Allow);
}

#[test]
fn non_task_yarn_modes_skip_manifest_decoding() {
    for command in [
        "cat /opt/input >package.json; yarn --ignore-scripts",
        "cat /opt/input >package.json; yarn install --ignore-scripts",
        "cat /opt/input >package.json; yarn info",
        "echo '{\"scripts\":{\"info\":\"rm -rf /\"}}' >package.json; yarn info",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn manifest_observations_survive_prior_shell_actions() {
    for (file, call) in [
        ("package.json", "yarn x"),
        ("composer.json", "composer run-script x"),
    ] {
        let mut core = ShellQueryCore::new();
        let r = core.check(request(
            &format!("echo '{{\"scripts\":{{\"x\":\"rm -rf /\"}}}}' >{file}"),
            1,
        ));
        assert_eq!(r.decision, Decision::Allow);
        assert_eq!(
            core.check(request(call, 2)).decision,
            Decision::Deny,
            "{call}"
        );
    }
}
