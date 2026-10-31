//! Real CLI/store checks only. Never launch a server, open a listener, or write a startup log.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn native_pypiserver_uses_the_existing_listener_guard_through_the_real_cli() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "pypiserver-listener-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(work.join("config")).unwrap();
    fs::write(work.join("keep.txt"), "unchanged\n").unwrap();
    for file in ["fixture-one.txt", "fixture-two.txt"] {
        fs::write(work.join("config").join(file), "sentinel = original\n").unwrap();
    }
    fs::create_dir(root.join("outside")).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let check = |command: &str| {
        let shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("pypiserver-listener-cli"),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "stdio-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some(work.to_str().unwrap().into()),
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_caushell"))
            .args(["serve-stdio", "--config"])
            .arg(root.join("defaults.yaml"))
            .arg("--store")
            .arg(root.join("store"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        serde_json::to_writer(&mut input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let RuntimeTransportResponse::Check(result) =
            serde_json::from_slice(&output.stdout).unwrap()
        else {
            panic!("unexpected transport response")
        };
        result.response
    };
    let outside = root.join("outside/listener.log");
    let cases = [
        ("pypi-server".to_string(), Decision::NeedApproval),
        (
            "pypi-server run --port 9123 ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run -i127.0.0.1 ./config".to_string(),
            Decision::Allow,
        ),
        ("pypi-server -H::1 ./config".to_string(), Decision::Allow),
        (
            "pypi-server run --host localhost ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host=--help ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host 127.0.0.1 --server gunicorn ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host 127.0.0.1 -a . -P . ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host 127.0.0.1 --log-file keep.txt ./config".to_string(),
            Decision::Allow,
        ),
        (
            format!(
                "pypi-server run --host 127.0.0.1 --log-file '{}' ./config",
                outside.display()
            ),
            Decision::NeedApproval,
        ),
        (
            format!(
                "pypi-server run --host 127.0.0.1 --log-file '{}' --log-file keep.txt ./config",
                outside.display()
            ),
            Decision::Allow,
        ),
        (
            format!(
                "pypi-server run --host 127.0.0.1 --log-file keep.txt --log-file '{}' ./config",
                outside.display()
            ),
            Decision::NeedApproval,
        ),
        (
            format!("pypi-server run --log-file '{}' --help", outside.display()),
            Decision::Allow,
        ),
        (
            "pypi-server update -x ./config".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host 127.0.0.1; rm keep.txt".to_string(),
            Decision::NeedApproval,
        ),
        (
            "pypi-server run --host 127.0.0.1; rm -rf /".to_string(),
            Decision::Deny,
        ),
        (
            "pypi-server run --unknown; rm -rf /".to_string(),
            Decision::Deny,
        ),
    ];
    for (command, expected) in cases {
        let response = check(&command);
        assert_eq!(
            response.decision, expected,
            "{command}: {:?}",
            response.reasons
        );
    }
    let response = check("pypi-server run --port 9123 ./config");
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NetworkListenerExposure)
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| !s.network_listeners.is_empty())
    );
    assert!(!outside.exists());
    assert_eq!(
        fs::read_to_string(work.join("keep.txt")).unwrap(),
        "unchanged\n"
    );
    assert_eq!(fs::read_dir(work.join("config")).unwrap().count(), 2);
    for file in ["fixture-one.txt", "fixture-two.txt"] {
        assert_eq!(
            fs::read_to_string(work.join("config").join(file)).unwrap(),
            "sentinel = original\n"
        );
    }
    assert_eq!(fs::read_dir(root.join("outside")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&work).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}
