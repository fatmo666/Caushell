//! Actual CLI/config/store checks; submitted commands are never executed.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn empty_config_requires_approval_for_unmodeled_execution_across_cli_restarts() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "unmodeled-execution-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("sentinel"), "untouched\n").unwrap();
    fs::write(
        work.join("local-program"),
        "#!/bin/sh\nprintf changed > sentinel\n",
    )
    .unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    for (index, (command, expected)) in [
        ("rq1_unmodeled_tool --help", Decision::NeedApproval),
        ("shutdown -r now", Decision::NeedApproval),
        ("auditctl -e 0", Decision::NeedApproval),
        ("printf data | rq1_unmodeled_tool", Decision::NeedApproval),
        ("bash -c 'rq1_unmodeled_tool'", Decision::NeedApproval),
        ("busybox httpd -f -p 12345 -h .", Decision::NeedApproval),
        (
            "bash -c 'enable -f /outside/code.so fixture'",
            Decision::NeedApproval,
        ),
        ("./local-program", Decision::Allow),
        ("printf safe", Decision::Allow),
        (
            "./local-program; rq1_unmodeled_tool",
            Decision::NeedApproval,
        ),
        ("./local-program > /outside/output", Decision::NeedApproval),
        ("rq1_unmodeled_tool; rm -rf /", Decision::Deny),
    ]
    .into_iter()
    .enumerate()
    {
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new(format!("unmodeled-cli-{index}")),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap())
                .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
                .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
                .with_variable_knowledge(ShellStateKnowledge::Complete)
                .with_alias_knowledge(ShellStateKnowledge::Complete)
                .with_function_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "unmodeled-stdio-regression".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
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
            panic!("check response")
        };
        assert_eq!(
            result.response.decision, expected,
            "{command}: {:?}",
            result.response.reasons
        );
        assert!(result.check_receipt.is_none());
        assert_eq!(
            fs::read_to_string(work.join("sentinel")).unwrap(),
            "untouched\n"
        );
        assert_eq!(fs::read_dir(&work).unwrap().count(), 2);
    }
    fs::remove_dir_all(root).unwrap();
}
