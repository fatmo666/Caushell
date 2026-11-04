//! Real CLI/store round trips. Candidate shell commands are never executed.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn arithmetic_words_keep_policy_and_judge_only_across_cli_restarts() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("arithmetic-words-cli-{}", std::process::id()));
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("sentinel"), "untouched\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    for (command, expected) in [
        ("echo $(($(printf '%d' 1)0))", Decision::Allow),
        ("(( $(printf '%d' 1)0 ))", Decision::Allow),
        (
            "echo $(($(printf '%d' 1)$(printf '%d' 2)))",
            Decision::Allow,
        ),
        ("echo $(( $(printf '%d' 1)0 ))", Decision::Allow),
        (
            "echo $(($(printf '%d' 1)0)); python3 -c 'pass'",
            Decision::NeedApproval,
        ),
        (
            "echo $(($(cat /tmp/unknown-arithmetic-input)0))",
            Decision::NeedApproval,
        ),
        ("echo $(($(touch /opt/out)0))", Decision::NeedApproval),
        ("echo $(($(rm -rf /)0))", Decision::Deny),
        ("bash -c 'echo $(($(rm -rf /)0))'", Decision::Deny),
        (
            "echo $(($(printf 1)0)); echo 'unfinished",
            Decision::NeedApproval,
        ),
        ("echo '$(( $(touch /opt/out)0 ))'", Decision::Allow),
    ] {
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("arithmetic-words-cli"),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap())
                .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
                .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
                .with_variable_knowledge(ShellStateKnowledge::Complete)
                .with_alias_knowledge(ShellStateKnowledge::Complete)
                .with_function_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "arithmetic-stdio-regression".into(),
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
        assert_eq!(fs::read_dir(&work).unwrap().count(), 1);
    }
    fs::remove_dir_all(root).unwrap();
}
