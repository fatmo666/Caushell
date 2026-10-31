//! Real CLI/store checks only. Never execute Postconf or change a configuration file.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn postconf_queries_and_edits_keep_file_authority_through_the_real_cli() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "postconf-check-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(work.join("config")).unwrap();
    fs::write(work.join("keep.txt"), "unchanged\n").unwrap();
    for file in ["main.cf", "master.cf"] {
        fs::write(work.join("config").join(file), "sentinel = original\n").unwrap();
    }
    fs::create_dir(root.join("outside")).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let check = |command: &str| {
        let shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("MAIL_CONFIG", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("postconf-cli"),
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
    let outside = root.join("outside");
    let cases = [
        ("postconf -n".to_string(), Decision::Allow),
        (
            "postconf -o setting=value -xh other".to_string(),
            Decision::Allow,
        ),
        (
            "postconf -e setting=value".to_string(),
            Decision::NeedApproval,
        ),
        ("postconf setting=value".to_string(), Decision::NeedApproval),
        ("postconf -X setting".to_string(), Decision::NeedApproval),
        (
            "postconf -c ./config -e setting=value".to_string(),
            Decision::Allow,
        ),
        (
            "postconf -c ./config -Me 'svc/inet=inet n - n - - smtpd'".to_string(),
            Decision::Allow,
        ),
        (
            "postconf -c ./config '-#' setting".to_string(),
            Decision::Allow,
        ),
        (
            "postconf -c ./config -e 'setting=$(rm -rf /)'".to_string(),
            Decision::Allow,
        ),
        (
            format!("postconf -c '{}' -e setting=value", outside.display()),
            Decision::NeedApproval,
        ),
        (
            "postconf -c ./config -b".to_string(),
            Decision::NeedApproval,
        ),
        ("postconf setting -X".to_string(), Decision::NeedApproval),
        (
            "postconf -c ./config -e setting=value; postfix start".to_string(),
            Decision::NeedApproval,
        ),
        ("postconf --unknown; rm -rf /".to_string(), Decision::Deny),
        (
            "postconf -e \"setting=$(rm -rf /)\"".to_string(),
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
    let response = check("postconf -e setting=value");
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Write)
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|s| s.state_operations.is_empty())
    );
    assert_eq!(
        fs::read_to_string(work.join("keep.txt")).unwrap(),
        "unchanged\n"
    );
    assert_eq!(fs::read_dir(work.join("config")).unwrap().count(), 2);
    for file in ["main.cf", "master.cf"] {
        assert_eq!(
            fs::read_to_string(work.join("config").join(file)).unwrap(),
            "sentinel = original\n"
        );
    }
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&work).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}
