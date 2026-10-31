//! Real CLI/store checks only. JudgeOnly must never run service or child commands.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn native_service_entries_keep_state_approval_and_deny_through_the_real_cli() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "service-entry-check-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(work.join("config")).unwrap();
    fs::write(work.join("keep.txt"), "unchanged\n").unwrap();
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
            session_id: SessionId::new("service-entry-cli"),
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
    for (command, expected) in [
        ("postfix start", Decision::NeedApproval),
        ("time /usr/sbin/postfix -v start", Decision::NeedApproval),
        (
            "postfix start 2>&1; postfix status 2>&1",
            Decision::NeedApproval,
        ),
        ("postfix -c ./config status", Decision::NeedApproval),
        ("postfix check", Decision::NeedApproval),
        ("postfix start > keep.txt", Decision::NeedApproval),
        ("postmulti -i example -p stop", Decision::NeedApproval),
        ("postmulti -e destroy -i example", Decision::NeedApproval),
        ("mailman --run-as-root start", Decision::NeedApproval),
        ("service example start --help", Decision::NeedApproval),
        ("service example status", Decision::Allow),
        ("postmulti -x sh -c 'rm -rf /'", Decision::Deny),
        ("postfix --unknown start; rm -rf /", Decision::Deny),
        ("mailman -C \"$(rm -rf /)\" start", Decision::Deny),
    ] {
        let response = check(command);
        assert_eq!(
            response.decision, expected,
            "{command}: {:?}",
            response.reasons
        );
    }
    let response = check("postfix start");
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::StateControl)
    );
    assert_eq!(
        fs::read_to_string(work.join("keep.txt")).unwrap(),
        "unchanged\n"
    );
    assert_eq!(fs::read_dir(work.join("config")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&work).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}
