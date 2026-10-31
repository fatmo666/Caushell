//! Real stdio admission path only; no compiler or submitted Shell is run.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn compiler_receives_facts_without_execution_or_extra_authority() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "cobc-admission-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("source.cbl"), "unchanged fixture\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    for (command, observe, expected) in [
        ("cobc --version", false, Decision::Allow),
        ("cobc -x -o program source.cbl", true, Decision::Allow),
        (
            "cobc -x -o program source.cbl",
            false,
            Decision::NeedApproval,
        ),
        (
            "cobc -x -o /opt/unowned-output source.cbl",
            true,
            Decision::NeedApproval,
        ),
        (
            "cobc -x -jV -o program source.cbl",
            true,
            Decision::NeedApproval,
        ),
        ("cobc -o--help source.cbl", true, Decision::NeedApproval),
        (
            "COB_CC='native-override' cobc -x -o program source.cbl",
            true,
            Decision::NeedApproval,
        ),
        (
            "cobc --version; rm source.cbl",
            false,
            Decision::NeedApproval,
        ),
        (
            "cobc -x -o program source.cbl; rm -rf /",
            true,
            Decision::Deny,
        ),
    ] {
        let mut shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_variable_knowledge(ShellStateKnowledge::Unknown)
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
        if observe {
            for name in [
                "COB_CC",
                "COB_CFLAGS",
                "COB_LDFLAGS",
                "COB_DEBUG_FLAGS",
                "COB_LIBS",
                "COB_LDADD",
                "COB_LIB_PATHS",
                "COB_CONFIG_DIR",
                "COBCPY",
                "TMPDIR",
                "TMP",
                "TEMP",
            ] {
                shell = shell.with_environment_observation(name, ShellEnvironmentValue::Absent);
            }
        }
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("cobc-cli"),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some(work.to_str().unwrap().into()),
            runtime: RuntimeMetadata {
                runtime_name: "stdio-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
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
            panic!("unexpected response")
        };
        assert_eq!(
            result.response.decision, expected,
            "{command}: {:?}",
            result.response.reasons
        );
    }
    assert_eq!(
        fs::read_to_string(work.join("source.cbl")).unwrap(),
        "unchanged fixture\n"
    );
    assert_eq!(fs::read_dir(&work).unwrap().count(), 1);
    assert!(!work.join("program").exists());
    fs::remove_dir_all(root).unwrap();
}
