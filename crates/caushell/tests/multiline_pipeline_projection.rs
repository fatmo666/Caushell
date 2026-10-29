//! Real stdio CLI and store restarts. Submitted shell commands never execute.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn multiline_pipeline_deletion_stays_ask_across_runtime_and_store_restarts() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("pipeline-projection-{}", std::process::id()));
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("victim"), "must remain untouched").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    for (command, expected, deletion) in [
        (
            "printf x | cat | head -3\nrm -f victim\nprintf done 2>err",
            Decision::NeedApproval,
            true,
        ),
        (
            "printf x | cat | cat\nprintf done >out",
            Decision::Allow,
            false,
        ),
        (
            "bash -c 'printf x | cat | cat\nrm -f victim\nprintf done >out'",
            Decision::NeedApproval,
            true,
        ),
        (
            "printf x | cat | cat\nrm -rf /\nprintf done >out",
            Decision::Deny,
            true,
        ),
        (
            "printf x | cat | cat\npython3 -c pass\nprintf done >out",
            Decision::NeedApproval,
            false,
        ),
        (
            "printf x | cat | cat\necho \"unterminated",
            Decision::NeedApproval,
            false,
        ),
        (
            "printf '%s' 'one\nrm -f victim' | cat | cat\nprintf done >out",
            Decision::Allow,
            false,
        ),
    ] {
        let shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("pipeline-cli"),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "stdio-regression".into(),
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
            panic!()
        };
        let response = result.response;
        assert_eq!(
            response.decision, expected,
            "{command}: {:?}",
            response.reasons
        );
        assert_eq!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|p| p.operation == PathTargetOperation::Delete),
            deletion,
            "{command}"
        );
        if deletion && expected == Decision::NeedApproval {
            assert!(
                response
                    .decision_trace
                    .decision_proposals
                    .iter()
                    .any(|p| p.rule_id == RuleId::FileDeletion)
            );
            assert!(
                response
                    .decision_trace
                    .execution_units
                    .iter()
                    .any(|u| u.raw_text == "rm -f victim")
            );
        }
        assert_eq!(
            fs::read_to_string(work.join("victim")).unwrap(),
            "must remain untouched"
        );
        assert!(!work.join("out").exists() && !work.join("err").exists());
    }
    fs::remove_dir_all(root).unwrap();
}
