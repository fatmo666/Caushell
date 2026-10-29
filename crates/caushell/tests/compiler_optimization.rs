//! Actual CLI processes, persistent store and current filesystem observations.
//! Compiler and submitted executable commands are judged, never executed here.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn optimized_builds_survive_restart_but_not_stale_paths_or_unknown_controls() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("compiler-optimization-{}", std::process::id()));
    let work = root.join("work");
    fs::create_dir_all(work.join("build")).unwrap();
    fs::write(work.join("input.c"), "not compiled\n").unwrap();
    fs::write(work.join("build/program"), "not executed\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let round = |command: &str, level: &str| {
        let shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete)
            .with_exact_scalar_variable("LEVEL", level, false);
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("optimization-cli"),
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
            panic!()
        };
        result.response
    };
    let command = "gcc -std=c17 -O\"$LEVEL\" -Wall input.c -o build/program && ./build/program";
    for (level, expected) in [
        ("2", Decision::Allow),
        ("g", Decision::Allow),
        ("unknown", Decision::NeedApproval),
        ("3", Decision::Allow),
        ("fast", Decision::Allow),
    ] {
        let result = round(command, level);
        assert_eq!(result.decision, expected, "{level}: {:?}", result.reasons);
        assert_eq!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty()),
            expected == Decision::Allow
        );
    }
    let deletion = round(
        "rm -f build/program; gcc -O2 input.c -o build/program && ./build/program",
        "2",
    );
    assert_eq!(deletion.decision, Decision::NeedApproval);
    assert!(
        deletion
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::FileDeletion)
    );
    assert!(
        !deletion
            .reasons
            .iter()
            .any(|r| r.contains("UnmodeledModifier")),
        "{:?}",
        deletion.reasons
    );
    assert_eq!(
        round("gcc -O2 input.c -o build/program; rm -rf /", "2").decision,
        Decision::Deny
    );
    assert_eq!(
        fs::read_to_string(work.join("build/program")).unwrap(),
        "not executed\n"
    );
    fs::remove_file(work.join("build/program")).unwrap();
    std::os::unix::fs::symlink("/outside/program", work.join("build/program")).unwrap();
    let stale = round(command, "2");
    assert_eq!(
        stale.decision,
        Decision::NeedApproval,
        "{:?}",
        stale.reasons
    );
    assert!(
        stale
            .decision_trace
            .path_targets
            .iter()
            .all(|p| p.namespace_proofs.is_empty())
    );
    fs::remove_dir_all(root).unwrap();
}
