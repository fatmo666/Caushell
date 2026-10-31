//! Judge shell text through real CLI/store/filesystem observations. Never execute it.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn wrapper_argument_ownership_preserves_child_effects_and_uncertainty_end_to_end() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("wrapper-argv-{}", std::process::id()));
    let work = root.join("work");
    fs::create_dir_all(work.join("frames")).unwrap();
    fs::write(work.join("clip.mp4"), "not processed\n").unwrap();
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
            session_id: SessionId::new("wrapper-argv"),
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
        let mut process = Command::new(env!("CARGO_BIN_EXE_caushell"))
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
        let mut input = process.stdin.take().unwrap();
        serde_json::to_writer(&mut input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        drop(input);
        let output = process.wait_with_output().unwrap();
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
    for (command, expected) in [
        ("time printf '%s' -v -f -o --help", Decision::Allow),
        (
            "time ffmpeg -v error -i clip.mp4 -vf fps=5 -vsync cfr frames/f_%04d.png",
            // The child argv must survive even when the output pattern's path
            // namespace cannot be proved. Argument preservation grants no access.
            Decision::NeedApproval,
        ),
        ("command rm -v /", Decision::Deny),
        ("exec rm -rf /", Decision::Deny),
        ("nohup rm -vfr /", Decision::Deny),
        ("stdbuf -oL rm -vfr /", Decision::Deny),
        ("time rm -vfr /", Decision::Deny),
        ("time command nohup rm -rf /", Decision::Deny),
        ("time rm -v frames/output", Decision::NeedApproval),
        ("time python3 -c 'print(1)'", Decision::NeedApproval),
        ("time \"$CHILD\" --format -x", Decision::NeedApproval),
        ("time --unmodeled printf ok", Decision::NeedApproval),
        ("time -f", Decision::NeedApproval),
        ("time -o", Decision::NeedApproval),
        ("time --unmodeled printf ok; rm -rf /", Decision::Deny),
        ("time printf '%s' '$(rm -rf /)'", Decision::Allow),
        ("time printf '%s' \"$(rm -rf /)\"", Decision::Deny),
    ] {
        let result = check(command);
        assert_eq!(result.decision, expected, "{command}: {:?}", result.reasons);
    }
    let result = check("time ffmpeg -v error -i clip.mp4 -vf fps=5 -vsync cfr frames/f_%04d.png");
    assert!(
        result
            .decision_trace
            .derived_invocations
            .iter()
            .any(|child| child.raw_text
                == "ffmpeg -v error -i clip.mp4 -vf fps=5 -vsync cfr frames/f_%04d.png")
    );
    assert_eq!(
        fs::read_to_string(work.join("clip.mp4")).unwrap(),
        "not processed\n"
    );
    assert_eq!(fs::read_dir(work.join("frames")).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}
