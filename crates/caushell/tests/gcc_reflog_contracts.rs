//! Actual CLI/store acceptance. No compiler, Git command or submitted program is run.
#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn native_gcc_and_reflog_contracts_survive_real_cli_round_trips() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "gcc-reflog-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let work = root.join("work");
    fs::create_dir_all(work.join("build")).unwrap();
    fs::write(work.join("source.c"), "not compiled\n").unwrap();
    fs::write(work.join("build/tool"), "not executed\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let check = |command: &str| {
        let shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);
        let input = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("gcc-reflog-cli"),
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
        let mut stdin = child.stdin.take().unwrap();
        serde_json::to_writer(&mut stdin, &input).unwrap();
        stdin.write_all(b"\n").unwrap();
        drop(stdin);
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
        result.response
    };
    for (command, decision) in [
        (
            "gcc -DRELEASE -UOLD -Iheaders -Llib -xc++ -v source.c -obuild/tool && ./build/tool",
            Decision::Allow,
        ),
        (
            "gcc -Wl,--as-needed,-Bstatic,-Bdynamic source.c -o build/tool",
            Decision::Allow,
        ),
        (
            "gcc -lstdc++ source.c -o build/tool",
            Decision::Allow,
        ),
        (
            "gcc -Wl,-Map,/outside/map source.c -o build/tool",
            Decision::NeedApproval,
        ),
        (
            "gcc --unknown -fplugin=/outside/p.so source.c -o build/tool",
            Decision::NeedApproval,
        ),
        (
            "gcc -DRELEASE source.c -o build/tool; rm build/tool",
            Decision::NeedApproval,
        ),
        (
            "gcc -DRELEASE source.c -o build/tool; rm -rf /",
            Decision::Deny,
        ),
        (
            "git --no-pager reflog show --date=iso -30 HEAD",
            Decision::Allow,
        ),
        ("git reflog --date=iso", Decision::NeedApproval),
        (
            "git --no-pager reflog delete HEAD@{0}",
            Decision::NeedApproval,
        ),
        (
            "git --no-pager reflog expire --expire=now --all",
            Decision::NeedApproval,
        ),
        (
            "git --no-pager reflog --output=/outside/log",
            Decision::NeedApproval,
        ),
        ("git --no-pager reflog; rm -rf /", Decision::Deny),
    ] {
        let result = check(command);
        assert_eq!(result.decision, decision, "{command}: {:?}", result.reasons);
    }
    assert_eq!(
        fs::read_to_string(work.join("source.c")).unwrap(),
        "not compiled\n"
    );
    assert_eq!(
        fs::read_to_string(work.join("build/tool")).unwrap(),
        "not executed\n"
    );
    assert!(!work.join(".git").exists());
    fs::remove_dir_all(root).unwrap();
}
