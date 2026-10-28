//! Transport -> runtime -> core -> persistent store, without executing commands.
#![cfg(unix)]
use caushell_types::*;
use std::{fs, io::Cursor};

#[test]
fn stdio_restore_rechecks_current_namespace_and_keeps_deletion_approval() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-compiler-paths-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let work = root.join("work");
    fs::create_dir_all(work.join("build")).unwrap();
    fs::create_dir(root.join("outside")).unwrap();
    fs::write(work.join("source.c"), "not compiled\n").unwrap();
    fs::write(work.join("build/tool"), "not executed\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let round = |command: &str| {
        let mut shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
        shell.observability.variables = ShellStateKnowledge::Complete;
        shell.observability.aliases = ShellStateKnowledge::Complete;
        shell.observability.functions = ShellStateKnowledge::Complete;
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("compiler-stdio"),
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
        let mut runtime =
            caushell::create_runtime(Some(&root.join("defaults.yaml")), Some(&root.join("store")))
                .unwrap();
        let mut output = Vec::new();
        caushell::serve_stdio(
            &mut runtime,
            Cursor::new(serde_json::to_string(&request).unwrap() + "\n"),
            &mut output,
        )
        .unwrap();
        let RuntimeTransportResponse::Check(result) = serde_json::from_slice(&output).unwrap()
        else {
            panic!()
        };
        result.response
    };
    let first = round("gcc -Wall -Wextra -pedantic source.c -o build/tool && ./build/tool");
    assert_eq!(first.decision, Decision::Allow, "{:?}", first.reasons);
    assert!(
        first
            .decision_trace
            .path_targets
            .iter()
            .any(|f| !f.namespace_proofs.is_empty())
    );
    assert_eq!(round("gcc --version").decision, Decision::Allow);
    assert_eq!(round("rm -f build/tool").decision, Decision::NeedApproval);
    assert_eq!(
        fs::read_to_string(work.join("build/tool")).unwrap(),
        "not executed\n"
    );
    assert!(!work.join("a.out").exists());
    fs::remove_file(work.join("build/tool")).unwrap();
    // /tmp is intentionally an execution grant on Linux, so an adjacent
    // temporary directory is not an ungranted outside-scope target.
    std::os::unix::fs::symlink("/outside/tool", work.join("build/tool")).unwrap();
    let stale = round("./build/tool");
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
            .all(|f| f.namespace_proofs.is_empty())
    );
    fs::remove_dir_all(root).unwrap();
}
