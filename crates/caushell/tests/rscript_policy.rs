#![cfg(unix)]
use caushell_types::*;
use std::{
    fs,
    io::Cursor,
    sync::atomic::{AtomicU64, Ordering},
};

#[test]
fn rscript_stdio_boundary_and_file_authority_are_separate() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-rscript-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(
        work.join("program.R"),
        "stop('the test must never execute R')\n",
    )
    .unwrap();
    let config = root.join("config.yaml");
    fs::write(&config, "{}\n").unwrap();
    let mut runtime = caushell::create_runtime(Some(&config), Some(&root.join("store"))).unwrap();
    let cases = [
        ("Rscript -e 'print(7)'", Decision::NeedApproval),
        ("Rscript -e 1 -e 2 --help", Decision::NeedApproval),
        ("Rscript --vanilla -e 1 --version", Decision::NeedApproval),
        ("printf 'print(7)' | Rscript -", Decision::NeedApproval),
        ("Rscript - <<< 'print(7)'", Decision::NeedApproval),
        ("timeout 5 /usr/bin/Rscript -e 1", Decision::NeedApproval),
        ("echo \"$(Rscript -e 1)\"", Decision::NeedApproval),
        ("Rscript --unmodeled-control -e 1", Decision::NeedApproval),
        ("Rscript -e", Decision::NeedApproval),
        ("Rscript --version", Decision::Allow),
        ("Rscript --help -e this_is_help_data", Decision::Allow),
        ("Rscript program.R", Decision::Allow),
        (
            "Rscript --vanilla program.R --help -e argument_data",
            Decision::Allow,
        ),
        ("Rscript /opt/foreign/program.R", Decision::NeedApproval),
        ("Rscript -e 1; rm ./ordinary-file", Decision::NeedApproval),
        ("Rscript -e 1; rm -rf /", Decision::Deny),
        ("bash -c 'Rscript -e 1; rm -rf /'", Decision::Deny),
    ];
    for (index, (command, expected)) in cases.into_iter().enumerate() {
        let request = RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new(format!("rscript-{index}")),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap()),
            shell_kind: ShellKind::Bash,
            home: Some(root.to_str().unwrap().into()),
            workspace_root: Some(work.to_str().unwrap().into()),
            runtime: RuntimeMetadata {
                runtime_name: "owning-test-executor".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        };
        let wire = serde_json::to_string(&RuntimeTransportRequest::Check(request)).unwrap() + "\n";
        let mut out = Vec::new();
        caushell::serve_stdio(&mut runtime, Cursor::new(wire), &mut out).unwrap();
        let RuntimeTransportResponse::Check(r) = serde_json::from_slice(&out).unwrap() else {
            panic!()
        };
        assert_eq!(
            r.response.decision, expected,
            "{command}: {:?}",
            r.response.reasons
        );
    }
    assert_eq!(
        fs::read_to_string(work.join("program.R")).unwrap(),
        "stop('the test must never execute R')\n"
    );
    drop(runtime);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rscript_explicit_policy_deny_is_preserved() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "caushell-rscript-deny-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let config = root.join("config.yaml");
    fs::write(
        &config,
        "version: 1\npolicy:\n  rules:\n    non_shell_script_execution: deny\n",
    )
    .unwrap();
    let mut runtime = caushell::create_runtime(Some(&config), Some(&root.join("store"))).unwrap();
    let request: RuntimeCheckRequest = serde_json::from_value(serde_json::json!({
        "intent":"judge_only","session_id":"rscript-deny","command":"Rscript -e 1",
        "shell_kind":"bash","shell_state_before":{"cwd":root},
        "workspace_root":root,"runtime":{"runtime_name":"fixture","tool_name":"Bash",
            "shell_runtime_capabilities":ShellRuntimeCapabilities::request_only()}
    }))
    .unwrap();
    assert_eq!(
        runtime.handle_runtime_request(request).unwrap().decision,
        Decision::Deny
    );
    drop(runtime);
    fs::remove_dir_all(root).unwrap();
}
