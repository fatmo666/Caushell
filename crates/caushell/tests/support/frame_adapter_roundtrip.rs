#[path = "owned_bash_frame.rs"]
mod owned_bash_frame;
use caushell_types::*;
use owned_bash_frame::OwnedBashFrame;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

pub fn roundtrip(
    runtime_name: &str,
    command: &str,
    attach: bool,
    model_only: bool,
    invalid: bool,
    run: impl FnOnce(&Path, &[u8], &mut Vec<u8>),
) -> CheckResponse {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "cs-frame-adapter-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("report.data"), "report\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let requirements = caushell_profile::execution_frame_requirements(registry.profiles());
    let owner = OwnedBashFrame::start(&work, &requirements);
    let request = CheckRequest {
        session_id: SessionId::new("adapter-frame"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap()),
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some(work.to_str().unwrap().into()),
        runtime: RuntimeMetadata {
            runtime_name: runtime_name.into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    };
    let mut payload = serde_json::json!({"session_id":"adapter-frame","cwd":work,
        "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":command}});
    let socket = root.join("runtime.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime_root = root.clone();
    let server = thread::spawn(move || {
        let mut runtime = caushell::create_runtime(
            Some(&runtime_root.join("defaults.yaml")),
            Some(&runtime_root.join("store")),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "adapter did not send a check"
            );
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut raw = String::new();
            BufReader::new(&stream).read_line(&mut raw).unwrap();
            let request: RuntimeTransportRequest = serde_json::from_str(&raw).unwrap();
            let is_check = matches!(request, RuntimeTransportRequest::Check(_));
            let response = runtime.handle_runtime_transport_request(request).unwrap();
            writeln!(stream, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            if is_check {
                if let RuntimeTransportResponse::Check(r) = response {
                    break r.response;
                }
            }
        }
    });
    if attach || model_only {
        let plan_request = ExecutionFramePlanRequest {
            executor_instance_id: owner.instance_id(),
            request: RuntimeCheckRequest {
                intent: CheckIntent::ProposeForExecution,
                session_id: request.session_id,
                command: request.command,
                shell_state_before: request.shell_state_before,
                shell_kind: request.shell_kind,
                runtime: request.runtime,
                home: request.home,
                workspace_root: request.workspace_root,
            },
        };
        let plan = caushell::plan_execution_frame_unix_socket(&socket, &plan_request).unwrap();
        assert_eq!(plan.requirements, requirements);
        let mut frame =
            ExecutionFrameObservation::collect(plan.binding, &plan.requirements, &owner).unwrap();
        if invalid {
            frame.binding.sequence_no = CommandSequenceNo(100);
        }
        if attach {
            payload["execution_frame"] = serde_json::to_value(&frame).unwrap();
        }
        if model_only {
            payload["tool_input"]["execution_frame"] = serde_json::to_value(&frame).unwrap();
        }
    }
    let mut output = Vec::new();
    run(&socket, &serde_json::to_vec(&payload).unwrap(), &mut output);
    let response = server.join().unwrap();
    let visible = if output.is_empty() {
        "allow".to_string()
    } else {
        serde_json::from_slice::<serde_json::Value>(&output).unwrap()["hookSpecificOutput"]["permissionDecision"]
            .as_str().unwrap().into()
    };
    assert_eq!(visible == "allow", response.decision == Decision::Allow);
    assert!(!work.join("out.tar").exists());
    assert_eq!(
        fs::read_to_string(work.join("report.data")).unwrap(),
        "report\n"
    );
    drop(owner);
    fs::remove_dir_all(root).unwrap();
    response
}
