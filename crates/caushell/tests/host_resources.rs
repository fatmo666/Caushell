use caushell::host::*;
use caushell_runner::{ManagedResource, ResourceLocatorScope, ResourceOwner};
use caushell_types::*;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
#[path = "support/owned_bash_frame.rs"]
mod owned_bash_frame;
use owned_bash_frame::OwnedBashFrame;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Client {
    process: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    root: PathBuf,
}
impl Client {
    fn start() -> Self {
        let root = std::env::temp_dir().join(format!(
            "caushell-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_caushell"))
            .args(["serve-host-stdio", "--config"])
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
        Self {
            input: process.stdin.take(),
            output: BufReader::new(process.stdout.take().unwrap()),
            process,
            root,
        }
    }
    fn send(&mut self, request: HostRequest) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    fn rpc(&mut self, request: HostRequest) -> HostResponse {
        self.send(request);
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "host closed before replying"
        );
        serde_json::from_str(&line).unwrap()
    }
    fn rejected(&mut self, request: HostRequest) {
        self.send(request);
        let mut line = String::new();
        assert_eq!(self.output.read_line(&mut line).unwrap(), 0, "{line}");
        self.input.take();
        assert!(!self.process.wait().unwrap().success());
    }
    fn frame(&mut self, command: &str, intent: CheckIntent, shell: &OwnedBashFrame) -> HostCheck {
        let mut request = self.request(command, intent);
        let HostResponse::ExecutionFramePlan(plan) =
            self.rpc(HostRequest::ExecutionFramePlan(ExecutionFramePlanRequest {
                request: request.clone(),
                executor_instance_id: shell.instance_id(),
            }))
        else {
            panic!("plan")
        };
        request.shell_state_before.execution_frame = Some(
            ExecutionFrameObservation::collect(plan.binding, &plan.requirements, shell).unwrap(),
        );
        HostCheck {
            request,
            owner: owner(shell),
            lifetime_ms: 60_000,
        }
    }
    fn shell(&mut self) -> OwnedBashFrame {
        let request = self.request("true", CheckIntent::JudgeOnly);
        let HostResponse::ExecutionFramePlan(plan) =
            self.rpc(HostRequest::ExecutionFramePlan(ExecutionFramePlanRequest {
                request,
                executor_instance_id: "planning".into(),
            }))
        else {
            panic!("plan")
        };
        OwnedBashFrame::start(&self.root, &plan.requirements)
    }
    fn request(&self, command: &str, intent: CheckIntent) -> RuntimeCheckRequest {
        RuntimeCheckRequest {
            intent,
            session_id: SessionId::new("host-session"),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new(self.root.to_str().unwrap())
                .with_variable_knowledge(ShellStateKnowledge::Complete)
                .with_alias_knowledge(ShellStateKnowledge::Complete)
                .with_function_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "owned-host".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some(self.root.to_str().unwrap().into()),
        }
    }
    fn judge(&mut self, command: &str, shell: &OwnedBashFrame) -> RuntimeCheckResponse {
        let request = self.frame(command, CheckIntent::JudgeOnly, shell);
        let HostResponse::Check(response) = self.rpc(HostRequest::Check(request)) else {
            panic!("check")
        };
        response
    }
    fn register(&mut self, origin: &str, shell: &OwnedBashFrame) -> ResourceHandle {
        let HostResponse::RegisterResource(handle) =
            self.rpc(HostRequest::RegisterResource(RegisterResource {
                resource: ManagedResource {
                    resource_id: "test-service".into(),
                    instance_id: "service-1".into(),
                    owner: owner(shell),
                    endpoints: vec![origin.into()],
                },
                scope: ResourceLocatorScope::HttpOrigin,
                lifetime_ms: 60_000,
            }))
        else {
            panic!("register")
        };
        handle
    }
    fn grant(&mut self, resource: ResourceHandle) -> GrantHandle {
        let HostResponse::GrantResource(handle) =
            self.rpc(HostRequest::GrantResource(GrantResource {
                grant_id: "test-policy-grant".into(),
                resource,
                domain: StateOperationDomain::RemoteResource,
                operation: StateOperationKind::Mutate,
                policy_id: "owned-result-service".into(),
                lifetime_ms: 60_000,
            }))
        else {
            panic!("grant")
        };
        handle
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.process.wait();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn owner(shell: &OwnedBashFrame) -> ResourceOwner {
    ResourceOwner {
        session_id: SessionId::new("host-session"),
        runtime_name: "owned-host".into(),
        executor_instance_id: shell.instance_id(),
        namespace_id: "owned-network".into(),
    }
}
fn frame_binding(request: &HostCheck) -> ExecutionFrameBinding {
    request
        .request
        .shell_state_before
        .execution_frame
        .as_ref()
        .unwrap()
        .binding
        .clone()
}
fn body_server(listener: TcpListener) -> std::thread::JoinHandle<Vec<u8>> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let began = std::time::Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && began.elapsed() < Duration::from_secs(10) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("HTTP accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
        }
        assert!(length <= 1024);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        body
    })
}

#[test]
fn private_host_pipe_checks_and_executes_with_separate_facts_grants_and_lifetimes() {
    let mut client = Client::start();
    let mut shell = client.shell();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let command = format!("curl -q --noproxy '*' --silent --data SAFE --url {origin}result");
    let resource = client.register(&origin, &shell);
    assert_eq!(
        client.judge(&command, &shell).decision,
        Decision::NeedApproval
    );
    let grant = client.grant(resource.clone());
    assert_eq!(client.judge(&command, &shell).decision, Decision::Allow);
    assert_eq!(
        client
            .judge(
                "curl -q --noproxy '*' --data SAFE --url http://127.0.0.1:1/result",
                &shell
            )
            .decision,
        Decision::NeedApproval
    );
    assert_eq!(
        client
            .judge(&format!("{command}; python3 -c 'pass'"), &shell)
            .decision,
        Decision::NeedApproval
    );
    assert_eq!(
        client
            .judge(&format!("{command}; rm -rf /"), &shell)
            .decision,
        Decision::Deny
    );
    client.rpc(HostRequest::RevokeResource(grant));
    assert_eq!(
        client.judge(&command, &shell).decision,
        Decision::NeedApproval
    );
    client.rpc(HostRequest::RetireResource(resource));
    assert_eq!(
        client.judge(&command, &shell).decision,
        Decision::NeedApproval
    );
    let resource = client.register(&origin, &shell);
    client.grant(resource.clone());
    let request = client.frame(&command, CheckIntent::ProposeForExecution, &shell);
    let binding = frame_binding(&request);
    let HostResponse::Check(response) = client.rpc(HostRequest::Check(request)) else {
        panic!("check")
    };
    assert_eq!(response.decision, Decision::Allow);
    let server = body_server(listener.try_clone().unwrap());
    assert!(matches!(
        client.rpc(HostRequest::BeginExecution(binding.clone())),
        HostResponse::BeginExecution(_)
    ));
    assert!(shell.execute(&command).success());
    assert_eq!(server.join().unwrap(), b"SAFE");
    client.rpc(HostRequest::CompleteExecution(ExecutionCompletion {
        binding,
        executed: true,
    }));
    client.rpc(HostRequest::RetireResource(resource));
    drop(listener);
}

#[test]
fn host_approval_is_single_call_and_cannot_start_a_denied_action() {
    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame(
        "python3 -c 'pass'",
        CheckIntent::ProposeForExecution,
        &shell,
    );
    let binding = frame_binding(&request);
    let HostResponse::Check(response) = client.rpc(HostRequest::Check(request)) else {
        panic!("check")
    };
    assert_eq!(response.decision, Decision::NeedApproval);
    let receipt = response.check_receipt.unwrap();
    let HostResponse::Authorize(response) = client.rpc(HostRequest::Authorize(ApprovalRequest {
        check_id: receipt.check_id,
        state_revision: receipt.state_revision,
        approved: true,
        authority: ApprovalAuthority::Host,
    })) else {
        panic!("approval")
    };
    assert!(response.approved);
    client.rpc(HostRequest::CompleteExecution(ExecutionCompletion {
        binding,
        executed: false,
    }));
    let request = client.frame("rm -rf /", CheckIntent::ProposeForExecution, &shell);
    let binding = frame_binding(&request);
    let HostResponse::Check(response) = client.rpc(HostRequest::Check(request)) else {
        panic!("check")
    };
    assert_eq!(response.decision, Decision::Deny);
    client.rejected(HostRequest::BeginExecution(binding));
}

#[test]
fn pending_execution_rejects_resource_changes_instead_of_releasing_its_lease() {
    let mut client = Client::start();
    let shell = client.shell();
    let resource = client.register("http://127.0.0.1:19221/", &shell);
    client.grant(resource.clone());
    let request = client.frame("true", CheckIntent::ProposeForExecution, &shell);
    assert!(matches!(
        client.rpc(HostRequest::Check(request)),
        HostResponse::Check(_)
    ));
    client.rejected(HostRequest::RetireResource(resource));
}

#[test]
fn judge_only_and_changed_bindings_cannot_start_execution() {
    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame("true", CheckIntent::JudgeOnly, &shell);
    let binding = frame_binding(&request);
    client.rpc(HostRequest::Check(request));
    client.rejected(HostRequest::BeginExecution(binding));

    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame("true", CheckIntent::ProposeForExecution, &shell);
    let mut binding = frame_binding(&request);
    client.rpc(HostRequest::Check(request));
    binding.command_sha256 = "a".repeat(64);
    client.rejected(HostRequest::BeginExecution(binding));
}

#[test]
fn retired_instance_and_reused_grant_ids_reject_stale_handles() {
    let mut client = Client::start();
    let shell = client.shell();
    let resource = client.register("http://127.0.0.1:19221/", &shell);
    let grant = client.grant(resource.clone());
    client.rpc(HostRequest::RevokeResource(grant.clone()));
    let renewed = client.grant(resource.clone());
    assert_ne!(grant.serial, renewed.serial);
    client.rejected(HostRequest::RevokeResource(grant));

    let mut client = Client::start();
    let shell = client.shell();
    let resource = client.register("http://127.0.0.1:19221/", &shell);
    client.rpc(HostRequest::RetireResource(resource.clone()));
    let renewed = client.register("http://127.0.0.1:19221/", &shell);
    assert_ne!(resource.generation, renewed.generation);
    client.rejected(HostRequest::RetireResource(resource));
}

#[test]
fn host_admission_requires_the_current_frame_owner_and_sequence() {
    let mut client = Client::start();
    let shell = client.shell();
    let mut request = client.frame("true", CheckIntent::JudgeOnly, &shell);
    request.owner.executor_instance_id = "another-executor".into();
    client.rejected(HostRequest::Check(request));

    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame("true", CheckIntent::JudgeOnly, &shell);
    client.rpc(HostRequest::Check(request.clone()));
    client.rejected(HostRequest::Check(request));
}

#[test]
fn admission_expiry_prevents_starting_an_already_checked_action() {
    let mut client = Client::start();
    let shell = client.shell();
    let mut request = client.frame("true", CheckIntent::ProposeForExecution, &shell);
    request.lifetime_ms = 1000;
    let binding = frame_binding(&request);
    let HostResponse::Check(response) = client.rpc(HostRequest::Check(request)) else {
        panic!("check")
    };
    assert_eq!(response.decision, Decision::Allow);
    std::thread::sleep(Duration::from_millis(1100));
    client.rejected(HostRequest::BeginExecution(binding));
}

#[test]
fn completion_and_approval_cannot_substitute_for_the_pending_binding() {
    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame("true", CheckIntent::ProposeForExecution, &shell);
    let binding = frame_binding(&request);
    client.rpc(HostRequest::Check(request));
    client.rejected(HostRequest::CompleteExecution(ExecutionCompletion {
        binding,
        executed: true,
    }));

    let mut client = Client::start();
    let shell = client.shell();
    let request = client.frame(
        "python3 -c 'pass'",
        CheckIntent::ProposeForExecution,
        &shell,
    );
    let HostResponse::Check(response) = client.rpc(HostRequest::Check(request)) else {
        panic!("check")
    };
    let mut receipt = response.check_receipt.unwrap();
    receipt.state_revision += 1;
    client.rejected(HostRequest::Authorize(ApprovalRequest {
        check_id: receipt.check_id,
        state_revision: receipt.state_revision,
        approved: true,
        authority: ApprovalAuthority::Host,
    }));
}
