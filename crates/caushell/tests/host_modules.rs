//! Real CLI/private-host protocol, persistent store and fresh filesystem facts.
//! Submitted interpreter/source commands are judged but are never executed.
#![cfg(unix)]
use caushell::host::*;
use caushell_core::LocalFilesystem;
use caushell_runner::{FilesystemView, ResourceOwner};
use caushell_types::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Client {
    process: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    root: PathBuf,
}
impl Client {
    fn start(root: PathBuf) -> Self {
        let mut process = Command::new(env!("CARGO_BIN_EXE_caushell"))
            .arg("serve-host-stdio")
            .arg("--config")
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
    fn rpc(&mut self, request: HostRequest) -> HostResponse {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).unwrap(), 0, "host exited");
        serde_json::from_str(&line).unwrap()
    }
    fn framed(&mut self, command: &str, intent: CheckIntent) -> HostCheck {
        let mut shell = ShellStateSnapshot::new(self.root.join("work").to_str().unwrap())
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);
        for name in [
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONPYCACHEPREFIX",
        ] {
            shell = shell.with_environment_observation(name, ShellEnvironmentValue::Absent);
        }
        let mut request = RuntimeCheckRequest {
            intent,
            session_id: SessionId::new("host-module"),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "owned-host".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
            home: None,
            workspace_root: Some(self.root.join("work").to_str().unwrap().into()),
        };
        let HostResponse::ExecutionFramePlan(plan) =
            self.rpc(HostRequest::ExecutionFramePlan(ExecutionFramePlanRequest {
                request: request.clone(),
                executor_instance_id: "module-executor".into(),
            }))
        else {
            panic!()
        };
        request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
            integer_variables: Default::default(),
            native_variants: Default::default(),
            binding: plan.binding,
            variables: Vec::new(),
            environment: request.shell_state_before.environment.clone(),
            pathname: None,
        });
        HostCheck {
            request,
            owner: ResourceOwner {
                session_id: SessionId::new("host-module"),
                runtime_name: "owned-host".into(),
                executor_instance_id: "module-executor".into(),
                namespace_id: "owned-module-ns".into(),
            },
            lifetime_ms: 60_000,
            module_identities: Vec::new(),
            module_permissions: Vec::new(),
        }
    }
    fn identity(&mut self, check: &HostCheck) -> ModuleIdentityFact {
        let HostResponse::ModuleContractPlan(queries) =
            self.rpc(HostRequest::ModuleContractPlan(ExecutionFramePlanRequest {
                request: check.request.clone(),
                executor_instance_id: "module-executor".into(),
            }))
        else {
            panic!()
        };
        let invocation = queries
            .into_iter()
            .find(|q| q.module == "py_compile")
            .unwrap();
        assert_eq!(
            invocation.binding,
            check
                .request
                .shell_state_before
                .execution_frame
                .as_ref()
                .unwrap()
                .binding
        );
        let view = LocalFilesystem;
        let executable = self
            .root
            .join("runtime/interpreter")
            .to_str()
            .unwrap()
            .to_string();
        let module_file = self
            .root
            .join("runtime/module.py")
            .to_str()
            .unwrap()
            .to_string();
        let files = [&executable, &module_file]
            .into_iter()
            .map(|path| {
                let o = view.runtime_file(path);
                (
                    path.clone(),
                    RuntimeFile {
                        sha256: o.content.sha256.unwrap(),
                        size: o.content.bytes_observed as u64,
                    },
                )
            })
            .collect();
        let namespace = [
            self.root.join("runtime"),
            self.root.join("work/py_compile.py"),
        ]
        .into_iter()
        .map(|p| {
            let path = p.to_str().unwrap().to_string();
            FilesystemObservation {
                source: view.source(),
                entry: view.entry(&path),
                path,
            }
        })
        .collect();
        ModuleIdentityFact {
            invocation,
            namespace_id: check.owner.namespace_id.clone(),
            loading_contract_sha256: "b".repeat(64),
            executable,
            module_file,
            files,
            namespace,
            directories: Vec::new(),
            environment: BTreeMap::from([
                ("PYTHONPATH".into(), ShellEnvironmentValue::Absent),
                ("PYTHONHOME".into(), ShellEnvironmentValue::Absent),
            ]),
        }
    }
    fn grant(identity: &ModuleIdentityFact) -> ModuleContractPermission {
        ModuleContractPermission {
            grant_id: "compiler-cli-policy".into(),
            namespace_id: identity.namespace_id.clone(),
            identity_sha256: identity.sha256(),
            loading_contract_sha256: identity.loading_contract_sha256.clone(),
        }
    }
    fn check(&mut self, check: HostCheck) -> RuntimeCheckResponse {
        let HostResponse::Check(response) = self.rpc(HostRequest::Check(check)) else {
            panic!()
        };
        response
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.process.wait();
    }
}
fn fixture() -> PathBuf {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "host-module-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("work")).unwrap();
    fs::create_dir_all(root.join("runtime")).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    fs::write(root.join("work/a.py"), "never executed").unwrap();
    fs::write(root.join("runtime/interpreter"), "pinned executable").unwrap();
    fs::set_permissions(
        root.join("runtime/interpreter"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(root.join("runtime/module.py"), "pinned loader closure").unwrap();
    root
}

#[test]
fn private_host_module_admission_survives_transport_but_not_restarts_or_scope_changes() {
    let root = fixture();
    let mut client = Client::start(root.clone());
    let check = client.framed("python3 -m py_compile a.py", CheckIntent::JudgeOnly);
    let identity = client.identity(&check);
    let old_grant = Client::grant(&identity);
    // Planning is read-only; it does not consume the frame's sequence.
    let check_again = client.framed("python3 -m py_compile a.py", CheckIntent::JudgeOnly);
    assert_eq!(
        check.request.shell_state_before.execution_frame,
        check_again.request.shell_state_before.execution_frame
    );
    let mut facts_only = check.clone();
    facts_only.module_identities = vec![identity.clone()];
    assert_eq!(client.check(facts_only).decision, Decision::NeedApproval);
    let mut check = client.framed("python3 -m py_compile a.py", CheckIntent::JudgeOnly);
    let identity = client.identity(&check);
    check.module_permissions = vec![Client::grant(&identity)];
    check.module_identities = vec![identity];
    let allowed = client.check(check);
    assert_eq!(allowed.decision, Decision::Allow, "{:?}", allowed.reasons);
    assert!(!root.join("work/__pycache__").exists());
    drop(client);
    let mut client = Client::start(root.clone());
    let check = client.framed("python3 -m py_compile a.py", CheckIntent::JudgeOnly);
    assert_eq!(client.check(check).decision, Decision::NeedApproval);
    let mut check = client.framed("python3 -m py_compile a.py", CheckIntent::JudgeOnly);
    let identity = client.identity(&check);
    check.module_identities = vec![identity.clone()];
    check.module_permissions = vec![old_grant];
    assert_eq!(client.check(check).decision, Decision::NeedApproval);
    let mut check = client.framed(
        "python3 -m py_compile a.py; rm a.py",
        CheckIntent::JudgeOnly,
    );
    let identity = client.identity(&check);
    check.module_permissions = vec![Client::grant(&identity)];
    check.module_identities = vec![identity];
    assert_eq!(client.check(check).decision, Decision::NeedApproval);
    drop(client);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn execution_begin_revalidates_module_artifacts_after_the_check() {
    let root = fixture();
    let mut client = Client::start(root.clone());
    let mut check = client.framed(
        "python3 -m py_compile a.py",
        CheckIntent::ProposeForExecution,
    );
    let identity = client.identity(&check);
    let binding = identity.invocation.binding.clone();
    check.module_permissions = vec![Client::grant(&identity)];
    check.module_identities = vec![identity];
    assert_eq!(client.check(check).decision, Decision::Allow);
    fs::write(root.join("runtime/module.py"), "replaced after check").unwrap();
    let input = client.input.as_mut().unwrap();
    serde_json::to_writer(&mut *input, &HostRequest::BeginExecution(binding)).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    assert_eq!(client.output.read_line(&mut line).unwrap(), 0, "{line}");
    client.input.take();
    assert!(!client.process.wait().unwrap().success());
    drop(client);
    fs::remove_dir_all(root).unwrap();
}
