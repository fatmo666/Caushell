//! Static admission tests. No submitted interpreter or source is executed.
#![cfg(unix)]
use caushell_core::{LocalFilesystem, ShellQueryCore};
use caushell_runner::{FilesystemView, ModuleContractScope};
use caushell_types::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    time::Duration,
};

struct Fixture {
    root: PathBuf,
    work: PathBuf,
    runtime: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "module-contract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work = root.join("work");
        let runtime = root.join("runtime");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        fs::write(work.join("a.py"), "source is not executed").unwrap();
        fs::write(work.join("b.py"), "another source").unwrap();
        fs::write(runtime.join("interpreter"), "pinned interpreter").unwrap();
        fs::set_permissions(
            runtime.join("interpreter"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(runtime.join("module.py"), "pinned CLI loading closure").unwrap();
        Self {
            root,
            work,
            runtime,
        }
    }
    fn request(&self, command: &str, sequence: u64) -> CheckRequest {
        let mut shell = ShellStateSnapshot::new(self.work.to_str().unwrap());
        for name in [
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONPYCACHEPREFIX",
        ] {
            shell = shell.with_environment_observation(name, ShellEnvironmentValue::Absent);
        }
        shell.observability.variables = ShellStateKnowledge::Complete;
        shell.observability.aliases = ShellStateKnowledge::Complete;
        shell.observability.functions = ShellStateKnowledge::Complete;
        let mut request = CheckRequest {
            session_id: SessionId::new("module-admission"),
            sequence_no: CommandSequenceNo(sequence),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "owning-executor".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
            home: None,
            workspace_root: Some(self.work.to_str().unwrap().into()),
        };
        request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
            variable_values: Vec::new(),
            integer_variables: Default::default(),
            native_variants: Default::default(),
            binding: ExecutionFrameBinding::for_request(&request, "executor-instance"),
            variables: Vec::new(),
            environment: request.shell_state_before.environment.clone(),
            pathname: None,
        });
        request
    }
    fn identity(&self, request: &CheckRequest) -> ModuleIdentityFact {
        let response = ShellQueryCore::new().check(request.clone());
        let query = response
            .decision_trace
            .evidence
            .into_iter()
            .find_map(|e| match e.kind {
                EvidenceKind::ModuleContract(e) => Some(e.invocation),
                _ => None,
            })
            .expect("registered module query");
        let view = LocalFilesystem;
        let executable = self
            .runtime
            .join("interpreter")
            .to_str()
            .unwrap()
            .to_string();
        let module_file = self.runtime.join("module.py").to_str().unwrap().to_string();
        let files = [&executable, &module_file]
            .into_iter()
            .map(|p| {
                let o = view.runtime_file(p);
                (
                    p.clone(),
                    RuntimeFile {
                        sha256: o.content.sha256.unwrap(),
                        size: o.content.bytes_observed as u64,
                    },
                )
            })
            .collect();
        let namespace = [
            self.runtime.clone(),
            self.work.join("py_compile.py"),
            self.work.join("py_compile"),
        ]
        .into_iter()
        .map(|p| {
            let p = p.to_str().unwrap().to_string();
            FilesystemObservation {
                source: view.source(),
                entry: view.entry(&p),
                path: p,
            }
        })
        .collect();
        ModuleIdentityFact {
            invocation: query,
            namespace_id: "container-ns".into(),
            loading_contract_sha256: "a".repeat(64),
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
    fn scope(&self, fact: ModuleIdentityFact, grant: bool) -> ModuleContractScope {
        let permissions = if grant {
            vec![ModuleContractPermission {
                grant_id: "host-cli-policy".into(),
                namespace_id: fact.namespace_id.clone(),
                identity_sha256: fact.sha256(),
                loading_contract_sha256: fact.loading_contract_sha256.clone(),
            }]
        } else {
            Vec::new()
        };
        ModuleContractScope::new(
            fact.invocation.binding.clone(),
            fact.namespace_id.clone(),
            vec![fact],
            permissions,
            Duration::from_secs(60),
        )
        .unwrap()
    }
    fn check(&self, request: CheckRequest, scope: ModuleContractScope) -> CheckResponse {
        let mut core = ShellQueryCore::new();
        core.set_module_contract_scope(Some(scope));
        core.check(request)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn identity_facts_and_cli_permission_are_independent_of_file_authority() {
    let f = Fixture::new();
    let request = f.request("python3 -m py_compile a.py", 1);
    let identity = f.identity(&request);
    let no_grant = f.check(request.clone(), f.scope(identity.clone(), false));
    assert_eq!(no_grant.decision, Decision::NeedApproval);
    assert!(no_grant.decision_trace.evidence.iter().any(|e|matches!(&e.kind,EvidenceKind::ModuleContract(e) if e.identity_verified && e.grant_id.is_none())));
    let allowed = f.check(request.clone(), f.scope(identity.clone(), true));
    assert_eq!(allowed.decision, Decision::Allow, "{:?}", allowed.reasons);
    assert!(
        allowed
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::DirectoryTree(e) if e.complete))
    );
    assert!(!f.work.join("__pycache__").exists());
    let outside = f.request(
        "PYTHONPYCACHEPREFIX=/outside/cache python3 -m py_compile a.py",
        2,
    );
    let identity = f.identity(&outside);
    let result = f.check(outside, f.scope(identity, true));
    assert_eq!(
        result.decision,
        Decision::NeedApproval,
        "{:?}",
        result.reasons
    );
}

#[test]
fn files_environment_namespace_and_request_replay_are_revalidated() {
    let f = Fixture::new();
    let request = f.request("python3 -m py_compile a.py", 1);
    let identity = f.identity(&request);
    let scope = f.scope(identity.clone(), true);
    assert_eq!(
        f.check(f.request("python3 -m py_compile a.py", 2), scope.clone())
            .decision,
        Decision::NeedApproval
    );
    fs::write(f.runtime.join("module.py"), "changed CLI").unwrap();
    assert_eq!(
        f.check(request.clone(), scope).decision,
        Decision::NeedApproval
    );
    let identity = f.identity(&request);
    let scope = f.scope(identity, true);
    fs::write(f.work.join("py_compile.py"), "shadow module").unwrap();
    assert_eq!(
        f.check(request.clone(), scope).decision,
        Decision::NeedApproval
    );
    fs::remove_file(f.work.join("py_compile.py")).unwrap();
    let identity = f.identity(&request);
    let scope = f.scope(identity, true);
    fs::remove_file(f.runtime.join("module.py")).unwrap();
    symlink(f.work.join("a.py"), f.runtime.join("module.py")).unwrap();
    assert_eq!(f.check(request, scope).decision, Decision::NeedApproval);
}

#[test]
fn unknown_environment_and_same_action_mutation_cannot_borrow_identity() {
    let f = Fixture::new();
    let mut request = f.request("python3 -m py_compile a.py", 1);
    let mut identity = f.identity(&request);
    request.shell_state_before = request
        .shell_state_before
        .with_environment_observation("UNOBSERVED_IMPORT_SETTING", ShellEnvironmentValue::Unknown);
    request
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .environment = request.shell_state_before.environment.clone();
    identity.environment.insert(
        "UNOBSERVED_IMPORT_SETTING".into(),
        ShellEnvironmentValue::Absent,
    );
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
    let command = format!(
        "touch {}/module.py; python3 -m py_compile a.py",
        f.runtime.display()
    );
    let request = f.request(&command, 1);
    let identity = f.identity(&request);
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
}

#[test]
fn directory_families_reject_links_missing_observations_and_keep_deletion_approval() {
    let f = Fixture::new();
    let request = f.request("python3 -m py_compile a.py b.py", 1);
    let identity = f.identity(&request);
    assert_eq!(
        f.check(request.clone(), f.scope(identity, true)).decision,
        Decision::Allow
    );
    fs::create_dir(f.work.join("__pycache__")).unwrap();
    symlink(
        f.runtime.join("module.py"),
        f.work.join("__pycache__/other.pyc"),
    )
    .unwrap();
    let identity = f.identity(&request);
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
    let request = f.request("python3 -m py_compile a.py; rm a.py", 2);
    let identity = f.identity(&request);
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
}

#[test]
fn loader_environment_requires_consistent_exported_shell_facts() {
    let f = Fixture::new();
    let mut request = f.request("python3 -m py_compile a.py", 1);
    request.shell_state_before = request
        .shell_state_before
        .with_exact_scalar_variable("HOME", "/home/owner", true)
        .with_environment_observation(
            "HOME",
            ShellEnvironmentValue::Present {
                value: "/home/owner".into(),
            },
        );
    request
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .environment = request.shell_state_before.environment.clone();
    let mut identity = f.identity(&request);
    identity.environment.insert(
        "HOME".into(),
        ShellEnvironmentValue::Present {
            value: "/home/owner".into(),
        },
    );
    assert_eq!(
        f.check(request.clone(), f.scope(identity.clone(), true))
            .decision,
        Decision::Allow
    );
    request.shell_state_before.variables.clear();
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
}

#[test]
fn explicit_deny_and_sibling_scripts_survive_module_admission() {
    let f = Fixture::new();
    for (command, rule) in [
        (
            "python3 -m py_compile a.py",
            RuleId::NonShellScriptExecution,
        ),
        ("python3 -m py_compile a.py; rm a.py", RuleId::FileDeletion),
    ] {
        let request = f.request(command, 1);
        let identity = f.identity(&request);
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(rule, RulePolicyEntry::new(RuleAction::Deny));
        let mut core = ShellQueryCore::with_policy(policy);
        core.set_module_contract_scope(Some(f.scope(identity, true)));
        assert_eq!(core.check(request).decision, Decision::Deny);
    }
    for command in [
        "python3 -m py_compile a.py; python3 -c 'print(1)'",
        "python3 -m py_compile a.py; unknown-operation",
    ] {
        let request = f.request(command, 1);
        let identity = f.identity(&request);
        assert_eq!(
            f.check(request, f.scope(identity, true)).decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn no_scope_is_resurrected_from_session_snapshots_or_reused_checks() {
    let f = Fixture::new();
    let request = f.request("python3 -m py_compile a.py", 1);
    let identity = f.identity(&request);
    let mut core = ShellQueryCore::new();
    core.set_module_contract_scope(Some(f.scope(identity, true)));
    assert_eq!(core.check(request.clone()).decision, Decision::Allow);
    assert_eq!(
        core.check(f.request("python3 -m py_compile a.py", 2))
            .decision,
        Decision::NeedApproval
    );
    if let Some(snapshot) = core.session_snapshot(&SessionId::new("module-admission"), 0) {
        let snapshot: SessionSnapshot =
            serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let mut restored = ShellQueryCore::new();
        restored.insert_session_state(
            snapshot.session_id.clone(),
            caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
        );
        assert_eq!(
            restored
                .check(f.request("python3 -m py_compile a.py", 3))
                .decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn output_families_resolve_physical_roots_without_leaking_authority() {
    let f = Fixture::new();
    let external = f.root.join("outside");
    fs::create_dir(&external).unwrap();
    symlink("/outside/cache", f.work.join("__pycache__")).unwrap();
    let request = f.request("python3 -m py_compile a.py", 1);
    let identity = f.identity(&request);
    let result = f.check(request, f.scope(identity, true));
    assert_eq!(
        result.decision,
        Decision::NeedApproval,
        "{:?}",
        result.reasons
    );
    fs::remove_file(f.work.join("__pycache__")).unwrap();
    for command in [
        "PYTHONPYCACHEPREFIX=cache python3 -m py_compile a.py",
        "PYTHONPYCACHEPREFIX= python3 -m py_compile a.py",
        "python3 -B -m py_compile a.py",
        "python3 -E -m py_compile a.py",
    ] {
        let request = f.request(command, 1);
        let identity = f.identity(&request);
        let result = f.check(request, f.scope(identity, true));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
    let mut request = f.request(
        "PYTHONPYCACHEPREFIX=\"$UNKNOWN\" python3 -m py_compile a.py",
        1,
    );
    request.shell_state_before = request
        .shell_state_before
        .with_opaque_dynamic_variable("UNKNOWN", "$RUNTIME", false);
    let identity = f.identity(&request);
    assert_eq!(
        f.check(request, f.scope(identity, true)).decision,
        Decision::NeedApproval
    );
}
