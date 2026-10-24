use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView, MAX_RUNTIME_FILE_BYTES, content_sha256};
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone)]
struct Files {
    data: BTreeMap<String, Vec<u8>>,
    directories: Vec<String>,
    executable: bool,
    unavailable: bool,
    lookup: Option<ShellExecutableObservation>,
}
fn identity(size: usize) -> FileContentIdentity {
    FileContentIdentity {
        device: 1,
        inode: 2,
        size: size as u64,
        modified_seconds: 1,
        modified_nanos: 0,
        changed_seconds: 1,
        changed_nanos: 0,
    }
}
impl Files {
    fn new() -> Self {
        Self {
            data: BTreeMap::from([
                ("/usr/bin/python3".into(), b"interpreter".to_vec()),
                ("/runtime/lib/json.py".into(), b"registered source".to_vec()),
            ]),
            directories: vec![
                "/".into(),
                "/workspace".into(),
                "/runtime".into(),
                "/usr".into(),
                "/usr/bin".into(),
                "/runtime/lib".into(),
                "/runtime/site".into(),
            ],
            executable: true,
            unavailable: false,
            lookup: None,
        }
    }
    fn children(&self, path: &str) -> Vec<DirectoryEntry> {
        let mut entries = BTreeMap::new();
        for (name, kind) in self
            .data
            .keys()
            .map(|n| (n, DirectoryEntryKind::File))
            .chain(
                self.directories
                    .iter()
                    .map(|n| (n, DirectoryEntryKind::Directory)),
            )
        {
            let p = std::path::Path::new(name);
            if p.parent().is_some_and(|p| p.to_str() == Some(path))
                && let Some(name) = p.file_name().and_then(|n| n.to_str())
            {
                entries.insert(
                    name.to_owned(),
                    DirectoryEntry {
                        name: name.into(),
                        kind,
                        identity: identity(0),
                    },
                );
            }
        }
        entries.into_values().collect()
    }
    fn contract(&self) -> PythonRuntimeContract {
        PythonRuntimeContract {
            schema: "caushell.python-runtime/v1".into(),
            version: [3, 11, 2],
            platform: "linux".into(),
            executable: "/usr/bin/python3".into(),
            account: RuntimeAccount {
                uid: 1,
                euid: 1,
                gid: 1,
                egid: 1,
            },
            account_home: "/account".into(),
            search_paths: vec!["/runtime/lib".into()],
            extension_suffixes: vec![".so".into()],
            site_directories: vec!["/runtime/site".into()],
            absent_configuration: vec![],
            stdlib_names: vec!["http".into(), "json".into(), "os".into(), "sys".into()],
            builtin_modules: vec!["sys".into()],
            frozen_modules: vec!["os".into()],
            modules: BTreeMap::from([
                (
                    "json".into(),
                    PythonModuleOrigin::File {
                        path: "/runtime/lib/json.py".into(),
                    },
                ),
                ("os".into(), PythonModuleOrigin::Frozen),
            ]),
            files: self
                .data
                .iter()
                .map(|(path, bytes)| {
                    (
                        path.clone(),
                        RuntimeFile {
                            sha256: content_sha256(bytes),
                            size: bytes.len() as u64,
                        },
                    )
                })
                .collect(),
            directories: BTreeMap::from([(
                "/runtime/lib".into(),
                self.children("/runtime/lib")
                    .into_iter()
                    .map(|e| RuntimeDirectoryEntry {
                        name: e.name,
                        kind: e.kind,
                    })
                    .collect(),
            )]),
            symlinks: BTreeMap::new(),
        }
    }
}
impl FilesystemView for Files {
    fn read_file(&self, path: &str, limit: usize) -> caushell_runner::FileContentRead {
        match self.data.get(path) {
            Some(bytes) => caushell_runner::FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                Some(identity(bytes.len())),
                bytes.clone(),
            ),
            None => caushell_runner::FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "missing fixture file",
            ),
        }
    }
    fn shell_executable(
        &self,
        _command: &str,
        _cwd: &str,
        _shell: ShellKind,
        _path: &ShellEnvironmentValue,
    ) -> Option<ShellExecutableObservation> {
        self.lookup.clone()
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        if self.unavailable {
            FilesystemEntry::Unavailable {
                reason: "no namespace".into(),
            }
        } else if self.directories.iter().any(|p| p == path) {
            FilesystemEntry::Directory
        } else if self.data.contains_key(path) {
            FilesystemEntry::File
        } else {
            FilesystemEntry::Missing
        }
    }
    fn execution_account(&self) -> Option<RuntimeAccount> {
        Some(RuntimeAccount {
            uid: 1,
            euid: 1,
            gid: 1,
            egid: 1,
        })
    }
    fn runtime_file(&self, path: &str) -> RuntimeFileObservation {
        let bytes = &self.data[path];
        RuntimeFileObservation {
            content: FileContentObservation {
                source: FileContentSource::SuppliedView,
                path: path.into(),
                status: FileContentStatus::Complete,
                byte_limit: MAX_RUNTIME_FILE_BYTES,
                bytes_observed: bytes.len(),
                sha256: Some(content_sha256(bytes)),
                identity: Some(identity(bytes.len())),
                detail: None,
            },
            executable: Some(self.executable),
        }
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        DirectoryRead::complete(
            FilesystemObservationSource::SuppliedView,
            path,
            limits,
            identity(0),
            self.children(path),
        )
    }
}
fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("runtime-origins"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(files: Files, contract: PythonRuntimeContract, command: &str) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .with_python_runtime_contract(contract)
        .check(request(command))
}
fn startup(response: &CheckResponse) -> &PythonStartupEvidence {
    response
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| match &e.kind {
            EvidenceKind::PythonStartup(p) => Some(p),
            _ => None,
        })
        .expect("startup evidence")
}
const PROGRAM: &str = "/usr/bin/python3 -c 'import json; print(json.dumps({\"a\":1}))'";

#[test]
fn ordinary_startup_uses_registered_runtime_and_fresh_module_origins() {
    let files = Files::new();
    let contract = files.contract();
    let response = check(files, contract, PROGRAM);
    assert!(startup(&response).complete, "{:?}", startup(&response));
    assert_eq!(
        response.decision,
        Decision::Allow,
        "{:?}",
        response.decision_trace
    );
    assert_eq!(
        startup(&response).executable.as_deref(),
        Some("/usr/bin/python3")
    );
    assert!(
        matches!(&startup(&response).modules["json"],PythonModuleOrigin::File {path} if path=="/runtime/lib/json.py")
    );
    assert!(
        startup(&response)
            .contract_sha256
            .as_ref()
            .is_some_and(|s| s.len() == 64)
    );
}

#[test]
fn changed_runtime_files_permissions_namespace_and_descriptor_fail_closed() {
    for change in 0..6 {
        let mut files = Files::new();
        let mut contract = files.contract();
        match change {
            0 => {
                files
                    .data
                    .insert("/usr/bin/python3".into(), b"other interpreter".to_vec());
            }
            1 => {
                files
                    .data
                    .insert("/runtime/lib/json.py".into(), b"other source".to_vec());
            }
            2 => files.executable = false,
            3 => files.unavailable = true,
            4 => contract.version = [3, 12, 0],
            5 => {
                files
                    .data
                    .insert("/runtime/lib/new_module.py".into(), vec![]);
            }
            _ => unreachable!(),
        }
        let r = check(files, contract, PROGRAM);
        assert!(!startup(&r).complete, "change {change}");
        assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
    }
    let mut files = Files::new();
    let contract = files.contract();
    files.data.insert("/usr/bin/python3".into(), vec![]);
    let r = check(files, contract, "/usr/bin/python3 -I -S -c 'print(1)'");
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(!startup(&r).complete);
}

#[test]
fn module_shadowing_covers_transitive_names_but_not_frozen_module_files() {
    for name in ["json.py", "http.py", "sitecustomize.py"] {
        let mut files = Files::new();
        let contract = files.contract();
        files
            .data
            .insert(format!("/workspace/{name}"), b"unknown code".to_vec());
        let r = check(files, contract, PROGRAM);
        assert!(!startup(&r).complete, "{name}: {:?}", startup(&r));
        assert_eq!(r.decision, Decision::NeedApproval);
    }
    let mut files = Files::new();
    let contract = files.contract();
    files
        .data
        .insert("/workspace/os.py".into(), b"not selected".to_vec());
    let r = check(files, contract, "/usr/bin/python3 -c 'import os; print(1)'");
    assert!(startup(&r).complete, "{:?}", startup(&r));
    assert_eq!(r.decision, Decision::Allow);
}

#[test]
fn startup_environment_and_site_controls_keep_actual_order_and_missing_facts() {
    for prefix in [
        "PYTHONHOME=/other ",
        "PYTHONINSPECT=1 ",
        "PYTHONWARNINGS=error ",
        "LD_PRELOAD=/unknown ",
    ] {
        let files = Files::new();
        let r = check(
            files.clone(),
            files.contract(),
            &format!("{prefix}{PROGRAM}"),
        );
        assert!(!startup(&r).complete, "{prefix}");
        assert_eq!(r.decision, Decision::NeedApproval);
    }
    let files = Files::new();
    let mut req = request(PROGRAM);
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files.clone()))
        .with_python_runtime_contract(files.contract())
        .check(req);
    assert!(!startup(&r).complete);
    let mut files = Files::new();
    let contract = files.contract();
    files
        .data
        .insert("/runtime/site/extra.pth".into(), b"import unknown".to_vec());
    let r = check(files.clone(), contract.clone(), PROGRAM);
    assert!(!startup(&r).complete);
    let r = check(
        files,
        contract,
        "/usr/bin/python3 -S -c 'import json; print(1)'",
    );
    assert!(startup(&r).complete, "{:?}", startup(&r));
}

#[test]
fn pending_namespace_writes_and_unobserved_shell_lookup_are_not_startup_proofs() {
    for command in [
        "touch /workspace/other; /usr/bin/python3 -c 'print(1)'",
        "/usr/bin/python3 -c 'print(1)' > /runtime/lib/json.py",
        "python3 -c 'print(1)'",
    ] {
        let files = Files::new();
        let r = check(files.clone(), files.contract(), command);
        assert!(!startup(&r).complete, "{command}: {:?}", startup(&r));
        assert_eq!(r.decision, Decision::NeedApproval);
    }
}

#[test]
fn output_producers_share_the_startup_contract_without_changing_argv_data() {
    let files = Files::new();
    let r = check(
        files.clone(),
        files.contract(),
        "touch -- \"/workspace/$(/usr/bin/python3 -c 'print(\"a b\")')\"",
    );
    assert!(
        r.decision_trace.evidence.iter().any(
            |e| matches!(&e.kind,EvidenceKind::PythonStdoutField(p) if p.value=="/workspace/a b")
        ),
        "{:?}",
        r.decision_trace
    );
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
}

#[test]
fn bare_command_lookup_is_scoped_to_name_cwd_path_and_shell() {
    let observation = ShellExecutableObservation {
        source: FilesystemObservationSource::SuppliedView,
        command: "python3".into(),
        cwd: "/workspace".into(),
        shell_kind: ShellKind::Bash,
        path_environment: ShellEnvironmentValue::Absent,
        executable: "/usr/bin/python3".into(),
    };
    let mut files = Files::new();
    let contract = files.contract();
    files.lookup = Some(observation.clone());
    let r = check(
        files.clone(),
        contract.clone(),
        "python3 -c 'import json; print(1)'",
    );
    assert!(startup(&r).complete, "{:?}", startup(&r));
    assert_eq!(r.decision, Decision::Allow);
    assert_eq!(startup(&r).executable_lookup, Some(observation.clone()));
    for change in 0..5 {
        let mut other = observation.clone();
        match change {
            0 => other.cwd = "/other".into(),
            1 => other.command = "python".into(),
            2 => other.shell_kind = ShellKind::Zsh,
            3 => {
                other.path_environment = ShellEnvironmentValue::Present {
                    value: "/other".into(),
                }
            }
            4 => other.executable = "/other/python3".into(),
            _ => unreachable!(),
        }
        files.lookup = Some(other);
        let r = check(files.clone(), contract.clone(), "python3 -c 'print(1)'");
        assert!(!startup(&r).complete, "change {change}");
        assert_eq!(r.decision, Decision::NeedApproval);
    }
}

#[test]
fn replacing_the_filesystem_view_cannot_reuse_another_namespace_contract() {
    let files = Files::new();
    let r = ShellQueryCore::new()
        .with_python_runtime_contract(files.contract())
        .with_filesystem_view(Arc::new(files))
        .check(request(PROGRAM));
    assert!(!startup(&r).complete);
    assert!(
        startup(&r)
            .gap
            .as_deref()
            .unwrap()
            .contains("not registered")
    );
}

#[test]
fn customization_requires_registered_source_and_independent_import_absence() {
    let mut files = Files::new();
    files.data.insert("/runtime/lib/sitecustomize.py".into(),
        b"try:\n import optional_hook\nexcept ImportError:\n pass\nelse:\n optional_hook.install()\n".to_vec());
    let contract = files.contract();
    let r = check(files.clone(), contract.clone(), PROGRAM);
    assert!(startup(&r).complete, "{:?}", startup(&r));
    for directory in ["/workspace", "/runtime/site"] {
        let mut other = files.clone();
        other
            .data
            .insert(format!("{directory}/optional_hook.py"), vec![]);
        let r = check(other, contract.clone(), PROGRAM);
        assert!(!startup(&r).complete, "{directory}");
        assert_eq!(r.decision, Decision::NeedApproval);
    }
    files
        .data
        .insert("/runtime/lib/sitecustomize.py".into(), b"print(1)".to_vec());
    let r = check(files.clone(), files.contract(), PROGRAM);
    assert!(!startup(&r).complete);
    assert!(startup(&r).gap.as_ref().unwrap().contains("startup action"));
}

#[test]
fn environment_search_paths_origin_account_and_configuration_are_bound() {
    let mut files = Files::new();
    files.directories.extend([
        "/extra".into(),
        "/base".into(),
        "/base/lib".into(),
        "/base/lib/python3.11".into(),
        "/base/lib/python3.11/site-packages".into(),
    ]);
    let contract = files.contract();
    let r = check(
        files.clone(),
        contract.clone(),
        "PYTHONPATH=/extra PYTHONUSERBASE=/base /usr/bin/python3 -c 'import json; print(1)'",
    );
    assert!(startup(&r).complete, "{:?}", startup(&r));
    assert_eq!(
        startup(&r).search_paths,
        [
            "/workspace",
            "/extra",
            "/runtime/lib",
            "/base/lib/python3.11/site-packages",
            "/runtime/site"
        ]
    );
    let r = check(
        files.clone(),
        contract.clone(),
        "PYTHONPATH=/extra PYTHONUSERBASE=/base /usr/bin/python3 -E -c 'print(1)'",
    );
    assert!(startup(&r).complete, "{:?}", startup(&r));
    assert!(!startup(&r).search_paths.iter().any(|p| p == "/extra"));
    assert!(
        startup(&r)
            .search_paths
            .iter()
            .any(|p| p == "/base/lib/python3.11/site-packages")
    );
    for change in 0..5 {
        let mut other = files.clone();
        let mut descriptor = contract.clone();
        match change {
            0 => {
                other.data.insert("/usr/pyvenv.cfg".into(), vec![]);
            }
            1 => descriptor.account.uid = 2,
            2 => {
                descriptor
                    .modules
                    .insert("json".into(), PythonModuleOrigin::Frozen);
            }
            3 => descriptor.absent_configuration = vec!["/runtime/lib".into()],
            4 => descriptor.search_paths = vec!["/missing".into()],
            _ => unreachable!(),
        }
        let r = check(other, descriptor, PROGRAM);
        assert!(!startup(&r).complete, "{change}: {:?}", startup(&r));
        assert_eq!(r.decision, Decision::NeedApproval);
    }
}

#[test]
fn contract_and_structured_evidence_roundtrip_without_unknown_contract_fields() {
    let files = Files::new();
    let contract = files.contract();
    let raw = serde_json::to_vec(&contract).unwrap();
    assert_eq!(
        serde_json::from_slice::<PythonRuntimeContract>(&raw).unwrap(),
        contract
    );
    let r = check(files, contract.clone(), PROGRAM);
    let raw = serde_json::to_vec(&r).unwrap();
    let decoded: CheckResponse = serde_json::from_slice(&raw).unwrap();
    assert_eq!(startup(&decoded), startup(&r));
    for nested in [false, true] {
        let mut value = serde_json::to_value(&contract).unwrap();
        let object = if nested {
            value["account"].as_object_mut().unwrap()
        } else {
            value.as_object_mut().unwrap()
        };
        object.insert("unexpected".into(), true.into());
        assert!(serde_json::from_value::<PythonRuntimeContract>(value).is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn deployed_cpython_inventory_and_startup_match_an_independent_native_run() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/python-runtime/capture.py");
    let capture = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-B"])
        .arg(script)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        capture.status.success(),
        "{}",
        String::from_utf8_lossy(&capture.stderr)
    );
    let contract: PythonRuntimeContract = serde_json::from_slice(&capture.stdout).unwrap();
    let source = "import os,sys,json,socket,subprocess\nfrom pathlib import Path\nfrom urllib.parse import quote_from_bytes\nfrom http.server import HTTPServer,BaseHTTPRequestHandler\nprint(json.dumps({\"encoded\":quote_from_bytes(b\"a b\",safe=\"\")}))";
    let mut req = request(&format!("/usr/bin/python3 -c '{}'", source));
    req.shell_state_before.cwd = "/source".into();
    req.workspace_root = Some("/source".into());
    let r = ShellQueryCore::new()
        .with_python_runtime_contract(contract.clone())
        .check(req);
    assert!(startup(&r).complete, "{:?}", startup(&r));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    let predicted = r
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| match &e.kind {
            EvidenceKind::PythonPayload(p) => Some(p.stdout.clone()),
            _ => None,
        })
        .unwrap();
    let native = std::process::Command::new("/usr/bin/python3")
        .args(["-c", source])
        .current_dir("/source")
        .env_clear()
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(predicted, native.stdout);

    let user = std::env::temp_dir().join(format!(
        "caushell-python-user-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&user).unwrap();
    let site = user.join("lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    for flags in ["", "-E", "-S", "-I", "-P"] {
        let mut req = request(&format!("/usr/bin/python3 {flags} -c 'print(1)'"));
        req.shell_state_before.cwd = "/source".into();
        req.workspace_root = Some("/source".into());
        req.shell_state_before
            .variables
            .push(ShellVariableSnapshot::new(
                "PYTHONUSERBASE",
                ShellValueSnapshot::ExactScalar {
                    value: user.to_str().unwrap().into(),
                },
                true,
            ));
        req.shell_state_before = req.shell_state_before.with_environment_observation(
            "PYTHONUSERBASE",
            ShellEnvironmentValue::Present {
                value: user.to_str().unwrap().into(),
            },
        );
        let r = ShellQueryCore::new()
            .with_python_runtime_contract(contract.clone())
            .check(req);
        assert!(startup(&r).complete, "{flags}: {:?}", startup(&r).gap);
        let mut native = std::process::Command::new("/usr/bin/python3");
        if !flags.is_empty() {
            native.arg(flags);
        }
        let native = native
            .args(["-c", "import sys,json; print(json.dumps(sys.path))"])
            .env_clear()
            .env("PYTHONUSERBASE", &user)
            .current_dir("/source")
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        let paths: Vec<String> = serde_json::from_slice(&native.stdout).unwrap();
        let paths = paths
            .into_iter()
            .map(|p| if p.is_empty() { "/source".into() } else { p })
            .filter(|p| std::path::Path::new(p).is_dir())
            .collect::<Vec<_>>();
        assert_eq!(startup(&r).search_paths, paths, "{flags}");
    }
    for suffix in ["lib/python3.11/site-packages", "lib/python3.11", "lib", ""] {
        std::fs::remove_dir(user.join(suffix)).unwrap();
    }
}
