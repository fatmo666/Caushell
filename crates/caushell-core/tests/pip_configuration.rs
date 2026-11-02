//! Supplied executor facts only: no pip process, package, Python body or network.
use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone)]
struct Files {
    bytes: BTreeMap<String, Vec<u8>>,
    links: BTreeMap<String, String>,
    layout: Option<PipRuntimeLayout>,
    unavailable: bool,
    tampered: bool,
    change_identity: bool,
    lose_lease: bool,
    wrong_source: bool,
    reads: Arc<AtomicUsize>,
    layouts: Arc<AtomicUsize>,
}
impl Files {
    fn clean() -> Self {
        Self {
            bytes: Default::default(),
            links: Default::default(),
            layout: Some(PipRuntimeLayout {
                variant: PIP_25_3_LINUX_VARIANT.into(),
                prefix: "/workspace/venv".into(),
                account_home: "/home/test".into(),
                account: account(),
                startup_read_only: true,
                configuration_snapshot_held: true,
            }),
            unavailable: false,
            tampered: false,
            change_identity: false,
            lose_lease: false,
            wrong_source: false,
            reads: Arc::new(AtomicUsize::new(0)),
            layouts: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn file(mut self, path: &str, text: &str) -> Self {
        self.bytes.insert(path.into(), text.as_bytes().to_vec());
        self
    }
}
fn account() -> RuntimeAccount {
    RuntimeAccount {
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
    }
}
impl FilesystemView for Files {
    fn pip_runtime(&self, _: &str) -> Option<PipRuntimeLayout> {
        if self.lose_lease && self.layouts.fetch_add(1, Ordering::SeqCst) > 0 {
            return None;
        }
        self.layout.clone()
    }
    fn execution_account(&self) -> Option<RuntimeAccount> {
        Some(account())
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        if self.unavailable {
            return FilesystemEntry::Unavailable {
                reason: "fixture unavailable".into(),
            };
        }
        if let Some(target) = self.links.get(path) {
            return FilesystemEntry::Symlink {
                target: target.clone(),
            };
        }
        if self.bytes.contains_key(path) {
            return FilesystemEntry::File;
        }
        if matches!(
            path,
            "/" | "/workspace" | "/workspace/venv" | "/etc" | "/etc/xdg" | "/home" | "/home/test"
        ) || self
            .bytes
            .keys()
            .chain(self.links.keys())
            .any(|p| p.starts_with(&format!("{}/", path.trim_end_matches('/'))))
        {
            FilesystemEntry::Directory
        } else {
            FilesystemEntry::Missing
        }
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if self.unavailable {
            return FileContentRead::failed(
                FileContentSource::Unavailable,
                path,
                limit,
                FileContentStatus::Unavailable,
                "fixture",
            );
        }
        if let Some(bytes) = self.bytes.get(path) {
            let mut r = FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                Some(FileContentIdentity {
                    device: 1,
                    inode: if self.change_identity {
                        self.reads.fetch_add(1, Ordering::SeqCst) as u64 + 1
                    } else {
                        1
                    },
                    size: bytes.len() as u64,
                    modified_seconds: 1,
                    modified_nanos: 0,
                    changed_seconds: 1,
                    changed_nanos: 0,
                }),
                bytes.clone(),
            );
            if self.tampered {
                r.observation.sha256 = Some("bad hash".into());
            }
            if self.wrong_source {
                r.observation.source = FileContentSource::Unavailable;
            }
            r
        } else {
            FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "observed absent",
            )
        }
    }
}
fn request(command: &str, extra: &[(&str, &str)]) -> CheckRequest {
    let mut req = CheckRequest {
        session_id: SessionId::new("pip-owned"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "private-test-host".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    };
    let names = caushell_profile::execution_frame_requirements(
        caushell_profile::ProfileRegistry::built_in()
            .unwrap()
            .profiles(),
    )
    .environment_names;
    let mut values = names
        .into_iter()
        .map(|name| (name, ShellEnvironmentValue::Absent))
        .collect::<BTreeMap<_, _>>();
    values.insert(
        "PYTHONDONTWRITEBYTECODE".into(),
        ShellEnvironmentValue::Present { value: "1".into() },
    );
    for (name, value) in extra {
        values.insert(
            (*name).into(),
            ShellEnvironmentValue::Present {
                value: (*value).into(),
            },
        );
    }
    req.shell_state_before.variables = values
        .iter()
        .filter_map(|(name, value)| {
            let ShellEnvironmentValue::Present { value } = value else {
                return None;
            };
            Some(ShellVariableSnapshot {
                name: name.clone(),
                value: ShellValueSnapshot::exact_scalar(value.clone()),
                exported: true,
            })
        })
        .collect();
    req.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding: ExecutionFrameBinding::for_request(&req, "owner"),
        environment: values
            .into_iter()
            .map(|(name, value)| ShellEnvironmentSnapshot { name, value })
            .collect(),
        pathname: None,
        variables: Vec::new(),
        variable_values: Vec::new(),
        integer_variables: BTreeSet::new(),
        native_variants: [
            ("pip".into(), PIP_25_3_LINUX_VARIANT.into()),
            ("pip3".into(), PIP_25_3_LINUX_VARIANT.into()),
        ]
        .into(),
    });
    req
}
fn check(command: &str, files: Files, env: &[(&str, &str)]) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command, env))
}
fn parse(r: &CheckResponse) -> &ToolConfigParseEvidence {
    r.decision_trace
        .evidence
        .iter()
        .find_map(|e| {
            if let EvidenceKind::ToolConfigParse(p) = &e.kind {
                Some(p)
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("{:?}", r.reasons))
}
fn expect(command: &str, files: Files, env: &[(&str, &str)], decision: Decision) -> CheckResponse {
    let r = check(command, files, env);
    assert_eq!(
        r.decision,
        decision,
        "{command}: {:?}\n{:#?}",
        r.reasons,
        parse(&r)
    );
    r
}
#[test]
fn trusted_readonly_queries_close_config_uncertainty_only() {
    for cmd in [
        "pip --disable-pip-version-check list",
        "pip list --disable-pip-version-check",
        "pip show package",
        "pip check",
        "pip config list",
        "pip config debug",
        "pip config get global.timeout",
    ] {
        let r = expect(cmd, Files::clean(), &[], Decision::Allow);
        assert!(parse(&r).complete, "{cmd}");
    }
    expect("pip list", Files::clean(), &[], Decision::NeedApproval);
}
#[test]
fn configuration_environment_and_cli_precedence_preserve_real_writes() {
    let files = Files::clean()
        .file("/etc/pip.conf", "[global]\nlog = /outside/first\n")
        .file(
            "/home/test/.config/pip/pip.conf",
            "[global]\nlog = /workspace/second\n",
        )
        .file("/workspace/venv/pip.conf", "[show]\nlog = /outside/final\n");
    expect(
        "pip show package",
        files.clone(),
        &[],
        Decision::NeedApproval,
    );
    expect(
        "pip --log /workspace/cli show package",
        files.clone(),
        &[],
        Decision::Allow,
    );
    expect(
        "pip show --log=/workspace/cli package",
        files.clone(),
        &[],
        Decision::Allow,
    );
    expect(
        "pip show package",
        files,
        &[("PIP_LOG", "/workspace/env")],
        Decision::Allow,
    );
}
#[test]
fn isolated_and_explicit_config_do_not_mean_no_configuration() {
    let files = Files::clean().file("/etc/pip.conf", "[global]\nlog=/outside/log\n");
    expect(
        "pip --isolated show package",
        files.clone(),
        &[],
        Decision::NeedApproval,
    );
    expect(
        "pip show package",
        files,
        &[("PIP_CONFIG_FILE", "/dev/null")],
        Decision::Allow,
    );
    let files = Files::clean()
        .file(
            "/home/test/.config/pip/pip.conf",
            "[global]\nlog=/outside/log\n",
        )
        .file("/workspace/settings.ini", "[global]\nquiet=true\n");
    expect(
        "pip show package",
        files.clone(),
        &[("PIP_CONFIG_FILE", "/workspace/settings.ini")],
        Decision::Allow,
    );
    expect(
        "pip --isolated show package",
        files,
        &[
            ("PIP_CONFIG_FILE", "/workspace/settings.ini"),
            ("PIP_LOG", "/outside/ignored"),
        ],
        Decision::Allow,
    );
}
#[test]
fn config_modification_selects_a_real_file_without_granting_permission() {
    let r = expect(
        "pip config set global.timeout 10",
        Files::clean().file("/workspace/venv/pip.conf", "[global]\ntimeout=5\n"),
        &[],
        Decision::Allow,
    );
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Write
                && p.lexical.concrete_path() == Some("/workspace/venv/pip.conf"))
    );
    expect(
        "pip config --user set global.timeout 10",
        Files::clean(),
        &[],
        Decision::NeedApproval,
    );
    expect(
        "PIP_CONFIG_FILE=/workspace/settings.ini pip config set global.timeout 10",
        Files::clean().file("/workspace/settings.ini", "[global]\ntimeout=5\n"),
        &[],
        Decision::NeedApproval,
    );
    expect(
        "pip config --site unset global.timeout",
        Files::clean().file("/workspace/venv/pip.conf", "[global]\ntimeout=5\n"),
        &[],
        Decision::Allow,
    );
    expect(
        "pip config --global set global.timeout 10",
        Files::clean(),
        &[],
        Decision::NeedApproval,
    );
}
#[test]
fn unavailable_runtime_content_and_unmodeled_data_stay_ask() {
    for tweak in [0, 1, 2, 3] {
        let mut f = Files::clean();
        match tweak {
            0 => f.layout = None,
            1 => f.layout.as_mut().unwrap().startup_read_only = false,
            2 => f.unavailable = true,
            _ => {
                f = f.file("/etc/pip.conf", "[global]\nlog=/workspace/log\n");
                f.tampered = true;
            }
        }
        expect("pip show package", f, &[], Decision::NeedApproval);
    }
    for data in [
        "[global]\nunknown-control=true\n",
        "[global]\nlog=x\n malformed",
        "[DEFAULT]\nlog=x\n[show]\nquiet=true",
        "[global]\nlog=/workspace/log\nlog=/outside/log",
    ] {
        let r = expect(
            "pip show package",
            Files::clean().file("/etc/pip.conf", data),
            &[],
            Decision::NeedApproval,
        );
        assert!(!parse(&r).complete);
    }
    for env in [
        [("PYTHONPATH", "/workspace/code")],
        [("PIP_PYTHON", "/other/python")],
        [("PYTHONDONTWRITEBYTECODE", "0")],
    ] {
        expect(
            "pip show package",
            Files::clean(),
            &env,
            Decision::NeedApproval,
        );
    }
}
#[test]
fn namespace_changes_execution_and_deny_are_independent() {
    for cmd in [
        "pip show package > /etc/pip.conf",
        "touch /etc/pip.conf; pip show package",
        "env pip show package",
        "python -c 'print(1)'",
        "pip download package -d /workspace/dist --no-deps",
        "pip install package --target /workspace/site",
    ] {
        let r = check(cmd, Files::clean(), &[]);
        assert_eq!(r.decision, Decision::NeedApproval, "{cmd}: {:?}", r.reasons);
    }
    for cmd in [
        "pip show package; rm -rf /",
        "pip --unknown show package; rm -rf /",
        "LD_PRELOAD=/outside/lib.so pip show package; rm -rf /",
    ] {
        assert_eq!(
            check(cmd, Files::clean(), &[]).decision,
            Decision::Deny,
            "{cmd}"
        );
    }
}

#[test]
fn complete_environment_identity_and_held_snapshot_are_required() {
    for knowledge in [ShellStateKnowledge::Unknown] {
        let mut req = request("pip show package", &[]);
        req.shell_state_before.observability.variables = knowledge;
        let r = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(Files::clean()))
            .check(req);
        assert_eq!(r.decision, Decision::NeedApproval);
        assert!(!parse(&r).complete);
    }
    for env in [
        [("PIP_log", "/outside/log")],
        [("PIP_AUTO_COMPLETE", "1")],
        [("PYTHONWARNINGS", "ignore::payload.Warning")],
        [("HOME", "")],
        [("XDG_CONFIG_HOME", " /outside ")],
        [("XDG_CONFIG_DIRS", "/etc/xdg :/outside")],
    ] {
        expect(
            "pip show package",
            Files::clean(),
            &env,
            Decision::NeedApproval,
        );
    }
    for fault in 0..6 {
        let mut files = Files::clean().file("/etc/pip.conf", "[global]\nlog=/workspace/log\n");
        match fault {
            0 => files.change_identity = true,
            1 => files.lose_lease = true,
            2 => files.wrong_source = true,
            3 => files.layout.as_mut().unwrap().configuration_snapshot_held = false,
            4 => files.layout.as_mut().unwrap().account.euid = 0,
            _ => files.layout.as_mut().unwrap().variant = "other_pip".into(),
        }
        let r = expect("pip show package", files, &[], Decision::NeedApproval);
        assert!(!parse(&r).complete, "fault {fault}");
    }
    for fault in 0..3 {
        let mut req = request("pip show package", &[]);
        let frame = req.shell_state_before.execution_frame.as_mut().unwrap();
        match fault {
            0 => frame.native_variants.clear(),
            1 => frame.binding.command_sha256 = "0".repeat(64),
            _ => {
                frame
                    .native_variants
                    .insert("pip".into(), "another_version".into());
            }
        }
        assert_eq!(
            ShellQueryCore::new()
                .with_filesystem_view(Arc::new(Files::clean()))
                .check(req)
                .decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn native_bootstrap_operands_repetition_and_data_keep_their_ownership() {
    // Native bootstrap sees this literal even past the option terminator. It
    // must not expose a global log that our non-isolated env merge had hidden.
    expect(
        "pip show -- --isolated",
        Files::clean().file("/etc/pip.conf", "[global]\nlog=/outside/global\n"),
        &[("PIP_LOG", "/workspace/env")],
        Decision::NeedApproval,
    );
    for cmd in [
        "pip --log show --isolated show package",
        "pip --log --isolated show package",
        "PIP_log=/outside/log pip show package",
        "pip freeze",
        "pip config --editor 'touch /workspace/marker' edit",
        "pip config --site --editor true edit",
    ] {
        assert_eq!(
            check(cmd, Files::clean(), &[]).decision,
            Decision::NeedApproval,
            "{cmd}"
        );
    }
    expect(
        "pip --log /outside/old show --log /workspace/final package",
        Files::clean(),
        &[],
        Decision::Allow,
    );
    expect(
        "pip show --log /workspace/old --log /outside/final package",
        Files::clean(),
        &[],
        Decision::NeedApproval,
    );
    let f = Files::clean().file(
        "/etc/pip.conf",
        "[global]\nlog = /workspace/$(touch marker)\n",
    );
    let r = expect("pip show package", f, &[], Decision::Allow);
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.lexical.concrete_path() == Some("/workspace/$(touch marker)"))
    );
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry {
            action: RuleAction::Deny,
            trust_sets: Vec::new(),
        },
    );
    let r = ShellQueryCore::with_policy(policy)
        .with_filesystem_view(Arc::new(Files::clean()))
        .check(request("pip install package --target /workspace/site", &[]));
    assert_eq!(r.decision, Decision::Deny);
}
