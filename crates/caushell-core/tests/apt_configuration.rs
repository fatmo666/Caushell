//! No APT process or network request is executed. Supplied executor filesystem facts.
use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FileContentRead, FilesystemView};
use caushell_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Default)]
struct Files {
    files: BTreeMap<String, Vec<u8>>,
    links: BTreeMap<String, String>,
    dirs: BTreeSet<String>,
    unavailable: bool,
    tampered: bool,
    changed: bool,
    reads: AtomicUsize,
}
impl Files {
    fn clean() -> Self {
        Self {
            dirs: ["/", "/workspace", "/etc", "/etc/apt", "/etc/apt/apt.conf.d"]
                .into_iter()
                .map(String::from)
                .collect(),
            ..Self::default()
        }
    }
    fn file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.into(), content.as_bytes().to_vec());
        self
    }
    fn link(mut self, path: &str, target: &str) -> Self {
        self.links.insert(path.into(), target.into());
        self
    }
}
fn identity() -> FileContentIdentity {
    FileContentIdentity {
        device: 1,
        inode: 1,
        size: 0,
        modified_seconds: 1,
        modified_nanos: 0,
        changed_seconds: 1,
        changed_nanos: 0,
    }
}
impl FilesystemView for Files {
    fn source(&self) -> FilesystemObservationSource {
        FilesystemObservationSource::SuppliedView
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        if let Some(target) = self.links.get(path) {
            FilesystemEntry::Symlink {
                target: target.clone(),
            }
        } else if self.files.contains_key(path) {
            FilesystemEntry::File
        } else if self.dirs.contains(path)
            || self
                .files
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
                "fixture unavailable",
            );
        }
        if let Some(bytes) = self.files.get(path) {
            let mut r = FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                None,
                bytes.clone(),
            );
            if self.tampered {
                r.observation.sha256 = Some("tampered".into())
            }
            r
        } else {
            FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "absent",
            )
        }
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        if self.unavailable {
            return DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Unavailable,
                "fixture unavailable",
            );
        }
        if self.entry(path) == FilesystemEntry::Missing {
            return DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Missing,
                "absent",
            );
        }
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let mut children = BTreeMap::new();
        for name in self
            .files
            .keys()
            .chain(self.dirs.iter())
            .chain(self.links.keys())
        {
            if let Some(rest) = name.strip_prefix(&prefix)
                && !rest.is_empty()
            {
                let first = rest.split('/').next().unwrap();
                let full = format!("{prefix}{first}");
                let kind = match self.entry(&full) {
                    FilesystemEntry::File => DirectoryEntryKind::File,
                    FilesystemEntry::Symlink { .. } => DirectoryEntryKind::Symlink,
                    _ => DirectoryEntryKind::Directory,
                };
                children.insert(
                    first.to_owned(),
                    DirectoryEntry {
                        name: first.into(),
                        kind,
                        identity: identity(),
                    },
                );
            }
        }
        let mut id = identity();
        if self.changed {
            id.inode = self.reads.fetch_add(1, Ordering::SeqCst) as u64;
        }
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            id,
            children.into_values().collect(),
        )
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("apt-native"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "supplied-executor".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
fn check(command: &str, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command))
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
fn package_code(r: &CheckResponse) -> bool {
    r.decision_trace
        .execution_semantics
        .iter()
        .any(|s| s.executes_imported_package_logic)
}
fn decision(command: &str, files: Files, expected: Decision) -> CheckResponse {
    let r = check(command, files);
    assert_eq!(
        r.decision,
        expected,
        "{command}: {:?}\n{:?}",
        r.reasons,
        parse(&r)
    );
    r
}

#[test]
fn download_information_and_install_have_distinct_effects() {
    for command in [
        "apt-get download example",
        "apt-get -y download example",
        "apt-get download --option=Acquire::Retries=3 example",
    ] {
        let r = decision(command, Files::clean(), Decision::Allow);
        assert!(!package_code(&r));
        assert!(parse(&r).complete);
    }
    for command in ["apt-get --version", "apt-get -v", "apt-get --help"] {
        decision(command, Files::clean(), Decision::Allow);
    }
    for command in [
        "apt-get install example",
        "apt-get install -d example",
        "apt-get -d install example",
        "apt-get install --download-only example",
        "apt-get -oAPT::Get::Download-Only=true install example",
    ] {
        let r = decision(command, Files::clean(), Decision::NeedApproval);
        assert_eq!(
            package_code(&r),
            !command.contains("-d") && !command.contains("Download-Only"),
            "{command}: {:?}",
            r.reasons
        );
        assert!(parse(&r).complete, "{command}: {:?}", parse(&r));
    }
}

#[test]
fn configuration_order_and_paths_are_not_authorization() {
    let config = r#"Dir "/workspace/stage"; Dir::State::status "/workspace/stage/status"; APT::Get::Download-Only "true";"#;
    for command in [
        "apt-get install -c settings.conf example",
        "apt-get -csettings.conf install example",
        "apt-get --config-file=settings.conf install example",
        "apt-get install --config-file=settings.conf example",
        "timeout 5 apt-get -c settings.conf install example",
        "env APT_CONFIG=/workspace/settings.conf apt-get install example",
    ] {
        let r = decision(
            command,
            Files::clean().file("/workspace/settings.conf", config),
            Decision::Allow,
        );
        assert!(!package_code(&r));
        assert!(parse(&r).complete);
    }
    let r = decision(
        "APT_CONFIG=/workspace/settings.conf apt-get install example",
        Files::clean().file("/workspace/settings.conf", config),
        Decision::Allow,
    );
    assert!(!package_code(&r));
    let files = Files::clean()
        .file(
            "/etc/apt/apt.conf.d/10.conf",
            "APT::Get::Download-Only \"false\";",
        )
        .file("/etc/apt/apt.conf.d/90.conf", config)
        .file("/etc/apt/apt.conf", "APT::Get::Download-Only \"false\";");
    let r = decision("apt-get -d install example", files, Decision::Allow);
    assert!(!package_code(&r));
    let r = decision(
        "apt-get -d -oAPT::Get::Download-Only=false install example",
        Files::clean().file("/etc/apt/apt.conf", config),
        Decision::NeedApproval,
    );
    assert!(package_code(&r));
    let r = decision(
        "apt-get -oAPT::Get::Download-Only=false install -d example",
        Files::clean().file("/etc/apt/apt.conf", config),
        Decision::Allow,
    );
    assert!(!package_code(&r));
    let r = decision(
        "apt-get --download-only=false install example",
        Files::clean().file("/etc/apt/apt.conf", config),
        Decision::NeedApproval,
    );
    assert!(package_code(&r));
    decision(
        "apt-get -o Dir=/foreign -d install example",
        Files::clean(),
        Decision::NeedApproval,
    );
    decision(
        "apt-get -o Dir=/workspace/stage install example",
        Files::clean(),
        Decision::NeedApproval,
    );
}

#[test]
fn hooks_and_unknown_configuration_never_become_benign_downloads() {
    for content in [
        "DPkg::Pre-Invoke { \"id\"; };",
        "APT::Update::Post-Invoke-Success { \"id\"; };",
        "Acquire::https::Verify-Peer \"false\";",
        "#include \"another.conf\";",
        "Unknown::Control \"x\";",
        "APT::Get::Download-Only \"true\"; malformed",
    ] {
        let r = decision(
            "apt-get -d install example",
            Files::clean().file("/etc/apt/apt.conf.d/50.conf", content),
            Decision::NeedApproval,
        );
        assert!(!parse(&r).complete);
        assert!(
            package_code(&r),
            "incomplete config cannot remove package execution"
        );
    }
    for command in [
        "apt-get -d -o DPkg::Pre-Invoke::=id install example",
        "apt-get install -d -o DPkg::Pre-Invoke::=id example",
        "apt-get -o Acquire::https::Verify-Peer=false download example",
        "apt-get download example --option=Unknown=true",
        "apt-get install -c missing.conf -d example",
    ] {
        let r = decision(command, Files::clean(), Decision::NeedApproval);
        assert!(!parse(&r).complete);
    }
    // '--option' after -- is package data, not configuration.
    let r = check("apt-get download -- --option=Unknown=true", Files::clean());
    assert!(parse(&r).options.is_empty());
}

#[test]
fn unavailable_changed_and_linked_resources_remain_gaps() {
    let mut unavailable = Files::clean();
    unavailable.unavailable = true;
    let r = decision(
        "apt-get download example",
        unavailable,
        Decision::NeedApproval,
    );
    assert!(!parse(&r).complete);
    let mut tampered = Files::clean().file("/etc/apt/apt.conf", "Acquire::Retries \"3\";");
    tampered.tampered = true;
    assert!(
        !parse(&decision(
            "apt-get download example",
            tampered,
            Decision::NeedApproval
        ))
        .complete
    );
    let mut changed = Files::clean();
    changed.changed = true;
    assert!(
        !parse(&decision(
            "apt-get download example",
            changed,
            Decision::NeedApproval
        ))
        .complete
    );
    let r = decision(
        "apt-get download example",
        Files::clean().link("/workspace/old.deb", "/foreign/target"),
        Decision::NeedApproval,
    );
    assert!(
        parse(&r).complete,
        "config is independent of output namespace proof"
    );
    assert!(
        r.decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::DirectoryTree(p) if !p.complete))
    );
    for command in [
        "apt-get download example > /etc/apt/apt.conf",
        "touch /etc/apt/apt.conf; apt-get download example",
    ] {
        assert!(!parse(&decision(command, Files::clean(), Decision::NeedApproval)).complete);
    }
    let mut unknown = request("apt-get download example");
    unknown.shell_state_before = ShellStateSnapshot::new("/workspace");
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Files::clean()))
        .check(unknown);
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(!parse(&r).complete);
}

#[test]
fn deletion_inline_and_existing_deny_survive_native_configuration() {
    for (command, expected) in [
        (
            "apt-get download example; rm /workspace/file",
            Decision::NeedApproval,
        ),
        (
            "apt-get download example; Rscript -e 1",
            Decision::NeedApproval,
        ),
        ("apt-get -d install example; rm -rf /", Decision::Deny),
        (
            "apt-get --unmodeled download example; rm -rf /",
            Decision::Deny,
        ),
    ] {
        let r = check(command, Files::clean());
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn update_cleanup_and_incomplete_package_modes_preserve_policy() {
    let r = check("apt-get -o Dir=/workspace/stage update", Files::clean());
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::FileDeletion),
        "{:?}",
        r.reasons
    );
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    let mut core =
        ShellQueryCore::with_policy(policy).with_filesystem_view(Arc::new(Files::clean()));
    let mut req = request("apt-get -d install example");
    req.shell_state_before = ShellStateSnapshot::new("/workspace");
    let r = core.check(req);
    assert_eq!(
        r.decision,
        Decision::Deny,
        "unknown config must preserve the package-code Deny: {:?}",
        r.reasons
    );
    assert!(package_code(&r));
}

#[test]
fn unmodeled_native_switches_do_not_hide_existing_deny() {
    for command in [
        "apt-get --unmodeled download example",
        "apt-get -d",
        "apt-get install -c",
        "apt-get --allow-unauthenticated download example",
    ] {
        assert_eq!(
            check(command, Files::clean()).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    let mut core =
        ShellQueryCore::with_policy(policy).with_filesystem_view(Arc::new(Files::clean()));
    let r = core.check(request(
        "apt-get -d -o Unknown::Control=true install example",
    ));
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.reasons);
}
