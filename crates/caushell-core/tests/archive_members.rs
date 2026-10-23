use std::{collections::BTreeMap, sync::Arc};

use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;

#[derive(Default)]
struct Files {
    bytes: Vec<u8>,
    entries: BTreeMap<String, FilesystemEntry>,
    failure: Option<FileContentStatus>,
    corrupt_hash: bool,
}

impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.entries.get(path).cloned().unwrap_or_else(|| {
            if path == "/workspace/bundle.tar" {
                FilesystemEntry::File
            } else if [
                "/",
                "/workspace",
                "/outside",
                "/workspace/cache",
                "/workspace/cache/sub",
                "/outside/cache",
            ]
            .contains(&path)
            {
                FilesystemEntry::Directory
            } else {
                FilesystemEntry::Missing
            }
        })
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if let Some(status) = self.failure {
            return FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                status,
                "fixture",
            );
        }
        if path != "/workspace/bundle.tar" {
            return FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "absent",
            );
        }
        let mut read = FileContentRead::complete(
            FileContentSource::SuppliedView,
            path,
            limit,
            None,
            self.bytes.clone(),
        );
        if self.corrupt_hash {
            read.observation.sha256 = Some("invalid".into());
        }
        read
    }
}

fn archive(members: &[(&str, u8, &str)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, kind, link) in members {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = *kind;
        header[157..157 + link.len()].copy_from_slice(link.as_bytes());
        header[257..265].copy_from_slice(b"ustar\000");
        let sum: u64 = header.iter().map(|c| u64::from(*c)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes.extend(header);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("archive-members"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn files() -> Files {
    Files {
        bytes: archive(&[("result.txt", b'0', "")]),
        ..Default::default()
    }
}
fn check(command: &str, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command, 1))
}
fn proof(response: &CheckResponse) -> &ArchiveMembersEvidence {
    response
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| match &e.kind {
            EvidenceKind::ArchiveMembers(e) => Some(e),
            _ => None,
        })
        .expect("archive evidence")
}
fn target(response: &CheckResponse, path: &str) {
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|t| t.operation == PathTargetOperation::Write
                && t.lexical.concrete_path() == Some(path)),
        "{response:#?}"
    );
}

#[test]
fn complete_plain_archive_proves_actual_member_targets() {
    for command in [
        "tar -xf bundle.tar",
        "tar xf bundle.tar",
        "tar --extract --file=bundle.tar",
        "tar -xvf bundle.tar",
    ] {
        let result = check(command, files());
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
        assert!(proof(&result).complete);
        target(&result, "/workspace/result.txt");
        assert_eq!(
            proof(&result).file.as_ref().unwrap().status,
            FileContentStatus::Complete
        );
    }
}

#[test]
fn native_environment_and_explicit_options_share_ordered_targets() {
    for (prefix, expected, decision) in [
        (
            "TAR_OPTIONS=--directory=/workspace/cache",
            "/workspace/cache/result.txt",
            Decision::Allow,
        ),
        (
            "TAR_OPTIONS=--directory=/outside/cache",
            "/outside/cache/result.txt",
            Decision::NeedApproval,
        ),
    ] {
        for invocation in ["tar -xf bundle.tar", "tar xf bundle.tar"] {
            let result = check(&format!("{prefix} {invocation}"), files());
            assert_eq!(result.decision, decision, "{result:#?}");
            assert!(proof(&result).complete, "{result:#?}");
            target(&result, expected);
        }
    }
    let result = check(
        "TAR_OPTIONS='--directory=cache' tar -xf bundle.tar -C sub",
        files(),
    );
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    target(&result, "/workspace/cache/sub/result.txt");
}

#[test]
fn archive_filename_uses_entry_cwd_not_extraction_directory() {
    for command in [
        "tar -C /workspace/cache -xf bundle.tar",
        "tar -xf bundle.tar -C /outside -C /workspace/cache",
    ] {
        let result = check(command, files());
        assert_eq!(result.decision, Decision::Allow, "{result:#?}");
        assert_eq!(
            proof(&result).file.as_ref().unwrap().path,
            "/workspace/bundle.tar"
        );
        target(&result, "/workspace/cache/result.txt");
    }
}

#[test]
fn only_exported_state_and_command_prefix_enter_native_options() {
    let mut core = ShellQueryCore::new().with_filesystem_view(Arc::new(files()));
    assert_eq!(
        core.check(request("export TAR_OPTIONS=--directory=/outside/cache", 1))
            .decision,
        Decision::Allow
    );
    let mut next = request("tar -xf bundle.tar", 2);
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let result = core.check(next);
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    target(&result, "/outside/cache/result.txt");
    let result = check(
        "TAR_OPTIONS=--directory=/outside/cache; tar -xf bundle.tar",
        files(),
    );
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    target(&result, "/workspace/result.txt");
    let result = check(
        "export TAR_OPTIONS=--directory=/outside/cache; TAR_OPTIONS=--directory=/workspace/cache tar -xf bundle.tar",
        files(),
    );
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    target(&result, "/workspace/cache/result.txt");
}

#[test]
fn directory_entries_duplicate_members_and_empty_archives_are_complete() {
    for members in [
        vec![],
        vec![
            ("folder/", b'5', ""),
            ("folder/file", b'0', ""),
            ("folder/file", b'0', ""),
        ],
    ] {
        let expected = members.len();
        let result = check(
            "tar -xf bundle.tar",
            Files {
                bytes: archive(&members),
                ..Default::default()
            },
        );
        assert_eq!(result.decision, Decision::Allow, "{result:#?}");
        assert_eq!(proof(&result).members.len(), expected);
        assert!(proof(&result).complete);
        for (order, member) in proof(&result).members.iter().enumerate() {
            assert_eq!(member.order, order);
        }
    }
}

#[test]
fn link_special_extended_and_traversing_members_never_prove_writes() {
    for (name, kind, link) in [
        ("link", b'2', "/outside"),
        ("hard", b'1', "elsewhere"),
        ("device", b'3', ""),
        ("fifo", b'6', ""),
        ("extended", b'x', ""),
        ("global", b'g', ""),
        ("long", b'L', ""),
        ("sparse", b'S', ""),
        ("../outside", b'0', ""),
        ("a/../../outside", b'0', ""),
        ("/outside/file", b'0', ""),
    ] {
        let result = check(
            "tar -xf bundle.tar",
            Files {
                bytes: archive(&[(name, kind, link), ("after", b'0', "")]),
                ..Default::default()
            },
        );
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{name}/{kind}: {result:#?}"
        );
        assert!(!proof(&result).complete);
        assert_eq!(proof(&result).members.len(), 2);
    }
}

#[test]
fn existing_links_and_file_parent_conflicts_are_not_proofs() {
    for (path, entry) in [
        (
            "/workspace/result.txt",
            FilesystemEntry::Symlink {
                target: "/outside/file".into(),
            },
        ),
        (
            "/workspace/cache",
            FilesystemEntry::Symlink {
                target: "/workspace/other".into(),
            },
        ),
    ] {
        let mut fixture = files();
        fixture.entries.insert(path.into(), entry);
        let result = check("tar -xf bundle.tar -C cache", fixture);
        // Check final-entry links without the -C as well.
        let result = if path.ends_with("result.txt") {
            let mut fixture = files();
            fixture.entries.insert(
                path.into(),
                FilesystemEntry::Symlink {
                    target: "/outside/file".into(),
                },
            );
            check("tar -xf bundle.tar", fixture)
        } else {
            result
        };
        assert_ne!(result.decision, Decision::Allow, "{result:#?}");
    }
    let result = check(
        "tar -xf bundle.tar",
        Files {
            bytes: archive(&[("a", b'0', ""), ("a/b", b'0', "")]),
            ..Default::default()
        },
    );
    assert_ne!(result.decision, Decision::Allow, "{result:#?}");
}

#[test]
fn incomplete_corrupt_compressed_and_oversized_bytes_keep_the_gap() {
    let valid = files().bytes;
    let mut corrupt = valid.clone();
    corrupt[0] ^= 1;
    let mut hidden = valid.clone();
    hidden.extend(archive(&[("hidden", b'0', "")]));
    for bytes in [
        valid[..valid.len() - 1].to_vec(),
        valid[..512].to_vec(),
        corrupt,
        hidden,
        vec![0x1f, 0x8b, 0x08],
        vec![0; 65_537],
        archive(&vec![("many", b'0', ""); 65]),
    ] {
        let result = check(
            "tar -xf bundle.tar",
            Files {
                bytes,
                ..Default::default()
            },
        );
        assert_ne!(result.decision, Decision::Allow, "{result:#?}");
        assert!(!proof(&result).complete);
    }
}

#[test]
fn unavailable_changed_and_tampered_content_never_becomes_complete() {
    for status in [
        FileContentStatus::Missing,
        FileContentStatus::Changed,
        FileContentStatus::NonRegular,
        FileContentStatus::Unavailable,
    ] {
        let result = check(
            "tar -xf bundle.tar",
            Files {
                failure: Some(status),
                ..files()
            },
        );
        assert_ne!(result.decision, Decision::Allow, "{result:#?}");
        assert!(!proof(&result).complete);
    }
    let result = check(
        "tar -xf bundle.tar",
        Files {
            corrupt_hash: true,
            ..files()
        },
    );
    assert_ne!(result.decision, Decision::Allow, "{result:#?}");
}

#[test]
fn changing_source_namespace_invalidates_the_content_observation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Changing {
        files: Files,
        changed: AtomicBool,
    }
    impl FilesystemView for Changing {
        fn entry(&self, path: &str) -> FilesystemEntry {
            if path == "/workspace/bundle.tar" && self.changed.load(Ordering::SeqCst) {
                FilesystemEntry::Symlink {
                    target: "/outside/other.tar".into(),
                }
            } else {
                self.files.entry(path)
            }
        }
        fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
            let read = self.files.read_file(path, limit);
            self.changed.store(true, Ordering::SeqCst);
            read
        }
    }
    let result = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Changing {
            files: files(),
            changed: AtomicBool::new(false),
        }))
        .check(request("tar -xf bundle.tar", 1));
    assert_ne!(result.decision, Decision::Allow, "{result:#?}");
    assert!(!proof(&result).complete);
    assert!(proof(&result).errors.iter().any(|e| e.contains("changed")));
}

#[test]
fn unknown_environment_cannot_certify_archive_members() {
    let mut req = request("tar -xf bundle.tar", 1);
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let result = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files()))
        .check(req);
    assert_ne!(result.decision, Decision::Allow, "{result:#?}");
    assert!(!proof(&result).complete);
}

#[test]
fn unsupported_options_filters_and_unresolved_environment_remain_ask() {
    for command in [
        "tar -xf bundle.tar --strip-components=1",
        "tar -xf bundle.tar --transform=s,a,b,",
        "tar -xf bundle.tar result.txt",
        "tar -zxf bundle.tar",
        "tar -Pxf bundle.tar",
        "tar -xf bundle.tar --keep-directory-symlink",
        "tar -xf bundle.tar --recursive-unlink",
        "TAR_OPTIONS=$(unknown) tar -xf bundle.tar",
        "TAR_OPTIONS='--directory=$UNKNOWN' tar -xf bundle.tar",
        "tar -xf bundle.tar > bundle.tar",
        "rm bundle.tar; tar -xf bundle.tar",
        "ln -s /outside cache; tar -xf bundle.tar -C cache",
    ] {
        let result = check(command, files());
        assert_ne!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}
