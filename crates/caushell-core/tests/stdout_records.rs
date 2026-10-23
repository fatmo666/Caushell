use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView};
use caushell_types::*;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn identity(inode: u64) -> FileContentIdentity {
    FileContentIdentity {
        device: 1,
        inode,
        size: 0,
        modified_seconds: 0,
        modified_nanos: 0,
        changed_seconds: 0,
        changed_nanos: 0,
    }
}
fn entry(name: &str, kind: DirectoryEntryKind, id: u64) -> DirectoryEntry {
    DirectoryEntry {
        name: name.into(),
        kind,
        identity: identity(id),
    }
}

struct Files {
    dirs: BTreeMap<String, (u64, Vec<DirectoryEntry>)>,
    failure: Option<DirectoryReadStatus>,
    changed: bool,
    calls: AtomicUsize,
}
impl Files {
    fn new() -> Self {
        Self {
            dirs: BTreeMap::from([
                (
                    "/workspace/input".into(),
                    (
                        1,
                        vec![
                            entry("a.csv", DirectoryEntryKind::File, 3),
                            entry("line\nbreak.csv", DirectoryEntryKind::File, 4),
                            entry(".hidden", DirectoryEntryKind::File, 5),
                            entry("sub", DirectoryEntryKind::Directory, 2),
                            entry("link.csv", DirectoryEntryKind::Symlink, 6),
                        ],
                    ),
                ),
                (
                    "/workspace/input/sub".into(),
                    (2, vec![entry("b.csv", DirectoryEntryKind::File, 7)]),
                ),
            ]),
            failure: None,
            changed: false,
            calls: AtomicUsize::new(0),
        }
    }
}
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if ["/", "/workspace"].contains(&path) || self.dirs.contains_key(path) {
            FilesystemEntry::Directory
        } else {
            for (parent, (_, entries)) in &self.dirs {
                if let Some(e) = entries
                    .iter()
                    .find(|e| format!("{parent}/{}", e.name) == path)
                {
                    return match e.kind {
                        DirectoryEntryKind::Directory => FilesystemEntry::Directory,
                        DirectoryEntryKind::Symlink => FilesystemEntry::Symlink {
                            target: "/outside/data".into(),
                        },
                        _ => FilesystemEntry::File,
                    };
                }
            }
            FilesystemEntry::Missing
        }
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        if let Some(status) = self.failure {
            return DirectoryRead::failed(self.source(), path, limits, status, "fixture failure");
        }
        let Some((id, entries)) = self.dirs.get(path) else {
            return DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Missing,
                "absent",
            );
        };
        let changed = self.changed && self.calls.fetch_add(1, Ordering::Relaxed) > 0;
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            identity(id + if changed { 100 } else { 0 }),
            entries.clone(),
        )
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("record-proof"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command))
}
fn proofs(response: &CheckResponse) -> Vec<&StdoutRecordsEvidence> {
    response
        .decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::StdoutRecords(r) => Some(r),
            _ => None,
        })
        .collect()
}

#[test]
fn complete_records_preserve_spelling_and_do_not_invent_traversal_order() {
    for (flag, encoding, sep) in [
        ("-print", StreamRecordEncoding::Lines, b'\n'),
        ("-print0", StreamRecordEncoding::Nul, 0),
    ] {
        let r = check(
            &format!("find ./input -type f -name '*.csv' {flag} | cat"),
            Files::new(),
        );
        let p = proofs(&r)[0];
        assert!(p.complete, "{p:#?}");
        assert_eq!(p.records.len(), 3);
        assert_eq!(p.encoding, Some(encoding));
        assert_eq!(p.order, StreamRecordOrder::Unspecified);
        assert!(p.complete_bytes().is_none());
        for record in &p.records {
            let mut bytes = record.path_spelling.as_bytes().to_vec();
            bytes.push(sep);
            assert_eq!(record.bytes, bytes);
        }
        assert!(
            p.records
                .iter()
                .any(|r| r.path_spelling == "./input/line\nbreak.csv")
        );
        assert_eq!(p.directory_observations.len(), 2);
    }
}

#[test]
fn empty_output_missing_directory_and_failed_observations_are_distinct() {
    let r = check("find input -name missing | cat", Files::new());
    let p = proofs(&r)[0];
    assert!(p.complete);
    assert_eq!(p.complete_bytes(), Some(vec![]));
    for status in [
        DirectoryReadStatus::Missing,
        DirectoryReadStatus::Unreadable,
        DirectoryReadStatus::NonUtf8,
        DirectoryReadStatus::Changed,
        DirectoryReadStatus::Unavailable,
        DirectoryReadStatus::TooLarge,
    ] {
        let mut files = Files::new();
        files.failure = Some(status);
        let r = check("find input -name '*.csv' | cat", files);
        let p = proofs(&r)[0];
        assert!(!p.complete);
        assert!(p.records.is_empty());
        assert!(p.complete_bytes().is_none());
    }
}

#[test]
fn formatting_and_single_record_exact_bytes_are_independent_of_path_containment() {
    let r = check(
        r"find ./input -name a.csv -printf '../dest/%P\0%f\n' | cat",
        Files::new(),
    );
    let p = proofs(&r)[0];
    assert!(p.complete, "{p:#?}");
    assert_eq!(p.records[0].path_spelling, "./input/a.csv");
    assert_eq!(p.complete_bytes(), Some(b"../dest/a.csv\0a.csv\n".to_vec()));
    assert_eq!(p.encoding, Some(StreamRecordEncoding::NativeFormat));
}

#[test]
fn physical_walk_includes_links_as_entries_but_never_follows_them() {
    let r = check("find input -type l -print0", Files::new());
    let p = proofs(&r)[0];
    assert!(p.complete, "{p:#?}");
    assert_eq!(p.complete_bytes(), Some(b"input/link.csv\0".to_vec()));
    let r = check("find input -maxdepth 0 -print0", Files::new());
    assert_eq!(proofs(&r)[0].complete_bytes(), Some(b"input\0".to_vec()));
}

#[test]
fn unsupported_expressions_changes_and_current_writes_do_not_certify_output() {
    for command in [
        "find input -name a.csv -o -name b.csv",
        "find input -print -name a.csv",
        "find input -printf '%s\\n'",
        "touch input/new.csv; find input -name '*.csv'",
        "find input > input/out",
        "unknown_namespace_mutator; find input -print0",
        "git checkout feature; find input -print0",
        "less /other; find input -print0",
    ] {
        let r = check(command, Files::new());
        let p = proofs(&r);
        assert!(!p.is_empty(), "{command}: {r:#?}");
        assert!(!p[0].complete, "{command}: {p:#?}");
    }
    let mut files = Files::new();
    files.changed = true;
    let r = check("find input -maxdepth 0", files);
    assert!(!proofs(&r)[0].complete);
}

#[test]
fn forwarding_requires_a_declared_byte_preserving_contract_and_plain_route() {
    let r = check("find input -name a.csv | cat | cat", Files::new());
    let p = proofs(&r);
    assert_eq!(p.len(), 3, "{r:#?}");
    assert!(
        p.iter()
            .all(|p| p.complete_bytes() == Some(b"input/a.csv\n".to_vec()))
    );
    assert!(p.iter().any(|p| p.forwarded_by.len() == 2));
    for command in [
        "find input -name a.csv | sort | cat",
        "find input -name a.csv |& cat",
        "find input -name a.csv 1>&2 | cat",
        "find input -name a.csv | cat /other",
        "find input -name a.csv | cat < /other",
    ] {
        let r = check(command, Files::new());
        assert_eq!(proofs(&r).len(), 1, "{command}: {r:#?}");
    }
}

#[test]
fn unknown_consumer_input_is_not_promoted_to_argv_by_the_observation_stage() {
    let r = check("find input -name a.csv | xargs -n1 cp source", Files::new());
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "cp" && s.operation_semantics_unresolved)
    );
}

#[test]
fn aggregate_byte_and_entry_budgets_do_not_return_partial_records() {
    for (count, name) in [(4097, "x".into()), (100, "x".repeat(800))] {
        let mut files = Files::new();
        files.dirs.insert(
            "/workspace/input".into(),
            (
                1,
                (0..count)
                    .map(|i| entry(&format!("{name}{i}"), DirectoryEntryKind::File, i + 3))
                    .collect(),
            ),
        );
        let r = check("find input -print0", files);
        let p = proofs(&r)[0];
        assert!(!p.complete);
        assert!(p.records.is_empty());
        assert!(p.complete_bytes().is_none());
    }
}

#[test]
fn changed_root_link_invalidates_an_unchanged_canonical_directory() {
    use std::sync::atomic::AtomicBool;
    struct Alias {
        files: Files,
        change: bool,
        shifted: AtomicBool,
    }
    impl FilesystemView for Alias {
        fn entry(&self, path: &str) -> FilesystemEntry {
            if path == "/workspace/alias" {
                FilesystemEntry::Symlink {
                    target: if self.shifted.load(Ordering::Relaxed) {
                        "/outside"
                    } else {
                        "input"
                    }
                    .into(),
                }
            } else {
                self.files.entry(path)
            }
        }
        fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
            let read = self.files.read_directory(path, limits);
            if self.change {
                self.shifted.store(true, Ordering::Relaxed);
            }
            read
        }
    }
    for change in [false, true] {
        let files = Alias {
            files: Files::new(),
            change,
            shifted: AtomicBool::new(false),
        };
        let r = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(files))
            .check(request("find alias/sub -print0"));
        let p = proofs(&r)[0];
        assert_eq!(p.complete, !change, "{p:#?}");
        if change {
            assert!(p.gap.as_deref().unwrap().contains("namespace changed"));
        }
    }
}

#[test]
fn terminal_mode_and_locale_dependencies_require_actual_frame_evidence() {
    let r = check("find input -name a.csv", Files::new());
    assert!(!proofs(&r)[0].complete);
    let r = check("find input -iname '*.CSV' | cat", Files::new());
    assert!(!proofs(&r)[0].complete);
    let r = check("LC_ALL=C find input -iname '*.CSV' | cat", Files::new());
    let p = proofs(&r)[0];
    assert!(p.complete, "{p:#?}");
    assert_eq!(p.environment_observations[0].name, "LC_ALL");
    let r = check(
        "LC_ALL=tr_TR.UTF-8 find input -iname '*.CSV' | cat",
        Files::new(),
    );
    assert!(!proofs(&r)[0].complete);
}

#[test]
fn producer_cwd_and_mixed_output_actions_keep_distinct_native_bytes() {
    let mut req = request("find . -name a.csv -print0 -print | cat");
    req.shell_state_before = ShellStateSnapshot::new("/workspace/input");
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Files::new()))
        .check(req);
    let p = proofs(&r)[0];
    assert!(p.complete, "{p:#?}");
    assert_eq!(p.cwd.as_deref(), Some("/workspace/input"));
    assert_eq!(p.complete_bytes(), Some(b"./a.csv\0./a.csv\n".to_vec()));
    let uncertain = check(
        "cd input; find . -name a.csv -print0 -print | cat",
        Files::new(),
    );
    assert!(!proofs(&uncertain)[0].complete);
    for command in [
        "find input -name a.csv | cat -n | cat",
        "find input -name a.csv | cat 2>/dev/stdout | cat",
    ] {
        let r = check(command, Files::new());
        assert!(proofs(&r).len() < 3, "{r:#?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_native_find_confirms_output_bytes_without_assuming_order() {
    use std::{fs, process::Command};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "caushell-record-oracle-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _fixture = Fixture(root.clone());
    for name in ["a.csv", "line\nbreak.csv", "space 'quote\\.csv", ".hidden"] {
        fs::write(root.join(name), b"content").unwrap();
    }
    fn permutation(bytes: &[u8], records: &[&[u8]]) -> bool {
        if records.is_empty() {
            return bytes.is_empty();
        }
        for (i, part) in records.iter().enumerate() {
            if let Some(rest) = bytes.strip_prefix(*part) {
                let remaining = records
                    .iter()
                    .enumerate()
                    .filter_map(|(j, r)| (i != j).then_some(*r))
                    .collect::<Vec<_>>();
                if permutation(rest, &remaining) {
                    return true;
                }
            }
        }
        false
    }
    for (source, args) in [
        (
            "find .// -type f -print0",
            vec![".//", "-type", "f", "-print0"],
        ),
        (
            "find ././ -type f -print0",
            vec!["././", "-type", "f", "-print0"],
        ),
        (
            "find . -type f -name '*.csv' -print | cat",
            vec![".", "-type", "f", "-name", "*.csv", "-print"],
        ),
        (
            "find . -type f -name '*.csv' -print0",
            vec![".", "-type", "f", "-name", "*.csv", "-print0"],
        ),
        (
            r"find . -type f -printf 'prefix/%P\0%f\n' | cat",
            vec![".", "-type", "f", "-printf", r"prefix/%P\0%f\n"],
        ),
    ] {
        let mut req = request(source);
        req.shell_state_before = ShellStateSnapshot::new(root.to_str().unwrap());
        req.workspace_root = Some(root.to_str().unwrap().into());
        let response = ShellQueryCore::new().check(req);
        let p = proofs(&response)[0];
        assert!(p.complete, "{source}: {p:#?}");
        let actual = Command::new("find")
            .args(args)
            .current_dir(&root)
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(actual.status.success());
        assert!(actual.stderr.is_empty());
        assert!(
            permutation(
                &actual.stdout,
                &p.records
                    .iter()
                    .map(|r| r.bytes.as_slice())
                    .collect::<Vec<_>>()
            ),
            "{source}"
        );
    }
}
