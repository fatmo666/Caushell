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
fn complete_consumer_input_is_bound_by_the_native_argv_stage() {
    let r = check("find input -name a.csv | xargs -n1 cp source", Files::new());
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "cp" && !s.operation_semantics_unresolved)
    );
}

fn expect_native(command: &str, files: Files, decision: Decision) -> CheckResponse {
    let response = check(command, files);
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
    response
}

#[test]
fn consumer_variants_reuse_binding_and_existing_file_namespace_facts() {
    for command in [
        "find input -name a.csv | xargs -n1 cp source",
        "find input -name a.csv | xargs -n1 env cp source",
        "find input -name a.csv | cat | xargs -n1 cp source",
        "find input -name '*.csv' -type f -print0 | xargs -0 -n1 chmod 644",
        "find input -name a.csv | xargs -I{} cp source {}",
        "find input -name a.csv -printf '%p|' | xargs -d '|' -n1 cp source",
    ] {
        let r = expect_native(command, Files::new(), Decision::Allow);
        assert!(
            r.decision_trace
                .evidence
                .iter()
                .any(|e| matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete)),
            "{r:#?}"
        );
    }
}

#[test]
fn native_line_decoding_does_not_inherit_path_containment() {
    let mut files = Files::new();
    files.dirs.insert(
        "/workspace/input".into(),
        (1, vec![entry("part\n", DirectoryEntryKind::Directory, 10)]),
    );
    files.dirs.insert(
        "/workspace/input/part\n".into(),
        (10, vec![entry("escape.csv", DirectoryEntryKind::File, 11)]),
    );
    // The actual newline splits a pathname into a workspace-relative item and
    // an absolute destination. Both are fed through ordinary cp binding.
    expect_native(
        "find input -name escape.csv | xargs -n1 cp source",
        files,
        Decision::NeedApproval,
    );
}

#[test]
fn filename_bytes_are_argv_data_and_may_be_native_control_options() {
    let response = expect_native(
        "find input -name a.csv -printf '--target-directory=/outside\\0' | xargs -0 -n1 cp source",
        Files::new(),
        Decision::NeedApproval,
    );
    assert!(
        response
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete))
    );
    let mut files = Files::new();
    files.dirs.insert(
        "/workspace/input".into(),
        (
            1,
            vec![entry("--reference=outside", DirectoryEntryKind::File, 10)],
        ),
    );
    let response = expect_native(
        "find input -type f -printf '%f\\n' | xargs -n1 chmod 644",
        files,
        Decision::Allow,
    );
    // Native --reference changes ownership: 644 is now the target filename,
    // not a mode. Existing policy permits metadata changes inside the workspace.
    assert!(response.decision_trace.path_targets.iter().any(|p|
        p.operation==PathTargetOperation::Metadata && matches!(&p.lexical,PathResolution::Concrete { path } if path=="/workspace/644")));
    assert!(
        response
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::NativeInputDecode(d) if d.complete))
    );
    let mut files = Files::new();
    files.dirs.insert(
        "/workspace/input".into(),
        (
            1,
            vec![entry("--reference=outside", DirectoryEntryKind::File, 10)],
        ),
    );
    files.dirs.insert(
        "/outside".into(),
        (20, vec![entry("victim", DirectoryEntryKind::File, 21)]),
    );
    let response = expect_native(
        "find input -type f -printf '%f\\n' | xargs -n1 chmod /outside/victim",
        files,
        Decision::NeedApproval,
    );
    assert!(response.decision_trace.path_targets.iter().any(|p|
        p.operation==PathTargetOperation::Metadata && matches!(&p.lexical,PathResolution::Concrete { path } if path=="/outside/victim")));
    assert!(
        response
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::NativeInputDecode(d) if d.complete))
    );
    let mut files = Files::new();
    files.dirs.insert(
        "/workspace/input".into(),
        (
            1,
            vec![entry(
                "$(touch marker);echo text",
                DirectoryEntryKind::File,
                10,
            )],
        ),
    );
    let response = expect_native(
        "find input -type f -print0 | xargs -0 -n1 chmod 644",
        files,
        Decision::Allow,
    );
    assert!(
        !response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|e| e.normalized_command_name == "touch")
    );
}

#[test]
fn changing_namespace_incomplete_decoding_and_order_limits_never_pass() {
    for command in [
        "find input -name a.csv | xargs -n1 mv source",
        "find input -name a.csv | xargs -n1 ln -s source",
        "find input -name a.csv | xargs -n1 cp --remove-destination source",
        "find input -name a.csv | xargs -s 64 -n1 cp source",
        "find input -name a.csv -printf '\\377' | xargs -n1 cp source",
        "find input -name a.csv -printf '\"%p\\n' | xargs -n1 cp source",
        "find input -type f -print0 | xargs -0 -n1 unknown_consumer",
        "find input -print0 | xargs -0 -n1 chmod 000",
    ] {
        expect_native(command, Files::new(), Decision::NeedApproval);
    }
    let mut files = Files::new();
    files.changed = true;
    expect_native(
        "find input -name a.csv | xargs -n1 cp source",
        files,
        Decision::NeedApproval,
    );
}

#[test]
fn complete_empty_input_preserves_run_if_empty_and_routing() {
    expect_native(
        "find input -name absent | xargs -n1 cp source /outside/dest",
        Files::new(),
        Decision::NeedApproval,
    );
    expect_native(
        "find input -name absent | xargs -r -n1 cp source /outside/dest",
        Files::new(),
        Decision::Allow,
    );
    for command in [
        "find input -name a.csv |& xargs -n1 cp source",
        "find input -name a.csv | xargs -n1 cp source < unknown-list",
        "find input -name a.csv | sed 's/a/b/' | xargs -n1 cp source",
    ] {
        expect_native(command, Files::new(), Decision::NeedApproval);
    }
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

#[test]
fn neutral_consumer_targets_preserve_fresh_native_input_proofs() {
    for consumer in ["ls -l", "stat -c %s"] {
        let r = check(
            &format!("find ./input -type f -print0 | xargs -0 {consumer}"),
            Files::new(),
        );
        assert_eq!(r.decision, Decision::Allow, "{consumer}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .evidence
                .iter()
                .any(|e| matches!(&e.kind,EvidenceKind::NativeInputDecode(d) if d.complete))
        );
        assert!(
            proofs(&r)
                .iter()
                .any(|p| p.complete && !p.records.is_empty())
        );
    }
}

fn metadata_without_concrete_input(response: &CheckResponse) {
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    assert!(response.decision_trace.evidence.iter().any(|e|matches!(&e.kind,EvidenceKind::NativeInputEffect(p) if p.effect_envelope==Some(NativeArgvEffectEnvelope::MetadataQuery))));
    assert!(
        !response
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::NativeInputDecode(p) if p.complete))
    );
    assert!(proofs(response).iter().all(|p| !p.complete));
}

#[test]
fn metadata_effect_closure_does_not_certify_changed_missing_or_mutating_input_bytes() {
    // A universal metadata query needs no invented record set. Its separate
    // effect proof does not waive unrelated mutation or execution policy.
    metadata_without_concrete_input(&check(
        "mkdir ./input/new; find ./input -type f -print0 | xargs -0 ls",
        Files::new(),
    ));
    let mut files = Files::new();
    files.changed = true;
    metadata_without_concrete_input(&check("find ./input -type f -print0 | xargs -0 ls", files));
    let mut files = Files::new();
    files.failure = Some(DirectoryReadStatus::TooLarge);
    metadata_without_concrete_input(&check("find ./input -type f -print0 | xargs -0 ls", files));
    for command in [
        "find ./input -type f -print0 | xargs -0 unknown_fixture",
        "mkdir /outside/new; find ./input -type f -print0 | xargs -0 ls",
    ] {
        assert_eq!(
            check(command, Files::new()).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
    assert_eq!(
        check(
            "find ./input -type f -print0 | xargs -0 sh -c 'rm -rf /'",
            Files::new()
        )
        .decision,
        Decision::Deny
    );
}

#[test]
fn find_boolean_actions_and_prune_preserve_exact_observed_records() {
    for (expression, expected, directories) in [
        (
            r"\( -name a.csv -o -name b.csv \) -type f -print0",
            vec!["./input/a.csv", "./input/sub/b.csv"],
            2,
        ),
        (
            "-name sub -prune -o -type f -print0",
            vec![
                "./input/a.csv",
                "./input/line\nbreak.csv",
                "./input/.hidden",
            ],
            1,
        ),
        (
            "-false -a -prune -o -type f -print0",
            vec![
                "./input/a.csv",
                "./input/line\nbreak.csv",
                "./input/.hidden",
                "./input/sub/b.csv",
            ],
            2,
        ),
        (
            "-type f -not -name '*.csv' -print0",
            vec!["./input/.hidden"],
            2,
        ),
        ("-name sub -prune", vec!["./input/sub"], 1),
    ] {
        let response = check(&format!("find ./input {expression} | cat"), Files::new());
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{expression}: {:?}",
            response.reasons
        );
        let proof = proofs(&response)[0];
        assert!(proof.complete, "{proof:#?}");
        let mut got = proof
            .records
            .iter()
            .map(|r| r.path_spelling.as_str())
            .collect::<Vec<_>>();
        let mut expected = expected;
        got.sort();
        expected.sort();
        assert_eq!(got, expected, "{expression}");
        assert_eq!(
            proof.directory_observations.len(),
            directories,
            "{expression}"
        );
    }
}

#[test]
fn conditional_output_and_negation_do_not_undo_already_executed_actions() {
    for (expression, records) in [
        ("-print0 -name missing", 7),
        ("-true -o -print0", 0),
        ("! -prune", 0),
        ("-prune", 1),
        ("-name a.csv -print0 -o -name sub -print0", 2),
    ] {
        let response = check(&format!("find ./input {expression} | cat"), Files::new());
        let proof = proofs(&response)[0];
        assert!(proof.complete, "{expression}: {proof:#?}");
        assert_eq!(proof.records.len(), records, "{expression}");
    }
    let response = check(
        "find ./input -name a.csv -print0 -o -name b.csv -print0 | xargs -0 stat -c %s",
        Files::new(),
    );
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    let proof = proofs(&response)[0];
    assert!(proof.complete);
    assert_eq!(proof.encoding, Some(StreamRecordEncoding::Nul));
    assert!(
        response
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,EvidenceKind::NativeInputDecode(d) if d.complete))
    );
}

#[test]
fn effect_proofs_never_replace_missing_find_observations_or_execution_proofs() {
    for expression in ["-mtime -1 -print0", "-L", "-false -a -mtime -1 -o -print0"] {
        let response = check(
            &format!("find ./input {expression} | xargs -0 ls"),
            Files::new(),
        );
        metadata_without_concrete_input(&response);
        let response = check(
            &format!("find ./input {expression} | xargs -0 chmod 444"),
            Files::new(),
        );
        assert_eq!(response.decision, Decision::NeedApproval, "{expression}");
    }
    for changed in [false, true] {
        let mut files = Files::new();
        files.changed = changed;
        if !changed {
            files.failure = Some(DirectoryReadStatus::Unavailable);
        }
        metadata_without_concrete_input(&check(
            "find ./input ! -name '*.tmp' -print0 | xargs -0 stat -c %s",
            files,
        ));
    }
    assert_eq!(
        check(
            "find ./input ! -name '*.tmp' -print0 | xargs -0 sh -c 'rm -rf /'",
            Files::new()
        )
        .decision,
        Decision::Deny
    );
}

#[test]
fn empty_name_selection_and_newline_ancestor_injection_remain_distinct() {
    let command =
        r"find ./input \( -name 1.txt -o -name 2.txt -o -name 3.txt \) -print | xargs chmod 444";
    let response = check(command, Files::new());
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    assert!(
        proofs(&response)
            .iter()
            .any(|p| p.complete && p.records.is_empty())
    );
    let mut files = Files::new();
    files.dirs.get_mut("/workspace/input").unwrap().1.extend([
        entry("safe", DirectoryEntryKind::File, 29),
        entry("safe\n", DirectoryEntryKind::Directory, 30),
    ]);
    files.dirs.insert(
        "/workspace/input/safe\n".into(),
        (
            30,
            vec![entry("outside", DirectoryEntryKind::Directory, 31)],
        ),
    );
    files.dirs.insert(
        "/workspace/input/safe\n/outside".into(),
        (
            31,
            vec![entry("victim\nleaf", DirectoryEntryKind::Directory, 32)],
        ),
    );
    files.dirs.insert(
        "/workspace/input/safe\n/outside/victim\nleaf".into(),
        (32, vec![entry("1.txt", DirectoryEntryKind::File, 33)]),
    );
    files.dirs.insert(
        "/workspace/leaf".into(),
        (40, vec![entry("1.txt", DirectoryEntryKind::File, 41)]),
    );
    files.dirs.insert(
        "/outside".into(),
        (90, vec![entry("victim", DirectoryEntryKind::File, 91)]),
    );
    let response = check(command, files);
    assert_eq!(
        response.decision,
        Decision::NeedApproval,
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Metadata
                && matches!(&p.lexical,PathResolution::Concrete{path} if path=="/outside/victim"))
    );
}
