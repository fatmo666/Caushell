//! Request-local namespace invariants, never execution or authorization facts.
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

struct Files {
    entries: BTreeMap<String, FilesystemEntry>,
    unavailable: bool,
    changing: bool,
    reads: AtomicUsize,
}
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
impl Files {
    fn new() -> Self {
        Self {
            entries: BTreeMap::from([
                ("/".into(), FilesystemEntry::Directory),
                ("/workspace".into(), FilesystemEntry::Directory),
                ("/outside".into(), FilesystemEntry::Directory),
                ("/workspace/input.bin".into(), FilesystemEntry::File),
            ]),
            unavailable: false,
            changing: false,
            reads: AtomicUsize::new(0),
        }
    }
    fn entry(mut self, path: &str, entry: FilesystemEntry) -> Self {
        self.entries.insert(path.into(), entry);
        self
    }
}
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.entries
            .get(path)
            .cloned()
            .unwrap_or(FilesystemEntry::Missing)
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        if self.unavailable {
            return DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Unavailable,
                "fixture observation unavailable",
            );
        }
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let entries = self
            .entries
            .iter()
            .filter_map(|(p, e)| {
                let name = p.strip_prefix(&prefix)?;
                if name.is_empty() || name.contains('/') {
                    return None;
                }
                let kind = match e {
                    FilesystemEntry::Directory => DirectoryEntryKind::Directory,
                    FilesystemEntry::File => DirectoryEntryKind::File,
                    FilesystemEntry::Symlink { .. } => DirectoryEntryKind::Symlink,
                    _ => DirectoryEntryKind::Other,
                };
                Some(DirectoryEntry {
                    name: name.into(),
                    kind,
                    identity: identity(p.len() as u64),
                })
            })
            .collect();
        let changed = self.changing && self.reads.fetch_add(1, Ordering::Relaxed) > 0;
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            identity(if changed { 2 } else { 1 }),
            entries,
        )
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("directory-creation-state"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/user".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command))
}

#[test]
fn directory_creation_preserves_namespace_without_claiming_success() {
    for command in [
        "mkdir -p output && printf x > output/result",
        "mkdir -p output; mkdir -p output/subdir",
        "mkdir -p output && ffmpeg -i input.bin output/frame_%03d.png",
        "mkdir -p output && ffmpeg -i input.bin -vf fps=2 output/clip.mp4",
    ] {
        let response = check(command, Files::new());
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty()),
            "{command}"
        );
        for observation in response
            .decision_trace
            .path_targets
            .iter()
            .flat_map(|p| &p.observations)
        {
            if observation.path == "/workspace/output" {
                assert_eq!(
                    observation.entry,
                    FilesystemEntry::Missing,
                    "an abstract producer is not an observed creation"
                );
            }
        }
    }
}

#[test]
fn bounded_output_families_require_complete_current_link_free_observations() {
    let command = "mkdir -p output && ffmpeg -i input.bin output/frame_%03d.png";
    let clean = Files::new()
        .entry("/workspace/output", FilesystemEntry::Directory)
        .entry("/workspace/output/old.png", FilesystemEntry::File);
    assert_eq!(check(command, clean).decision, Decision::Allow);
    let linked = Files::new()
        .entry("/workspace/output", FilesystemEntry::Directory)
        .entry(
            "/workspace/output/frame_001.png",
            FilesystemEntry::Symlink {
                target: "/outside/file".into(),
            },
        );
    assert_eq!(check(command, linked).decision, Decision::NeedApproval);
    let mut unavailable = Files::new().entry("/workspace/output", FilesystemEntry::Directory);
    unavailable.unavailable = true;
    assert_eq!(check(command, unavailable).decision, Decision::NeedApproval);
    let mut changing = Files::new().entry("/workspace/output", FilesystemEntry::Directory);
    changing.changing = true;
    assert_eq!(check(command, changing).decision, Decision::NeedApproval);
}

#[test]
fn namespace_proofs_do_not_grant_outside_authority_or_trust_unknown_siblings() {
    for command in [
        "mkdir -p /outside/output && ffmpeg -i input.bin /outside/output/frame_%03d.png",
        "mkdir -p output; ln -s /outside output/link; ffmpeg -i input.bin output/frame_%03d.png",
        "mkdir -p output; mystery; ffmpeg -i input.bin output/frame_%03d.png",
        "mkdir -p output; ./program; ffmpeg -i input.bin output/frame_%03d.png",
        "mkdir -p output && ffmpeg -i input.bin output_%03d/frame.png",
        "mkdir -p output && ffmpeg -i input.bin -vf movie=/outside/input output/frame.png",
        "mkdir -p output && ffmpeg -i input.bin output/frame.png; rm output/frame.png",
        "mkdir -p output && ffmpeg -i input.bin output/frame.png; python3 -c pass",
    ] {
        let response = check(
            command,
            Files::new().entry("/workspace/program", FilesystemEntry::File),
        );
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        if command.starts_with("mkdir -p /outside/output") {
            assert!(response.decision_trace.path_targets.iter().any(|p| {
                matches!(&p.resolution, SemanticResolution::Resolved { value: PathResolution::BoundedPathSet { roots, may_escape: false } }
                    if roots.iter().any(|root| root == "/outside/output"))
            }), "the outside namespace can be proved without authorizing it");
            assert!(
                response
                    .decision_trace
                    .decision_proposals
                    .iter()
                    .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
            );
        }
        if command.contains("ln -s /outside output/link") {
            let family = response
                .decision_trace
                .path_targets
                .iter()
                .find(|p| {
                    matches!(&p.lexical, PathResolution::BoundedPathSet { roots, may_escape: false }
                    if roots.iter().any(|root| root == "/workspace/output"))
                })
                .expect("the output family remains in the trace");
            assert!(
                matches!(
                    &family.resolution,
                    SemanticResolution::Unresolved {
                        gap: SemanticGap {
                            kind: SemanticGapKind::NamespaceMutation,
                            ..
                        },
                        ..
                    }
                ),
                "a future child link must invalidate the family: {family:#?}"
            );
            assert!(family.namespace_proofs.is_empty());
        }
    }
    assert_eq!(
        check(
            "mkdir -p output && ffmpeg -i input.bin output/frame.png; rm -rf /",
            Files::new()
        )
        .decision,
        Decision::Deny
    );
    assert_eq!(
        check(
            "./program",
            Files::new().entry("/workspace/program", FilesystemEntry::File)
        )
        .decision,
        Decision::Allow,
        "Rejecting an opaque namespace transformer must not revoke existing file-execution authority"
    );
}

#[test]
fn bounded_families_never_fall_back_to_lexical_success_on_budget_exhaustion() {
    let command = "mkdir -p output && ffmpeg -i input.bin output/frame_%03d.png";
    let mut wide = Files::new().entry("/workspace/output", FilesystemEntry::Directory);
    for index in 0..=MAX_DIRECTORY_ENTRIES {
        wide.entries
            .insert(format!("/workspace/output/{index}"), FilesystemEntry::File);
    }
    assert_eq!(check(command, wide).decision, Decision::NeedApproval);
    let mut deep = Files::new().entry("/workspace/output", FilesystemEntry::Directory);
    let mut path = "/workspace/output".to_owned();
    for _ in 0..=MAX_DIRECTORY_DEPTH {
        path.push_str("/child");
        deep.entries
            .insert(path.clone(), FilesystemEntry::Directory);
    }
    assert_eq!(check(command, deep).decision, Decision::NeedApproval);
}

#[test]
fn restored_sessions_reobserve_directory_families_instead_of_reusing_proofs() {
    let mut core = ShellQueryCore::new().with_filesystem_view(Arc::new(Files::new()));
    let first = core.check(request(
        "mkdir -p output && ffmpeg -i input.bin output/frame_%03d.png",
    ));
    assert_eq!(first.decision, Decision::Allow);
    let session = SessionId::new("directory-creation-state");
    let snapshot = core.session_snapshot(&session, 1).unwrap();
    let snapshot = serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let mut restored = ShellQueryCore::new().with_filesystem_view(Arc::new(Files::new().entry(
        "/workspace/output",
        FilesystemEntry::Symlink {
            target: "/outside".into(),
        },
    )));
    restored.insert_session_state(
        session,
        caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
    );
    let mut next = request("ffmpeg -i input.bin output/frame_%03d.png");
    next.sequence_no = CommandSequenceNo(2);
    let response = restored.check(next);
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .all(|p| p.namespace_proofs.is_empty())
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .flat_map(|p| &p.observations)
            .any(|o| o.path == "/workspace/output"
                && matches!(o.entry, FilesystemEntry::Symlink { .. }))
    );
}
