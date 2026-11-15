//! Judge-only tests with an explicit, complete filesystem view; no command executes.
use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView};
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};
struct Namespace(BTreeMap<String, FilesystemEntry>);
impl Namespace {
    fn ordinary() -> Self {
        Self(BTreeMap::from([
            ("/".into(), FilesystemEntry::Directory),
            ("/workspace".into(), FilesystemEntry::Directory),
            ("/workspace/src".into(), FilesystemEntry::Directory),
            ("/tmp".into(), FilesystemEntry::Directory),
            ("/outside".into(), FilesystemEntry::Directory),
            ("/outside/secret".into(), FilesystemEntry::File),
            ("/workspace/file".into(), FilesystemEntry::File),
            ("/workspace/src/input".into(), FilesystemEntry::File),
        ]))
    }
    fn set(mut self, path: &str, entry: FilesystemEntry) -> Self {
        self.0.insert(path.into(), entry);
        self
    }
}
impl FilesystemView for Namespace {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0
            .get(path)
            .cloned()
            .unwrap_or(FilesystemEntry::Missing)
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let entries = self
            .0
            .iter()
            .filter_map(|(p, k)| {
                let name = p.strip_prefix(&prefix)?;
                if name.is_empty() || name.contains('/') {
                    return None;
                }
                let kind = match k {
                    FilesystemEntry::Directory => DirectoryEntryKind::Directory,
                    FilesystemEntry::File => DirectoryEntryKind::File,
                    FilesystemEntry::Symlink { .. } => DirectoryEntryKind::Symlink,
                    _ => return None,
                };
                Some(DirectoryEntry {
                    name: name.into(),
                    kind,
                    identity: FileContentIdentity {
                        device: 1,
                        inode: 2,
                        size: 0,
                        modified_seconds: 0,
                        modified_nanos: 0,
                        changed_seconds: 0,
                        changed_nanos: 0,
                    },
                })
            })
            .collect();
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            FileContentIdentity {
                device: 1,
                inode: 1,
                size: 0,
                modified_seconds: 0,
                modified_nanos: 0,
                changed_seconds: 0,
                changed_nanos: 0,
            },
            entries,
        )
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("namespace-preservation"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent),
        shell_kind: ShellKind::Bash,
        home: Some("/home/auditor".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "namespace-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
fn check(command: &str, view: Namespace) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(view))
        .check(request(command))
}
fn allowed(command: &str, view: Namespace) {
    let r = check(command, view);
    assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
}
#[test]
fn removing_an_ordinary_leaf_preserves_its_parent_lookup() {
    for present in [false, true] {
        let mut ns = Namespace::ordinary();
        if present {
            ns = ns.set("/workspace/temp", FilesystemEntry::File);
        }
        allowed("grep -v pattern file > temp && mv temp file", ns);
    }
}
#[test]
fn in_place_regular_file_families_preserve_their_namespace() {
    allowed(
        "find . -type f -exec dos2unix {} {} \\;",
        Namespace::ordinary(),
    );
}
#[test]
fn bounded_directory_creation_preserves_the_closed_link_free_family() {
    allowed(
        "find src/ -type d -exec mkdir -p dest/{} \\; -o -type f -exec touch dest/{} \\;",
        Namespace::ordinary(),
    );
}
#[test]
fn link_creation_and_link_moves_never_inherit_leaf_authority() {
    for command in [
        "ln -s /outside temp; mv temp file; printf x > file",
        "ln -s /outside parent; grep -v pattern file > parent/temp && mv parent/temp file",
        "mv temp file; printf x > file",
    ] {
        let r = check(
            command,
            Namespace::ordinary().set(
                "/workspace/temp",
                FilesystemEntry::Symlink {
                    target: "/outside/secret".into(),
                },
            ),
        );
        assert_ne!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
    }
}
#[test]
fn directory_relocation_opaque_effects_and_system_targets_remain_guarded() {
    for command in [
        "mv temp file; printf x > file/child",
        "unknown-tool; grep -v pattern file > temp && mv temp file",
        "mv /etc/passwd file",
    ] {
        let r = check(
            command,
            Namespace::ordinary().set("/workspace/temp", FilesystemEntry::Directory),
        );
        assert_ne!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
    }
    assert_eq!(
        check(
            "grep -v pattern file > temp && mv temp file; rm -rf /",
            Namespace::ordinary()
        )
        .decision,
        Decision::Deny
    );
}
#[test]
fn symlinked_or_unobserved_families_do_not_receive_a_closed_tree_proof() {
    let r = check(
        "find . -type f -exec dos2unix {} {} \\;",
        Namespace::ordinary().set(
            "/workspace/door",
            FilesystemEntry::Symlink {
                target: "/outside".into(),
            },
        ),
    );
    assert_ne!(r.decision, Decision::Allow, "{:?}", r.reasons);
    let r = check(
        "find src/ -type d -exec mkdir -p dest/{} \\; -o -type f -exec touch dest/{} \\;",
        Namespace::ordinary().set(
            "/workspace/dest",
            FilesystemEntry::Unavailable {
                reason: "no observation".into(),
            },
        ),
    );
    assert_ne!(r.decision, Decision::Allow, "{:?}", r.reasons);
}

#[test]
fn backup_modes_keep_known_effects_but_cannot_certify_hidden_output_names() {
    for command in [
        "mv -b temp file",
        "mv --backup=numbered temp file",
        "mv -S '~' temp file",
        "mv -b -t dest temp",
    ] {
        let r = check(
            command,
            Namespace::ordinary().set("/workspace/temp", FilesystemEntry::File),
        );
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|f| f.normalized_command_name == "mv" && f.operation_semantics_unresolved)
        );
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .all(|f| f.namespace_proofs.is_empty()),
            "{command}"
        );
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|f| f.operation == PathTargetOperation::MoveSource),
            "{command}"
        );
    }
}
#[test]
fn removal_proofs_preserve_absence_observations_and_do_not_assert_execution() {
    let r = check(
        "grep -v pattern file > temp && mv temp file",
        Namespace::ordinary(),
    );
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    let facts = &r.decision_trace.path_targets;
    assert!(facts.iter().any(|f| {
        f.namespace_proofs
            .iter()
            .any(|p| p.effect == PathNamespaceEffect::EntryRemoval)
    }));
    for o in facts
        .iter()
        .flat_map(|f| &f.observations)
        .filter(|o| o.path == "/workspace/temp")
    {
        assert_eq!(o.entry, FilesystemEntry::Missing);
    }
    let roundtrip: Vec<PathTargetFact> =
        serde_json::from_str(&serde_json::to_string(facts).unwrap()).unwrap();
    assert_eq!(*facts, roundtrip);
}
#[test]
fn repeated_and_conditional_leaf_removals_keep_the_same_scope_invariant() {
    for command in [
        "mv temp file; printf x > temp",
        "if true; then mv temp file; fi; printf x > temp",
        "for n in 1 2; do mv temp file; printf x > temp; done",
    ] {
        allowed(
            command,
            Namespace::ordinary().set("/workspace/temp", FilesystemEntry::File),
        );
    }
}
#[test]
fn unmodeled_symlink_modes_and_ancestor_relocation_keep_approval() {
    for command in [
        "find . -type f -exec dos2unix --follow-symlink {} \\;",
        "find . -type f -exec dos2unix --replace-symlink {} \\;",
        "mv src old; grep -v pattern file > src/temp && mv src/temp file",
        "ln -s /outside dest; find src -exec mkdir -p dest/{} \\;",
    ] {
        assert_ne!(
            check(command, Namespace::ordinary()).decision,
            Decision::Allow,
            "{command}"
        );
    }
}

#[test]
fn removal_certificates_do_not_survive_as_current_observations_after_restore() {
    let mut core = ShellQueryCore::new().with_filesystem_view(Arc::new(Namespace::ordinary()));
    let r = core.check(request("grep -v pattern file > temp && mv temp file"));
    assert_eq!(r.decision, Decision::Allow);
    let session = SessionId::new("namespace-preservation");
    let snapshot = core.session_snapshot(&session, 1).unwrap();
    let snapshot: SessionSnapshot =
        serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
    let mut restored =
        ShellQueryCore::new().with_filesystem_view(Arc::new(Namespace::ordinary().set(
            "/workspace/temp",
            FilesystemEntry::Symlink {
                target: "/outside/secret".into(),
            },
        )));
    restored.insert_session_state(
        session,
        caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
    );
    let mut next = request("printf x > temp");
    next.sequence_no = CommandSequenceNo(2);
    let r = restored.check(next);
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .all(|f| f.namespace_proofs.is_empty())
    );
}
