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
fn bash_pid_redirect_keeps_the_directory_proof_and_namespace_checks() {
    for (command, root) in [
        ("printf fixture >> /tmp/$$", "/tmp"),
        ("printf fixture >> /tmp/.$$", "/tmp"),
        (r#"printf fixture > "/workspace/out-$$.txt""#, "/workspace"),
        ("printf fixture > src/name-$$.log", "/workspace/src"),
    ] {
        let result = check(command, Namespace::ordinary());
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Write
                && matches!(&target.resolution,
                    SemanticResolution::Resolved {
                        value: PathResolution::BoundedPathSet { roots, may_escape: false }
                    } if roots == &[root.to_string()])
        }), "{command}: {:?}", result.reasons);
    }

    let link = FilesystemEntry::Symlink { target: "/outside/secret".into() };
    let result = check("printf fixture >> /tmp/$$", Namespace::ordinary().set("/tmp/123", link));
    assert_eq!(result.decision, Decision::NeedApproval, "{:?}", result.reasons);

    for command in [
        "printf fixture >> /outside/$$",
        "printf fixture >> /tmp/$$-$OUT",
        "printf fixture >> /tmp/$$/child",
        "printf fixture >> /tmp/.link/../$$",
        "printf fixture >> /tmp/.$$.",
        "printf fixture >> /tmp/$$*",
    ] {
        let result = check(command, Namespace::ordinary());
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }

    let quoted = check("printf fixture >> '/tmp/$$'", Namespace::ordinary());
    assert_eq!(quoted.decision, Decision::Allow, "{:?}", quoted.reasons);
    assert!(quoted.decision_trace.path_targets.iter().any(|target| {
        target.operation == PathTargetOperation::Write
            && target.lexical.concrete_path() == Some("/tmp/$$")
    }));
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
fn a_metadata_reference_preserves_the_shared_regular_file_namespace() {
    let command = "touch /tmp/stamp; touch -acmr src/input /tmp/stamp";
    for present in [false, true] {
        let mut view = Namespace::ordinary();
        if present {
            view = view.set("/tmp/stamp", FilesystemEntry::File);
        }
        let result = check(command, view);
        assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
        let writes: Vec<_> = result
            .decision_trace
            .path_targets
            .iter()
            .filter(|target| target.operation == PathTargetOperation::Write)
            .collect();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|target| {
            matches!(&target.resolution,
                SemanticResolution::Resolved { value }
                    if value.concrete_path() == Some("/tmp/stamp"))
                && target.namespace_proofs.iter().any(|proof| {
                    proof.effect == PathNamespaceEffect::RegularFileWrite
                        && proof.path == "/tmp/stamp"
                        && proof.producer_node_id != target.source_node_id
                })
        }));
    }
}

#[test]
fn metadata_reference_does_not_authorize_unproved_or_external_writes() {
    let command = "touch /tmp/stamp; touch -r src/input /tmp/stamp";
    let link = FilesystemEntry::Symlink {
        target: "/outside/secret".into(),
    };
    let linked = check(command, Namespace::ordinary().set("/tmp/stamp", link));
    assert_ne!(linked.decision, Decision::Allow);
    assert!(
        linked
            .decision_trace
            .path_targets
            .iter()
            .all(|target| target.namespace_proofs.is_empty())
    );

    let external = check(
        "touch /outside/stamp; touch -r src/input /outside/stamp",
        Namespace::ordinary(),
    );
    assert_ne!(external.decision, Decision::Allow);

    let opaque = check(
        "touch /tmp/stamp; touch -r src/input /tmp/stamp; unmodeled-fixture",
        Namespace::ordinary(),
    );
    assert_ne!(opaque.decision, Decision::Allow);
    assert!(
        opaque
            .decision_trace
            .path_targets
            .iter()
            .all(|target| target.namespace_proofs.is_empty())
    );
}

#[test]
fn mv_into_current_directory_tracks_the_landing_entry() {
    for target in [".", "./", "./."] {
        let command = format!("mv src/input {target}");
        let result = check(&command, Namespace::ordinary());
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let mutations: Vec<_> = result
            .decision_trace
            .path_targets
            .iter()
            .filter(|fact| {
                matches!(
                    fact.operation,
                    PathTargetOperation::MoveSource | PathTargetOperation::Write
                )
            })
            .map(|fact| {
                let SemanticResolution::Resolved { value } = &fact.resolution else {
                    panic!("unresolved path: {fact:?}");
                };
                (fact.operation, value.concrete_path())
            })
            .collect();
        assert_eq!(mutations.len(), 2, "{command}: {mutations:?}");
        assert!(mutations.contains(&(
            PathTargetOperation::MoveSource,
            Some("/workspace/src/input")
        )));
        assert!(mutations.contains(&(PathTargetOperation::Write, Some("/workspace/input"))));
    }
}

#[test]
fn mv_into_current_directory_still_checks_links_and_other_modes() {
    let symlink = || FilesystemEntry::Symlink {
        target: "/outside/secret".into(),
    };
    let destination = Namespace::ordinary().set("/workspace/input", symlink());
    assert_ne!(check("mv src/input .", destination).decision, Decision::Allow);
    let source = Namespace::ordinary().set("/workspace/src/input", symlink());
    assert_ne!(
        check("mv src/input .; printf x > input", source).decision,
        Decision::Allow
    );
    for command in [
        "mv /outside/secret .",
        "mv src/input ..",
        "mv src/input ./../.",
        "mv -b src/input .",
        "mv -T src/input .",
    ] {
        assert_ne!(
            check(command, Namespace::ordinary()).decision,
            Decision::Allow,
            "{command}"
        );
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
    for (command, backup_slot) in [
        ("mv -b temp file", "effect_2"),
        ("mv --backup=numbered temp file", "effect_2"),
        ("mv -S '~' temp file", "effect_2"),
        ("mv -b -t dest temp", "effect_1"),
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
        let writes: Vec<_> = r
            .decision_trace
            .path_targets
            .iter()
            .filter(|f| f.operation == PathTargetOperation::Write)
            .collect();
        assert_eq!(writes.len(), 2, "{command}: {writes:?}");
        assert!(
            writes.iter().any(|f| {
                f.slot_name == backup_slot
                    && matches!(f.lexical, PathResolution::UnsupportedDynamicText { .. })
            }),
            "{command}: {writes:?}"
        );
    }
}

#[test]
fn ordinary_and_information_moves_have_no_implicit_backup_write() {
    for (command, count) in [
        ("mv temp file", 1),
        ("mv -t dest temp", 1),
        ("mv -- temp -b", 1),
        ("mv --help -b temp file", 0),
        ("mv --version -b temp file", 0),
        ("mv -b temp", 0),
    ] {
        let r = check(command, Namespace::ordinary());
        let writes = r
            .decision_trace
            .path_targets
            .iter()
            .filter(|f| f.operation == PathTargetOperation::Write)
            .count();
        assert_eq!(writes, count, "{command}: {:?}", r.reasons);
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

#[test]
fn batched_find_rename_excludes_unmatchable_literal_dialect() {
    let command = "find . -name '*.item.cache' -exec rename -v 's/\\.cache$//' '{}' +";
    let result = check(command, Namespace::ordinary());
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    let relocations: Vec<_> = result
        .decision_trace
        .path_targets
        .iter()
        .filter(|target| {
            matches!(
                target.operation,
                PathTargetOperation::MoveSource | PathTargetOperation::Write
            )
        })
        .collect();
    assert_eq!(relocations.len(), 2);
    assert!(relocations.iter().all(|target| matches!(
        target.resolution,
        SemanticResolution::Resolved {
            value: PathResolution::BoundedPathSet { may_escape: false, .. }
        }
    )));
}

#[test]
fn batched_find_rename_retains_unproved_and_outside_mutations() {
    for command in [
        "find dir//child -name '*.item.cache' -exec rename -v 's/\\.cache$//' '{}' +",
        "find . -name '*.item.cache' -exec rename 's/\\.cache$/.out/' '{}' +",
        "find . -name '*.cache' -exec rename 's/\\.cache$//' '{}' +",
        "find /outside -name '*.item.cache' -exec rename 's/\\.cache$//' '{}' +",
        "find -L . -name '*.item.cache' -exec rename 's/\\.cache$//' '{}' +",
        "find . -name '*.item.cache' -exec rename --symlink 's/\\.cache$//' '{}' +",
    ] {
        let view = Namespace::ordinary()
            .set("/workspace/dir", FilesystemEntry::Directory)
            .set("/workspace/dir/child", FilesystemEntry::Directory);
        let result = check(command, view);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }
}

#[test]
fn utility_rename_cannot_match_a_slash_in_plain_leaf_globs() {
    for command in [
        "rename.ul 'peach/tree' berries berry*",
        "rename.ul 'peach/tree' berry*",
    ] {
        let response = check(command, Namespace::ordinary());
        assert_eq!(response.decision, Decision::Allow, "{command}: {:?}", response.reasons);
        assert!(response.decision_trace.path_targets.iter().all(|target| {
            !matches!(target.operation, PathTargetOperation::MoveSource | PathTargetOperation::Write)
        }));
    }

    for command in [
        "rename.ul 'peach/tree' berries peach/tree*",
        "rename.ul 'peach/tree' berries \"$unobserved\"",
        "rename.ul 'berry' berries berry*",
        "rename 's/^berry/peach/' berry*",
    ] {
        let response = check(command, Namespace::ordinary());
        assert_eq!(response.decision, Decision::NeedApproval, "{command}: {:?}", response.reasons);
        assert!(response.decision_trace.path_targets.iter().any(|target| {
            matches!(target.operation, PathTargetOperation::MoveSource | PathTargetOperation::Write)
        }));
    }
}
