use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;

#[derive(Default)]
struct MemoryFilesystem(Mutex<BTreeMap<String, FilesystemEntry>>);

impl MemoryFilesystem {
    fn link(&self, path: &str, target: &str) {
        self.0.lock().unwrap().insert(
            path.into(),
            FilesystemEntry::Symlink {
                target: target.into(),
            },
        );
    }
}
impl FilesystemView for MemoryFilesystem {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or(FilesystemEntry::Directory)
    }
}

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("target-resolution"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn core(view: Arc<MemoryFilesystem>) -> ShellQueryCore {
    ShellQueryCore::new().with_filesystem_view(view)
}

#[test]
fn file_and_directory_links_use_observed_targets() {
    for (name, probe, suffix) in [
        ("report-link", "printf x > report-link", "report.txt"),
        ("directory-link", "mkdir -- directory-link/child", "output"),
    ] {
        for (scope, expected) in [
            ("workspace", Decision::Allow),
            ("outside", Decision::NeedApproval),
        ] {
            let view = Arc::new(MemoryFilesystem::default());
            let mut core = core(view.clone());
            let response = core.check(request(1, &format!("ln -s /{scope}/{suffix} {name}")));
            assert_eq!(response.decision, Decision::Allow, "{response:#?}");
            view.link(&format!("/workspace/{name}"), &format!("/{scope}/{suffix}"));
            let response = core.check(request(2, probe));
            assert_eq!(response.decision, expected, "{response:#?}");
            assert!(response.decision_trace.path_targets.iter().any(|fact| fact.observations.iter().any(|o|
                matches!(&o.entry, FilesystemEntry::Symlink { target } if target == &format!("/{scope}/{suffix}")))));
        }
    }
}

#[test]
fn dotdot_is_resolved_after_links_for_argv_and_redirections() {
    for command in [
        "printf x > link/../result",
        "touch link/../result",
        "mkdir -p missing/../link/../result",
    ] {
        let view = Arc::new(MemoryFilesystem::default());
        view.link("/workspace/link", "/outside/dir");
        view.0
            .lock()
            .unwrap()
            .insert("/workspace/missing".into(), FilesystemEntry::Missing);
        let response = core(view).check(request(1, command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(response.decision_trace.path_targets.iter().any(|fact| matches!(&fact.resolution,
            SemanticResolution::Resolved { value } if value.concrete_path() == Some("/outside/result"))));
    }
}

#[test]
fn unknown_command_and_compound_redirects_keep_target_obligations() {
    for command in ["mystery > link", "{ printf x; } > link", "> link"] {
        let view = Arc::new(MemoryFilesystem::default());
        view.link("/workspace/link", "/outside/result");
        let response = core(view).check(request(1, command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(!response.decision_trace.path_targets.is_empty());
    }
}

#[test]
fn unzip_default_directory_follows_an_observed_cwd_link() {
    let view = Arc::new(MemoryFilesystem::default());
    view.link("/workspace/linked", "/outside");
    let response = core(view).check(request(1, "cd linked && unzip archive.zip"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn unzip_explicit_directory_follows_an_observed_destination_link() {
    let view = Arc::new(MemoryFilesystem::default());
    view.link("/workspace/linked", "/outside");
    let response = core(view).check(request(1, "unzip archive.zip -d linked"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn directory_setup_orders_the_literal_transfer_on_success() {
    for command in [
        "mkdir -p temp && mv -- input temp/",
        "mkdir -p temp && cp --backup=numbered input temp/",
    ] {
        let view = Arc::new(MemoryFilesystem::default());
        view.0.lock().unwrap().extend([
            ("/workspace/temp".into(), FilesystemEntry::Missing),
            ("/workspace/input".into(), FilesystemEntry::File),
        ]);
        let result = core(view).check(request(1, command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|fact| {
            fact.slot_name == "destination_path"
                && matches!(&fact.resolution, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == &["/workspace/temp"])
        }));
    }
}

#[test]
fn directory_setup_requires_success_and_a_stable_namespace() {
    for command in [
        "mkdir -p temp || mv -- input temp/",
        "mkdir -p temp & mv -- input temp/",
    ] {
        let view = Arc::new(MemoryFilesystem::default());
        view.0.lock().unwrap().extend([
            ("/workspace/temp".into(), FilesystemEntry::Missing),
            ("/workspace/input".into(), FilesystemEntry::File),
        ]);
        let result = core(view).check(request(1, command));
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }

    let view = Arc::new(MemoryFilesystem::default());
    view.link("/workspace/temp", "/outside/temp");
    assert_eq!(
        core(view).check(request(1, "mkdir -p temp && cp -- input temp/")).decision,
        Decision::NeedApproval
    );
}

#[cfg(unix)]
#[test]
fn directory_setup_checks_entries_in_an_existing_transfer_destination() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-ordered-transfer-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let destination = root.join("temp");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(root.join("input"), "fixture").unwrap();
    let mut input = request(1, "mkdir -p temp && cp -- input temp/");
    input.workspace_root = Some(root.to_string_lossy().into_owned());
    input.shell_state_before = ShellStateSnapshot::new(root.to_string_lossy());

    let ordinary = ShellQueryCore::new().check(input.clone());
    std::os::unix::fs::symlink("/outside/input", destination.join("input")).unwrap();
    let linked = ShellQueryCore::new().check(input);
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(ordinary.decision, Decision::Allow, "{:?}", ordinary.reasons);
    assert_eq!(linked.decision, Decision::NeedApproval, "{:?}", linked.reasons);
}

#[cfg(unix)]
#[test]
fn directory_setup_orders_bounded_glob_moves_and_preserves_path_checks() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-ordered-glob-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let checkout_root = root.to_str().unwrap();

    let check = |command| {
        let mut input = request(1, command);
        input.workspace_root = Some(checkout_root.into());
        input.shell_state_before = ShellStateSnapshot::new(checkout_root);
        ShellQueryCore::new().check(input)
    };
    let with_nullglob = "mkdir -p templates && shopt -s nullglob && mv -- *.py templates/";
    let zero_matches = check(with_nullglob);
    std::fs::write(root.join("sample.py"), "fixture").unwrap();
    let matched = check(with_nullglob);
    let verbose = check("mkdir -p templates && mv -v -- *.py templates/");
    let overlapping = check("mkdir -p templates.py && mv -- *.py templates.py/");
    let unordered = check("mkdir -p templates & mv -- *.py templates/");

    let destination = root.join("templates");
    std::fs::create_dir(&destination).unwrap();
    std::os::unix::fs::symlink("/outside/sample.py", destination.join("sample.py")).unwrap();
    let linked = check("mkdir -p templates && mv -v -- *.py templates/");
    std::fs::remove_dir_all(&root).unwrap();

    for result in [zero_matches, matched, verbose] {
        assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|fact| {
            fact.slot_name == "destination_path"
                && matches!(&fact.resolution, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == &[destination.to_string_lossy().into_owned()])
        }));
    }
    for result in [overlapping, unordered, linked] {
        assert_eq!(result.decision, Decision::NeedApproval, "{:?}", result.reasons);
    }
}

#[test]
#[cfg(unix)]
fn directory_setup_orders_direct_find_transfers_and_preserves_path_checks() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-ordered-find-{}", std::process::id()));
    let source = root.join("source");
    let destination = root.join("out");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("report.txt"), "fixture").unwrap();

    let check = |command| {
        let mut input = request(1, command);
        let cwd = root.to_str().unwrap();
        input.workspace_root = Some(cwd.into());
        input.shell_state_before = ShellStateSnapshot::new(cwd);
        ShellQueryCore::new().check(input)
    };
    let copy = "mkdir -p out && find . -name report.txt -exec cp -t out {} +";
    let move_files = "mkdir -p out && find source -name report.txt -exec mv -t out {} +";
    let ordered_copy = check(copy);
    let ordered_move = check(move_files);
    let unordered = check("mkdir -p out & find . -name report.txt -exec cp -t out {} +");
    let different_cwd = check("mkdir -p out && find source -name report.txt -execdir cp -t out {} +");
    let overlapping = check("mkdir -p out && find . -name report.txt -exec mv -t out {} +");

    std::fs::create_dir(&destination).unwrap();
    std::os::unix::fs::symlink(source.join("report.txt"), destination.join("report.txt")).unwrap();
    let linked_destination = check(copy);
    std::fs::remove_file(destination.join("report.txt")).unwrap();
    std::os::unix::fs::symlink(destination.join("report.txt"), source.join("linked.txt")).unwrap();
    let linked_source = check(move_files);
    std::fs::remove_dir_all(&root).unwrap();

    for result in [&ordered_copy, &ordered_move] {
        assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|fact| {
            fact.slot_name == "destination_directory"
                && matches!(&fact.resolution, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == &[destination.to_str().unwrap()])
        }));
    }
    assert!(ordered_move.decision_trace.path_targets.iter().any(|fact| {
        fact.operation == PathTargetOperation::MoveSource
            && matches!(&fact.resolution, SemanticResolution::Resolved {
                value: PathResolution::BoundedPathSet { roots, may_escape: false },
            } if roots == &[source.to_str().unwrap()])
    }));
    assert!(!different_cwd.decision_trace.path_targets.iter().any(|fact| {
        fact.slot_name == "destination_directory"
            && matches!(&fact.resolution, SemanticResolution::Resolved {
                value: PathResolution::BoundedPathSet { roots, .. },
            } if roots == &[destination.to_str().unwrap()])
    }));
    for result in [unordered, overlapping, linked_destination, linked_source] {
        assert_eq!(result.decision, Decision::NeedApproval, "{:?}", result.reasons);
    }
}

#[test]
#[cfg(unix)]
fn directory_setup_closes_find_shell_loop_paths_and_records_local_order() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-ordered-find-loop-{}", std::process::id()));
    let source = root.join("input");
    let destination = root.join("archive").join("input");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("nested/report.txt"), "fixture").unwrap();

    let check = |body: &str| {
        let command = format!("mkdir -p archive && find input -type f -exec sh -c '{body}' _ {{}} +");
        let mut input = request(1, &command);
        let cwd = root.to_str().unwrap();
        input.workspace_root = Some(cwd.into());
        input.shell_state_before = ShellStateSnapshot::new(cwd);
        ShellQueryCore::new().check(input)
    };
    let body = r#"for item; do mkdir -p "archive/$(dirname "$item")" && mv -- "$item" "archive/$item"; done"#;
    let ordered = check(body);
    let explicit = check(&body.replacen("for item;", "for item in \"$@\";", 1));
    let failure_branch = check(&body.replace("&& mv", "|| mv"));
    let later_loop = check(
        r#"for item; do mkdir -p "archive/$(dirname "$item")"; done && for item; do mv -- "$item" "archive/$item"; done"#,
    );

    std::fs::create_dir_all(destination.join("nested")).unwrap();
    let existing = check(body);
    let outside = root.with_extension("outside");
    std::os::unix::fs::symlink(&outside, destination.join("nested/report.txt")).unwrap();
    let linked_destination = check(body);
    std::fs::remove_file(destination.join("nested/report.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, source.join("nested/linked.txt")).unwrap();
    let linked_source = check(body);
    std::fs::remove_dir_all(&root).unwrap();

    for (case, response) in [
        ("implicit positionals", ordered),
        ("explicit positionals", explicit),
        ("existing destination", existing),
    ] {
        let targets = &response.decision_trace.path_targets;
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{case}: {:?}, paths: {:?}",
            response.reasons,
            targets
                .iter()
                .map(|f| (&f.slot_name, &f.lexical, &f.resolution))
                .collect::<Vec<_>>(),
        );
        for (slot, path) in [
            ("source_paths", source.as_path()),
            ("destination_path", destination.as_path()),
        ] {
            assert!(targets.iter().any(|fact| {
                fact.slot_name == slot
                    && matches!(&fact.resolution, SemanticResolution::Resolved {
                        value: PathResolution::BoundedPathSet { roots, may_escape: false },
                    } if roots == &[path.to_str().unwrap()])
            }));
        }
        assert!(targets.iter().any(|fact| {
            fact.slot_name == "destination_path"
                && fact.namespace_proofs.iter().any(|proof| proof.same_iteration_success)
        }));
    }
    for response in [failure_branch, later_loop] {
        assert!(!response.decision_trace.path_targets.iter().any(|fact| {
            fact.namespace_proofs.iter().any(|proof| proof.same_iteration_success)
        }));
    }
    for response in [linked_source, linked_destination] {
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{:?}",
            response.reasons
        );
    }
}

#[test]
fn unavailable_namespace_is_not_a_workspace_proof() {
    let mut core = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem));
    let response = core.check(request(1, "printf x > local"));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(response.decision_trace.path_targets.iter().any(|fact| matches!(&fact.resolution,
        SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::FilesystemUnavailable)));
}

#[test]
fn cycles_and_long_link_chains_remain_explicit_gaps() {
    for cycle in [true, false] {
        let view = Arc::new(MemoryFilesystem::default());
        for index in 0..45 {
            view.link(
                &format!("/workspace/link{index}"),
                &format!("link{}", if cycle { (index + 1) % 2 } else { index + 1 }),
            );
        }
        let response = core(view).check(request(1, "printf x > link0"));
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(response.decision_trace.path_targets.iter().any(|fact| matches!(&fact.resolution,
            SemanticResolution::Unresolved { gap } if gap.kind == if cycle { SemanticGapKind::LinkCycle } else { SemanticGapKind::BudgetExceeded })));
    }
}

#[test]
fn same_action_namespace_changes_cannot_borrow_old_observations() {
    for command in [
        "ln -s /outside door; printf x > door/result",
        "ln -s /outside/dir door; printf x > door/../result",
    ] {
        let view = Arc::new(MemoryFilesystem::default());
        let response = core(view).check(request(1, command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(response.decision_trace.path_targets.iter().any(|fact| matches!(&fact.resolution,
            SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::NamespaceMutation)));
    }
}

#[test]
fn facts_survive_snapshots_but_are_not_reused_as_current_observations() {
    let view = Arc::new(MemoryFilesystem::default());
    let mut core = core(view.clone());
    assert_eq!(
        core.check(request(1, "printf x > result")).decision,
        Decision::Allow
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("target-resolution"), 1)
        .unwrap();
    let roundtrip = caushell_graph::SessionGraph::from_snapshot(snapshot.graph.clone())
        .unwrap()
        .to_snapshot();
    assert_eq!(roundtrip, snapshot.graph);
    assert!(snapshot.graph.nodes.iter().any(|node| matches!(
        &node.kind,
        SessionGraphNodeKindSnapshot::PathTargetFact { .. }
    )));
    view.link("/workspace/result", "/outside/changed");
    assert_eq!(
        core.check(request(2, "printf x > result")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn standard_channels_have_explicit_not_applicable_results() {
    let response =
        core(Arc::new(MemoryFilesystem::default())).check(request(1, "printf x > /dev/null"));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| matches!(&fact.resolution, SemanticResolution::NotApplicable { .. }))
    );
}

#[test]
fn a_plain_unknown_command_keeps_its_existing_policy() {
    let mut core =
        ShellQueryCore::new().with_filesystem_view(Arc::new(MemoryFilesystem::default()));
    let response = core.check(request(1, "mystery"));
    assert_eq!(response.decision, Decision::Allow);
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .all(|fact| matches!(
                fact.operation,
                PathTargetOperation::WorkingDirectory | PathTargetOperation::WorkspaceRoot
            ))
    );
}

#[test]
fn lexical_sets_and_filename_families_are_not_physical_target_proofs() {
    for command in [
        "find . -type f -print0 | xargs -0 chmod 644",
        "for f in ./*.jpg; do cp \"$f\" \"${f}.bak\"; done",
        "csplit -f prefix input '/x/'",
    ] {
        let response = core(Arc::new(MemoryFilesystem::default())).check(request(1, command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|fact| matches!(&fact.resolution,
            SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::UnknownTarget))
        );
    }
}

#[test]
fn unknown_cwd_never_uses_the_request_cwd_as_a_target_proof() {
    let response = core(Arc::new(MemoryFilesystem::default()))
        .check(request(1, "cd \"$UNKNOWN\"; printf x > result"));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| matches!(fact.resolution, SemanticResolution::Unresolved { .. }))
    );
}

#[test]
fn wrapper_descriptor_inheritance_does_not_invent_a_tool_cwd_target() {
    let response = core(Arc::new(MemoryFilesystem::default()))
        .check(request(1, "env -C /outside tee /dev/fd/3 3>./log"));
    let nodes: Vec<_> = response
        .decision_trace
        .execution_semantics
        .iter()
        .filter(|fact| fact.normalized_command_name == "tee")
        .map(|fact| &fact.source.node_id)
        .collect();
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| fact.effect_key.starts_with("redirect:")
                && fact.lexical.concrete_path() == Some("/workspace/log"))
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| nodes.contains(&&fact.source_node_id)
                && matches!(fact.resolution, SemanticResolution::Unresolved { .. })),
        "{response:#?}"
    );
    assert!(
        !response
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| fact.lexical.concrete_path() == Some("/outside/log"))
    );
}

#[test]
fn tool_directory_parent_components_require_their_own_namespace_proof() {
    let view = Arc::new(MemoryFilesystem::default());
    view.link("/workspace/link", "/outside/directory");
    let response = core(view).check(request(1, "env -C link/.. touch result"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(response.decision_trace.path_targets.iter().any(|fact| matches!(&fact.resolution,
        SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::UnresolvedOperation)));
}

#[test]
fn leaf_transforms_still_require_a_proven_execution_directory() {
    for command in [
        "env -C link/.. ln -s /opt/input",
        "env -C link/.. curl -O https://example.test/report",
    ] {
        let view = Arc::new(MemoryFilesystem::default());
        view.link("/workspace/link", "/outside/directory");
        let response = core(view).check(request(1, command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response.decision_trace.path_targets.iter().any(|fact| {
                fact.operation == PathTargetOperation::Write
                    && matches!(&fact.resolution, SemanticResolution::Unresolved { gap }
                    if gap.kind == SemanticGapKind::UnresolvedOperation)
            }),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn actions_without_path_targets_or_workspace_do_not_probe_the_filesystem() {
    struct CountingView(Arc<std::sync::atomic::AtomicUsize>);
    impl FilesystemView for CountingView {
        fn entry(&self, _path: &str) -> FilesystemEntry {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            FilesystemEntry::Directory
        }
    }
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut core =
        ShellQueryCore::new().with_filesystem_view(Arc::new(CountingView(count.clone())));
    let mut request = request(1, "printf hello");
    request.workspace_root = None;
    let response = core.check(request);
    assert_eq!(response.decision, Decision::Allow);
    assert!(response.decision_trace.path_targets.is_empty());
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn alias_expansion_does_not_duplicate_a_namespace_mutation() {
    let mut core = core(Arc::new(MemoryFilesystem::default()));
    assert_eq!(
        core.check(request(1, "alias clone='cp'")).decision,
        Decision::Allow
    );
    let response = core.check(request(2, "clone input output"));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn ln_into_current_directory_tracks_each_entry() {
    for (command, expected) in [
        ("ln -s source/alpha .", vec!["/workspace/alpha"]),
        ("ln -sv -- source/alpha .//.", vec!["/workspace/alpha"]),
        (
            "ln -s -- source/alpha -f .",
            vec!["/workspace/alpha", "/workspace/-f"],
        ),
        (
            "ln source/alpha source/beta ./",
            vec!["/workspace/alpha", "/workspace/beta"],
        ),
    ] {
        let result = core(Arc::new(MemoryFilesystem::default())).check(request(1, command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
        let paths: Vec<_> = result
            .decision_trace
            .path_targets
            .iter()
            .filter(|effect| effect.operation == PathTargetOperation::Write)
            .map(|effect| effect.lexical.concrete_path())
            .collect();
        assert_eq!(
            paths,
            expected.into_iter().map(Some).collect::<Vec<_>>(),
            "{command}"
        );
    }
}

#[test]
fn ln_current_directory_keeps_ownership_and_namespace_checks() {
    for command in ["ln -s \"$unknown\" .", "cd /outside; ln -s source/alpha ."] {
        let result = core(Arc::new(MemoryFilesystem::default())).check(request(1, command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
    let view = Arc::new(MemoryFilesystem::default());
    view.link("/workspace/alpha", "/outside/file");
    let result = core(view).check(request(1, "ln -sf source/alpha ."));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");

    for command in [
        "ln -sT source/alpha .",
        "ln -s source/alpha link",
        "ln -s source/alpha . -f",
        "ln -s source/alpha -f .",
        "ln -s source/alpha -- .",
    ] {
        let result = core(Arc::new(MemoryFilesystem::default())).check(request(1, command));
        assert!(
            !result
                .decision_trace
                .path_targets
                .iter()
                .any(|effect| effect.operation == PathTargetOperation::Write
                    && matches!(effect.lexical, PathResolution::DerivedConcrete { .. })),
            "{command}: {result:#?}"
        );
    }
}
