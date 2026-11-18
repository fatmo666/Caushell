use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;

#[derive(Default)]
struct View(Mutex<BTreeMap<String, FilesystemEntry>>);
impl View {
    fn link(&self, path: &str, target: &str) {
        self.0.lock().unwrap().insert(
            path.into(),
            FilesystemEntry::Symlink {
                target: target.into(),
            },
        );
    }
}
impl FilesystemView for View {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or(FilesystemEntry::Directory)
    }
}

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("consumption-targets"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn request_without_bash_env(command: &str, sequence: u64) -> CheckRequest {
    let mut req = request(command, sequence);
    req.shell_state_before = req
        .shell_state_before
        .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent);
    req
}

fn uses(path: &str) -> [(String, PathTargetOperation, RuleId); 4] {
    [
        (
            format!("bash {path}"),
            PathTargetOperation::ExecuteFile,
            RuleId::OutsideWorkspaceScriptSource,
        ),
        (
            format!("ssh-keygen -D {path}"),
            PathTargetOperation::LoadCode,
            RuleId::CodeLoadPath,
        ),
        (
            format!("bash --rcfile {path} -c ':'"),
            PathTargetOperation::StartupConfig,
            RuleId::OutsideWorkspaceStartupConfig,
        ),
        (
            format!("BASH_ENV={path} bash -c ':'"),
            PathTargetOperation::StartupConfig,
            RuleId::OutsideWorkspaceStartupConfig,
        ),
    ]
}

fn configured_core() -> ShellQueryCore {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::OutsideWorkspaceStartupConfig,
        RulePolicyEntry::new(RuleAction::NeedApproval),
    );
    ShellQueryCore::with_policy(policy)
}

#[test]
fn startup_rule_actions_are_preserved() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let view = Arc::new(View::default());
        view.link("/workspace/entry", "/outside/entry");
        let mut policy = PolicyConfig::default();
        assert_eq!(
            policy
                .rule_policy
                .action_for(RuleId::OutsideWorkspaceStartupConfig),
            RuleAction::Observe
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
            RulePolicyEntry::new(action),
        );
        let result = ShellQueryCore::with_policy(policy)
            .with_filesystem_view(view)
            .check(request("bash --rcfile ./entry -c ':'", 1));
        assert_eq!(result.decision, expected, "{result:#?}");
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceStartupConfig)
        );
    }
}

#[test]
fn file_and_directory_links_share_physical_target_proofs() {
    for (entry, target, operand) in [
        ("/workspace/entry", "file", "./entry"),
        ("/workspace/dir", "target-dir", "./dir/file"),
    ] {
        for (root, expected) in [
            ("/workspace", Decision::Allow),
            ("/outside", Decision::NeedApproval),
        ] {
            for (command, operation, rule) in uses(operand) {
                let view = Arc::new(View::default());
                view.link(entry, &format!("{root}/{target}"));
                let result = configured_core()
                    .with_filesystem_view(view)
                    .check(request_without_bash_env(&command, 1));
                assert_eq!(result.decision, expected, "{command}: {result:#?}");
                assert_eq!(
                    result
                        .decision_trace
                        .findings
                        .iter()
                        .any(|finding| finding.rule_id == rule),
                    expected == Decision::NeedApproval,
                    "{result:#?}"
                );
                assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == operation &&
                    matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path().is_some_and(|p| p.starts_with(root)))));
            }
        }
    }
}

#[test]
fn original_components_are_retained_for_all_file_consumers() {
    for (command, operation, _) in uses("door/../file") {
        let view = Arc::new(View::default());
        view.link("/workspace/door", "/outside/dir");
        let result = configured_core()
            .with_filesystem_view(view)
            .check(request(&command, 1));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
        assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == operation &&
            matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path() == Some("/outside/file"))), "{result:#?}");
    }
}

#[test]
fn unavailable_namespace_never_proves_a_file_input() {
    for (command, operation, _) in uses("./entry") {
        let result = configured_core()
            .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
            .check(request(&command, 1));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
        assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == operation &&
            matches!(&fact.resolution, SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::FilesystemUnavailable)));
    }
}

#[test]
fn earlier_namespace_mutation_invalidates_file_consumption() {
    for (command, operation, _) in uses("door/file") {
        let command = format!("ln -s /outside door; {command}");
        let result = configured_core()
            .with_filesystem_view(Arc::new(View::default()))
            .check(request(&command, 1));
        assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
        assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == operation &&
            matches!(&fact.resolution, SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::NamespaceMutation)), "{result:#?}");
    }
}

#[test]
fn explicit_executable_path_uses_the_same_contract() {
    for (target, expected) in [
        ("/workspace/real-tool", Decision::Allow),
        ("/outside/tool", Decision::NeedApproval),
    ] {
        let view = Arc::new(View::default());
        view.link("/workspace/tool", target);
        let result = configured_core()
            .with_filesystem_view(view)
            .check(request("./tool", 1));
        assert_eq!(result.decision, expected, "{result:#?}");
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|fact| fact.operation == PathTargetOperation::ExecuteFile)
        );
    }
    for (command, path, expected) in [
        ("~/tool", "/home/test/tool", Decision::NeedApproval),
        ("'~/tool'", "/workspace/~/tool", Decision::Allow),
        ("CMD='~/tool'; $CMD", "/workspace/~/tool", Decision::Allow),
    ] {
        let result = configured_core()
            .with_filesystem_view(Arc::new(View::default()))
            .check(request(command, 1));
        assert_eq!(result.decision, expected, "{command}: {result:#?}");
        assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == PathTargetOperation::ExecuteFile &&
            matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path() == Some(path))), "{result:#?}");
    }
}

#[test]
fn unknown_descriptors_are_gaps_not_channels() {
    for (command, operation, _) in uses("/dev/fd/9") {
        let view = Arc::new(View::default());
        view.link("/dev/fd/9", "/workspace/unrelated-observer-file");
        let result = configured_core()
            .with_filesystem_view(view)
            .check(request(&command, 1));
        assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|fact| fact.operation == operation
                    && matches!(&fact.resolution, SemanticResolution::Unresolved { .. })),
            "{result:#?}"
        );
        assert!(!result.decision_trace.path_targets.iter().any(|fact| {
            fact.observations
                .iter()
                .any(|entry| entry.path == "/dev/fd/9")
        }));
    }
    let result = configured_core()
        .with_filesystem_view(Arc::new(View::default()))
        .check(request("bash /dev/fd/9", 1));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        result
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| fact.operation == PathTargetOperation::ExecuteFile
                && matches!(&fact.resolution, SemanticResolution::Unresolved { .. })),
        "{result:#?}"
    );
}

#[test]
fn known_stream_channels_do_not_become_filesystem_grants() {
    for command in ["bash <(printf ':')", "bash /dev/fd/0 <<'EOF'\n:\nEOF"] {
        let result = configured_core()
            .with_filesystem_view(Arc::new(View::default()))
            .check(request_without_bash_env(command, 1));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|fact| fact.operation == PathTargetOperation::ExecuteFile
                    && matches!(&fact.resolution, SemanticResolution::NotApplicable { .. })),
            "{result:#?}"
        );
    }
}

#[test]
fn descriptor_file_inputs_follow_the_opening_path() {
    for operand in ["./entry", "door/../file"] {
        let view = Arc::new(View::default());
        view.link("/workspace/entry", "/outside/file");
        view.link("/workspace/door", "/outside/dir");
        let command = format!("bash /dev/fd/0 < {operand}");
        let result = configured_core()
            .with_filesystem_view(view)
            .check(request(&command, 1));
        assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
        assert!(result.decision_trace.path_targets.iter().any(|fact| fact.operation == PathTargetOperation::ExecuteFile &&
            matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path() == Some("/outside/file"))), "{result:#?}");
    }
}

#[test]
fn unknown_startup_environment_is_not_an_absent_configuration() {
    for state in [
        ShellStateSnapshot::new("/workspace"),
        ShellStateSnapshot::new("/workspace").with_opaque_dynamic_variable(
            "BASH_ENV",
            "unknown-startup",
            true,
        ),
        ShellStateSnapshot::new("/workspace").with_runtime_input_variable(
            "BASH_ENV",
            RuntimeInputSource::StdinData,
            RuntimeInputCapture::NotCaptured,
            true,
        ),
    ] {
        let mut req = request("bash -c ':'", 1);
        req.shell_state_before = state;
        let result = configured_core()
            .with_filesystem_view(Arc::new(View::default()))
            .check(req);
        assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|fact| fact.operation == PathTargetOperation::StartupConfig
                    && matches!(&fact.resolution, SemanticResolution::Unresolved { .. }))
        );
    }
}

#[test]
fn temporary_roots_do_not_hide_external_link_targets() {
    let view = Arc::new(View::default());
    view.link("/tmp/plugin.so", "/outside/plugin.so");
    let result = configured_core()
        .with_filesystem_view(view)
        .check(request("ssh-keygen -D /tmp/plugin.so", 1));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
}

#[test]
fn snapshots_retain_proofs_without_reusing_them_for_the_next_request() {
    let view = Arc::new(View::default());
    let mut core = configured_core().with_filesystem_view(view.clone());
    assert_eq!(
        core.check(request_without_bash_env("bash ./entry", 1))
            .decision,
        Decision::Allow
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("consumption-targets"), 1)
        .unwrap();
    let restored = caushell_graph::SessionGraph::from_snapshot(snapshot.graph.clone())
        .unwrap()
        .to_snapshot();
    assert_eq!(restored, snapshot.graph);
    view.link("/workspace/entry", "/outside/entry");
    let result = core.check(request_without_bash_env("bash ./entry", 2));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|proposal| {
                proposal.rule_id == RuleId::OutsideWorkspaceScriptSource
                    && proposal.decision == Decision::NeedApproval
            })
    );
}
