use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use caushell_core::{SessionState, ShellQueryCore};
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

fn request(cwd: &str, workspace: Option<&str>, sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("cwd-targets"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new(cwd),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: workspace.map(str::to_owned),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn context_targets(response: &CheckResponse) -> Vec<&PathTargetFact> {
    response
        .decision_trace
        .path_targets
        .iter()
        .filter(|fact| {
            matches!(
                fact.operation,
                PathTargetOperation::WorkingDirectory | PathTargetOperation::WorkspaceRoot
            )
        })
        .collect()
}

#[test]
fn cwd_links_are_compared_by_physical_target() {
    for (target, expected) in [
        ("/workspace/local", Decision::Allow),
        ("/outside/local", Decision::NeedApproval),
    ] {
        for suffix in ["", "/child"] {
            let view = Arc::new(View::default());
            view.link("/workspace/door", target);
            let response = ShellQueryCore::new()
                .with_filesystem_view(view)
                .check(request(
                    &format!("/workspace/door{suffix}"),
                    Some("/workspace"),
                    1,
                    "pwd",
                ));
            assert_eq!(response.decision, expected, "{response:#?}");
            let targets = context_targets(&response);
            assert_eq!(targets.len(), 2);
            assert!(targets.iter().any(|fact| fact.operation == PathTargetOperation::WorkingDirectory &&
                matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path() == Some(format!("{target}{suffix}").as_str()))));
        }
    }
}

#[test]
fn physical_aliases_of_the_workspace_are_allowed() {
    for cwd in [
        "/workspace/child",
        "/physical/project/child",
        "/other-alias/child",
    ] {
        let view = Arc::new(View::default());
        view.link("/workspace", "/physical/project");
        view.link("/other-alias", "/physical/project");
        let response = ShellQueryCore::new()
            .with_filesystem_view(view)
            .check(request(cwd, Some("/workspace"), 1, "pwd"));
        assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    }
}

#[test]
fn cwd_and_root_retain_original_parent_components() {
    for (cwd, root, link, target, expected) in [
        (
            "/workspace/door/..",
            "/workspace",
            "/workspace/door",
            "/outside/child",
            Decision::NeedApproval,
        ),
        (
            "/outside/child",
            "/workspace/door/..",
            "/workspace/door",
            "/outside/child",
            Decision::Allow,
        ),
        (
            "/workspace/child",
            "/workspace/door/..",
            "/workspace/door",
            "/outside/child",
            Decision::NeedApproval,
        ),
    ] {
        let view = Arc::new(View::default());
        view.link(link, target);
        let response = ShellQueryCore::new()
            .with_filesystem_view(view)
            .check(request(cwd, Some(root), 1, "pwd"));
        assert_eq!(response.decision, expected, "{response:#?}");
        assert!(context_targets(&response).iter().any(|fact| {
            fact.spelling
                .as_deref()
                .is_some_and(|s| s.contains("/../") || s.ends_with("/.."))
        }));
    }
}

#[test]
fn unavailable_context_requires_approval_even_without_file_effects() {
    let response = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
        .check(request("/workspace", Some("/workspace"), 1, "pwd"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(context_targets(&response).iter().all(|fact|
        matches!(&fact.resolution, SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::FilesystemUnavailable)));
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CwdOutsideWorkspaceRoot)
    );
}

#[test]
fn invalid_and_cyclic_contexts_do_not_gain_scope() {
    for (cwd, root) in [
        ("relative", "/workspace"),
        ("/workspace", "relative"),
        ("/workspace/loop", "/workspace"),
        ("/workspace", "/workspace/loop"),
        ("/workspace\0suffix", "/workspace"),
    ] {
        let view = Arc::new(View::default());
        view.link("/workspace/loop", "/workspace/loop");
        let response = ShellQueryCore::new()
            .with_filesystem_view(view)
            .check(request(cwd, Some(root), 1, "pwd"));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            context_targets(&response)
                .iter()
                .any(|fact| matches!(&fact.resolution, SemanticResolution::Unresolved { .. }))
        );
    }
}

#[test]
fn request_entry_context_is_not_a_future_mutation_result() {
    for command in ["touch /workspace/new; pwd", "touch \"$unknown\"; pwd"] {
        let response = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(View::default()))
            .check(request("/workspace", Some("/workspace"), 1, command));
        assert_eq!(context_targets(&response).len(), 2);
        assert!(
            context_targets(&response)
                .iter()
                .all(|fact| matches!(&fact.resolution, SemanticResolution::Resolved { .. })),
            "{response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CwdOutsideWorkspaceRoot)
        );
    }
}

#[test]
fn current_context_is_reobserved_after_snapshot_restore() {
    let view = Arc::new(View::default());
    view.link("/workspace/door", "/workspace/local");
    let mut core = ShellQueryCore::new().with_filesystem_view(view.clone());
    let response = core.check(request("/workspace/door", Some("/workspace"), 1, "pwd"));
    assert_eq!(response.decision, Decision::Allow);
    let snapshot = core
        .session_snapshot(&SessionId::new("cwd-targets"), 1)
        .unwrap();
    let mut restored = ShellQueryCore::new().with_filesystem_view(view.clone());
    restored.insert_session_state(
        SessionId::new("cwd-targets"),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    view.link("/workspace/door", "/outside/local");
    let response = restored.check(request("/workspace/door", Some("/workspace"), 2, "pwd"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        context_targets(&response)
            .iter()
            .all(|fact| fact.sequence_no == CommandSequenceNo::new(2))
    );
}

#[test]
fn context_facts_attach_to_the_request_even_without_commands() {
    let response = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(View::default()))
        .check(request("/workspace", Some("/workspace"), 1, "# comment"));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(response.decision_trace.execution_units.is_empty());
    assert_eq!(context_targets(&response).len(), 2);
    assert!(
        context_targets(&response)
            .iter()
            .all(|fact| fact.source_node_id == "command-request:cwd-targets:1")
    );
}

#[test]
fn absent_workspace_keeps_the_existing_boundary_policy() {
    let response = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
        .check(request("/outside", None, 1, "pwd"));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(context_targets(&response).is_empty());
}

#[test]
fn context_has_no_temporary_or_code_loading_grants() {
    for cwd in ["/workspace-other", "/outside", "/tmp"] {
        let response = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(View::default()))
            .check(request(cwd, Some("/workspace"), 1, "pwd"));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    }
}

#[test]
fn cwd_rule_actions_remain_configurable() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::CwdOutsideWorkspaceRoot,
            RulePolicyEntry::new(action),
        );
        let response = ShellQueryCore::with_policy(policy)
            .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
            .check(request("/workspace", Some("/workspace"), 1, "pwd"));
        assert_eq!(response.decision, expected, "{response:#?}");
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CwdOutsideWorkspaceRoot)
        );
    }
}

#[test]
fn directory_and_file_scopes_share_the_original_root_spelling() {
    for (path, expected) in [
        ("/workspace/file", Decision::NeedApproval),
        ("/outside/file", Decision::Allow),
        ("/workspace/door/../file", Decision::Allow),
    ] {
        for command in [
            format!("touch {path}"),
            format!("bash {path}"),
            format!("ssh-keygen -D {path}"),
            format!("bash --rcfile {path} -c ':'"),
            format!("BASH_ENV={path} bash -c ':'"),
        ] {
            let view = Arc::new(View::default());
            view.link("/workspace/door", "/outside/child");
            let mut policy = PolicyConfig::default();
            policy.rule_policy.rules.insert(
                RuleId::OutsideWorkspaceStartupConfig,
                RulePolicyEntry::new(RuleAction::NeedApproval),
            );
            let response = ShellQueryCore::with_policy(policy)
                .with_filesystem_view(view)
                .check(request("/outside", Some("/workspace/door/.."), 1, &command));
            assert_eq!(response.decision, expected, "{command}: {response:#?}");
            assert!(context_targets(&response).iter().any(|fact| fact.operation == PathTargetOperation::WorkspaceRoot &&
                matches!(&fact.resolution, SemanticResolution::Resolved { value } if value.concrete_path() == Some("/outside"))));
        }
    }
}
