//! Static Postconf query/edit classification. Never execute a configuration tool.
use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView};
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};

struct Files {
    entries: BTreeMap<String, FilesystemEntry>,
    unavailable: bool,
}
impl Files {
    fn clean() -> Self {
        Self {
            entries: [
                ("/", FilesystemEntry::Directory),
                ("/workspace", FilesystemEntry::Directory),
                ("/workspace/config", FilesystemEntry::Directory),
                ("/outside", FilesystemEntry::Directory),
                ("/outside/config", FilesystemEntry::Directory),
                ("/tmp", FilesystemEntry::Directory),
                ("/tmp/config", FilesystemEntry::Directory),
                ("/workspace/program", FilesystemEntry::File),
                ("/workspace/config/main.cf", FilesystemEntry::File),
                ("/workspace/config/master.cf", FilesystemEntry::File),
            ]
            .into_iter()
            .map(|(p, e)| (p.into(), e))
            .collect(),
            unavailable: false,
        }
    }
}
fn identity() -> FileContentIdentity {
    FileContentIdentity {
        device: 1,
        inode: 1,
        size: 0,
        modified_seconds: 0,
        modified_nanos: 0,
        changed_seconds: 0,
        changed_nanos: 0,
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
                "fixture unavailable",
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
                Some(DirectoryEntry {
                    name: name.into(),
                    kind: match e {
                        FilesystemEntry::Directory => DirectoryEntryKind::Directory,
                        FilesystemEntry::File => DirectoryEntryKind::File,
                        FilesystemEntry::Symlink { .. } => DirectoryEntryKind::Symlink,
                        _ => DirectoryEntryKind::Other,
                    },
                    identity: identity(),
                })
            })
            .collect();
        DirectoryRead::complete(self.source(), path, limits, identity(), entries)
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("postconf-configuration"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_environment_observation("MAIL_CONFIG", ShellEnvironmentValue::Absent),
        home: None,
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
fn explicit_and_implicit_edits_never_borrow_query_classification() {
    for command in [
        "postconf -e 'example_setting=value'",
        "postconf 'example_setting=value'",
        "postconf -h 'example_setting=value'",
        "postconf -n -e 'example_setting=value'",
        "postconf -X example_setting",
        "postconf '-#' example_setting",
        "postconf -Me 'demo/inet=inet n - n - - smtpd'",
        "postconf -Fe 'demo/inet/chroot=n'",
        "postconf -Pe 'demo/inet/example_setting=value'",
        "postconf -MX demo/inet",
        "postconf -PX demo/inet/example_setting",
    ] {
        let response = check(command, Files::clean());
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|p| p.operation == PathTargetOperation::Write),
            "{command}"
        );
    }
}

#[test]
fn plain_queries_and_owned_query_overrides_do_not_create_writes() {
    for command in [
        "postconf",
        "postconf myhostname",
        "postconf -n",
        "postconf -dh myhostname",
        "postconf -M",
        "postconf -F demo/inet/chroot",
        "postconf -P demo/inet/example_setting",
        "postconf -o example_setting=value -xh other_setting",
        "postconf -c /workspace/config -o example_setting=value -n",
    ] {
        let response = check(command, Files::clean());
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            !response
                .decision_trace
                .path_targets
                .iter()
                .any(|p| matches!(
                    p.operation,
                    PathTargetOperation::Write
                        | PathTargetOperation::Delete
                        | PathTargetOperation::MoveSource
                )),
            "{command}"
        );
    }
}

#[test]
fn explicit_local_roots_use_existing_write_authority_without_granting_service_control() {
    for command in [
        "postconf -c /workspace/config -e 'example_setting=value'",
        "postconf -c/workspace/config 'example_setting=value'",
        "MAIL_CONFIG=/tmp/config postconf -e 'example_setting=value'",
        "postconf -c /workspace/config -o config_directory=/outside/config -e 'example_setting=value'",
        "MAIL_CONFIG=/outside/config postconf -c /workspace/config -e 'example_setting=value'",
        "postconf -c /outside/config -c /workspace/config -e 'example_setting=value'",
        // Known absence is a complete namespace fact, not unknown scope or
        // a promise that the native tool will succeed/create the directory.
        "postconf -c /workspace/missing -e 'example_setting=value'",
        "postconf -c /workspace/config -e a=value && postconf -c /workspace/config -e b=value && postconf -c /workspace/config a b",
    ] {
        let response = check(command, Files::clean());
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
                .any(|p| p.operation == PathTargetOperation::Write
                    && matches!(
                        &p.resolution,
                        SemanticResolution::Resolved {
                            value: PathResolution::BoundedPathSet {
                                may_escape: false,
                                ..
                            }
                        }
                    )),
            "{command}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.state_operations.is_empty()),
            "file editing is not a service transition"
        );
    }
    let response = check(
        "postconf -c /outside/config -e 'example_setting=value'",
        Files::clean(),
    );
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    let response = check(
        "postconf -c /workspace/config -e 'example_setting=value'; postfix start",
        Files::clean(),
    );
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::StateControl)
    );
}

#[test]
fn incomplete_modes_namespaces_and_mutating_siblings_retain_approval() {
    for command in [
        "postconf -c",
        "postconf -e",
        "postconf --unknown",
        "postconf -c /workspace/config -n --unknown",
        "postconf -c /workspace/config $UNKNOWN",
        "postconf example_setting -X",
        "postconf -e 'example_setting=value' -c /workspace/config",
        "./program; postconf -c /workspace/config -e 'example_setting=value'",
        "ln -s /outside /workspace/config/future; postconf -c /workspace/config -e 'example_setting=value'",
        "postconf -c /workspace/config -b",
        "postconf -c /workspace/config -m",
        "postconf -c /workspace/config -MF",
        "postconf -c /workspace/config -c /outside/config -e 'example_setting=value'",
        "MAIL_CONFIG= postconf -e 'example_setting=value'",
    ] {
        let response = check(command, Files::clean());
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
    let mut files = Files::clean();
    files.unavailable = true;
    assert_eq!(
        check(
            "postconf -c /workspace/config -e 'example_setting=value'",
            files
        )
        .decision,
        Decision::NeedApproval
    );
    let mut files = Files::clean();
    files.entries.insert(
        "/workspace/config/main.cf".into(),
        FilesystemEntry::Symlink {
            target: "/outside/main.cf".into(),
        },
    );
    assert_eq!(
        check(
            "postconf -c /workspace/config -e 'example_setting=value'",
            files
        )
        .decision,
        Decision::NeedApproval
    );
}

#[test]
fn observed_environment_paths_remain_facts_and_read_targets_remain_data() {
    for (environment, expected) in [
        (Some("/workspace/config"), Decision::Allow),
        (Some("/outside/config"), Decision::NeedApproval),
        (None, Decision::NeedApproval),
    ] {
        let mut request = request("postconf -e setting=value");
        request.shell_state_before = ShellStateSnapshot::new("/workspace");
        if let Some(value) = environment {
            request.shell_state_before = request.shell_state_before.with_environment_observation(
                "MAIL_CONFIG",
                ShellEnvironmentValue::Present {
                    value: value.into(),
                },
            );
        }
        let response = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(Files::clean()))
            .check(request);
        assert_eq!(
            response.decision, expected,
            "{environment:?}: {:?}",
            response.reasons
        );
    }
    let response = check("postconf -c /workspace/config -n", Files::clean());
    assert_eq!(response.decision, Decision::Allow);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|s| !s.loads_tool_config
                && !s.loads_startup_config
                && !s.executes_config_defined_task)
    );
    assert!(
        response
            .decision_trace
            .path_targets
            .iter()
            .all(|p| p.operation != PathTargetOperation::Write)
    );
}

#[test]
fn configuration_data_is_not_shell_code_and_independent_denies_survive() {
    let response = check(
        "postconf -c /workspace/config -e 'example_setting=$(rm -rf /)'",
        Files::clean(),
    );
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    for command in [
        "postconf --unknown; rm -rf /",
        "postconf -e \"example_setting=$(rm -rf /)\"",
        "postconf -c /workspace/config -e example_setting=value; rm -rf /",
        "postconf -c /workspace/config -e example_setting=value; rm /workspace/file",
    ] {
        let expected = if command.ends_with("rm /workspace/file") {
            Decision::NeedApproval
        } else {
            Decision::Deny
        };
        assert_eq!(
            check(command, Files::clean()).decision,
            expected,
            "{command}"
        );
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::OutsideWorkspaceMutation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    for command in [
        "postconf -e example_setting=value",
        "postconf -e example_setting=value --unknown",
    ] {
        let response = ShellQueryCore::with_policy(policy.clone())
            .with_filesystem_view(Arc::new(Files::clean()))
            .check(request(command));
        assert_eq!(
            response.decision,
            Decision::Deny,
            "{command}: {:?}",
            response.reasons
        );
    }
}
