use std::collections::BTreeMap;
use std::sync::Arc;

use caushell_core::{SessionState, ShellQueryCore};
use caushell_runner::FilesystemView;
use caushell_types::*;

#[derive(Default)]
struct Filesystem(BTreeMap<String, FilesystemEntry>);

impl Filesystem {
    fn with_entry(mut self, path: &str, entry: FilesystemEntry) -> Self {
        self.0.insert(path.into(), entry);
        self
    }
}

impl FilesystemView for Filesystem {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0.get(path).cloned().unwrap_or_else(|| {
            if path.ends_with("/.curlrc") || path.ends_with("/curlrc") {
                FilesystemEntry::Missing
            } else {
                FilesystemEntry::Directory
            }
        })
    }
}

fn check(command: &str, filesystem: Filesystem, complete_environment: bool) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(filesystem))
        .check(request(command, complete_environment))
}

fn request(command: &str, complete_environment: bool) -> CheckRequest {
    let mut snapshot = ShellStateSnapshot::new("/workspace");
    if complete_environment {
        snapshot = snapshot.with_variable_knowledge(ShellStateKnowledge::Complete);
    }
    CheckRequest {
        session_id: SessionId::new("implicit-config"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: snapshot,
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn assert_opaque_config(response: &CheckResponse, path: Option<&str>) {
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|semantics| {
                semantics.loads_tool_config && semantics.operation_semantics_unresolved
            }),
        "{response:#?}"
    );
    let evidence = format!("{:?}", response.decision_trace.evidence);
    assert!(evidence.contains("ToolConfigInput"), "{response:#?}");
    if let Some(path) = path {
        assert!(evidence.contains(path), "{response:#?}");
    }
}

#[test]
fn exported_and_command_prefix_config_inputs_are_not_ignored() {
    for prefix in [
        "export CURL_HOME=/workspace/settings;",
        "CURL_HOME=/workspace/settings",
    ] {
        let response = check(
            &format!("{prefix} curl https://example.test/"),
            Filesystem::default().with_entry("/workspace/settings/.curlrc", FilesystemEntry::File),
            true,
        );
        assert_opaque_config(&response, Some("/workspace/settings/.curlrc"));
    }
}

#[test]
fn confirmed_absence_does_not_require_approval() {
    let response = check("curl https://example.test/", Filesystem::default(), true);
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|s| !s.loads_tool_config)
    );
}

#[test]
fn missing_or_invalid_account_home_is_not_config_absence() {
    for home in [
        None,
        Some(""),
        Some("relative/home"),
        Some("/home/invalid\0value"),
    ] {
        let mut request = request("curl https://example.test/", true);
        request.home = home.map(str::to_owned);
        let response = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(Filesystem::default()))
            .check(request);
        assert_opaque_config(&response, None);
    }
}

#[test]
fn disable_is_recognized_only_at_the_first_argument() {
    for flag in ["-q", "-qs", "--disable", "'--disable'"] {
        let response = check(
            &format!("curl {flag} https://example.test/"),
            Filesystem::default().with_entry("/home/test/.curlrc", FilesystemEntry::File),
            false,
        );
        assert_eq!(response.decision, Decision::Allow, "{response:#?}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.loads_tool_config)
        );
    }
    let response = check(
        "curl --silent -q https://example.test/",
        Filesystem::default().with_entry("/home/test/.curlrc", FilesystemEntry::File),
        true,
    );
    assert_opaque_config(&response, Some("/home/test/.curlrc"));
}

#[test]
fn unknown_environment_and_unavailable_files_remain_incomplete() {
    assert_opaque_config(
        &check("curl https://example.test/", Filesystem::default(), false),
        None,
    );
    assert_opaque_config(
        &check(
            "CURL_HOME=/workspace/settings curl https://example.test/",
            Filesystem::default().with_entry(
                "/workspace/settings/.curlrc",
                FilesystemEntry::Unavailable {
                    reason: "not observed".into(),
                },
            ),
            true,
        ),
        Some("/workspace/settings/.curlrc"),
    );
}

#[test]
fn unexported_variables_do_not_change_child_config_search() {
    let response = check(
        "CURL_HOME=/workspace/settings; curl https://example.test/",
        Filesystem::default().with_entry("/workspace/settings/.curlrc", FilesystemEntry::File),
        true,
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn config_creation_in_the_same_action_invalidates_snapshot_absence() {
    let response = check(
        "printf insecure > /workspace/settings/.curlrc; CURL_HOME=/workspace/settings curl https://example.test/",
        Filesystem::default(),
        true,
    );
    assert_opaque_config(&response, Some("/workspace/settings/.curlrc"));
}

#[test]
fn relative_search_paths_use_the_execution_working_directory() {
    let response = check(
        "cd /workspace/sub; CURL_HOME=settings curl https://example.test/",
        Filesystem::default().with_entry("/workspace/sub/settings/.curlrc", FilesystemEntry::File),
        true,
    );
    assert_opaque_config(&response, Some("/workspace/sub/settings/.curlrc"));
}

#[test]
fn nested_frames_use_their_own_environment() {
    let filesystem =
        || Filesystem::default().with_entry("/workspace/settings/.curlrc", FilesystemEntry::File);
    for command in [
        "env CURL_HOME=/workspace/settings curl https://example.test/",
        "CURL_HOME=/workspace/settings sh -c 'curl https://example.test/'",
        "export CURL_HOME=/workspace/settings; sh -c 'curl https://example.test/'",
    ] {
        assert_opaque_config(
            &check(command, filesystem(), true),
            Some("/workspace/settings/.curlrc"),
        );
    }
    for command in [
        "export CURL_HOME=/workspace/settings; env -i curl https://example.test/",
        "export CURL_HOME=/workspace/settings; env -u CURL_HOME curl https://example.test/",
        "export CURL_HOME=/workspace/settings; env CURL_HOME= curl https://example.test/",
        "export CURL_HOME=/workspace/settings; unset CURL_HOME; curl https://example.test/",
        "CURL_HOME=/workspace/settings env -i curl https://example.test/",
    ] {
        let response = check(command, filesystem(), true);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn pipeline_execution_units_keep_configuration_inputs() {
    for command in [
        "CURL_HOME=/workspace/settings curl https://example.test/ | cat",
        "printf safe | CURL_HOME=/workspace/settings curl https://example.test/",
        "export CURL_HOME=/workspace/settings; curl https://example.test/ | cat",
    ] {
        assert_opaque_config(
            &check(
                command,
                Filesystem::default()
                    .with_entry("/workspace/settings/.curlrc", FilesystemEntry::File),
                true,
            ),
            Some("/workspace/settings/.curlrc"),
        );
    }
    let response = check(
        "curl -q https://example.test/ | cat",
        Filesystem::default().with_entry("/home/test/.curlrc", FilesystemEntry::File),
        false,
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn fallback_locations_and_empty_xdg_follow_declared_search_rules() {
    for (command, path) in [
        (
            "XDG_CONFIG_HOME=/workspace/xdg curl https://example.test/",
            "/workspace/xdg/.curlrc",
        ),
        (
            "XDG_CONFIG_HOME=/workspace/xdg curl https://example.test/",
            "/workspace/xdg/curlrc",
        ),
        (
            "HOME=/workspace/home curl https://example.test/",
            "/workspace/home/.curlrc",
        ),
        (
            "CURL_HOME=/workspace/settings curl https://example.test/",
            "/workspace/settings/.config/curlrc",
        ),
        (
            "HOME=/workspace/home curl https://example.test/",
            "/workspace/home/.config/curlrc",
        ),
        (
            "HOME=/workspace/home curl https://example.test/",
            "/home/test/.curlrc",
        ),
    ] {
        assert_opaque_config(
            &check(
                command,
                Filesystem::default().with_entry(path, FilesystemEntry::File),
                true,
            ),
            Some(path),
        );
    }
    let response = check(
        "XDG_CONFIG_HOME= CURL_HOME=/workspace/settings curl https://example.test/",
        Filesystem::default()
            .with_entry("/workspace/settings/.config/curlrc", FilesystemEntry::File),
        true,
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn filesystem_aliases_are_resolved_before_parent_components() {
    let response = check(
        "CURL_HOME=/workspace/link/.. curl https://example.test/",
        Filesystem::default()
            .with_entry(
                "/workspace/link",
                FilesystemEntry::Symlink {
                    target: "/settings/sub".into(),
                },
            )
            .with_entry("/settings/.curlrc", FilesystemEntry::File),
        true,
    );
    assert_opaque_config(&response, None);
    assert!(response.decision_trace.evidence.iter().any(|evidence| {
        matches!(&evidence.kind, EvidenceKind::ToolConfigInput(input)
            if input.resolved_path.as_deref() == Some("/settings/.curlrc") && input.observations.iter().any(|o| matches!(o.entry, FilesystemEntry::Symlink { .. })))
    }));
    let response = check(
        "CURL_HOME=/workspace/cycle curl https://example.test/",
        Filesystem::default().with_entry(
            "/workspace/cycle",
            FilesystemEntry::Symlink {
                target: "/workspace/cycle".into(),
            },
        ),
        true,
    );
    assert_opaque_config(&response, Some("/workspace/cycle/.curlrc"));
}

#[test]
fn unrelated_writes_do_not_invalidate_config_absence() {
    let response = check(
        "printf safe > /workspace/other; CURL_HOME=/workspace/settings curl https://example.test/",
        Filesystem::default(),
        true,
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn quoted_scalar_disable_and_unknown_leading_fields_stay_distinct() {
    let filesystem =
        || Filesystem::default().with_entry("/home/test/.curlrc", FilesystemEntry::File);
    let response = check(
        "flag=-q; curl \"$flag\" https://example.test/",
        filesystem(),
        true,
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    for command in [
        "curl $UNKNOWN -q https://example.test/",
        "curl \"$UNKNOWN\" -q https://example.test/",
    ] {
        let response = check(command, filesystem(), false);
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    }
}

#[test]
fn inspection_and_prior_approval_do_not_authorize_a_later_config_load() {
    let filesystem = Arc::new(
        Filesystem::default().with_entry("/workspace/settings/.curlrc", FilesystemEntry::File),
    );
    let command = "export CURL_HOME=/workspace/settings; curl https://example.test/";
    let mut core = ShellQueryCore::new().with_filesystem_view(filesystem.clone());
    let mut inspection = request(command, true);
    inspection.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::persistent_shell();
    let outcome = core
        .try_check_with_intent(inspection, CheckIntent::JudgeOnly)
        .unwrap();
    assert_opaque_config(&outcome.response, Some("/workspace/settings/.curlrc"));
    assert!(outcome.check_receipt.is_none());
    let snapshot = core
        .session_snapshot(&SessionId::new("implicit-config"), 0)
        .unwrap();
    assert!(snapshot.summary.variable_binding("CURL_HOME").is_none());

    let mut next = request(command, true);
    next.sequence_no = CommandSequenceNo(2);
    next.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::persistent_shell();
    let outcome = core.try_check_with_outcome(next).unwrap();
    let receipt = outcome.check_receipt.unwrap();
    let snapshot = core
        .session_snapshot(&SessionId::new("implicit-config"), 0)
        .unwrap();
    let mut restored = ShellQueryCore::new().with_filesystem_view(filesystem);
    restored.insert_session_state(
        snapshot.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    restored
        .authorize(&ApprovalRequest {
            check_id: receipt.check_id,
            state_revision: receipt.state_revision,
            approved: true,
            authority: ApprovalAuthority::SimulatedUser,
        })
        .unwrap();
    let mut next = request(command, true);
    next.sequence_no = CommandSequenceNo(3);
    assert_opaque_config(&restored.check(next), Some("/workspace/settings/.curlrc"));
}
