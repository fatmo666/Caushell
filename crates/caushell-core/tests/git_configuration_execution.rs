//! Static judgments only. Programs mentioned below are never executed.
use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};
#[derive(Default)]
struct Files {
    files: BTreeMap<String, String>,
    unavailable: bool,
}
impl Files {
    fn config(mut self, path: &str, text: &str) -> Self {
        self.files.insert(path.into(), text.into());
        self
    }
}
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if self.files.contains_key(path) {
            FilesystemEntry::File
        } else if ["/", "/workspace", "/workspace/.git", "/home", "/home/test"].contains(&path)
            || self
                .files
                .keys()
                .any(|p| p.starts_with(&format!("{}/", path.trim_end_matches('/'))))
        {
            FilesystemEntry::Directory
        } else {
            FilesystemEntry::Missing
        }
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if self.unavailable {
            return FileContentRead::failed(
                FileContentSource::Unavailable,
                path,
                limit,
                FileContentStatus::Unavailable,
                "unavailable",
            );
        }
        match self.files.get(path) {
            Some(text) => FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                None,
                text.as_bytes().to_vec(),
            ),
            None => FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "absent",
            ),
        }
    }
}
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("git-config-execution"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_exact_scalar_variable("HOME", "/home/test", true)
            .with_exact_scalar_variable("GIT_CONFIG_NOSYSTEM", "1", true),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
fn check(command: &str, files: Files, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(request(command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}
fn clean() -> Files {
    Files::default().config("/workspace/.git/config", "")
}
#[test]
fn command_line_configuration_enters_shared_dispatch_not_read_only_allow() {
    for command in [
        "git -c 'core.fsmonitor=rm -rf /' ls-files",
        "env git -c 'core.fsmonitor=rm -rf /' ls-files",
        "printf x | xargs -I{} git -c 'core.fsmonitor=rm -rf /' ls-files",
        "sh -c \"git -c 'core.fsmonitor=rm -rf /' ls-files\"",
    ] {
        let r = check(command, clean(), Decision::Deny);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|e| e.normalized_command_name == "rm"),
            "{r:#?}"
        );
    }
    check(
        "git -c core.fsmonitor=/outside/unknown ls-files",
        clean().config("/outside/unknown", "\u{7f}ELFopaque"),
        Decision::NeedApproval,
    );
    // An observed missing executable cannot run. This is distinct from an
    // unavailable namespace or unreadable executable.
    check(
        "git -c core.fsmonitor=/outside/missing ls-files",
        clean(),
        Decision::Allow,
    );
}
#[test]
fn disabled_and_absent_modes_do_not_invent_executions() {
    for command in [
        "git ls-files",
        "git -c core.fsmonitor=false ls-files",
        "git -c core.fsmonitor=0 ls-files",
        "git -c core.fsmonitor= ls-files",
        "git -c 'core.fsmonitor=printf SAFE' ls-files",
    ] {
        check(command, clean(), Decision::Allow);
    }
    check(
        "git -c core.fsmonitor=true ls-files",
        clean(),
        Decision::NeedApproval,
    );
}
#[test]
fn file_values_and_overrides_use_native_last_value_precedence() {
    let bad = "[core]\nfsmonitor = rm -rf /\n";
    check(
        "git ls-files",
        clean().config("/workspace/.git/config", bad),
        Decision::Deny,
    );
    check(
        "git -c core.fsmonitor=false ls-files",
        clean().config("/workspace/.git/config", bad),
        Decision::Allow,
    );
    check(
        "git -c 'core.fsmonitor=rm -rf /' -c core.fsmonitor=false ls-files",
        clean(),
        Decision::Allow,
    );
    check(
        "git -c core.fsmonitor=false -c 'core.fsmonitor=rm -rf /' ls-files",
        clean(),
        Decision::Deny,
    );
    check(
        "git ls-files",
        clean().config(
            "/workspace/.git/config",
            "[core]\nfsmonitor=rm -rf /\nfsmonitor=false\n",
        ),
        Decision::Allow,
    );
}
#[test]
fn included_configuration_retains_order_and_unknown_inputs() {
    for command in [
        "git -c include.path=/workspace/extra ls-files",
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=include.path GIT_CONFIG_VALUE_0=/workspace/extra git ls-files",
    ] {
        check(
            command,
            clean().config("/workspace/extra", "[core]\nfsmonitor=rm -rf /\n"),
            Decision::Deny,
        );
    }
    check(
        "git ls-files",
        clean()
            .config("/workspace/.git/config", "[include]\npath=extra\n")
            .config("/workspace/.git/extra", "[core]\nfsmonitor=rm -rf /\n"),
        Decision::Deny,
    );
    check(
        "git ls-files",
        clean().config(
            "/workspace/.git/config",
            "[includeIf \"onbranch:main\"]\npath=extra\n",
        ),
        Decision::NeedApproval,
    );
    check(
        "git -c core.fsmonitor=false ls-files",
        clean().config(
            "/workspace/.git/config",
            "[includeIf \"onbranch:main\"]\npath=extra\n",
        ),
        Decision::Allow,
    );
}
#[test]
fn environment_overrides_and_config_env_are_observed_at_execution_point() {
    check(
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0='rm -rf /' git ls-files",
        clean(),
        Decision::Deny,
    );
    check(
        "GIT_CONFIG_PARAMETERS=\"'core.fsmonitor=rm -rf /'\" git ls-files",
        clean(),
        Decision::Deny,
    );
    check(
        "F='rm -rf /' git --config-env=core.fsmonitor=F ls-files",
        clean(),
        Decision::Deny,
    );
    check(
        "F='rm -rf /'; git --config-env=core.fsmonitor=F ls-files",
        clean(),
        Decision::NeedApproval,
    );
}
#[test]
fn known_file_programs_and_hooks_share_source_and_policy() {
    let files = clean()
        .config("/workspace/.git/config", "[core]\nfsmonitor=./monitor\n")
        .config("/workspace/monitor", "#!/bin/sh\nrm -rf /\n");
    let r = check("git ls-files", files, Decision::Deny);
    assert!(r.decision_trace.nested_payloads.iter().any(|p|matches!(&p.origin,NestedPayloadOrigin::ConfigDefinedTask{task_name,..} if task_name=="git-config:core.fsmonitor")));
    check(
        "git -c core.fsmonitor=false commit --allow-empty -m x",
        clean().config("/workspace/.git/hooks/pre-commit", "#!/bin/sh\nrm -rf /\n"),
        Decision::Deny,
    );
}
#[test]
fn unknown_observations_do_not_fall_back_to_host_snapshots() {
    let mut files = clean();
    files.unavailable = true;
    check("git ls-files", files, Decision::NeedApproval);
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
        .check(request("git -c core.fsmonitor=/outside/monitor ls-files"));
    assert_eq!(r.decision, Decision::NeedApproval);
}
#[test]
fn non_index_queries_do_not_execute_fsmonitor_configuration() {
    for command in [
        "git --no-pager -c 'core.fsmonitor=rm -rf /' log",
        "git -c 'core.fsmonitor=rm -rf /' rev-parse --show-toplevel",
    ] {
        check(command, clean(), Decision::Allow);
    }
}

#[test]
fn metadata_pointers_and_worktree_configuration_keep_native_precedence() {
    let files = clean()
        .config("/workspace/.git", "gitdir: /workspace/meta\n")
        .config("/workspace/meta/commondir", "../common\n")
        .config(
            "/workspace/common/config",
            "[extensions]\nworktreeConfig=true\n[core]\nfsmonitor=false\n",
        )
        .config(
            "/workspace/meta/config.worktree",
            "[core]\nfsmonitor=rm -rf /\n",
        );
    check("git ls-files", files, Decision::Deny);
    let files = clean().config("/workspace/other/config", "[core]\nfsmonitor=rm -rf /\n");
    check(
        "GIT_COMMON_DIR=/workspace/other git ls-files",
        files,
        Decision::Deny,
    );
}

#[test]
fn changed_config_and_helper_arguments_cannot_borrow_stale_safe_state() {
    check(
        "printf '[core]\\nfsmonitor=false\\n' >.git/config; ln -sf /workspace/evil .git/config; git ls-files",
        clean().config("/workspace/evil", "[core]\nfsmonitor=rm -rf /\n"),
        Decision::NeedApproval,
    );
    // $1 belongs to the native monitor protocol, not the caller's 'safe'.
    check(
        "set -- safe; git ls-files",
        clean()
            .config("/workspace/.git/config", "[core]\nfsmonitor=./monitor\n")
            .config("/workspace/monitor", "#!/bin/sh\ntouch \"$1\"\n"),
        Decision::NeedApproval,
    );
    check(
        "git ls-files",
        clean().config("/workspace/.git/config", "[include]\npath=config\n"),
        Decision::NeedApproval,
    );
}

#[test]
fn runtime_state_and_nested_helpers_use_the_same_environment_contract() {
    check(
        "F='rm -rf /'; export F; git --config-env=core.fsmonitor=F ls-files",
        clean(),
        Decision::Deny,
    );
    check(
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0='rm -rf /' env -u GIT_CONFIG_COUNT git ls-files",
        clean(),
        Decision::Allow,
    );
    // The helper's own git call inherits command-line config as native data.
    check(
        "git -c core.fsmonitor=./monitor -c 'extra.note=a' ls-files",
        clean().config(
            "/workspace/monitor",
            "#!/bin/sh\ngit -c 'core.fsmonitor=rm -rf /' ls-files\n",
        ),
        Decision::Deny,
    );
}

#[test]
fn native_pathname_interpolation_is_not_a_missing_literal_path() {
    check(
        "git -c 'core.fsmonitor=~/monitor' ls-files",
        clean().config("/home/test/monitor", "#!/bin/sh\nrm -rf /\n"),
        Decision::Deny,
    );
    check(
        "git -c 'core.hooksPath=~/hooks' commit -m x",
        clean().config("/home/test/hooks/pre-commit", "#!/bin/sh\nrm -rf /\n"),
        Decision::Deny,
    );
    for command in [
        "git -c 'core.fsmonitor=~other/monitor' ls-files",
        "git -c 'core.hooksPath=%(prefix)/hooks' commit -m x",
    ] {
        check(command, clean(), Decision::NeedApproval);
    }
}

#[test]
fn explicit_git_directory_and_test_monitor_use_native_not_caller_discovery() {
    check(
        "GIT_DIR=/workspace/other git -C /workspace/sub ls-files",
        clean()
            .config("/workspace/other/config", "[core]\nfsmonitor=./monitor\n")
            .config("/workspace/sub/monitor", "#!/bin/sh\nrm -rf /\n"),
        Decision::Deny,
    );
    // The environment fallback '0' names a program; it is not config false.
    check(
        "GIT_TEST_FSMONITOR=0 git ls-files",
        clean(),
        Decision::NeedApproval,
    );
}

#[test]
fn system_configuration_location_requires_native_selector_evidence() {
    check(
        "env -u GIT_CONFIG_NOSYSTEM git ls-files",
        clean(),
        Decision::NeedApproval,
    );
    check(
        "GIT_CONFIG_SYSTEM= env -u GIT_CONFIG_NOSYSTEM git ls-files",
        clean(),
        Decision::Allow,
    );
    check(
        "GIT_CONFIG_SYSTEM=/workspace/system env -u GIT_CONFIG_NOSYSTEM git ls-files",
        clean().config("/workspace/system", "[core]\nfsmonitor=rm -rf /\n"),
        Decision::Deny,
    );
}
