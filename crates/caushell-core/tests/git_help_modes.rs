use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("git-help-modes"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
    })
}

#[test]
fn manual_viewers_and_paged_listings_require_approval() {
    for command in [
        "git help config",
        "git --help config",
        "git -h config",
        "git branch --help",
        "git branch --help config\n!/bin/sh",
        "git help --help",
        "git help --man config",
        "git help --info config",
        "git help --web config",
        "git --no-pager help config",
        "git help --all",
        "git help -av",
        "git --help -a",
        "git help --config",
        "git -p help",
        "git -p branch -h",
        "git -p --version",
        "git -P -p help --all",
        "git help --all --no-verbose --verbose",
        "git --help --all --no-verbose --verbose",
        "git -C /opt/repo branch --help",
        "mode=--help; git branch \"$mode\"",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::InteractiveEscapeSurface),
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "git" && s.form_id == "create_branch_ref"),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn noninteractive_usage_and_version_output_remain_allowed() {
    for command in [
        "git help",
        "git --help",
        "git -h",
        "git --version",
        "git -v",
        "git branch -h",
        "git status -h",
        "git help -h",
        "git help --guides",
        "git help --user-interfaces",
        "git help --developer-interfaces",
        "git help --all --no-verbose",
        "git --no-pager help --all",
        "git --no-pager help --config",
        "git --help --guides",
        "git --no-pager --help --all",
        "git -p -P help --all",
        "git -p -P help",
        "git -p -P --version",
        "git help --all --verbose --no-verbose",
        "git --help --all --verbose --no-verbose",
        "git -C /opt/repo --help",
        "git -c color.ui=never help",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::InteractiveEscapeSurface),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn help_spelling_as_data_keeps_the_original_operation() {
    for command in [
        "git branch -- --help",
        "git -C --help status",
        "git branch ordinary --help",
        "git commit -m --help",
    ] {
        let response = check(command);
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "git" && s.form_id == "help_through_viewer"),
            "{command}: {response:#?}"
        );
    }
    let response = check("git reset --hard");
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn help_does_not_erase_shell_side_effects_or_expansions() {
    for command in [
        "git help > /opt/output",
        "git help $(rm victim)",
        "git branch -h; rm victim",
        "git -C $directories branch --help",
        "git --unmodeled reset --hard",
        "git --help $arguments",
    ] {
        let response = check(command);
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}
