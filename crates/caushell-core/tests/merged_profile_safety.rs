//! Analyze only: none of these command strings are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    let mut state = ShellStateSnapshot::new("/workspace");
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("merged-profile-safety"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
    })
}

#[test]
fn supported_local_git_config_forms_remain_fully_modeled() {
    for command in [
        "git config --local user.name example",
        "git config --local --get user.name",
        "git ls-remote --get-url origin",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(
            !result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| semantics.operation_semantics_unresolved),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn added_git_forms_do_not_approve_unmodeled_or_outside_mutations() {
    for command in [
        "git config --global user.name example",
        "git config --local --unset user.name",
        "git config --local --rename-section old new",
        "git config --local --get",
        "git ls-remote --unknown https://example.test/repo.git",
        "git -C /outside config --local user.name example",
        "git -C /workspace -C /outside config --local user.name example",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        let result = check(&format!("{command}; rm -rf /"));
        assert_eq!(result.decision, Decision::Deny, "{command}: {result:?}");
    }
}

#[test]
fn git_config_uses_execution_cwd_without_rebasing_caller_redirection() {
    let result = check("git -C /outside config --local user.name example > local.log");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
    assert!(
        result
            .decision_trace
            .path_targets
            .iter()
            .any(|target| matches!(&target.lexical,
                PathResolution::ToolConvention { path, convention }
                    if path == "/outside/.git/config" && convention == "git.local_config"
            )),
        "{result:?}"
    );
    assert!(
        result.decision_trace.path_targets.iter().any(
            |target| matches!(&target.lexical, PathResolution::Concrete { path }
            if path == "/workspace/local.log")
        ),
        "{result:?}"
    );
}

#[test]
fn login_modifier_does_not_bypass_non_shell_approval_or_deny() {
    assert_eq!(
        check("bash -lc 'python3 -c pass'").decision,
        Decision::NeedApproval
    );
    assert_eq!(
        check("bash -lc 'python3 -c pass; rm -rf /'").decision,
        Decision::Deny
    );
}
