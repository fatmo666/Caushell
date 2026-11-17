//! End-to-end static checks. Only fixture files are written; commands are not executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, observed: bool) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/work/project")
        .with_variable_knowledge(ShellStateKnowledge::Complete);
    if observed {
        state = state.with_exact_scalar_variable("BASH_ENV", "/work/external/startup.sh", true);
    }
    CheckRequest {
        session_id: SessionId::new("effective-environment"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        workspace_root: Some("/work/project".into()),
        home: Some("/home/test".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str, observed: bool, action: RuleAction) -> CheckResponse {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::OutsideWorkspaceStartupConfig,
        RulePolicyEntry::new(action),
    );
    ShellQueryCore::with_policy(policy).check(request(command, observed))
}

fn startup_paths(r: &CheckResponse) -> Vec<String> {
    r.decision_trace
        .path_targets
        .iter()
        .filter(|p| p.slot_name == "startup_config")
        .filter_map(|p| p.spelling.clone())
        .collect()
}

#[test]
fn startup_policies_follow_execution_exports_through_all_assignment_forms() {
    let cases = [
        "BASH_ENV=/work/external/startup.sh bash -c 'printf BODY'",
        "export BASH_ENV=/work/external/startup.sh; bash -c 'printf BODY'",
        "BASH_ENV=/work/external/startup.sh; export BASH_ENV; bash -c 'printf BODY'",
        "f() { export BASH_ENV=/work/external/startup.sh; }; f; bash -c 'printf BODY'",
        "env BASH_ENV=/work/external/startup.sh bash -c 'printf BODY'",
    ];
    for action in [
        RuleAction::Observe,
        RuleAction::NeedApproval,
        RuleAction::Deny,
    ] {
        for command in cases {
            let r = check(command, false, action);
            let expected = match action {
                RuleAction::Deny => Decision::Deny,
                RuleAction::NeedApproval => Decision::NeedApproval,
                _ => Decision::Allow,
            };
            assert_eq!(r.decision, expected, "{command}: {r:#?}");
            assert!(
                startup_paths(&r)
                    .iter()
                    .any(|p| p == "/work/external/startup.sh"),
                "{command}: {r:#?}"
            );
            assert!(
                r.decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceStartupConfig)
            );
            assert!(
                r.decision_trace
                    .execution_semantics
                    .iter()
                    .any(|s| s.normalized_command_name == "bash" && s.loads_startup_config)
            );
        }
    }
}

#[test]
fn cleared_exports_never_fall_back_to_entry_values() {
    for command in [
        "unset BASH_ENV; bash -c 'printf BODY'",
        "export -n BASH_ENV; bash -c 'printf BODY'",
        "env -u BASH_ENV bash -c 'printf BODY'",
        "env BASH_ENV= bash -c 'printf BODY'",
        "BASH_ENV='' bash -c 'printf BODY'",
        "env -i bash -c 'printf BODY'",
    ] {
        let r = check(command, true, RuleAction::NeedApproval);
        assert!(startup_paths(&r).is_empty(), "{command}: {r:#?}");
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceStartupConfig),
            "{command}: {r:#?}"
        );
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "bash" && s.loads_startup_config)
        );
    }
}

#[test]
fn local_variables_do_not_become_child_environment() {
    for command in [
        "BASH_ENV=/work/external/startup.sh; bash -c 'printf BODY'",
        "f() { local BASH_ENV=/work/external/startup.sh; }; f; bash -c 'printf BODY'",
        "( export BASH_ENV=/work/external/startup.sh ); bash -c 'printf BODY'",
    ] {
        let r = check(command, false, RuleAction::NeedApproval);
        assert!(startup_paths(&r).is_empty(), "{command}: {r:#?}");
    }
}

#[test]
fn unknown_export_cannot_reuse_an_old_known_path_or_prove_absence() {
    let mut req = request("bash -c 'printf BODY'", false);
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::OutsideWorkspaceStartupConfig,
        RulePolicyEntry::new(RuleAction::NeedApproval),
    );
    let r = ShellQueryCore::with_policy(policy).check(req);
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceStartupConfig)
    );
    for command in [
        "read BASH_ENV; export BASH_ENV; bash -c 'printf BODY'",
        "if test \"$flag\" = yes; then unset BASH_ENV; fi; bash -c 'printf BODY'",
    ] {
        let r = check(command, true, RuleAction::NeedApproval);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
}

#[test]
fn multiple_launches_keep_distinct_paths_and_provenance() {
    let r = check(
        "export BASH_ENV=/work/external/first.sh; bash -c 'printf ONE'; BASH_ENV=/work/external/second.sh; bash -c 'printf TWO'",
        false,
        RuleAction::NeedApproval,
    );
    let paths = startup_paths(&r);
    assert!(
        paths.iter().any(|p| p == "/work/external/first.sh"),
        "{r:#?}"
    );
    assert!(
        paths.iter().any(|p| p == "/work/external/second.sh"),
        "{r:#?}"
    );
    assert_eq!(r.decision, Decision::NeedApproval);
}

#[test]
fn environment_changes_cannot_hide_hard_denies() {
    let r = check(
        "export BASH_ENV=/work/external/startup.sh; bash -c 'rm -rf /'",
        false,
        RuleAction::Observe,
    );
    assert_eq!(r.decision, Decision::Deny, "{r:#?}");
}

#[test]
fn git_config_selection_uses_execution_environment_even_when_other_rules_ask() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "caushell-exec-env-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let work = root.join("project");
    let home = root.join("home");
    let hooks = root.join("external/hooks");
    let config = root.join("external/gitconfig");
    for p in [&work.join(".git/hooks"), &home, &hooks] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(
        work.join(".git/config"),
        "[core]\nrepositoryformatversion = 0\n",
    )
    .unwrap();
    std::fs::write(
        &config,
        format!("[core]\nhooksPath = {}\n", hooks.display()),
    )
    .unwrap();
    // Both alternatives contain an actual executable fixture. Selection is
    // inspected as a script read, rather than conflating a missing hook probe
    // (configuration metadata) with a program that may execute.
    for hook in [work.join(".git/hooks/pre-commit"), hooks.join("pre-commit")] {
        std::fs::write(&hook, "#!/bin/sh\nprintf SAFE\n").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let config = config.display().to_string();
    for (command, observed, external) in [
        (
            "git commit --allow-empty -m fixture".to_string(),
            false,
            false,
        ),
        (
            "git commit --allow-empty -m fixture".to_string(),
            true,
            true,
        ),
        (
            format!("GIT_CONFIG_GLOBAL={config} git commit --allow-empty -m fixture"),
            false,
            true,
        ),
        (
            format!("export GIT_CONFIG_GLOBAL={config}; git commit --allow-empty -m fixture"),
            false,
            true,
        ),
        (
            format!("env GIT_CONFIG_GLOBAL={config} git commit --allow-empty -m fixture"),
            false,
            true,
        ),
        (
            "unset GIT_CONFIG_GLOBAL; git commit --allow-empty -m fixture".into(),
            true,
            false,
        ),
        (
            "export -n GIT_CONFIG_GLOBAL; git commit --allow-empty -m fixture".into(),
            true,
            false,
        ),
        (
            "env -u GIT_CONFIG_GLOBAL git commit --allow-empty -m fixture".into(),
            true,
            false,
        ),
        (
            "GIT_CONFIG_GLOBAL= git commit --allow-empty -m fixture".into(),
            true,
            false,
        ),
    ] {
        let mut req = request(&command, false);
        req.shell_state_before = ShellStateSnapshot::new(work.display().to_string())
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_exact_scalar_variable("HOME", home.display().to_string(), true)
            .with_exact_scalar_variable("GIT_CONFIG_NOSYSTEM", "1", true);
        if observed {
            req.shell_state_before = req.shell_state_before.with_exact_scalar_variable(
                "GIT_CONFIG_GLOBAL",
                config.clone(),
                true,
            );
        }
        req.workspace_root = Some(work.display().to_string());
        req.home = Some(home.display().to_string());
        let r = ShellQueryCore::new().check(req);
        let selected = if external {
            hooks.join("pre-commit")
        } else {
            work.join(".git/hooks/pre-commit")
        };
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|p| p.slot_name == "git_hook_pre_commit"
                    && p.spelling == Some(selected.display().to_string())),
            "{command}: {r:#?}"
        );
        let other = if external {
            work.join(".git/hooks/pre-commit")
        } else {
            hooks.join("pre-commit")
        };
        assert!(
            !r.decision_trace
                .path_targets
                .iter()
                .any(|p| p.slot_name == "git_hook_pre_commit"
                    && p.spelling == Some(other.display().to_string())),
            "{command}: {r:#?}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn execution_value_provenance_does_not_merge_distinct_launches() {
    let command = "export BASH_ENV=/work/external/first.sh; bash -c 'printf ONE'; BASH_ENV=/work/external/second.sh; bash -c 'printf TWO'";
    let mut core = ShellQueryCore::new();
    core.check(request(command, false));
    let graph = core
        .session_graph(&SessionId::new("effective-environment"))
        .unwrap();
    let nodes: Vec<_> = graph
        .nodes()
        .filter_map(|n| match &n.kind {
            caushell_graph::NodeKind::ProvenanceArtifact {
                artifact: ProvenanceArtifact::VariableValue { name, state, .. },
                ..
            } if name == "BASH_ENV" => Some((n.id.clone(), state.clone())),
            _ => None,
        })
        .collect();
    assert!(nodes.iter().any(|(_,s)| matches!(s,ProvenanceVariableValueState::ExactScalar{value} if value=="/work/external/first.sh")),"{nodes:#?}");
    assert!(nodes.iter().any(|(_,s)| matches!(s,ProvenanceVariableValueState::ExactScalar{value} if value=="/work/external/second.sh")),"{nodes:#?}");
    let ids: std::collections::BTreeSet<_> = nodes.iter().map(|(id, _)| id).collect();
    assert_eq!(ids.len(), nodes.len());
}

#[test]
fn unknown_git_selectors_do_not_invent_an_absent_global_config() {
    let mut req = request("git commit -m fixture", false);
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let r = ShellQueryCore::new().check(req);
    assert_ne!(r.decision, Decision::Allow, "{r:#?}");
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.slot_name == "git_hook_pre_commit"
                && !matches!(&p.resolution, SemanticResolution::Resolved { .. })),
        "{r:#?}"
    );
}
