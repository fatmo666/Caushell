//! Static guard/Graph checks only; sample shell actions never execute.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-path-scope"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn expect(command: &str, decision: Decision, rule: Option<RuleId>) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
    if let Some(rule) = rule {
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == rule),
            "{command}: {result:#?}"
        );
    }
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::SelectionError),
        "{command}: {result:#?}"
    );
}
fn path_facts(command: &str) -> Vec<(Option<String>, ResolvedPathRole, PathResolution)> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                normalized_command_name,
                role,
                resolution,
                ..
            } => Some((normalized_command_name.clone(), *role, resolution.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn implicit_and_explicit_catastrophic_roots_have_the_same_hard_deny() {
    for command in [
        "find / -delete",
        "cd /; find -delete",
        "cd /; find -mtime -7 -delete",
        "find / -mindepth 1 -delete",
        "cd /; find -mindepth 1 -delete",
        "root=/; cd \"$root\"; find -delete",
        "bash -c 'cd /; find -delete'",
    ] {
        expect(
            command,
            Decision::Deny,
            Some(RuleId::CatastrophicFileSystemDelete),
        );
    }
    for command in [
        "find . -delete",
        "find -delete",
        "find -mindepth 1 -delete",
        "cd /; find /tmp/project -delete",
        "cd /opt/shared; find /tmp/project -delete",
    ] {
        expect(command, Decision::Allow, None);
    }
    for command in ["cd /opt/shared; find -delete", "find /opt/shared -delete"] {
        expect(
            command,
            Decision::NeedApproval,
            Some(RuleId::OutsideWorkspaceMutation),
        );
    }
    let result = ShellQueryCore::new().check(request("cd \"$unknown\"; find -delete"));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete)
    );
}

#[test]
fn symlink_traversal_is_part_of_direct_deletion_not_only_child_dispatch() {
    for command in [
        "find -L . -delete",
        "find -H . -delete",
        "find . -follow -delete",
        "find -L -delete",
        "find -L ./src ./cache -delete",
        "find -L . -false -delete",
    ] {
        expect(
            command,
            Decision::NeedApproval,
            Some(RuleId::OutsideWorkspaceMutation),
        );
    }
    for command in [
        "find . -delete",
        "find -P . -delete",
        "find ./src ./cache -delete",
        "find -L . -print",
        "find -H . -print",
        "find . -name '-follow' -delete",
    ] {
        expect(command, Decision::Allow, None);
    }
    for command in [
        r"find -L . -exec rm -- {} \;",
        r"find -L . -mindepth 1 -execdir rm -- {} \;",
    ] {
        expect(
            command,
            Decision::NeedApproval,
            Some(RuleId::OutsideWorkspaceMutation),
        );
    }
}

#[test]
fn graph_keeps_traversal_bounds_and_escape_without_replacing_root_reads() {
    for (command, escape) in [("find . -delete", false), ("find -L . -delete", true)] {
        let paths = path_facts(command);
        assert!(
            paths
                .iter()
                .any(|(name, role, path)| name.as_deref() == Some("find")
                    && *role == ResolvedPathRole::Read
                    && path.concrete_path() == Some("/tmp/project")),
            "{paths:?}"
        );
        assert!(paths.iter().any(|(name,role,path)|name.as_deref()==Some("find") && *role==ResolvedPathRole::Target
            && matches!(path,PathResolution::BoundedPathSet {roots,may_escape} if roots==&vec!["/tmp/project".to_string()] && *may_escape==escape)),"{paths:?}");
    }
    let paths = path_facts("find -L ./src /opt/shared -delete");
    for expected in ["/tmp/project/src", "/opt/shared"] {
        assert!(paths.iter().any(|(_,role,path)|*role==ResolvedPathRole::Target
            && matches!(path,PathResolution::BoundedPathSet {roots,may_escape:true} if roots.contains(&expected.to_string()))),"{paths:?}");
    }
    let paths = path_facts("cd /; find -delete");
    assert!(paths.iter().any(|(_,role,path)|*role==ResolvedPathRole::Target
        && matches!(path,PathResolution::BoundedPathSet {roots,may_escape:false} if roots==&vec!["/".to_string()])),"{paths:?}");
}

#[test]
fn supplemental_defaults_do_not_replace_or_widen_explicit_glob_roots() {
    for command in ["find ./* -delete", "find ./src/* -delete"] {
        expect(command, Decision::Allow, None);
    }
    for command in [
        "find /opt/shared/* -delete",
        "find /tmp/project/* -delete",
        "find -L ./* -delete",
    ] {
        expect(
            command,
            Decision::NeedApproval,
            Some(RuleId::OutsideWorkspaceMutation),
        );
    }
    let paths = path_facts("find ./src/* -delete");
    assert!(
        paths
            .iter()
            .any(|(name, role, _)| name.as_deref() == Some("find")
                && *role == ResolvedPathRole::Target),
        "{paths:?}"
    );
    assert!(paths.iter().filter(|(name,role,_)|name.as_deref()==Some("find") && *role==ResolvedPathRole::Target)
                .all(|(_,_,path)|matches!(path,PathResolution::BoundedPathSet {roots,may_escape:false} if roots.iter().all(|root|root.trim_end_matches('/')=="/tmp/project"))),"{paths:?}");
    let result = ShellQueryCore::new().check(request("cd /; find -f /tmp/project -delete"));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete)
    );
}

#[test]
fn configured_hard_deny_uses_declared_semantics_not_the_find_command_name() {
    let profile = caushell_profile::load_command_profile_from_str(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_tree_tool}
forms:
  - id: tree
    parameters:
      - name: roots
        semantic: {kind: path, role: read}
        binding: {kind: remaining_positionals}
        cardinality: optional_many
    effects:
      - kind: delete_path
        target:
          kind: configured_path
          sources: [{slot: roots, projection: {kind: identity}}]
          default_value: '.'
        path_scope: {kind: subtree}
        catastrophic: {semantic_class: delete_path}
"#,
    )
    .unwrap();
    for (cwd, command, denied) in [
        ("/", "arbitrary_tree_tool", true),
        ("/tmp/project", "arbitrary_tree_tool", false),
        ("/tmp/project", "arbitrary_tree_tool /", true),
        ("/tmp/project", "arbitrary_tree_tool \"$unknown\"", false),
    ] {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile.clone()]).unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_analysis_pass(caushell_passes::CatastrophicDeleteGuardPass);
        let mut input = request(command);
        input.shell_state_before = ShellStateSnapshot::new(cwd);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(input);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        assert_eq!(
            ctx.findings
                .iter()
                .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete),
            denied,
            "{command}: {:?}",
            ctx.findings
        );
    }
}

#[test]
fn file_output_aliases_cannot_manufacture_a_pure_stdout_record_domain() {
    for alias in ["/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"] {
        for action in [
            format!("-fprintf {alias} '/opt/shared/file\\0'"),
            format!("-fprint {alias}"),
            format!("-fprint0 {alias}"),
            format!("-fls {alias}"),
        ] {
            let command = format!("find . {action} -print0 | xargs -0 rm --");
            expect(
                &command,
                Decision::NeedApproval,
                Some(RuleId::OutsideWorkspaceMutation),
            );
            let paths = path_facts(&command);
            assert!(
                paths
                    .iter()
                    .any(|(name, _, path)| name.as_deref() == Some("rm")
                        && !matches!(
                            path,
                            PathResolution::BoundedPathSet {
                                may_escape: false,
                                ..
                            }
                        )),
                "{command}: {paths:?}"
            );
        }
    }
    for command in [
        "find . -print0 | xargs -0 rm --",
        "find . -print0 | tee ./paths | xargs -0 rm --",
        "find . -fprintf ./out '%p\\0'",
        "find . -fprintf /dev/null '%p\\0'",
    ] {
        expect(command, Decision::Allow, None);
    }
    // The Profile provides an unconditional guarantee, not per-file fd routing.
    // Even a local output plus -print0 has no unconditional pure-path contract.
    expect(
        "find . -fprint ./paths -print0 | xargs -0 rm --",
        Decision::NeedApproval,
        Some(RuleId::OutsideWorkspaceMutation),
    );
}
