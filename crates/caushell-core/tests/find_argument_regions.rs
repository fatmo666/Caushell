//! Static checks only: none of these command strings are executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuleId, RuntimeMetadata, SessionId, SessionSummary,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-argument-regions"),
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

#[test]
fn child_data_never_triggers_outer_deletion() {
    for command in [
        r"find /opt/shared -exec printf %s -delete \;",
        r"find /opt/shared -exec printf %s -delete -type b -name /etc -exec -- {} \;",
        r"find /opt/shared -execdir printf %s -delete -- {} \;",
        r"find /opt/shared -name -delete -exec printf %s {} \;",
        r"find /opt/shared -exec printf %s + -delete {} \;",
        "find /opt/shared '-exec' printf %s '-delete' ';'",
        "find /opt/shared '-name' '-delete' '-exec' printf %s ';'",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(
            !result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
        assert_eq!(
            result.decision_trace.derived_invocations.len(),
            1,
            "{command}: {result:?}"
        );
    }
}

#[test]
fn real_outer_and_child_deletion_still_reach_existing_guards() {
    for command in [
        r"find /opt/shared -delete -exec printf %s -delete \;",
        r"find /opt/shared -exec printf %s -delete \; -delete",
        r"find /opt/shared -exec echo {} + -delete",
        r"find . -exec printf %s -- {} \; -exec rm /opt/shared/file \;",
        r"find . -exec printf %s -delete \; -execdir rm {} \;",
        r"find /opt/shared -exec rm {} \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn known_option_operands_cannot_create_fake_children() {
    for command in [
        "find . -name '-exec' -print",
        "find . -name '-execdir' -print",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{result:?}");
        assert!(
            result.decision_trace.derived_invocations.is_empty(),
            "{result:?}"
        );
    }
}

#[test]
fn child_symlink_and_type_flags_cannot_widen_other_child_domains() {
    for command in [
        r"find . -exec printf %s -L {} \; -exec rm {} \;",
        r"find . -exec printf %s -type b {} \; -exec rm {} \;",
        r"find . -type f -exec printf %s -name /etc {} \; -exec rm {} \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert_eq!(result.decision_trace.derived_invocations.len(), 2);
    }
    let result = ShellQueryCore::new().check(request(r"find -L . -exec rm {} \;"));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
}

#[test]
fn ownership_errors_are_not_silently_allowed() {
    for command in [
        "find . -exec",
        "find . -exec printf",
        "find . -exec printf ;",
        "find . -exec ';'",
        "find . -exec printf $unknown ';'",
        "find . -name",
        "find . -unsupported -exec printf ';'",
        "find . -exec echo {} + -execdir printf",
        "find $unknown -delete",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
    }
}

#[test]
fn graph_retains_separate_children_and_only_real_outer_search_roots() {
    let command = r"find /opt/shared -name *.txt -exec printf %s -delete -type b -name /etc -exec -- {} \; -execdir rm -- /opt/shared/file \; -delete";
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
    let children = staged
        .graph()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::DerivedInvocation {
                command_name,
                raw_text,
                ..
            } => Some((command_name.as_deref(), raw_text.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        children,
        [
            (
                Some("printf"),
                "printf %s -delete -type b -name /etc -exec --"
            ),
            (Some("rm"), "rm -- /opt/shared/file")
        ]
    );
    assert!(!staged.graph().nodes().any(|node| matches!(&node.kind, NodeKind::PathFact { resolution, .. } if resolution.concrete_path() == Some("/etc"))));
}

#[test]
fn materialized_argv_opener_obeys_the_same_boundary() {
    let command =
        "action=-exec; option=-delete; find /opt/shared \"$action\" printf %s \"$option\" ';'";
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
    assert_eq!(result.decision_trace.derived_invocations.len(), 1);
}

#[test]
fn unknown_path_and_payload_still_reach_specific_existing_guards() {
    for (command, rule) in [
        (
            r#"find "$UNKNOWN_ROOT" -exec rm {} \;"#,
            RuleId::OutsideWorkspaceMutation,
        ),
        (
            r#"find . -exec echo {} \; -exec rm "$UNKNOWN_TARGET" \;"#,
            RuleId::OutsideWorkspaceMutation,
        ),
        (
            r#"find /var/tmp -exec sh -c "$UNKNOWN_SCRIPT" _ {} \;"#,
            RuleId::TaintedExecution,
        ),
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == rule),
            "{response:?}"
        );
        assert!(!response.decision_trace.derived_invocations.is_empty());
    }
}
