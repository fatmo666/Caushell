//! Static scope/Graph checks; shell strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, DerivedInvocationOrigin, PolicyConfig,
    ResolvedPathRole, RuleId, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("shell-syntax"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
    }
}
fn check(command: &str, expected: Decision) -> caushell_types::CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    r
}
fn carriers(body: &str) -> Vec<String> {
    assert!(!body.contains('\''));
    vec![
        body.into(),
        format!("bash -c '{body}'"),
        format!("sh -c '{body}'"),
    ]
}
#[test]
fn compound_and_bare_redirections_are_not_lost_in_shell_payloads() {
    for body in [
        "{ printf DATA; } > /opt/shared/out",
        "(printf DATA) > /opt/shared/out",
        "if true; then printf DATA; fi > /opt/shared/out",
        "for x in item; do printf DATA; done > /opt/shared/out",
        "printf DATA | { cat; } > /opt/shared/out",
        "{ printf DATA; } >> /opt/shared/out",
        "{ printf DATA; } >| /opt/shared/out",
        "{ :; } > /opt/shared/out",
        "> /opt/shared/out",
    ] {
        for c in carriers(body) {
            let r = check(&c, Decision::NeedApproval);
            assert!(
                r.decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
            );
            assert!(
                !r.decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::SelectionError)
            );
        }
    }
}
#[test]
fn local_temporary_and_discard_outputs_keep_existing_policy() {
    for body in [
        "{ printf DATA; } > ./out",
        "{ printf DATA; } > /tmp/lab-out",
        "{ printf DATA; } > /private/tmp/lab-out",
        "{ printf DATA; } >/dev/null",
        "> ./out",
        "> /tmp/lab-out",
        "{ :; } 3>/opt/shared/out 1>&3",
    ] {
        for c in carriers(body) {
            check(
                &c,
                if body.contains("/opt/shared") {
                    Decision::NeedApproval
                } else {
                    Decision::Allow
                },
            );
        }
    }
}
#[test]
fn opening_cwd_is_not_the_last_body_command_cwd() {
    check(
        r#"bash -c 'cd /opt/shared; { cd /bench/workspace; printf DATA; } > outfile'"#,
        Decision::NeedApproval,
    );
    check(
        r#"bash -c 'cd "$UNKNOWN"; { :; } > outfile'"#,
        Decision::NeedApproval,
    );
    check(
        r#"bash -c '{ cd /opt/shared; printf DATA; } > ./outfile'"#,
        Decision::Allow,
    );
    check(
        r#"bash -c '{ cd /opt/shared; { printf DATA; } > outfile; }'"#,
        Decision::NeedApproval,
    );
}
#[test]
fn opening_variables_are_not_overwritten_by_body_assignments() {
    check(
        r#"bash -c 'target=/opt/shared/out; { target=./out; printf DATA; } > "$target"'"#,
        Decision::NeedApproval,
    );
    check(
        r#"bash -c 'target=./out; { target=/opt/shared/out; printf DATA; } > "$target"'"#,
        Decision::Allow,
    );
    check(
        r#"bash -c 'target=/opt/shared/out; > "$target"'"#,
        Decision::NeedApproval,
    );
    check(r#"bash -c '{ :; } > "$UNKNOWN"'"#, Decision::NeedApproval);
}
#[test]
fn deeper_shells_functions_and_known_script_payloads_preserve_effects() {
    for c in [
        r#"bash -c "sh -c '{ :; } >/opt/shared/out'""#,
        r#"f() { { :; } >/opt/shared/out; }; f"#,
        r#"f() { > /opt/shared/out; }; f"#,
        r#"bash -c 'f() { > /opt/shared/out; }; f'"#,
        "printf '%s\\n' '> /opt/shared/out' | sh",
        "printf '%s\\n' '{ :; } > /opt/shared/out' | bash",
    ] {
        check(c, Decision::NeedApproval);
    }
    check("f() { > /opt/shared/out; }; printf SAFE", Decision::Allow);
}
#[test]
fn command_and_process_substitution_scopes_include_pure_redirections() {
    for c in [
        r#"printf "%s" "$(> /opt/shared/out)""#,
        r#"x=$(> /opt/shared/out)"#,
        r#"cat <(> /opt/shared/out)"#,
        r#"cat < <(> /opt/shared/out)"#,
        r#"bash -c 'printf "%s" "$(> /opt/shared/out)"'"#,
    ] {
        check(c, Decision::NeedApproval);
    }
    check(r#"x=$(> ./out)"#, Decision::Allow);
}

#[test]
fn empty_nested_bodies_keep_local_cwd_and_shell_input_bindings() {
    for c in [
        "f() { > ./out; }; f",
        "bash -c 'f() { > ./out; }; f'",
        "printf '%s\\n' '> ./out' | sh",
        "cat <(> ./out)",
        "cat < <(> ./out)",
        "bash -c 'x=$(> ./out)'",
        "export target=./out; bash -c '> \"$target\"'",
        "target=./out bash -c '> \"$target\"'",
        "bash -c '> \"$1\"' shell ./out",
    ] {
        check(c, Decision::Allow);
    }
    for c in [
        "cd /opt/shared; f() { > ./out; }; f",
        "bash -c 'cd /opt/shared; x=$(> ./out)'",
        "bash -c '> \"$1\"' shell /opt/shared/out",
        "export target=/opt/shared/out; bash -c '> \"$target\"'",
    ] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn block_device_floor_and_unreachable_sources_remain_distinct() {
    for c in [
        "bash -c '{ :; } >/dev/sda'",
        "sh -c '> /dev/sda'",
        "{ :; } >/dev/sd*",
        "bash -c '{ :; } >/dev/sd*'",
        "bash -c 'cd /dev; { :; } >sd*'",
    ] {
        check(c, Decision::Deny);
    }
    check("bash -c 'exit 0; { :; } >/opt/shared/out'", Decision::Allow);
    check(
        "bash -c '(exit 0); { :; } >/opt/shared/out'",
        Decision::NeedApproval,
    );
    check(
        "bash -c 'if true; then exit 0; fi; { :; } >/opt/shared/out'",
        Decision::NeedApproval,
    );
}
#[test]
fn expansion_budget_still_requires_approval_without_silent_syntax_drop() {
    let mut p = PolicyConfig::default();
    p.semantic_expansion.max_nested_parse_depth = 0;
    let r = ShellQueryCore::with_policy(p).check(request("bash -c '> /opt/shared/out'"));
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
}
#[test]
fn syntax_units_have_distinct_graph_identity_and_no_fake_executable() {
    let c = "bash -c '{ :; } >/opt/shared/a 2>/opt/shared/b'; sh -c '> /opt/shared/c'";
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(c));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    let staged = StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations());
    let graph = staged.graph();
    let syntax: Vec<_> = graph
        .nodes()
        .filter(|n| {
            matches!(
                &n.kind,
                NodeKind::DerivedInvocation {
                    origin: DerivedInvocationOrigin::ShellRedirection { .. },
                    command_name: None,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(syntax.len(), 2);
    for p in ["/opt/shared/a", "/opt/shared/b", "/opt/shared/c"] {
        assert!(
            graph.nodes().any(|n| matches!(&n.kind,NodeKind::PathFact {
            role:ResolvedPathRole::Write,resolution,..} if resolution.concrete_path()==Some(p))),
            "{p}"
        );
    }
    let ids: std::collections::BTreeSet<_> = syntax.iter().map(|n| &n.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(
        ctx.execution_unit_resolve_records()
            .iter()
            .all(|r| !ids.contains(&r.source_node_id))
    );
}
