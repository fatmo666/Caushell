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
fn final_subshell_keeps_function_body_and_group_write_authorization() {
    for (body, decision, path) in [
        ("printf fixture", Decision::Allow, None),
        (
            "printf fixture > ./report.txt",
            Decision::Allow,
            Some("/bench/workspace/report.txt"),
        ),
        (
            "printf fixture > /opt/shared/report.txt",
            Decision::NeedApproval,
            Some("/opt/shared/report.txt"),
        ),
    ] {
        let explicit = check(&format!("work() {{ ({body}); }}\nwork"), decision);
        let implicit = check(&format!("work() {{ ({body}) }}\nwork"), decision);
        assert_eq!(explicit.reasons, implicit.reasons);
        if let Some(path) = path {
            for result in [&explicit, &implicit] {
                assert!(
                    result.decision_trace.path_targets.iter().any(|target| {
                        target.operation == caushell_types::PathTargetOperation::Write
                            && target.lexical.concrete_path() == Some(path)
                    }),
                    "{result:#?}"
                );
            }
        }
    }
}

#[test]
fn conditional_heredoc_reassociation_preserves_data_execution_and_substitution_boundaries() {
    check("true && cat <<'EOF'\nrm -rf /\nEOF", Decision::Allow);
    check("true && bash <<'EOF'\nrm -rf /\nEOF", Decision::Deny);
    check("true && bash - <<'EOF'\nrm -rf /\nEOF", Decision::Deny);
    check("bash - <<'EOF' 2>&1 | cat\nrm -rf /\nEOF", Decision::Deny);
    check("cat <<'EOF' 2>&1 | cat\nrm -rf /\nEOF", Decision::Allow);
    check("cat <<EOF 2>&1 | cat\n$(rm -rf /)\nEOF", Decision::Deny);
    check("sh - <<'EOF'\nrm -rf /\nEOF", Decision::Deny);
    check("printf '%s\\n' 'rm -rf /' | bash -", Decision::Deny);
    check("printf '%s\\n' 'rm -rf /' | sh -", Decision::Deny);
    check("bash -", Decision::NeedApproval);
    check("bash - /opt/shared/script", Decision::NeedApproval);
    check("bash -c 'printf x'", Decision::Allow);
    check(
        "bash /opt/shared/script -c 'printf x'",
        Decision::NeedApproval,
    );
    check("bash ./script -c 'rm -rf /'", Decision::Allow);
    check("true && cat <<EOF\n$(rm -rf /)\nEOF", Decision::Deny);
    check("false || cat <<< 'literal > text'", Decision::Allow);
    check(
        "true && python - <<'EOF'\nprint(1)\nEOF",
        Decision::NeedApproval,
    );
}

#[test]
fn unix_monitor_profile_preserves_peer_control_approval() {
    let r = check(
        "socat - UNIX-CONNECT:/tmp/qemu-monitor.sock",
        Decision::NeedApproval,
    );
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::SelectionError)
    );
}
#[test]
fn redirected_conditional_tail_groups_open_in_the_outer_scope() {
    check(
        "true && (cd /opt/shared; printf DATA) > ./out | cat",
        Decision::Allow,
    );
    check(
        "true && { cd /opt/shared; printf DATA; } > ./out | cat",
        Decision::Allow,
    );
    check(
        "cd /opt/shared && (cd /bench/workspace; printf DATA) > out | cat",
        Decision::NeedApproval,
    );
    check(
        "true && (printf '%s' \"$(rm -rf /)\") > ./out | cat",
        Decision::Deny,
    );
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
fn signed_pipeline_arguments_keep_redirect_paths_under_policy() {
    check("printf DATA | head -200>./out", Decision::Allow);
    let outside = check(
        "printf DATA | head -200>/opt/shared/out",
        Decision::NeedApproval,
    );
    assert!(
        outside
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    let malformed = check(
        "printf DATA | head -200>./out; printf \"unterminated",
        Decision::NeedApproval,
    );
    assert!(
        malformed
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::CommandParseFailure)
    );
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
