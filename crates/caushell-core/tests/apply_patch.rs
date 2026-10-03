//! Shell strings are static analyser inputs only; no patch or inserted code is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, ResolveGapKind, ResolvedPathRole,
    RuleAction, RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("patch-profile"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}
fn strict_core() -> ShellQueryCore {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.no_profile.action = RuleAction::Deny;
    for kind in [
        ResolveGapKind::NoProfile,
        ResolveGapKind::UnknownSubcommandPath,
        ResolveGapKind::FormSelectionUnmatched,
        ResolveGapKind::FormSelectionAmbiguous,
    ] {
        policy
            .rule_policy
            .resolve_gap
            .defaults
            .insert(kind, RuleAction::Deny);
    }
    ShellQueryCore::try_with_policy(policy).unwrap()
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn patch(body: &str) -> String {
    format!("*** Begin Patch\n{body}\n*** End Patch")
}
fn argv(body: &str) -> String {
    format!("apply_patch {}", quote(&patch(body)))
}
fn stdin(body: &str) -> String {
    format!("apply_patch <<'PATCH'\n{}\nPATCH", patch(body))
}
fn inspect(command: &str, decision: Decision) -> Vec<(ResolvedPathRole, String)> {
    let mut core = strict_core();
    let r = core.check(request(command));
    assert_eq!(r.decision, decision, "{command}: {r:?}");
    if decision != Decision::Allow {
        // Approval candidates are staged facts, not executed session history.
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
        return staged
            .graph()
            .nodes()
            .filter_map(|n| match &n.kind {
                NodeKind::PathFact {
                    role, resolution, ..
                } => resolution.concrete_path().map(|p| (*role, p.to_string())),
                _ => None,
            })
            .collect();
    }
    core.session_graph(&SessionId::new("patch-profile"))
        .unwrap()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => resolution.concrete_path().map(|p| (*role, p.to_string())),
            _ => None,
        })
        .collect()
}

#[test]
fn workspace_operations_allow_and_external_operations_require_approval() {
    for body in [
        "*** Add File: new\n+x",
        "*** Update File: old\n-old\n+new",
        "*** Delete File: gone",
        "*** Update File: src\n*** Move to: dest\n x",
    ] {
        inspect(&argv(body), Decision::Allow);
        inspect(&stdin(body), Decision::Allow);
    }
    for body in [
        "*** Add File: /etc/new\n+x",
        "*** Update File: /etc/old\n-old\n+new",
        "*** Delete File: /etc/gone",
        "*** Update File: src\n*** Move to: /etc/dest\n x",
        "*** Update File: /etc/src\n*** Move to: dest\n x",
        "*** Add File: ../outside\n+x",
    ] {
        inspect(&argv(body), Decision::NeedApproval);
        inspect(&stdin(body), Decision::NeedApproval);
    }
}
#[test]
fn graph_retains_read_write_and_move_source_deletion() {
    let paths = inspect(
        &argv("*** Update File: src\n*** Move to: dest\n-old\n+new"),
        Decision::Allow,
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/tmp/project/src".into())),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Target, "/tmp/project/src".into())),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Write, "/tmp/project/dest".into())),
        "{paths:?}"
    );
    assert!(
        !paths.contains(&(ResolvedPathRole::Write, "/tmp/project/src".into())),
        "{paths:?}"
    );
}
#[test]
fn complete_here_string_and_printf_pipeline_reach_canonical_graph() {
    for body in ["*** Add File: local\n+x", "*** Delete File: /etc/outside"] {
        let expected = if body.contains("/etc") {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        let p = quote(&patch(body));
        for c in [
            format!("apply_patch <<< {p}"),
            format!("printf '%s' {p} | apply_patch"),
            format!("printf '%s' {p} | env apply_patch"),
        ] {
            inspect(&c, expected.clone());
        }
    }
}
#[test]
fn unknown_ambient_file_and_partial_pipeline_are_not_complete_patches() {
    for c in [
        "apply_patch".into(),
        "apply_patch < missing.patch".into(),
        "cat missing.patch | apply_patch".into(),
        "apply_patch <<< \"$UNKNOWN\"".into(),
        format!(
            "printf '%s' {} \"$UNKNOWN\" | apply_patch",
            quote(&patch("*** Add File: safe\n+x"))
        ),
        "apply_patch 0<&3".into(),
    ] {
        inspect(&c, Decision::NeedApproval);
    }
}
#[test]
fn explicit_and_last_stdin_redirection_take_precedence() {
    let safe = quote(&patch("*** Add File: safe\n+x"));
    let outside = quote(&patch("*** Add File: /etc/outside\n+x"));
    inspect(
        &format!("printf '%s' {outside} | apply_patch <<< {safe}"),
        Decision::Allow,
    );
    inspect(
        &format!("apply_patch <<< {outside} <<< {safe}"),
        Decision::Allow,
    );
    inspect(
        &format!("apply_patch <<< {safe} <<< {outside}"),
        Decision::NeedApproval,
    );
    inspect(
        &format!("apply_patch <<< {safe} < missing.patch"),
        Decision::NeedApproval,
    );
}
#[test]
fn argument_overrides_stdin_even_if_stdin_is_unknown_or_dangerous() {
    inspect(
        &format!("{} < missing.patch", argv("*** Add File: safe\n+x")),
        Decision::Allow,
    );
    inspect(
        &format!(
            "printf '%s' {} | {}",
            quote(&patch("*** Delete File: /etc/outside")),
            argv("*** Add File: safe\n+x")
        ),
        Decision::Allow,
    );
}
#[test]
fn quoted_patch_code_and_fake_headers_never_become_commands_or_targets() {
    inspect(
        &argv(
            "*** Add File: script.sh\n+rm -rf /\n+$(unknown-command)\n+*** Delete File: /etc/file",
        ),
        Decision::Allow,
    );
    inspect(
        &stdin("*** Add File: script.sh\n+$(unknown-command)\n+rm -rf /"),
        Decision::Allow,
    );
    inspect(
        &argv("*** Update File: script.sh\n *** Delete File: /etc/file\n+rm -rf /"),
        Decision::Allow,
    );
}
#[test]
fn filenames_are_literal_data_not_second_expansion() {
    let c = format!("INNER=/etc; {}", argv("*** Add File: $INNER/$(whoami)\n+x"));
    let paths = inspect(&c, Decision::Allow);
    assert!(
        paths.contains(&(
            ResolvedPathRole::Write,
            "/tmp/project/$INNER/$(whoami)".into()
        )),
        "{paths:?}"
    );
    inspect(&argv("*** Add File: ~/literal\n+x"), Decision::Allow);
    inspect(
        &argv("*** Add File: ../outside name/文件\n+x"),
        Decision::NeedApproval,
    );
}
#[test]
fn outer_known_scalar_and_unquoted_heredoc_expansion_are_materialized() {
    let p = quote(&patch("*** Add File: /etc/outside\n+x"));
    inspect(
        &format!("PATCH={p}; apply_patch \"$PATCH\""),
        Decision::NeedApproval,
    );
    inspect(
        "DEST=/etc/outside; apply_patch <<PATCH\n*** Begin Patch\n*** Add File: $DEST\n+x\n*** End Patch\nPATCH",
        Decision::NeedApproval,
    );
    inspect(
        "apply_patch <<PATCH\n*** Begin Patch\n*** Add File: $UNKNOWN\n+x\n*** End Patch\nPATCH",
        Decision::NeedApproval,
    );
}
#[test]
fn invalid_and_nonlocal_protocols_do_not_allow_a_valid_prefix() {
    for c in [
        "apply_patch --help".into(),
        "apply_patch --".into(),
        format!(
            "apply_patch {}",
            quote("*** Begin Patch\n*** Add File: safe\n+x")
        ),
        format!(
            "apply_patch {}",
            quote("*** Begin Patch\n*** Add File: safe\n+x\n*** End Patch\nextra")
        ),
        argv("*** Environment ID: remote\n*** Add File: safe\n+x"),
        format!("{} extra", argv("*** Add File: safe\n+x")),
    ] {
        inspect(&c, Decision::NeedApproval);
    }
}
#[test]
fn empty_protocol_has_no_unknown_modification_fallback() {
    inspect(
        "apply_patch '*** Begin Patch\n*** End Patch'",
        Decision::Allow,
    );
    inspect(
        "apply_patch <<'PATCH'\n*** Begin Patch\n*** End Patch\nPATCH",
        Decision::Allow,
    );
}
#[test]
fn one_external_operation_in_a_batch_is_not_hidden() {
    inspect(
        &argv("*** Add File: safe\n+x\n*** Add File: /etc/outside\n+x\n*** Add File: safe2\n+x"),
        Decision::NeedApproval,
    );
}
#[test]
fn cwd_transitions_and_unknown_cwd_use_existing_path_guard() {
    inspect(
        &format!("cd /tmp/outside; {}", argv("*** Delete File: file")),
        Decision::NeedApproval,
    );
    inspect(
        &format!("cd /tmp/project/sub; {}", argv("*** Add File: file\n+x")),
        Decision::Allow,
    );
    inspect(
        &format!("cd \"$UNKNOWN\"; {}", argv("*** Add File: file\n+x")),
        Decision::NeedApproval,
    );
}
#[test]
fn wrapper_nested_shell_and_function_share_the_same_projection_gate() {
    for body in ["*** Add File: safe\n+x", "*** Add File: /etc/outside\n+x"] {
        let expected = if body.contains("/etc") {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        for c in [
            format!("env {}", argv(body)),
            format!(
                "bash -c {}",
                quote(&format!("apply_patch <<PATCH\n{}\nPATCH", patch(body)))
            ),
            format!("patcher() {{ {}\n}}; patcher", stdin(body)),
        ] {
            inspect(&c, expected.clone());
        }
    }
}
#[test]
fn missing_workspace_and_unknown_request_cwd_do_not_guess_local_targets() {
    let mut r = request(&argv("*** Add File: file\n+x"));
    r.workspace_root = None;
    assert_eq!(strict_core().check(r).decision, Decision::NeedApproval);
}
#[test]
fn catastrophic_patch_targets_keep_existing_stronger_guards() {
    // Whether applying such a patch would fail at runtime is not assumed.
    inspect(&argv("*** Delete File: /"), Decision::Deny);
}

#[test]
fn dispatcher_output_is_not_confused_with_its_original_stdin_through_wrappers() {
    let p = quote(&patch("*** Add File: safe\n+x"));
    for child in ["apply_patch", "env apply_patch", "env env apply_patch"] {
        inspect(
            &format!("printf '%s' {p} | nsys stats -o '@{child}' report.sqlite"),
            Decision::NeedApproval,
        );
    }
}

#[test]
fn multiline_double_quoted_patches_keep_targets_directly_and_in_nested_shells() {
    for (target, expected) in [
        ("safe", Decision::Allow),
        ("/etc/outside", Decision::NeedApproval),
    ] {
        let body = format!("*** Add File: {target}\n+x");
        for command in [
            format!("bash -c \"{}\"", argv(&body)),
            format!("apply_patch \"{}\"", patch(&body)),
        ] {
            let paths = inspect(&command, expected.clone());
            let concrete = if target.starts_with('/') {
                target.to_string()
            } else {
                format!("/tmp/project/{target}")
            };
            assert!(
                paths.contains(&(ResolvedPathRole::Write, concrete)),
                "{paths:?}"
            );
        }
    }
}

#[test]
fn multiline_double_quoted_patch_data_survives_stdin_producers() {
    for (target, expected) in [
        ("safe", Decision::Allow),
        ("/etc/outside", Decision::NeedApproval),
    ] {
        let p = patch(&format!("*** Add File: {target}\n+x"));
        for command in [
            format!("apply_patch <<< \"{p}\""),
            format!("printf '%s' \"{p}\" | apply_patch"),
            format!("PATCH=\"{p}\"; apply_patch \"$PATCH\""),
        ] {
            inspect(&command, expected.clone());
        }
    }
}

#[test]
fn escaped_double_quoted_patch_filenames_are_not_expanded_again() {
    let paths = inspect(
        "DEST=/etc; apply_patch \"*** Begin Patch\n*** Add File: \\$DEST/literal\n+\\$(unknown-command)\n*** End Patch\"",
        Decision::Allow,
    );
    assert!(paths.contains(&(ResolvedPathRole::Write, "/tmp/project/$DEST/literal".into())));
}

#[test]
fn statically_created_patch_file_can_supply_complete_data_without_host_read() {
    for body in ["*** Add File: safe\n+x", "*** Delete File: /etc/outside"] {
        let expected = if body.contains("/etc") {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        inspect(
            &format!(
                "printf '%s' {} > patch.txt; apply_patch < patch.txt",
                quote(&patch(body))
            ),
            expected,
        );
    }
}

#[test]
fn patch_protocol_is_not_mistaken_for_resulting_file_contents_in_session_history() {
    let mut core = strict_core();
    let first = request(&argv("*** Add File: output.patch\n+not a patch"));
    assert_eq!(core.check(first).decision, Decision::Allow);
    let mut second = request("apply_patch < output.patch");
    second.sequence_no = CommandSequenceNo::new(2);
    assert_eq!(core.check(second).decision, Decision::NeedApproval);
}

#[test]
fn default_operation_and_byte_budgets_do_not_allow_a_safe_prefix() {
    let body = "*** Delete File: safe\n".repeat(4097);
    inspect(&argv(body.trim_end()), Decision::NeedApproval);
    inspect(
        &argv(&format!("*** Add File: safe\n+{}", "x".repeat(1048576))),
        Decision::NeedApproval,
    );
}
