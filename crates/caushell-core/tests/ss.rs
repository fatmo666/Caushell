//! All socket-control and dangerous examples are static analyser inputs only.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, ResolveGapKind, ResolvedPathRole,
    RuleAction, RuleId, RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("ss-profile"),
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

fn assert_decision(command: &str, expected: Decision) {
    let r = strict_core().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {r:?}");
}

#[test]
fn queries_and_socket_closure_are_resolved_allow_not_missing_profile_fallback() {
    for c in [
        "ss",
        "ss -lntp",
        "ss -E -t",
        "ss -K",
        "ss --kill dst 192.0.2.1",
        "ss -Ktn state established",
        "ss -x src /run/app.sock",
        "ss --family=inet --query=tcp,udp --net=lab --bpf-map-id=12",
    ] {
        assert_decision(c, Decision::Allow);
    }
}

#[test]
fn query_and_close_filters_do_not_invent_file_process_or_listener_effects() {
    for c in [
        "ss -lntp",
        "ss --events",
        "ss -Ktn dst 192.0.2.1",
        "ss -x src /run/app.sock",
    ] {
        let mut core = strict_core();
        assert_eq!(core.check(request(c)).decision, Decision::Allow, "{c}");
        for n in core
            .session_graph(&SessionId::new("ss-profile"))
            .unwrap()
            .nodes()
        {
            assert!(
                !matches!(
                    n.kind,
                    NodeKind::PathFact { .. } | NodeKind::MutationScopeFact { .. }
                ),
                "{c}: {n:?}"
            );
            if let NodeKind::ExecutionSemantics { semantics } = &n.kind {
                assert!(!semantics.controls_process, "{c}: {semantics:?}");
                assert!(semantics.network_listeners.is_empty(), "{c}: {semantics:?}");
            }
        }
    }
}

#[test]
fn workspace_diagnostic_output_is_written_and_external_filter_is_only_read() {
    for c in [
        "ss -D dump.bin -F /etc/ss-filter",
        "ss -KtDdump.bin -F /etc/ss-filter",
        "ss --kill --diag=dump.bin --filter=/etc/ss-filter",
    ] {
        let mut core = strict_core();
        assert_eq!(core.check(request(c)).decision, Decision::Allow, "{c}");
        let paths: Vec<_> = core
            .session_graph(&SessionId::new("ss-profile"))
            .unwrap()
            .nodes()
            .filter_map(|n| match &n.kind {
                NodeKind::PathFact {
                    role, resolution, ..
                } => resolution.concrete_path().map(|p| (*role, p)),
                _ => None,
            })
            .collect();
        assert!(
            paths.contains(&(ResolvedPathRole::Write, "/tmp/project/dump.bin")),
            "{c}: {paths:?}"
        );
        assert!(
            paths.contains(&(ResolvedPathRole::Read, "/etc/ss-filter")),
            "{c}: {paths:?}"
        );
        assert!(
            !paths.contains(&(ResolvedPathRole::Write, "/etc/ss-filter")),
            "{c}: {paths:?}"
        );
    }
}

#[test]
fn external_and_unknown_diagnostic_outputs_still_require_approval() {
    for c in [
        "ss -D /etc/dump.bin",
        "ss --diag=/etc/dump.bin",
        "ss -KtD/etc/dump.bin",
        "ss -K4tD/etc/dump.bin",
        "ss --kill --diag=../dump.bin",
        "ss -K -D \"$OUTPUT\"",
        "ss --kill --diag=\"$OUTPUT\"",
        "ss -D /etc/first --diag=second.bin",
        "ss -K -D /etc/dump -F -",
    ] {
        let r = strict_core().check(request(c));
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{c}: {r:?}"
        );
    }
}

#[test]
fn stdout_and_stdin_sentinels_never_become_fake_paths() {
    for c in [
        "ss -tD-",
        "ss -K --diag=-anything",
        "ss -F -",
        "ss --kill --filter=-anything",
        "printf 'dst 192.0.2.1' | ss -KtF-",
    ] {
        let mut core = strict_core();
        assert_eq!(core.check(request(c)).decision, Decision::Allow, "{c}");
        assert!(
            !core
                .session_graph(&SessionId::new("ss-profile"))
                .unwrap()
                .nodes()
                .any(|n| matches!(n.kind, NodeKind::PathFact { .. })),
            "{c}"
        );
    }
}

#[test]
fn dot_slash_dash_targets_are_real_files_and_unknown_filter_is_read_only() {
    for c in ["ss -K -D ./-dump -F ./-filter", "ss -F \"$FILTER\""] {
        assert_decision(c, Decision::Allow);
    }
    assert_decision("ss -K -D /etc/-dump", Decision::NeedApproval);
}

#[test]
fn information_does_not_write_but_outer_redirection_still_does() {
    for c in [
        "ss --version",
        "ss -v",
        "ss -K -D /etc/out --help",
        "ss -F /etc/filter --help",
    ] {
        assert_decision(c, Decision::Allow);
    }
    assert_decision("ss --help > /etc/ss-help", Decision::NeedApproval);
}

#[test]
fn closure_allow_scope_cannot_suppress_composed_command_or_substitution_risks() {
    for c in [
        "ss -K > /etc/out",
        "ss --kill; rm -f /etc/ss-test",
        "ss -K && tee /etc/out",
        "ss -F <(rm -f /etc/ss-test)",
        "ss -K -D \"$(rm -f /etc/ss-test; printf dump.bin)\"",
    ] {
        assert_decision(c, Decision::NeedApproval);
    }
    assert_decision("ss -K; rm -rf /", Decision::Deny);
}

#[test]
fn closure_and_output_effects_survive_nested_execution() {
    assert_decision("env -i ss -KtD/etc/dump.bin", Decision::NeedApproval);
    assert_decision(
        "bash -c 'ss --kill --diag=/etc/dump.bin'",
        Decision::NeedApproval,
    );
    assert_decision("env -i ss -K", Decision::Allow);
}

#[test]
fn known_output_variables_are_materialized_before_path_projection() {
    assert_decision("OUT=dump.bin; ss -K -D \"$OUT\"", Decision::Allow);
    assert_decision(
        "OUT=/etc/dump.bin; ss -K -D \"$OUT\"",
        Decision::NeedApproval,
    );
    assert_decision("OUT=-; ss -K -D \"$OUT\"", Decision::Allow);
}

#[test]
fn dashdash_filter_tokens_do_not_create_a_diagnostic_write() {
    let mut core = strict_core();
    let r = core.check(request("ss -- -K -D /etc/not-an-output"));
    assert_eq!(r.decision, Decision::Allow, "{r:?}");
    assert!(
        !core
            .session_graph(&SessionId::new("ss-profile"))
            .unwrap()
            .nodes()
            .any(|n| matches!(n.kind, NodeKind::PathFact { .. }))
    );
}

#[test]
fn compact_operands_remain_file_targets_and_terminated_operands_remain_data() {
    let mut core = strict_core();
    assert_eq!(
        core.check(request("ss -Ddump -Ffilter")).decision,
        Decision::Allow
    );
    let paths: Vec<_> = core
        .session_graph(&SessionId::new("ss-profile"))
        .unwrap()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => resolution.concrete_path().map(|p| (*role, p)),
            _ => None,
        })
        .collect();
    assert!(
        paths.contains(&(ResolvedPathRole::Write, "/tmp/project/dump")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/tmp/project/filter")),
        "{paths:?}"
    );
    for c in [
        "ss -- -Ddump -Ffilter",
        "ss -K -- -Ddump",
        "ss -K -F - -- -Ddump",
    ] {
        let mut core = strict_core();
        assert_eq!(core.check(request(c)).decision, Decision::Allow, "{c}");
        assert!(
            !core
                .session_graph(&SessionId::new("ss-profile"))
                .unwrap()
                .nodes()
                .any(|n| matches!(n.kind, NodeKind::PathFact { .. })),
            "{c}"
        );
    }
    assert_decision("cd /etc; ss -Ddump", Decision::NeedApproval);
    assert_decision(
        "cd /etc; ss -Ddump -- state established",
        Decision::NeedApproval,
    );
    let mut core = strict_core();
    let r = core.check(request("ss -Ddump -- -Dother"));
    assert_eq!(r.decision, Decision::Allow, "{r:?}");
    let writes: Vec<_> = core
        .session_graph(&SessionId::new("ss-profile"))
        .unwrap()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                resolution,
                ..
            } => resolution.concrete_path(),
            _ => None,
        })
        .collect();
    assert_eq!(writes, ["/tmp/project/dump"]);
    assert_decision(
        "ss -K -D /etc/real-output -- -Ddump",
        Decision::NeedApproval,
    );
}

#[test]
fn graph_retains_closure_forms_including_attached_and_numeric_option_clusters() {
    for (c, form) in [
        ("ss -K", "close_sockets_unchecked"),
        ("ss -K4tnDdump.bin", "close_sockets_unchecked"),
        ("ss -KtF-", "close_sockets_stdin_filter_unchecked"),
        (
            "ss --kill --filter=-",
            "close_sockets_stdin_filter_unchecked",
        ),
    ] {
        let mut core = strict_core();
        let r = core.check(request(c));
        assert_eq!(r.decision, Decision::Allow, "{c}: {r:?}");
        assert!(core.session_graph(&SessionId::new("ss-profile")).unwrap().nodes().any(|n| matches!(&n.kind,
            NodeKind::ExecutionSemantics { semantics } if semantics.normalized_command_name == "ss" && semantics.form_id == form && !semantics.controls_process
        )), "{c}: expected {form} in Graph");
    }
}
