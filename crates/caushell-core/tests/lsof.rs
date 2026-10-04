//! Static proposals only. The lsof/cache/process examples are not executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("lsof-static"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
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
fn check(command: &str, expected: Decision) -> (ShellQueryCore, CheckResponse) {
    let mut core = ShellQueryCore::new();
    let r = core.check(request(command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
    (core, r)
}

#[test]
fn ordinary_external_metadata_and_socket_queries_are_allowed() {
    for c in [
        "lsof",
        "lsof -nP -i TCP:8080",
        "lsof -i -nP",
        "lsof -nPiTCP",
        "lsof -p 123 -d cwd",
        "lsof -c python +c20",
        "lsof +d /etc",
        "lsof +D/etc",
        "lsof /etc/shadow",
        "lsof +L1",
        "lsof -F pfn",
        "lsof +f -- /mnt",
        "lsof -r5m%H:%M:%S",
        "lsof +m",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn query_graph_has_no_fictitious_file_content_listener_kill_or_mutation_facts() {
    for c in ["lsof -nP -i @192.0.2.1 -p 123 +D/etc", "lsof /etc/shadow"] {
        let (core, r) = check(c, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
        let graph = core.session_graph(&SessionId::new("lsof-static")).unwrap();
        let mut has_semantics = false;
        for n in graph.nodes() {
            assert!(
                !matches!(
                    n.kind,
                    NodeKind::PathFact { .. } | NodeKind::MutationScopeFact { .. }
                ),
                "{c}: {n:?}"
            );
            if let NodeKind::ExecutionSemantics { semantics } = &n.kind {
                has_semantics = true;
                assert!(!semantics.controls_process, "{c}: {semantics:?}");
                assert!(semantics.network_listeners.is_empty());
                assert!(!semantics.operation_semantics_unresolved);
            }
        }
        assert!(has_semantics);
        let restored = SessionGraph::from_snapshot(graph.to_snapshot()).unwrap();
        assert_eq!(restored.to_snapshot(), graph.to_snapshot());
    }
}
#[test]
fn unsupported_cache_and_unknown_forms_use_existing_opaque_approval() {
    for c in [
        "lsof -D b/etc/cache",
        "lsof -nPDu/etc/cache",
        "lsof +D -Db/etc/cache",
        "lsof -i -D b/etc/cache",
        "lsof -k /tmp/kernel",
        "lsof -Z label",
        "lsof --unknown",
        "lsof +D",
        "lsof -c",
        "lsof -r5Db/etc/cache",
        "lsof +L1Db/etc/cache",
    ] {
        let (core, r) = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.operation_semantics_unresolved),
            "{c}: {:?}",
            r.decision_trace
        );
        assert!(
            !core
                .session_graph(&SessionId::new("lsof-static"))
                .unwrap()
                .nodes()
                .any(|n| matches!(
                    n.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                        ..
                    }
                )),
            "{c}"
        );
    }
}
#[test]
fn cache_looking_file_data_after_native_boundary_is_not_a_cache_operation() {
    for c in [
        "lsof -- -D b/etc/cache",
        "lsof ++ -Db/etc/cache",
        "lsof file.txt -D b/etc/cache",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn output_redirections_keep_their_independent_workspace_scope() {
    check("lsof -nP -i > report.txt", Decision::Allow);
    let (_, r) = check("lsof -nP -i > /etc/report.txt", Decision::NeedApproval);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}
#[test]
fn using_lsof_pid_output_to_kill_is_not_downgraded_to_a_metadata_query() {
    // This Profile must retain the child's semantics/policy, not introduce a
    // process-control risk rule. The current default core registers no such
    // approval guard; that independent pre-existing gap is recorded privately.
    let existing_kill_decision = ShellQueryCore::new().check(request("kill 123")).decision;
    let (_, r) = check("lsof -t -i :8080 | xargs kill", existing_kill_decision);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.controls_process),
        "{:?}",
        r.decision_trace
    );
}
#[test]
fn mount_supplement_read_is_a_real_read_but_not_a_write() {
    let (core, _) = check("lsof +m /etc/lsof-mounts", Decision::Allow);
    let paths: Vec<_> = core
        .session_graph(&SessionId::new("lsof-static"))
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
        paths.contains(&(ResolvedPathRole::Read, "/etc/lsof-mounts")),
        "{paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|(role, _)| *role == ResolvedPathRole::Write)
    );
}
