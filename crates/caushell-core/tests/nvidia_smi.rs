use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, ResolveGapKind, ResolvedPathRole,
    RuleAction, RuleId, RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("nvidia-profile"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.to_string(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project".to_string()),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".to_string(),
            tool_name: Some("Bash".to_string()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".to_string()),
        workspace_root: Some("/tmp/project".to_string()),
    }
}

fn strict_coverage_core() -> ShellQueryCore {
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

#[test]
fn nvidia_smi_approved_hardware_calls_allow_even_with_strict_coverage_policy() {
    for command in [
        "nvidia-smi -i 0 -pl 200",
        "nvidia-smi --id=GPU-abcd --power-limit=200.5 --scope=0",
        "nvidia-smi -i 0 --gpu-reset",
        "nvidia-smi -r bus -i 0,1",
    ] {
        // Only the static analyser runs. No NVIDIA tool or GPU is accessed.
        let mut core = strict_coverage_core();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        let graph = core
            .session_graph(&SessionId::new("nvidia-profile"))
            .unwrap();
        assert!(
            !graph
                .nodes()
                .any(|n| matches!(n.kind, NodeKind::PathFact { .. })),
            "{command}"
        );
        assert!(
            !response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| matches!(p.rule_id, RuleId::NoProfile | RuleId::SelectionError)),
            "{command}: {response:?}"
        );
    }
}

#[test]
fn nvidia_smi_workspace_outputs_are_preserved_in_graph() {
    for command in [
        "nvidia-smi -q -f report.xml --debug=debug.log",
        "nvidia-smi --filename=report.xml --debug debug.log",
        "nvidia-smi -pl 200 -f report.xml --debug=debug.log",
        "nvidia-smi --gpu-reset --filename=report.xml --debug debug.log",
    ] {
        let mut core = strict_coverage_core();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        let mut writes: Vec<_> = core
            .session_graph(&SessionId::new("nvidia-profile"))
            .unwrap()
            .nodes()
            .filter_map(|node| match &node.kind {
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    resolution,
                    ..
                } => resolution.concrete_path(),
                _ => None,
            })
            .collect();
        writes.sort_unstable();
        assert_eq!(
            writes,
            ["/tmp/project/debug.log", "/tmp/project/report.xml"],
            "{command}"
        );
    }
}

#[test]
fn nvidia_smi_outside_and_unknown_outputs_still_require_approval() {
    for command in [
        "nvidia-smi -f /etc/report.xml",
        "nvidia-smi --filename=/etc/report.xml",
        "nvidia-smi --debug=/etc/debug.log",
        "nvidia-smi --debug /etc/debug.log",
        "nvidia-smi -pl 200 -f /etc/report.xml",
        "nvidia-smi --gpu-reset --debug=/etc/debug.log",
        "nvidia-smi -f \"$OUTPUT\"",
        "nvidia-smi --debug=\"$OUTPUT\"",
        "nvidia-smi replay -f input.log -r /etc/report.txt",
        "nvidia-smi replay -f input.log -r \"$OUTPUT\"",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:?}"
        );
    }
}

#[test]
fn nvidia_smi_replay_external_log_is_a_read_not_a_write() {
    let mut core = strict_coverage_core();
    let response = core.check(request(
        "nvidia-smi replay -f /var/log/nvstats/log -r report.txt",
    ));
    assert_eq!(response.decision, Decision::Allow, "{response:?}");
    let graph = core
        .session_graph(&SessionId::new("nvidia-profile"))
        .unwrap();
    let paths: Vec<_> = graph
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => resolution.concrete_path().map(|path| (*role, path)),
            _ => None,
        })
        .collect();
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/var/log/nvstats/log")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Write, "/tmp/project/report.txt")),
        "{paths:?}"
    );
    assert!(
        !paths.contains(&(ResolvedPathRole::Write, "/var/log/nvstats/log")),
        "{paths:?}"
    );
}

#[test]
fn nvidia_smi_queries_and_monitors_do_not_create_fake_mutation_facts() {
    for command in [
        "nvidia-smi -q -i 0 -l",
        "nvidia-smi --query-compute-apps=pid,used_memory --format=csv",
        "nvidia-smi dmon -i 0 -s pucm -c 1 -d 2",
        "nvidia-smi pmon -i 0 -s um -c 1 -d 2",
        "nvidia-smi topo -p2p r",
    ] {
        let mut core = strict_coverage_core();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        assert!(
            !core
                .session_graph(&SessionId::new("nvidia-profile"))
                .unwrap()
                .nodes()
                .any(|node| matches!(node.kind, NodeKind::PathFact { .. })),
            "{command}"
        );
    }
}

#[test]
fn nvidia_smi_help_does_not_create_output_writes() {
    for command in [
        "nvidia-smi --help",
        "nvidia-smi --version",
        "nvidia-smi --help-query-gpu",
        "nvidia-smi -h -f /etc/out",
        "nvidia-smi replay -h -r /etc/out",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        assert!(
            !core
                .session_graph(&SessionId::new("nvidia-profile"))
                .unwrap()
                .nodes()
                .any(|node| matches!(
                    node.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write,
                        ..
                    }
                )),
            "{command}"
        );
    }
}

#[test]
fn nvidia_smi_allow_scope_does_not_suppress_shell_composition_risks() {
    for command in [
        "nvidia-smi -pl 200 > /etc/report.txt",
        "nvidia-smi --gpu-reset; rm -f /etc/nvidia-test",
        "nvidia-smi -L && tee /etc/report.txt",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:?}"
        );
    }
    let response = ShellQueryCore::new().check(request("nvidia-smi --gpu-reset; rm -rf /"));
    assert_eq!(response.decision, Decision::Deny, "{response:?}");
}

#[test]
fn nvidia_smi_advanced_unmodeled_calls_do_not_gain_strict_coverage_allow() {
    for command in [
        "nvidia-smi -mig 1",
        "nvidia-smi --ecc-config=1",
        "nvidia-smi daemon",
    ] {
        let response = strict_coverage_core().check(request(command));
        assert_eq!(response.decision, Decision::Deny, "{command}: {response:?}");
    }
}
