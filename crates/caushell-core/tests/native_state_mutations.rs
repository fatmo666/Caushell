//! Static decisions and staged Graph checks, never native command execution.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("native-state"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    r
}

#[test]
fn known_queries_and_bsd_non_setting_conversion_remain_allowed() {
    for c in [
        "ifconfig",
        "ifconfig -a",
        "ifconfig -s eth0",
        "ifconfig eth0",
        "ifconfig eth0 inet",
        "ifconfig -l",
        "hostname",
        "hostname -f",
        "hostname -I",
        "hostname -s",
        "hostname --all-ip-addresses",
        "hostname --all-ip-address",
        "date",
        "date +%Y",
        "date -u +%Y",
        "date -d 010100001971 +%s",
        "date -f ./dates.txt +%Y",
        "date -r ./file +%s",
        "date -Iseconds",
        "date -v+1d",
        "date -j 010100001971",
        "date -j -f %Y%m%d 20260101 +%s",
        "arp -an",
        "arp -i eth0 192.0.2.1",
        "ifconfig --help eth0 down",
        "hostname --help -F /etc/hostname",
        "date --help --set 1971-01-01",
        "arp --help -f ./entries",
    ] {
        check(c, Decision::Allow);
    }
}

#[test]
fn system_mutations_have_typed_state_proposals_not_fake_filesystem_writes() {
    for (c, domain) in [
        (
            "ifconfig eth0 down",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "ifconfig eth0 up",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "ifconfig eth0 hw ether 00:80:48:BA:d1:30",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "ifconfig eth0 -arp",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "ifconfig eth0 192.0.2.1 netmask 255.255.255.0",
            StateOperationDomain::NetworkConfiguration,
        ),
        ("hostname buildbox", StateOperationDomain::HostIdentity),
        ("hostname -s buildbox", StateOperationDomain::HostIdentity),
        ("hostname -F ./name", StateOperationDomain::HostIdentity),
        ("hostname -b", StateOperationDomain::HostIdentity),
        ("date 010100001971", StateOperationDomain::SystemClock),
        ("date --set 1971-01-01", StateOperationDomain::SystemClock),
        ("date -f %Y%m%d 20260101", StateOperationDomain::SystemClock),
        (
            "arp -f ./entries",
            StateOperationDomain::NetworkConfiguration,
        ),
        ("arp -f", StateOperationDomain::NetworkConfiguration),
        (
            "arp -s 192.0.2.1 00:80:48:ba:d1:30",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "arp -d 192.0.2.1",
            StateOperationDomain::NetworkConfiguration,
        ),
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::StateMutation),
            "{c}: {r:#?}"
        );
        assert!(
            r.decision_trace.execution_semantics.iter().any(|s| s
                .state_operations
                .iter()
                .any(|op| op.domain == domain && op.operation == StateOperationKind::Mutate)),
            "{c}: {r:#?}"
        );
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
}

#[test]
fn wrappers_nested_shells_substitutions_and_pipelines_preserve_state_effects() {
    for c in [
        "env ifconfig eth0 down",
        "timeout 2s hostname buildbox",
        "bash -c 'date 010100001971'",
        "echo $(hostname buildbox)",
        "ifconfig eth0 down | cat",
        "watch -n1 ifconfig eth0 down",
        "watch -x hostname buildbox",
        "find . -type f -exec arp -f {} \\;",
        "find . -type f -print0 | xargs -0 arp -f",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::StateMutation),
            "{c}: {r:#?}"
        );
    }
}

#[test]
fn unknown_forms_and_argv_expansion_cannot_borrow_query_classification() {
    for c in [
        "ifconfig $ARGS",
        "ifconfig eth0 \"$OP\"",
        "hostname \"$NAME\"",
        "date \"$OPERAND\"",
        "date $ARGS",
        "arp -f \"$FILE\"",
        "arp \"$ARGS\"",
        "arp -s -a 192.0.2.1",
        "arp -f -d 192.0.2.1",
        "ifconfig --future",
        "hostname --future",
        "date --future",
        "arp --future",
    ] {
        check(c, Decision::NeedApproval);
    }
    check("date +\"$FORMAT\"", Decision::Allow);
}

#[test]
fn existing_state_policy_override_and_independent_deny_keep_precedence() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::StateMutation,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    for c in [
        "ifconfig eth0 down",
        "hostname buildbox",
        "date 010100001971",
        "arp -f ./entries",
    ] {
        assert_eq!(
            ShellQueryCore::with_policy(policy.clone())
                .check(request(c))
                .decision,
            Decision::Allow,
            "{c}"
        );
    }
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("hostname buildbox; rm -rf /"))
            .decision,
        Decision::Deny
    );
    policy.rule_policy.rules.insert(
        RuleId::StateMutation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("arp -f ./entries"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn graph_query_retains_state_and_input_file_roles() {
    use caushell_graph::{NodeKind, SessionGraph, SessionRead};
    use caushell_passes::{
        ComputeEffectiveCwdPass, ExtractExecutionSemanticsPass, ExtractPathFactsPass,
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_profile::ProfileRegistry;
    use caushell_query::{ExecutionSemanticsQuery, QuerySession};
    use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
    for (c, path, domain) in [
        (
            "arp -f",
            "/etc/ethers",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "arp -f ./entries",
            "/workspace/project/entries",
            StateOperationDomain::NetworkConfiguration,
        ),
        (
            "hostname -F ./name",
            "/workspace/project/name",
            StateOperationDomain::HostIdentity,
        ),
    ] {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request(c));
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
        assert!(staged.graph().nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution, role: ResolvedPathRole::Read, ..} if resolution.concrete_path() == Some(path))), "{c}");
        assert!(
            !staged.graph().nodes().any(|n| matches!(
                &n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    ..
                }
            )),
            "{c}"
        );
        assert!(
            ExecutionSemanticsQuery::new()
                .execute(QuerySession::from_session(&staged))
                .semantics()
                .iter()
                .any(|s| s.state_operations().iter().any(|op| op.domain == domain)),
            "{c}"
        );
    }
}
