use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuleId, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("wrapper-scope"),
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

#[test]
fn wrapped_outside_mutations_reach_the_existing_guard() {
    // Only static Caushell checks: none of these commands are executed.
    for command in [
        "sshpass -e rm -f /etc/wrapper-test",
        "sshpass -p DUMMY rm -f /etc/wrapper-test",
        "sshpass -f pass.txt rm -f /etc/wrapper-test",
        "sshpass -d 3 rm -f /etc/wrapper-test",
        "sshpass -veCUSTOM -- rm -- /etc/wrapper-test",
        "env rm -f /etc/wrapper-test",
        "env --block-signal rm -f /etc/wrapper-test",
        "env --default-signal=PIPE rm -f /etc/wrapper-test",
        "nice -n 1 rm -f /etc/wrapper-test",
        "timeout -s TERM 2s rm -f /etc/wrapper-test",
        "timeout -f 2s rm -f /etc/wrapper-test",
        "env A=value timeout -k 1s 2s sshpass -e rm -f /etc/wrapper-test",
        "sshpass -e bash -c 'rm -f /etc/wrapper-test'",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.decision_trace
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {:?}",
            response.decision_trace.findings
        );
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(
                    |invocation| invocation.raw_text == "rm -f /etc/wrapper-test"
                        || invocation.raw_text == "rm -- /etc/wrapper-test"
                ),
            "{command}: {:?}",
            response.decision_trace.derived_invocations
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id.family() == caushell_types::RuleFamily::ResolveGap),
            "{command}: {:?}",
            response.decision_trace.findings
        );
    }
}

#[test]
fn workspace_mutations_keep_complete_child_argv_and_graph() {
    for command in [
        "sshpass -e rm -f local.txt",
        "sshpass -p DUMMY -- rm -- local.txt",
        "env timeout 2s sshpass -e rm -f local.txt",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.decision_trace.findings
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id.family() == caushell_types::RuleFamily::ResolveGap)
        );
        let graph = core
            .session_graph(&SessionId::new("wrapper-scope"))
            .unwrap();
        assert!(graph.nodes().any(|node| matches!(&node.kind, NodeKind::DerivedInvocation { command_name: Some(name), raw_text, .. } if name == "rm" && (raw_text == "rm -f local.txt" || raw_text == "rm -- local.txt"))), "{command}");
    }
}

#[test]
fn child_help_does_not_suppress_child_modelling() {
    let mut core = ShellQueryCore::new();
    let response = core.check(request("sshpass -e nice timeout 2s rm --help"));
    assert_eq!(response.decision, Decision::Allow);
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id.family() == caushell_types::RuleFamily::ResolveGap)
    );
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|invocation| invocation.raw_text == "rm --help")
    );
    let response = ShellQueryCore::new().check(request("sshpass -h rm -f /etc/wrapper-test"));
    assert_eq!(response.decision, Decision::Allow);
    assert!(response.decision_trace.derived_invocations.is_empty());
}

#[test]
fn deep_wrapper_chain_obeys_the_existing_configured_expansion_limit() {
    let command = "env A=value nice -n 1 timeout -k 1s 2s sshpass -e rm -f /etc/wrapper-test";
    let default_response = ShellQueryCore::new().check(request(command));
    assert_eq!(
        caushell_types::PolicyConfig::default()
            .semantic_expansion
            .max_nested_parse_depth,
        8
    );
    assert_eq!(default_response.decision, Decision::NeedApproval);
    assert_eq!(
        default_response
            .decision_trace
            .derived_invocations
            .iter()
            .map(|invocation| invocation.depth)
            .max(),
        Some(4)
    );
    assert!(
        default_response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|invocation| invocation.command_name.as_deref() == Some("rm"))
    );

    // A lower explicit limit must stop expansion and require approval rather
    // than silently treating the unanalysed mutation as safe.
    let mut policy = caushell_types::PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 3;
    let response = ShellQueryCore::try_with_policy(policy)
        .unwrap()
        .check(request(command));
    assert_eq!(
        response.decision,
        Decision::NeedApproval,
        "{:?}",
        response.decision_trace
    );
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|proposal| proposal.rule_id == RuleId::ExecutionExpansionLimit)
    );
    assert!(
        !response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|invocation| invocation.command_name.as_deref() == Some("rm"))
    );
}
