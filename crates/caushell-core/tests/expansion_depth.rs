use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, EvidenceKind, PolicyConfig, RuleId, RuntimeMetadata,
    SessionId, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("expansion-depth"),
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

fn wrapped(depth: usize, leaf: &str) -> String {
    format!("{}{}", "env ".repeat(depth), leaf)
}

fn has_limit(response: &caushell_types::CheckResponse) -> bool {
    response
        .decision_trace
        .decision_proposals
        .iter()
        .any(|proposal| proposal.rule_id == RuleId::ExecutionExpansionLimit)
}

#[test]
fn default_budget_analyses_eight_levels_without_approving_a_leaf_at_the_limit() {
    assert_eq!(
        PolicyConfig::default()
            .semantic_expansion
            .max_nested_parse_depth,
        8
    );
    for depth in [0, 3, 4, 6, 8] {
        let response = ShellQueryCore::new().check(request(&wrapped(depth, "echo ok")));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "depth {depth}: {response:?}"
        );
        assert!(!has_limit(&response), "depth {depth}: {response:?}");
        if depth > 0 {
            assert!(
                response
                    .decision_trace
                    .derived_invocations
                    .iter()
                    .any(|invocation| {
                        invocation.raw_text == "echo ok" && invocation.depth as usize == depth
                    }),
                "depth {depth}: {response:?}"
            );
        }
    }
}

#[test]
fn pending_child_above_default_budget_requires_approval_and_is_not_projected() {
    for depth in [9, 20] {
        // All tests call the static analyser only. No shell command is executed.
        let response = ShellQueryCore::new().check(request(&wrapped(depth, "rm -f local.txt")));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
        assert!(has_limit(&response), "{response:?}");
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .all(|invocation| invocation.depth <= 8)
        );
        assert!(
            !response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|invocation| invocation.command_name.as_deref() == Some("rm"))
        );
        assert!(response.decision_trace.evidence.iter().any(|evidence| matches!(
            &evidence.kind,
            EvidenceKind::ExecutionExpansionTruncated(truncated)
                if truncated.depth == 8 && truncated.max_depth == 8 && truncated.next_candidate_count > 0
        )), "{response:?}");
    }
}

#[test]
fn explicit_lower_budget_approves_only_incomplete_chains() {
    for depth in [0, 1, 3, 6] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = depth;
        let core = || ShellQueryCore::try_with_policy(policy.clone()).unwrap();
        let leaf = core().check(request(&wrapped(depth as usize, "echo ok")));
        assert_eq!(leaf.decision, Decision::Allow, "limit {depth}: {leaf:?}");
        assert!(!has_limit(&leaf));
        let pending = core().check(request(&wrapped(depth as usize + 1, "echo ok")));
        assert_eq!(
            pending.decision,
            Decision::NeedApproval,
            "limit {depth}: {pending:?}"
        );
        assert!(has_limit(&pending));
    }
}

#[test]
fn fully_analysed_outside_mutation_uses_the_real_risk_rule_not_the_budget_rule() {
    let response = ShellQueryCore::new().check(request(&wrapped(8, "rm -f /etc/depth-test")));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    assert!(!has_limit(&response));
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}

#[test]
fn shell_payload_truncation_is_not_suppressed_by_a_parsed_ancestor() {
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 1;
    let response = ShellQueryCore::try_with_policy(policy)
        .unwrap()
        .check(request(r#"bash -c 'sh -c "echo ok"'"#));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    assert!(has_limit(&response));
    assert!(
        response
            .decision_trace
            .evidence
            .iter()
            .any(|evidence| matches!(evidence.kind, EvidenceKind::NestedPayloadTruncated(_)))
    );
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .all(|invocation| invocation.depth <= 1)
    );
}

#[test]
fn shell_payload_at_a_wrapper_boundary_requires_approval() {
    let response = ShellQueryCore::new().check(request(&wrapped(8, "bash -c 'echo ok'")));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    assert!(has_limit(&response));
    assert!(
        !response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|invocation| invocation.raw_text == "echo ok")
    );
}

#[test]
fn pending_find_and_xargs_children_use_the_same_budget_rule() {
    for leaf in [
        "find . -exec echo '{}' ';'",
        "xargs echo",
        "xargs -r echo",
        "echo $(echo inner)",
        "cat <(echo inner)",
    ] {
        let command = wrapped(8, leaf);
        let response = ShellQueryCore::new().check(request(&command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
        assert!(has_limit(&response), "{command}: {response:?}");
    }
}

#[test]
fn empty_shell_payload_and_help_are_not_pending_execution() {
    for leaf in ["bash -c ''", "rm --help", "sshpass -h"] {
        let command = wrapped(8, leaf);
        let response = ShellQueryCore::new().check(request(&command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        assert!(!has_limit(&response), "{command}: {response:?}");
    }
}

#[test]
fn unknown_child_executable_at_the_boundary_cannot_silently_disappear() {
    let response = ShellQueryCore::new().check(request(&wrapped(8, "env \"$UNKNOWN_COMMAND\"")));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    assert!(has_limit(&response), "{response:?}");
}

#[test]
fn a_known_deny_still_wins_over_an_incomplete_chain() {
    let command = format!("rm -rf /; {}", wrapped(9, "echo ok"));
    let response = ShellQueryCore::new().check(request(&command));
    assert_eq!(response.decision, Decision::Deny, "{response:?}");
    assert!(has_limit(&response));
}
