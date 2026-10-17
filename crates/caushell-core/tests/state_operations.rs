//! Root-owned generic state semantics, Graph/Query and policy regressions.
use caushell_graph::SessionGraph;
use caushell_passes::{
    DecisionAssemblyPass, ExtractExecutionSemanticsPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass, StateOperationGuardPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_query::{ExecutionSemanticsQuery, QuerySession};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn yaml(domain: &str, operation: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: state-tool}}
forms:
  - id: run
    effects:
      - kind: state_operation
        state_operation: {{domain: {domain}, operation: {operation}}}
        target: {{kind: none}}
"#
    )
}

fn run(profile: &str, policy: PolicyConfig, expected: Decision) -> Vec<ExecutionSemanticsFact> {
    run_at(profile, policy, expected, 1)
}

fn run_at(
    profile: &str,
    policy: PolicyConfig,
    expected: Decision,
    sequence: u64,
) -> Vec<ExecutionSemanticsFact> {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(profile).unwrap()])
            .unwrap();
    let request = CheckRequest {
        session_id: SessionId::new("state-test"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: "state-tool".into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        workspace_root: Some("/workspace".into()),
        home: None,
        runtime: RuntimeMetadata {
            runtime_name: "static".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_session_analysis_pass(StateOperationGuardPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::with_policy(request, policy);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    assert_eq!(ctx.final_decision, Some(expected), "{:?}", ctx.findings);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    ExecutionSemanticsQuery::new()
        .execute(QuerySession::from_session(&staged))
        .semantics()
        .iter()
        .map(|s| s.to_execution_semantics_fact())
        .collect()
}

#[test]
fn schema_accepts_only_typed_state_effects_without_fake_filesystem_targets() {
    for domain in [
        "system_clock",
        "network_configuration",
        "host_identity",
        "connection_verification",
        "display_configuration",
        "container_runtime",
        "remote_resource",
        "print_service",
        "terminal_broadcast",
        "filesystem_mount",
        "service_manager",
        "cloud_resource",
        "remote_access",
        "shell_history",
    ] {
        for operation in ["inspect", "mutate", "control", "opaque"] {
            assert!(load_command_profile_from_str(&yaml(domain, operation)).is_ok());
        }
    }
    for invalid in [
        yaml("unknown", "mutate"),
        yaml("system_clock", "unknown"),
        yaml("system_clock", "mutate").replace(
            "target: {kind: none}",
            "target: {kind: slot, name: resource}",
        ),
        yaml("system_clock", "mutate").replace("kind: state_operation", "kind: write_path"),
        yaml("system_clock", "mutate").replace(
            "state_operation: {domain: system_clock, operation: mutate}",
            "",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn graph_query_preserves_state_classes_and_default_policy_ignores_workspace_membership() {
    for operation in ["inspect", "mutate", "control", "opaque"] {
        let expected = if operation == "inspect" {
            Decision::Allow
        } else {
            Decision::NeedApproval
        };
        let facts = run(
            &yaml("system_clock", operation),
            PolicyConfig::default(),
            expected,
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].state_operations.len(), 1);
        assert_eq!(
            facts[0].state_operations[0].domain,
            StateOperationDomain::SystemClock
        );
    }
}

#[test]
fn duplicate_effects_are_deduplicated_and_partial_selection_keeps_declared_state() {
    let duplicated = yaml("service_manager", "control")
        + "      - {kind: state_operation, state_operation: {domain: service_manager, operation: control}, target: {kind: none}}\n";
    let facts = run(&duplicated, PolicyConfig::default(), Decision::NeedApproval);
    assert_eq!(facts[0].state_operations.len(), 1);
    let partial = yaml("service_manager", "control").replace(
        "forms:\n  - id: run\n    effects:",
        "selection_failure_effects:",
    ) + "forms:\n  - id: unmatched\n    selector: {kind: has_flag, flag: '--unmatched'}\n";
    let facts = run(&partial, PolicyConfig::default(), Decision::NeedApproval);
    assert_eq!(
        facts[0].state_operations[0].operation,
        StateOperationKind::Control
    );
}

#[test]
fn state_family_and_rule_actions_follow_existing_policy_precedence() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.families.insert(
        RuleFamily::StateSafety,
        FamilyPolicy {
            action: RuleAction::Observe,
            trust_sets: vec![],
        },
    );
    run(
        &yaml("cloud_resource", "mutate"),
        policy.clone(),
        Decision::Allow,
    );
    policy.rule_policy.rules.insert(
        RuleId::StateMutation,
        RulePolicyEntry {
            action: RuleAction::Deny,
            trust_sets: vec![],
        },
    );
    run(&yaml("cloud_resource", "mutate"), policy, Decision::Deny);
}

#[test]
fn state_query_window_includes_zero_without_wrapping_sequence_bounds() {
    run_at(
        &yaml("system_clock", "mutate"),
        PolicyConfig::default(),
        Decision::NeedApproval,
        0,
    );
    run_at(
        &yaml("system_clock", "mutate"),
        PolicyConfig::default(),
        Decision::NeedApproval,
        u64::MAX,
    );
}

#[test]
fn state_policy_override_does_not_bypass_file_guards_or_leak_into_later_checks() {
    use caushell_core::ShellQueryCore;
    fn request(command: &str, sequence: u64) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("state-sequence"),
            sequence_no: CommandSequenceNo::new(sequence),
            command: command.into(),
            shell_kind: ShellKind::Bash,
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            workspace_root: Some("/workspace".into()),
            home: None,
            runtime: RuntimeMetadata {
                runtime_name: "static".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        }
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.families.insert(
        RuleFamily::StateSafety,
        FamilyPolicy {
            action: RuleAction::Observe,
            trust_sets: vec![],
        },
    );
    let mut core = ShellQueryCore::with_policy(policy);
    let response = core.check(request("date --set='2030-01-01'; rm /outside/file", 1));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    let response = core.check(request("printf ok", 2));
    assert_eq!(response.decision, Decision::Allow);
    assert!(!response.decision_trace.findings.iter().any(|p| matches!(
        p.rule_id,
        RuleId::StateMutation | RuleId::StateControl | RuleId::StateOpaqueOperation
    )));
    let response = ShellQueryCore::new().check(request("env date --set='2030-01-01'", 1));
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::StateMutation)
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|f| f.normalized_command_name == "date" && !f.state_operations.is_empty())
    );
}
