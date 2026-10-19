//! Static analysis only; the supplied shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("file-erasure"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn has(response: &CheckResponse, rule: RuleId) -> bool {
    response
        .decision_trace
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule)
}

#[test]
fn erasure_requires_approval_independently_of_path_and_wrapper() {
    for command in [
        "shred my-existing-file",
        "shred /workspace/file",
        "shred /tmp/file",
        "shred /private/tmp/file",
        "shred /opt/shared/file",
        "shred \"$TARGET\"",
        "shred -- -file",
        "shred -- --help",
        "shred -n0 -z file",
        "shred -zn0 file",
        "shred --iterations=1 file",
        "shred file --size=10",
        "shred -s10 - file",
        "shred -u file",
        "env shred file",
        "bash -c 'shred file'",
        "f(){ shred file; }; f",
        "find . -type f -exec shred {} +",
        "find . -print0 | xargs -0 shred",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            has(&response, RuleId::FileContentErasure),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn stdout_information_and_proven_zero_overwrites_are_not_file_erasure() {
    for command in [
        "shred --help",
        "shred --version",
        "shred --help file",
        "shred --version file",
        "shred -s10 -",
        "shred -s10 - > my-file",
        "shred -s10 - > /tmp/my-file",
        "shred -n0 file",
        "shred --iterations=00 file",
        "shred -s0 file",
        "shred -s0 -z file",
        "touch file",
        "printf data > file",
        "sed -i 's/x/y/' file",
        "mv old new",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            !has(&response, RuleId::FileContentErasure),
            "{command}: {response:#?}"
        );
    }
    let response = ShellQueryCore::new().check(request("shred -n0 -u file"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(has(&response, RuleId::FileDeletion));
    // --remove also truncates the file before unlinking, even with zero passes.
    assert!(has(&response, RuleId::FileContentErasure));
    let response = ShellQueryCore::new().check(request("shred -fn0 /opt/shared/file"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(!has(&response, RuleId::FileContentErasure));
}

#[test]
fn repeated_or_dynamic_options_cannot_prove_a_zero_overwrite() {
    for command in [
        "shred -n0 -n3 file",
        "shred -n3 -n0 file",
        "shred -s0 -s10 file",
        "shred -s10 -s0 file",
        "shred -n0 -n\"$N\" file",
        "shred -n\"$N\" file",
        "shred --unknown file",
        "shred -n file",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn erasure_policy_is_independent_from_deletion_and_other_guards() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let policy = caushell_config::load_config_from_str(&format!(
            "version: 1\npolicy:\n  rules:\n    file_content_erasure: {}\n",
            match action {
                RuleAction::Observe => "allow",
                RuleAction::NeedApproval => "need_approval",
                RuleAction::Deny => "deny",
            },
        ))
        .unwrap()
        .policy;
        let response = ShellQueryCore::with_policy(policy).check(request("shred file"));
        assert_eq!(response.decision, expected, "{response:#?}");
        assert!(has(&response, RuleId::FileContentErasure));
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::FileContentErasure,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    for command in ["shred -u file", "shred /opt/shared/file"] {
        let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
    let response = ShellQueryCore::with_policy(policy).check(request("shred /dev/sda"));
    assert_eq!(response.decision, Decision::Deny, "{response:#?}");
}

#[test]
fn a_custom_profile_gets_the_same_guard_without_a_reserved_command_name() {
    use caushell_graph::SessionGraph;
    use caushell_passes::{
        DecisionAssemblyPass, FileDeletionGuardPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::{PassRunner, RunnerContext, SessionView};

    let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_eraser}
forms:
  - id: erase
    parameters:
      - {name: files, semantic: {kind: path, role: write}, binding: {kind: remaining_positionals}, cardinality: required_many}
    effects:
      - kind: write_path
        target: {kind: slot, name: files}
        host_risk: {semantic_class: file_content_erasure_target}
"#).unwrap();
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::from_profiles(vec![profile]).unwrap(),
    ));
    runner.register_session_analysis_pass(FileDeletionGuardPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request("arbitrary_eraser file"));
    runner.run(SessionView::new(&graph, &summary), &mut context);
    assert_eq!(context.final_decision, Some(Decision::NeedApproval));
    assert!(
        context
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::FileContentErasure)
    );
}
