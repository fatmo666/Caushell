use caushell_graph::SessionGraph;
use caushell_passes::{
    DecisionAssemblyPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    ResolvePolicyPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView};
use caushell_types::*;

fn run(target: &str, command: &str, execution: bool) -> RunnerContext {
    let effect = if execution {
        "execute_payload"
    } else {
        "load_config"
    };
    let yaml = format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-config-runner}}
forms:
  - id: run
    parameters:
      - {{name: config, semantic: {{kind: plain_value}}, binding: {{kind: next_positional}}, cardinality: optional_one}}
    effects:
      - {{kind: {effect}, target: {target}}}
"#
    );
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&yaml).unwrap()])
            .unwrap();
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
    runner.register_session_analysis_pass(ResolvePolicyPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let mut ctx = RunnerContext::new(CheckRequest {
        session_id: SessionId::new("configured-payloads"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    });
    runner.run(
        SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
        &mut ctx,
    );
    ctx
}

#[test]
fn configured_execution_is_declarative_and_not_a_bundler_name_rule() {
    for (target, command, expected_path) in [
        (
            "{kind: configured_path, sources: [{slot: config, projection: {kind: identity}}], missing: unknown}",
            "arbitrary-config-runner ./definition",
            Some("/workspace/definition"),
        ),
        (
            "{kind: configured_path, sources: [{slot: config, projection: {kind: identity}}], missing: unknown}",
            "arbitrary-config-runner",
            None,
        ),
        (
            "{kind: tool_convention_path, path: settings, convention: arbitrary.executable_config}",
            "arbitrary-config-runner",
            Some("/workspace/settings"),
        ),
        (
            "{kind: tool_convention_path, path: /opt/settings, convention: arbitrary.executable_config}",
            "arbitrary-config-runner",
            Some("/opt/settings"),
        ),
        (
            "{kind: configured_path, sources: [], environment: {name: CODE_SOURCE, empty_is_unset: true}, missing: unknown}",
            "CODE_SOURCE=/tmp/EnvironmentFile arbitrary-config-runner",
            Some("/tmp/EnvironmentFile"),
        ),
    ] {
        let ctx = run(target, command, true);
        assert_eq!(
            ctx.final_decision,
            Some(Decision::NeedApproval),
            "{command}: {:?}",
            ctx.findings
        );
        assert_eq!(ctx.nested_payload_records().len(), 1);
        if let Some(path) = expected_path {
            assert!(ctx.evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::NestedPayloadUnresolved(u)
                if matches!(&u.context.origin, NestedPayloadOriginEvidence::ConfigDefinedTask {config_path, ..} if config_path == path)
                && u.unresolved_execution_payload_subtype == Some(UnresolvedExecutionPayloadSubtype::OpaqueNonShell))), "{command} {path}: {:?}", ctx.evidence);
        }
    }
}

#[test]
fn absent_optional_sources_and_passive_config_reads_are_not_code_execution() {
    let target = "{kind: configured_path, sources: [{slot: config, projection: {kind: identity}}], missing: skip}";
    let ctx = run(target, "arbitrary-config-runner", true);
    assert_eq!(ctx.final_decision, Some(Decision::Allow));
    assert!(ctx.nested_payload_records().is_empty());
    let ctx = run(target, "arbitrary-config-runner /opt/settings", false);
    assert_eq!(ctx.final_decision, Some(Decision::Allow));
    assert!(ctx.nested_payload_records().is_empty());
}

#[test]
fn configured_execution_keeps_filesystem_contract_validation() {
    for target in [
        "{kind: configured_path, sources: [], missing: incidental_cache, purpose: incidental_cache}",
        "{kind: configured_path, sources: [{slot: undeclared, projection: {kind: identity}}], missing: unknown}",
        "{kind: configured_path, sources: [], missing: unknown, fallback_parent_slots: [config]}",
    ] {
        let yaml = format!(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-config-runner}}
forms:
  - id: run
    parameters: [{{name: config, semantic: {{kind: plain_value}}, binding: {{kind: next_positional}}, cardinality: optional_one}}]
    effects: [{{kind: execute_payload, target: {target}}}]
"#
        );
        assert!(load_command_profile_from_str(&yaml).is_err(), "{target}");
    }
}
