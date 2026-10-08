//! Static analyser only. No find, shell payload, or deletion is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ExtractValueProvenancePass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("implicit-payload"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn find_substitution_into_program_text_requires_approval_with_correct_source() {
    for command in [
        r"find . -exec sh -c 'echo {}' \;",
        r"find . -exec bash -c 'echo {}' \;",
        r"find . -execdir sh -c 'echo {}' \;",
        r#"find . -exec sh -c 'echo "{}"' \;"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(result.decision_trace.evidence.iter().any(|e| matches!(
            &e.kind, EvidenceKind::NestedPayloadUnresolved(u)
            if matches!(u.reason, NestedPayloadUnresolvedReasonEvidence::RequiresImplicitInput { source: ImplicitInputSource::DispatchOutput })
                && u.unresolved_execution_payload_subtype == Some(UnresolvedExecutionPayloadSubtype::DynamicInlinePayload)
        )), "{result:?}");
        assert!(
            result
                .decision_trace
                .nested_payloads
                .iter()
                .any(|n| matches!(
                    n.input,
                    NestedPayloadInput::ImplicitInput {
                        source: ImplicitInputSource::DispatchOutput
                    }
                ) && n.resolution.kind
                    == NestedPayloadResolutionKind::RequiresImplicitInput
                    && n.resolution.runtime_input_source.is_none()),
            "{result:?}"
        );
    }
}

#[test]
fn fixed_program_and_unknown_data_are_not_blanket_approved_or_blocked() {
    for command in [
        r#"find . -exec sh -c 'echo "$1"' _ {} \;"#,
        r#"find . -exec bash -c 'echo "$1"' _ {} \;"#,
        r#"find . -execdir sh -c 'echo "$1"' _ {} \;"#,
        r"find . -exec echo {} \;",
        r"find . -exec sh -c 'echo fixed' \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(!result.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::NestedPayloadUnresolved(u)
            if matches!(u.reason, NestedPayloadUnresolvedReasonEvidence::RequiresImplicitInput { .. })
        )), "{result:?}");
    }
}

#[test]
fn known_nested_mutation_is_not_lost_while_another_program_is_unknown() {
    let result = ShellQueryCore::new().check(request(
        r"find . -exec sh -c 'echo {}' \; -exec sh -c 'rm /opt/shared/file' \;",
    ));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
    assert!(
        result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
        "{result:?}"
    );
}

#[test]
fn depth_boundary_preserves_deferred_source_without_panicking() {
    for depth in [0, 1, 2, 8] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = depth;
        let result =
            ShellQueryCore::with_policy(policy).check(request(r"find . -exec sh -c 'echo {}' \;"));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "depth {depth}: {result:?}"
        );
    }
}

#[test]
fn graph_and_value_provenance_retain_dispatch_source_and_unknown_state() {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ExtractValueProvenancePass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(r"find . -exec sh -c 'echo {}' \;"));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    assert!(staged.graph().nodes().any(|n| matches!(&n.kind,
        NodeKind::NestedPayload { input_source: Some(ImplicitInputSource::DispatchOutput), resolution_kind, resolution_runtime_input_source: None, .. }
        if resolution_kind == "requires_implicit_input"
    )));
    assert!(staged.graph().nodes().any(|n| matches!(&n.kind,
        NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::MaterializedValue {
            source_kind, state: ProvenanceMaterializedValueState::RequiresImplicitInput { source: ImplicitInputSource::DispatchOutput }, ..
        } } if source_kind == "implicit_input:dispatch_output"
    )));
    assert!(staged.graph().nodes().any(|n| matches!(&n.kind,
        NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::MaterializedValue {
            state: ProvenanceMaterializedValueState::RequiresImplicitInput { source: ImplicitInputSource::DispatchOutput }, ..
        } }
    ) && staged.graph().incoming_edges(&n.id).any(|edge| matches!(&edge.semantics,
        Some(ProvenanceEdgeSemantics::Produce { slot_name: Some(slot), .. }) if slot == "payload"
    ))));
}

#[test]
fn runtime_stdin_evidence_keeps_original_type_and_policy() {
    let result = ShellQueryCore::new().check(request("sh -s"));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
    assert!(result.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
        EvidenceKind::NestedPayloadUnresolved(u)
        if matches!(u.reason, NestedPayloadUnresolvedReasonEvidence::RequiresRuntimeInput { source: RuntimeInputSource::StdinPayload })
    )), "{result:?}");
}

#[test]
fn another_dispatch_carrier_uses_the_same_unknown_source_contract() {
    for command in [r"env find . -exec sh -c 'echo {}' \;"] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(result.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::TaintedExecutionUnresolvedOrigin(u)
            if matches!(u.reason, TaintedExecutionUnresolvedReasonEvidence::RequiresImplicitInput { source: ImplicitInputSource::DispatchOutput })
        )), "{command}: {result:?}");
    }
}

#[test]
fn profile_declared_non_stream_sources_use_existing_unresolved_policy() {
    for source in ["dispatch_output", "inherited_environment"] {
        let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: source-fixture}
forms:
  - id: run
    implicit_inputs:
      - source: inherited_environment
        semantic: {kind: payload, language: sh, source: inline_string, recursive: true}
    effects:
      - {kind: execute_payload, target: {kind: implicit_input, source: inherited_environment}}
"#;
        let mut profile = caushell_profile::load_command_profile_from_str(yaml).unwrap();
        // DispatchOutput is intentionally internal, not a user-authored DSL
        // input. Exercise its shared model without widening the DSL schema.
        let implicit_source = if source == "dispatch_output" {
            caushell_profile::ImplicitInputSource::DispatchOutput
        } else {
            caushell_profile::ImplicitInputSource::InheritedEnvironment
        };
        profile.forms[0].implicit_inputs[0].source = implicit_source;
        profile.forms[0].effects[0].target =
            caushell_profile::EffectTarget::ImplicitInput(implicit_source);
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_request_analysis_pass(caushell_passes::ResolvePolicyPass);
        runner.register_final_decision_pass(caushell_passes::DecisionAssemblyPass);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request("source-fixture"));
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        assert_eq!(
            ctx.final_decision,
            Some(Decision::NeedApproval),
            "{source}: {:?}",
            ctx.evidence
        );
        let expected = if source == "dispatch_output" {
            ImplicitInputSource::DispatchOutput
        } else {
            ImplicitInputSource::InheritedEnvironment
        };
        assert!(ctx.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::NestedPayloadUnresolved(u)
            if matches!(u.reason, NestedPayloadUnresolvedReasonEvidence::RequiresImplicitInput { source } if source == expected)
        )));
    }
}

#[test]
fn exact_dispatch_input_still_materializes_and_allows_a_known_program() {
    let result = ShellQueryCore::new().check(request(r"printf one | xargs -I@ sh -c 'echo @'"));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
    assert!(
        result
            .decision_trace
            .derived_invocations
            .iter()
            .any(|i| i.raw_text == "echo one"),
        "{result:?}"
    );
}

#[test]
fn xargs_unknown_replacement_in_program_text_is_not_a_known_empty_program() {
    for command in [
        r"find . -name *.so -print0 | xargs -0 -I % sh -c 'echo %'",
        r"find . -name *.so -print0 | xargs -0 -I % bash -c 'echo %'",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(result.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::TaintedExecutionUnresolvedOrigin(u)
            if matches!(u.reason, TaintedExecutionUnresolvedReasonEvidence::RequiresRuntimeInput {
                source: RuntimeInputSource::StdinData
            })
        )), "{result:?}");
    }
    let result = ShellQueryCore::new().check(request(
        r#"find . -name *.so -print0 | xargs -0 sh -c 'echo "$1"' _"#,
    ));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
}

#[test]
fn xargs_child_options_cannot_become_parent_confirmation_or_batching_flags() {
    for command in [
        r"find . -name *.jpg -print0 | xargs -0 -I {} mkdir -p /opt/shared/{}",
        r"find . -name *.jpg -print0 | xargs -0 -I ‘{}’ mkdir -p /opt/shared/{}",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .derived_invocations
                .iter()
                .any(|i| i.command_name.as_deref() == Some("mkdir")),
            "{result:?}"
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{result:?}"
        );
    }
    let result = ShellQueryCore::new().check(request(
        r"find . -name *.jpg -print0 | xargs -0 -I ‘{}’ mkdir -p ./cache/{}",
    ));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
}

#[test]
fn xargs_optional_inline_operands_preserve_the_child_command_boundary() {
    for command in [
        r"printf 'one\n' | xargs -i echo {}",
        r"printf 'one\n' | xargs -ti@ echo @",
        r"printf 'one\n' | xargs --replace=@ echo @",
        r"printf 'one\n' | xargs --replace echo {}",
        r"printf 'one\n' | xargs -e echo",
        r"printf 'one\n' | xargs -l echo",
        r"printf 'one\n' | xargs -l2 echo",
        r"printf 'one\n' | xargs -P2 -s1000 -t echo",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(
            result
                .decision_trace
                .derived_invocations
                .iter()
                .any(|i| i.raw_text == "echo one"),
            "{command}: {result:?}"
        );
    }
    for command in ["xargs -I", "xargs -L", "xargs -o sh", "xargs -J X echo X"] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
    }
}
