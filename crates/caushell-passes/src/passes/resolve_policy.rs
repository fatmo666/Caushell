use caushell_profile::ResolveInvocationArtifactResult;
use caushell_runner::{RequestAnalysisPass, RunnerContext};
use std::collections::BTreeSet;

use caushell_types::{
    Decision, EvidenceKind, RuleAction, RuleId, UnresolvedExecutionPayloadSubtype,
};

pub struct ResolvePolicyPass;

impl RequestAnalysisPass for ResolvePolicyPass {
    fn name(&self) -> &'static str {
        "resolve_policy"
    }

    fn run(&self, ctx: &mut RunnerContext) {
        let mut escalations: Vec<(RuleId, RuleAction, String)> = {
            let policy = &ctx.policy().rule_policy;

            ctx.execution_unit_resolve_records()
                .iter()
                .filter_map(|record| match &record.result {
                    ResolveInvocationArtifactResult::MissingCommandName { gap_kind } => Some((
                        RuleId::MissingCommandName,
                        policy.action_for_resolve_gap(*gap_kind),
                        missing_command_name_reason(record),
                    )),
                    ResolveInvocationArtifactResult::NoProfile {
                        normalized_command_name,
                        gap_kind,
                    } => Some((
                        RuleId::NoProfile,
                        action_for_no_profile_gap(policy, normalized_command_name, *gap_kind),
                        format!(
                            "command {} has no registered profile",
                            normalized_command_name
                        ),
                    )),
                    ResolveInvocationArtifactResult::SelectionError {
                        normalized_command_name,
                        gap_kind,
                        error,
                        ..
                    } => Some((
                        RuleId::SelectionError,
                        policy.action_for_resolve_gap(*gap_kind),
                        format!(
                            "command {} matched a profile but invocation selection failed: {}",
                            normalized_command_name, error
                        ),
                    )),
                    ResolveInvocationArtifactResult::Resolved(_) => None,
                })
                .collect()
        };

        for (evidence, action) in
            unresolved_execution_payload_evidence(ctx).filter_map(|evidence| {
                unresolved_execution_payload_action(&ctx.policy().rule_policy, evidence)
                    .map(|action| (evidence, action))
            })
        {
            escalations.push((
                RuleId::NestedPayloadExpansion,
                action,
                format!(
                    "execution payload could not be resolved: {}",
                    evidence.summary
                ),
            ));
        }

        let unresolved_wrapper_action = ctx
            .policy()
            .rule_policy
            .action_for_resolve_gap(caushell_types::ResolveGapKind::UnresolvedWrapperChild);
        if decision_for_rule_action(unresolved_wrapper_action).is_some() {
            for record in ctx.unresolved_dispatch_records() {
                escalations.push((
                    RuleId::SelectionError,
                    unresolved_wrapper_action,
                    format!(
                        "wrapper child command in slot {} at parsed index {} could not be resolved into a singular dispatched command",
                        record.command_slot, record.command_ref.command_index
                    ),
                ));
            }
        }

        for (rule_id, action, reason) in escalations {
            propose_gap_escalation(ctx, self.name(), rule_id, action, reason);
        }
    }
}

fn propose_gap_escalation(
    ctx: &mut RunnerContext,
    pass_name: &str,
    rule_id: RuleId,
    action: RuleAction,
    reason: String,
) {
    let Some(decision) = decision_for_rule_action(action) else {
        return;
    };

    ctx.propose_decision(pass_name, rule_id, decision, reason);
}

fn decision_for_rule_action(action: RuleAction) -> Option<Decision> {
    match action {
        RuleAction::Observe => None,
        RuleAction::NeedApproval => Some(Decision::NeedApproval),
        RuleAction::Deny => Some(Decision::Deny),
    }
}

fn action_for_no_profile_gap(
    policy: &caushell_types::RulePolicy,
    normalized_command_name: &str,
    gap_kind: caushell_types::ResolveGapKind,
) -> RuleAction {
    policy
        .no_profile
        .commands
        .get(normalized_command_name)
        .copied()
        .unwrap_or_else(|| {
            if policy.no_profile.action != RuleAction::Observe {
                policy.no_profile.action
            } else {
                policy.action_for_resolve_gap(gap_kind)
            }
        })
}

fn missing_command_name_reason(record: &caushell_runner::ExecutionUnitResolveRecord) -> String {
    format!(
        "command at parsed index {} is missing command_name and cannot be resolved semantically",
        record.command_ref.command_index
    )
}

fn unresolved_execution_payload_evidence(
    ctx: &RunnerContext,
) -> impl Iterator<Item = &caushell_types::Evidence> {
    let resolved_execution_payloads: BTreeSet<(usize, String)> = ctx
        .evidence
        .iter()
        .filter_map(|evidence| match &evidence.kind {
            EvidenceKind::NestedPayloadParsed(parsed)
                if matches!(
                    parsed.context.origin,
                    caushell_types::NestedPayloadOriginEvidence::Parameter { .. }
                        | caushell_types::NestedPayloadOriginEvidence::FormImplicitInput
                ) =>
            {
                Some((
                    parsed.context.root_command_index,
                    nested_payload_origin_key(&parsed.context.origin),
                ))
            }
            _ => None,
        })
        .collect();

    ctx.evidence
        .iter()
        .filter(move |evidence| match &evidence.kind {
            EvidenceKind::NestedPayloadUnresolved(unresolved)
                if evidence.rule_id == RuleId::NestedPayloadExpansion
                    && matches!(
                        unresolved.context.origin,
                        caushell_types::NestedPayloadOriginEvidence::Parameter { .. }
                            | caushell_types::NestedPayloadOriginEvidence::FormImplicitInput
                    ) =>
            {
                !resolved_execution_payloads.contains(&(
                    unresolved.context.root_command_index,
                    nested_payload_origin_key(&unresolved.context.origin),
                ))
            }
            _ => false,
        })
}

fn unresolved_execution_payload_action(
    policy: &caushell_types::RulePolicy,
    evidence: &caushell_types::Evidence,
) -> Option<RuleAction> {
    let EvidenceKind::NestedPayloadUnresolved(unresolved) = &evidence.kind else {
        return None;
    };

    let action = unresolved
        .unresolved_execution_payload_subtype
        .map(|subtype| policy.action_for_unresolved_execution_payload_subtype(subtype))
        .unwrap_or_else(|| {
            policy.action_for_unresolved_execution_payload_subtype(
                UnresolvedExecutionPayloadSubtype::UnknownPayloadShape,
            )
        });

    decision_for_rule_action(action).map(|_| action)
}

fn nested_payload_origin_key(origin: &caushell_types::NestedPayloadOriginEvidence) -> String {
    match origin {
        caushell_types::NestedPayloadOriginEvidence::Parameter { slot_name } => {
            format!("parameter:{slot_name}")
        }
        caushell_types::NestedPayloadOriginEvidence::FormImplicitInput => {
            "form_implicit_input".to_string()
        }
        caushell_types::NestedPayloadOriginEvidence::ConfigDefinedTask {
            config_path,
            task_name,
        } => format!("config_defined_task:{config_path}:{task_name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::ResolvePolicyPass;
    use caushell_graph::NodeId;
    use caushell_graph::SessionGraph;
    use caushell_parse::SourceSpan;
    use caushell_profile::{BindError, ResolveInvocationArtifactResult};
    use caushell_runner::{
        ExecutionUnitInheritedScope, ExecutionUnitOriginKind, ExecutionUnitOriginLocator,
        ExecutionUnitResolveRecord, ParsedCommandRef, PassRunner, RunnerContext, SessionView,
        UnresolvedDispatchRecord,
    };
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, Evidence, NestedPayloadContextEvidence,
        NestedPayloadInputEvidence, NestedPayloadLanguageEvidence, NestedPayloadOriginEvidence,
        NestedPayloadParentEvidence, NestedPayloadSourceEvidence,
        NestedPayloadUnresolvedReasonEvidence, NoProfilePolicy, PolicyConfig, ResolveGapKind,
        ResolveGapPolicy, RuleAction, RuleId, RulePolicy, RuntimeMetadata, SessionId,
        SessionSummary, ShellKind, UnresolvedExecutionPayloadSubtype,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn empty_span() -> SourceSpan {
        SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            start_column: 0,
            end_row: 0,
            end_column: 0,
        }
    }

    fn empty_parsed_scope() -> caushell_parse::ParsedCommandArtifact {
        caushell_parse::ParsedCommandArtifact {
            raw_command: String::new(),
            shell_kind: ShellKind::Bash,
            commands: Vec::new(),
            status: caushell_parse::ParseStatus::Complete,
            declaration_commands: Vec::new(),
            assignment_commands: Vec::new(),
            unset_commands: Vec::new(),
            function_definitions: Vec::new(),
            redirections: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn run_pass(
        policy: PolicyConfig,
        records: Vec<ExecutionUnitResolveRecord>,
        unresolved_dispatch_records: Vec<UnresolvedDispatchRecord>,
        evidence: Vec<Evidence>,
        command: &str,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_analysis_pass(ResolvePolicyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::with_policy(sample_request(command), policy);
        ctx.set_execution_unit_resolve_records(records);
        ctx.set_unresolved_dispatch_records(unresolved_dispatch_records);
        for item in evidence {
            ctx.add_evidence(item);
        }

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn execution_unit_record(
        source_node_id: &str,
        command_index: usize,
        result: ResolveInvocationArtifactResult,
    ) -> ExecutionUnitResolveRecord {
        ExecutionUnitResolveRecord {
            source_node_id: NodeId::new(source_node_id),
            command_ref: ParsedCommandRef::new(command_index, empty_span()),
            parsed_scope: empty_parsed_scope(),
            rendered_command_text: String::new(),
            result,
            shell_kind: ShellKind::Bash,
            root_command_index: command_index,
            depth: 0,
            parent_execution_node_id: NodeId::new(source_node_id),
            bindings: caushell_profile::SessionBindings::default(),
            origin_kind: ExecutionUnitOriginKind::TopLevel,
            origin_index: command_index,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        }
    }

    #[test]
    fn resolve_policy_pass_ignores_no_profile_under_default_policy() {
        let ctx = run_pass(
            PolicyConfig::default(),
            vec![execution_unit_record(
                "command:sess-1:1:0",
                0,
                ResolveInvocationArtifactResult::NoProfile {
                    normalized_command_name: "unknown-tool".to_string(),
                    gap_kind: ResolveGapKind::NoProfile,
                },
            )],
            Vec::new(),
            Vec::new(),
            "unknown-tool --help",
        );

        assert_eq!(ctx.executed_passes, vec!["resolve_policy".to_string()]);
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn resolve_policy_pass_applies_command_specific_no_profile_override() {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.no_profile = NoProfilePolicy {
            action: RuleAction::Observe,
            commands: std::collections::BTreeMap::from([("sudo".to_string(), RuleAction::Deny)]),
        };

        let ctx = run_pass(
            policy,
            vec![execution_unit_record(
                "command:sess-1:1:0",
                0,
                ResolveInvocationArtifactResult::NoProfile {
                    normalized_command_name: "sudo".to_string(),
                    gap_kind: ResolveGapKind::NoProfile,
                },
            )],
            Vec::new(),
            Vec::new(),
            "sudo whoami",
        );

        assert_eq!(ctx.decision_proposals[0].decision, Decision::Deny);
        assert_eq!(ctx.decision_proposals[0].rule_id, RuleId::NoProfile);
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "command sudo has no registered profile"
        );
    }

    #[test]
    fn resolve_policy_pass_escalates_missing_command_name() {
        let ctx = run_pass(
            PolicyConfig::default(),
            vec![execution_unit_record(
                "command:sess-1:1:0",
                2,
                ResolveInvocationArtifactResult::MissingCommandName {
                    gap_kind: ResolveGapKind::MissingCommandName,
                },
            )],
            Vec::new(),
            Vec::new(),
            "$USER_CMD",
        );

        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::MissingCommandName
        );
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "command at parsed index 2 is missing command_name and cannot be resolved semantically"
        );
    }

    #[test]
    fn resolve_policy_pass_escalates_selection_error_per_policy() {
        let ctx = run_pass(
            PolicyConfig {
                rule_policy: RulePolicy {
                    resolve_gap: ResolveGapPolicy {
                        defaults: std::collections::BTreeMap::from([(
                            ResolveGapKind::FormSelectionAmbiguous,
                            RuleAction::Deny,
                        )]),
                        unresolved_execution_payload_subtypes: std::collections::BTreeMap::new(),
                    },
                    ..RulePolicy::default()
                },
                semantic_expansion: caushell_types::SemanticExpansionPolicy::default(),
                runtime_taint: caushell_types::RuntimeTaintPolicy::default(),
                path_trust_sets: std::collections::BTreeMap::new(),
            },
            vec![execution_unit_record(
                "command:sess-1:1:0",
                0,
                ResolveInvocationArtifactResult::SelectionError {
                    normalized_command_name: "bash".to_string(),
                    gap_kind: ResolveGapKind::FormSelectionAmbiguous,
                    error: BindError::MultipleFormsMatched {
                        command_name: "bash".to_string(),
                        form_ids: vec![
                            "stdin_script_implicit".to_string(),
                            "interactive".to_string(),
                        ],
                    },
                    partial_bound: None,
                },
            )],
            Vec::new(),
            Vec::new(),
            "bash",
        );

        assert_eq!(ctx.decision_proposals[0].decision, Decision::Deny);
        assert_eq!(ctx.decision_proposals[0].rule_id, RuleId::SelectionError);
        assert_eq!(
            ctx.decision_proposals[0].reason,
            r#"command bash matched a profile but invocation selection failed: multiple forms matched for command "bash": ["stdin_script_implicit", "interactive"]"#
        );
    }

    #[test]
    fn resolve_policy_pass_escalates_no_profile_from_derived_invocation() {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.no_profile = NoProfilePolicy {
            action: RuleAction::Observe,
            commands: std::collections::BTreeMap::from([(
                "unknown-tool".to_string(),
                RuleAction::NeedApproval,
            )]),
        };

        let ctx = run_pass(
            policy,
            vec![execution_unit_record(
                "derived-dispatch:sess-1:1:0:0",
                0,
                ResolveInvocationArtifactResult::NoProfile {
                    normalized_command_name: "unknown-tool".to_string(),
                    gap_kind: ResolveGapKind::NoProfile,
                },
            )],
            Vec::new(),
            Vec::new(),
            "sudo unknown-tool --help",
        );

        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.decision_proposals[0].rule_id, RuleId::NoProfile);
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "command unknown-tool has no registered profile"
        );
    }

    #[test]
    fn resolve_policy_pass_observes_unknown_subcommand_gap_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            vec![execution_unit_record(
                "command:sess-1:1:0",
                0,
                ResolveInvocationArtifactResult::SelectionError {
                    normalized_command_name: "git".to_string(),
                    gap_kind: ResolveGapKind::UnknownSubcommandPath,
                    error: BindError::UnknownSubcommand {
                        command_name: "git".to_string(),
                        attempted_path: vec!["diff".to_string()],
                    },
                    partial_bound: None,
                },
            )],
            Vec::new(),
            Vec::new(),
            "git diff",
        );

        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn resolve_policy_pass_escalates_dynamic_command_target_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            vec![execution_unit_record(
                "command:sess-1:1:0",
                0,
                ResolveInvocationArtifactResult::MissingCommandName {
                    gap_kind: ResolveGapKind::DynamicCommandTarget,
                },
            )],
            Vec::new(),
            Vec::new(),
            "$USER_CMD --help",
        );

        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::MissingCommandName
        );
    }

    #[test]
    fn resolve_policy_pass_escalates_unresolved_execution_payload_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            Vec::new(),
            Vec::new(),
            vec![Evidence::nested_payload_unresolved(
                sample_nested_payload_context("payload"),
                NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                    variable_name: "USER_CMD".to_string(),
                },
                Some(UnresolvedExecutionPayloadSubtype::DynamicInlinePayload),
            )],
            r#"bash -c "$USER_CMD""#,
        );

        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::NestedPayloadExpansion
        );
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "execution payload could not be resolved: nested payload record 0 at depth 1 could not be materialized because variable USER_CMD is missing"
        );
    }

    #[test]
    fn resolve_policy_pass_ignores_unresolved_non_execution_nested_payload() {
        let ctx = run_pass(
            PolicyConfig::default(),
            Vec::new(),
            Vec::new(),
            vec![Evidence::nested_payload_unresolved(
                NestedPayloadContextEvidence {
                    origin: NestedPayloadOriginEvidence::ConfigDefinedTask {
                        config_path: "/tmp/project/package.json".to_string(),
                        task_name: "build".to_string(),
                    },
                    ..sample_nested_payload_context("payload")
                },
                NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                    variable_name: "USER_CMD".to_string(),
                },
                None,
            )],
            "npm run build",
        );

        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn resolve_policy_pass_escalates_unresolved_wrapper_child_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            Vec::new(),
            vec![UnresolvedDispatchRecord::new(
                NodeId::new("command:sess-1:1:0"),
                ParsedCommandRef::new(0, empty_span()),
                0,
                "wrapped_command",
            )],
            Vec::new(),
            r#"sudo "$USER_CMD""#,
        );

        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
        assert_eq!(ctx.decision_proposals[0].rule_id, RuleId::SelectionError);
        assert_eq!(
            ctx.decision_proposals[0].reason,
            "wrapper child command in slot wrapped_command at parsed index 0 could not be resolved into a singular dispatched command"
        );
    }

    #[test]
    fn resolve_policy_pass_observes_static_inline_unresolved_execution_payload_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            Vec::new(),
            Vec::new(),
            vec![Evidence::nested_payload_unresolved(
                NestedPayloadContextEvidence {
                    input: NestedPayloadInputEvidence::ArgumentFragments {
                        text: "print(1)".to_string(),
                        fragments: vec![],
                    },
                    ..sample_nested_payload_context("payload")
                },
                NestedPayloadUnresolvedReasonEvidence::UnsupportedLanguage,
                Some(UnresolvedExecutionPayloadSubtype::StaticInlineLiteral),
            )],
            r#"python -c 'print(1)'"#,
        );

        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn resolve_policy_pass_observes_static_heredoc_unresolved_execution_payload_by_default() {
        let ctx = run_pass(
            PolicyConfig::default(),
            Vec::new(),
            Vec::new(),
            vec![Evidence::nested_payload_unresolved(
                NestedPayloadContextEvidence {
                    origin: NestedPayloadOriginEvidence::FormImplicitInput,
                    input: NestedPayloadInputEvidence::LiteralText {
                        text: "print(1)\n".to_string(),
                    },
                    ..sample_nested_payload_context("payload")
                },
                NestedPayloadUnresolvedReasonEvidence::UnsupportedLanguage,
                Some(UnresolvedExecutionPayloadSubtype::StaticHeredocLiteral),
            )],
            "python <<'PY'\nprint(1)\nPY",
        );

        assert!(ctx.decision_proposals.is_empty());
    }

    fn sample_nested_payload_context(slot_name: &str) -> NestedPayloadContextEvidence {
        NestedPayloadContextEvidence {
            record_id: 0,
            parent_ref: NestedPayloadParentEvidence::RootCommand { command_index: 0 },
            root_command_index: 0,
            depth: 1,
            language: NestedPayloadLanguageEvidence::Bash,
            source: NestedPayloadSourceEvidence::DynamicReference,
            origin: NestedPayloadOriginEvidence::Parameter {
                slot_name: slot_name.to_string(),
            },
            input: NestedPayloadInputEvidence::ArgumentFragments {
                text: "$USER_CMD".to_string(),
                fragments: Vec::new(),
            },
        }
    }
}
