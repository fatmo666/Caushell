mod context;
mod mutation;
mod nested;
mod node_ids;
mod pass;
mod runner;
mod staged;

pub use context::{
    BlockDeviceSearchScope, CatastrophicSearchRootScope, DecisionProposal, EffectiveCwd,
    ExecutionUnitInheritedScope, ExecutionUnitOriginKind, ExecutionUnitOriginLocator,
    ExecutionUnitResolveRecord, ParsedCommandRef, ParsedCommandScope,
    ProcessSubstitutionLocationKind, ProcessSubstitutionOuterRelation, RunnerContext,
    UnresolvedDispatchRecord,
};
pub use mutation::{MutationGraphError, PendingMutation};
pub use nested::{
    NestedPayloadParentRef, NestedPayloadRecord, NestedPayloadRecordId, NestedPayloadResolution,
};
pub use node_ids::{
    request_anchor_node_id, request_anchor_node_id_for,
    shell_state_reconciliation_anchor_node_id_for, top_level_command_node_id,
    top_level_command_node_id_for, variable_value_artifact_node_id,
};
pub use pass::{
    FinalDecisionPass, RequestAnalysisPass, RequestTransformPass, SessionAnalysisPass,
    SessionTransformPass, SessionView,
};
pub use runner::PassRunner;
pub use staged::StagedSession;

#[cfg(test)]
mod tests {
    use super::{
        DecisionProposal, FinalDecisionPass, NestedPayloadParentRef, NestedPayloadRecord,
        NestedPayloadRecordId, NestedPayloadResolution, PassRunner, PendingMutation,
        RequestAnalysisPass, RequestTransformPass, RunnerContext, SessionAnalysisPass,
        SessionTransformPass, SessionView, request_anchor_node_id, top_level_command_node_id,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_parse::{ParseStatus, ParsedCommandArtifact, SourceSpan};
    use caushell_profile::{
        MaterializedRecursivePayloadCandidate, PayloadLanguage, PayloadSource,
        RecursivePayloadCandidate, RecursivePayloadInput, RecursivePayloadOrigin, SlotName,
        ValueMaterialization,
    };
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, Evidence, Finding, PathResolution,
        ResolvedPathPurpose, ResolvedPathRole, RuleId, RuntimeMetadata, SessionId, SessionSummary,
        SessionVariableBinding, SessionVariableValue, ShellKind, ShellStateSnapshot,
    };

    fn sample_request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: "ls -la".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
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

    struct AddPathFactPass;

    impl RequestTransformPass for AddPathFactPass {
        fn name(&self) -> &'static str {
            "normalize_paths"
        }

        fn run(&self, ctx: &mut RunnerContext) {
            let request = ctx.request().clone();
            ctx.stage_mutation(PendingMutation::AddRequestAnchor {
                node_id: request_anchor_node_id(&request),
                session_id: request.session_id.clone(),
                sequence_no: request.sequence_no,
                raw_text: request.command.clone(),
                cwd_before: request.shell_state_before.cwd.clone(),
                shell_kind: request.shell_kind,
            });
            ctx.stage_mutation(PendingMutation::AddTopLevelCommandInvocation {
                node_id: top_level_command_node_id(&request, 0),
                session_id: request.session_id.clone(),
                sequence_no: request.sequence_no,
                command_index: 0,
                raw_text: request.command.clone(),
                cwd_before: request.shell_state_before.cwd.clone(),
                shell_kind: request.shell_kind,
            });
            ctx.stage_mutation(PendingMutation::AddPathFact {
                source_node_id: NodeId::new("command:sess-1:1:0"),
                node_id: NodeId::new("path-1"),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path".to_string(),
                normalized_command_name: None,
                relation: EdgeKind::Reads,
            });
        }
    }

    struct SessionMirrorPass;

    impl SessionTransformPass for SessionMirrorPass {
        fn name(&self) -> &'static str {
            "session_mirror"
        }

        fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
            assert_eq!(session.graph().node_count(), 0);

            if session.summary().last_sequence_no() == Some(CommandSequenceNo::new(7)) {
                ctx.stage_mutation(PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:1:0"),
                    node_id: NodeId::new("path-2"),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/from-session".to_string(),
                    },
                    role: ResolvedPathRole::Target,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "path".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Targets,
                });
            }
        }
    }

    struct WorkspaceGuardPass;

    impl RequestAnalysisPass for WorkspaceGuardPass {
        fn name(&self) -> &'static str {
            "workspace_guard"
        }

        fn run(&self, ctx: &mut RunnerContext) {
            if ctx
                .pending_mutations()
                .iter()
                .any(|mutation| matches!(mutation, PendingMutation::AddPathFact { .. }))
            {
                ctx.add_finding(RuleId::CwdOutsideWorkspaceRoot, "resolved path observed");
                ctx.add_evidence(Evidence::prior_path_write(
                    RuleId::CwdOutsideWorkspaceRoot,
                    "/tmp/project",
                    CommandSequenceNo::new(1),
                    "ls -la",
                ));
                ctx.propose_decision(
                    self.name(),
                    RuleId::CwdOutsideWorkspaceRoot,
                    Decision::NeedApproval,
                    "graph contains resolved path evidence",
                );
            }
        }
    }

    struct SessionSummaryGuardPass;

    impl SessionAnalysisPass for SessionSummaryGuardPass {
        fn name(&self) -> &'static str {
            "session_summary_guard"
        }

        fn run(
            &self,
            session: SessionView<'_>,
            _staged_session: SessionView<'_>,
            ctx: &mut RunnerContext,
        ) {
            if session.summary().last_sequence_no() == Some(CommandSequenceNo::new(7)) {
                ctx.add_finding(RuleId::NonMonotonicSequence, "session summary observed");
            }
        }
    }

    struct StagedVariableGuardPass;

    impl SessionAnalysisPass for StagedVariableGuardPass {
        fn name(&self) -> &'static str {
            "staged_variable_guard"
        }

        fn run(
            &self,
            _session: SessionView<'_>,
            staged_session: SessionView<'_>,
            ctx: &mut RunnerContext,
        ) {
            let Some(binding) = staged_session.summary().variable_binding("SCRIPT") else {
                return;
            };

            if binding.value == SessionVariableValue::ExactScalar("build.sh".to_string()) {
                ctx.add_finding(
                    RuleId::NonMonotonicSequence,
                    "staged summary exposes pending variable binding",
                );
            }
        }
    }

    struct StagedGraphGuardPass;

    impl SessionAnalysisPass for StagedGraphGuardPass {
        fn name(&self) -> &'static str {
            "staged_graph_guard"
        }

        fn run(
            &self,
            _session: SessionView<'_>,
            staged_session: SessionView<'_>,
            ctx: &mut RunnerContext,
        ) {
            let command_node = staged_session
                .graph()
                .get_node(&NodeId::new("command:sess-1:1:0"));
            let path_node = staged_session.graph().get_node(&NodeId::new("path-1"));

            if command_node.is_some()
                && path_node.is_some()
                && staged_session.graph().edge_count() == 1
            {
                ctx.add_finding(
                    RuleId::NonMonotonicSequence,
                    "staged graph exposes pending command-to-path edge",
                );
            }
        }
    }

    struct NestedPayloadSeedPass;

    impl SessionTransformPass for NestedPayloadSeedPass {
        fn name(&self) -> &'static str {
            "nested_payload_seed"
        }

        fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
            ctx.set_nested_payload_records(vec![NestedPayloadRecord {
                record_id: NestedPayloadRecordId(0),
                parent_ref: NestedPayloadParentRef::RootCommand { command_index: 0 },
                root_command_index: 0,
                depth: 1,
                bindings: caushell_profile::SessionBindings::new(),
                candidate: MaterializedRecursivePayloadCandidate {
                    candidate: RecursivePayloadCandidate {
                        language: PayloadLanguage::Bash,
                        source: PayloadSource::InlineString,
                        origin: RecursivePayloadOrigin::Parameter {
                            slot: SlotName::new("payload"),
                        },
                        input: RecursivePayloadInput::ArgumentFragments {
                            fragments: vec![caushell_profile::RecursivePayloadArgumentFragment {
                                text: "echo ok".to_string(),
                                quoted: true,
                                node_kind: "raw_string".to_string(),
                                span: SourceSpan {
                                    start_byte: 0,
                                    end_byte: 0,
                                    start_row: 0,
                                    start_column: 0,
                                    end_row: 0,
                                    end_column: 0,
                                },
                                materialization:
                                    caushell_profile::RecursivePayloadFragmentMaterialization::Literal,
                            }],
                        },
                    },
                    resolution: ValueMaterialization::Static,
                    fragment_resolutions: vec![ValueMaterialization::Static],
                },
                resolution: NestedPayloadResolution::Parsed {
                    shell_kind: ShellKind::Bash,
                    parsed: ParsedCommandArtifact {
                        raw_command: "echo ok".to_string(),
                        shell_kind: ShellKind::Bash,
                        status: ParseStatus::Complete,
                        commands: Vec::new(),
                        declaration_commands: Vec::new(),
                        assignment_commands: Vec::new(),
                        unset_commands: Vec::new(),
                        function_definitions: Vec::new(),
                        redirections: Vec::new(),
                        diagnostics: Vec::new(),
                    },
                },
            }]);
        }
    }

    struct AggregateDecisionPass;

    impl FinalDecisionPass for AggregateDecisionPass {
        fn name(&self) -> &'static str {
            "decision"
        }

        fn run(&self, ctx: &mut RunnerContext) {
            if ctx
                .decision_proposals
                .iter()
                .any(|proposal| proposal.decision == Decision::Deny)
            {
                ctx.set_final_decision(Decision::Deny);
            } else if ctx
                .decision_proposals
                .iter()
                .any(|proposal| proposal.decision == Decision::NeedApproval)
            {
                ctx.set_final_decision(Decision::NeedApproval);
            } else {
                ctx.set_final_decision(Decision::Allow);
            }
        }
    }

    #[test]
    fn runner_executes_request_and_session_phases_in_order() {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(AddPathFactPass);
        runner.register_session_transform_pass(SessionMirrorPass);
        runner.register_session_transform_pass(NestedPayloadSeedPass);
        runner.register_request_analysis_pass(WorkspaceGuardPass);
        runner.register_session_analysis_pass(SessionSummaryGuardPass);
        runner.register_final_decision_pass(AggregateDecisionPass);

        let graph = SessionGraph::new();
        let mut summary = SessionSummary::new();
        summary.observe_sequence(CommandSequenceNo::new(7));
        let mut ctx = RunnerContext::new(sample_request());
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(
            ctx.executed_passes,
            vec![
                "normalize_paths".to_string(),
                "session_mirror".to_string(),
                "nested_payload_seed".to_string(),
                "workspace_guard".to_string(),
                "session_summary_guard".to_string(),
                "decision".to_string(),
            ]
        );
        assert_eq!(graph.node_count(), 0);
        assert_eq!(
            ctx.findings,
            vec![
                Finding::new(RuleId::CwdOutsideWorkspaceRoot, "resolved path observed"),
                Finding::new(RuleId::NonMonotonicSequence, "session summary observed"),
            ]
        );
        assert_eq!(
            ctx.evidence,
            vec![Evidence::prior_path_write(
                RuleId::CwdOutsideWorkspaceRoot,
                "/tmp/project",
                CommandSequenceNo::new(1),
                "ls -la",
            )]
        );
        assert_eq!(ctx.nested_payload_records().len(), 1);
        assert_eq!(
            ctx.nested_payload_records()[0].record_id,
            NestedPayloadRecordId(0)
        );
        assert_eq!(
            ctx.nested_payload_records()[0].parent_ref,
            NestedPayloadParentRef::RootCommand { command_index: 0 }
        );
        assert_eq!(ctx.nested_payload_records()[0].root_command_index, 0);
        assert_eq!(ctx.nested_payload_records()[0].depth, 1);
        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::AddRequestAnchor {
                    node_id: NodeId::new("command-request:sess-1:1"),
                    session_id: SessionId::new("sess-1"),
                    sequence_no: CommandSequenceNo::new(1),
                    raw_text: "ls -la".to_string(),
                    cwd_before: "/tmp/project".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                PendingMutation::AddTopLevelCommandInvocation {
                    node_id: NodeId::new("command:sess-1:1:0"),
                    session_id: SessionId::new("sess-1"),
                    sequence_no: CommandSequenceNo::new(1),
                    command_index: 0,
                    raw_text: "ls -la".to_string(),
                    cwd_before: "/tmp/project".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:1:0"),
                    node_id: NodeId::new("path-1"),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project".to_string(),
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "path".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:1:0"),
                    node_id: NodeId::new("path-2"),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/from-session".to_string(),
                    },
                    role: ResolvedPathRole::Target,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "path".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Targets,
                },
            ]
        );
        assert_eq!(
            ctx.decision_proposals,
            vec![DecisionProposal {
                source_pass: "workspace_guard".to_string(),
                rule_id: RuleId::CwdOutsideWorkspaceRoot,
                decision: Decision::NeedApproval,
                reason: "graph contains resolved path evidence".to_string(),
            }]
        );
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    }

    #[test]
    fn runner_tracks_registered_pass_count_across_all_phases() {
        let mut runner = PassRunner::new();
        assert_eq!(runner.pass_count(), 0);

        runner.register_request_transform_pass(AddPathFactPass);
        runner.register_session_transform_pass(SessionMirrorPass);
        runner.register_session_transform_pass(NestedPayloadSeedPass);
        runner.register_request_analysis_pass(WorkspaceGuardPass);
        runner.register_session_analysis_pass(SessionSummaryGuardPass);
        runner.register_final_decision_pass(AggregateDecisionPass);

        assert_eq!(runner.pass_count(), 6);
    }

    #[test]
    fn session_analysis_reads_summary_overlay_from_pending_mutations() {
        struct SeedVariablePass;

        impl RequestTransformPass for SeedVariablePass {
            fn name(&self) -> &'static str {
                "seed_variable"
            }

            fn run(&self, ctx: &mut RunnerContext) {
                ctx.stage_mutation(PendingMutation::UpsertVariableBinding {
                    binding: SessionVariableBinding::new(
                        "SCRIPT",
                        SessionVariableValue::exact_scalar("build.sh"),
                        false,
                        CommandSequenceNo::new(1),
                    ),
                });
            }
        }

        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(SeedVariablePass);
        runner.register_session_analysis_pass(StagedVariableGuardPass);
        runner.register_final_decision_pass(AggregateDecisionPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::NonMonotonicSequence,
                "staged summary exposes pending variable binding",
            )]
        );
    }

    #[test]
    fn session_analysis_reads_graph_overlay_from_pending_mutations() {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(AddPathFactPass);
        runner.register_session_analysis_pass(StagedGraphGuardPass);
        runner.register_final_decision_pass(AggregateDecisionPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::NonMonotonicSequence,
                "staged graph exposes pending command-to-path edge",
            )]
        );
    }
}
