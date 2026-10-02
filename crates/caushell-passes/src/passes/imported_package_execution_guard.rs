use std::collections::BTreeSet;

use caushell_graph::{EdgeKind, GraphRead, NodeKind};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, ExecutionRiskSubtype, FindingEnforcementClass, ImportedPackageExecutionSinkEvidence,
    PackageLocatorKind, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuleId,
    RulePolicy,
};

use crate::support::{
    decision_for_rule_action, execution_semantics_node_id, graph_backed_execution_resolve_records,
};

pub struct ImportedPackageExecutionGuardPass;

impl SessionAnalysisPass for ImportedPackageExecutionGuardPass {
    fn name(&self) -> &'static str {
        "imported_package_execution_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let graph = staged_session.graph();

        for sink in collect_imported_package_sinks(ctx, graph) {
            let rule_action = ctx
                .policy()
                .rule_policy
                .action_for_imported_package_locator_kind(sink.locator_kind);
            let evidence = Evidence::imported_package_execution(
                sink.clone(),
                imported_package_source_summary(&sink),
            );
            let reason = evidence.summary.clone();

            ctx.add_evidence(evidence);
            ctx.add_finding_with_class(
                RuleId::ImportedPackageExecution,
                reason.clone(),
                FindingEnforcementClass::Normal,
            );

            if let Some(decision) = decision_for_rule_action(rule_action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::ImportedPackageExecution,
                    decision,
                    reason,
                );
            }
        }
    }
}

fn collect_imported_package_sinks(
    ctx: &RunnerContext,
    graph: &dyn GraphRead,
) -> Vec<ImportedPackageExecutionSinkEvidence> {
    let mut sinks = Vec::new();
    let mut seen = BTreeSet::new();

    for record in graph_backed_execution_resolve_records(ctx) {
        let semantics_node_id = execution_semantics_node_id(record.source_node_id());
        let Some(semantics_node) = graph.get_node(&semantics_node_id) else {
            continue;
        };
        // Reuse the existing execution fact as the trigger; downloads, queries
        // and other calls do not traverse package-source edges for this guard.
        if !matches!(&semantics_node.kind, NodeKind::ExecutionSemantics { semantics }
            if semantics.executes_imported_package_logic)
        {
            continue;
        }

        let Some(execution_info) = execution_unit_info(graph, record.source_node_id()) else {
            continue;
        };
        if execution_info.sequence_no != ctx.request().sequence_no {
            continue;
        }

        for edge in graph.outgoing_edges(record.source_node_id()) {
            if edge.kind != EdgeKind::Consumes
                || !matches!(
                    &edge.semantics,
                    Some(ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ImportedPackageLogic,
                        ..
                    })
                )
            {
                continue;
            }
            let Some(node) = graph.get_node(&edge.to) else {
                continue;
            };
            let NodeKind::ProvenanceArtifact {
                artifact:
                    ProvenanceArtifact::ImportedPackage {
                        manager,
                        locator,
                        locator_kind,
                        ..
                    },
            } = &node.kind
            else {
                continue;
            };
            // Repeated argv/slots may consume the same artifact several times.
            // Deduplicate per invocation, never across separate executions.
            if !seen.insert((record.source_node_id(), &edge.to)) {
                continue;
            }
            sinks.push(ImportedPackageExecutionSinkEvidence {
                node_id: execution_info.node_id.clone(),
                sequence_no: execution_info.sequence_no,
                depth: execution_info.depth,
                command: execution_info.command.clone(),
                package_manager: *manager,
                risk_subtype: ExecutionRiskSubtype::ImportedPackage,
                source_class: RulePolicy::imported_package_source_class_for_locator_kind(
                    *locator_kind,
                ),
                locator: locator.clone(),
                locator_kind: *locator_kind,
            });
        }
    }

    sinks
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionUnitInfo {
    node_id: String,
    sequence_no: caushell_types::CommandSequenceNo,
    depth: u8,
    command: String,
}

fn execution_unit_info(
    graph: &dyn GraphRead,
    node_id: &caushell_graph::NodeId,
) -> Option<ExecutionUnitInfo> {
    let node = graph.get_node(node_id)?;

    match &node.kind {
        NodeKind::CommandInvocation {
            sequence_no,
            raw_text,
            ..
        } => Some(ExecutionUnitInfo {
            node_id: node.id.0.clone(),
            sequence_no: *sequence_no,
            depth: 0,
            command: raw_text.clone(),
        }),
        NodeKind::DerivedInvocation {
            root_command_sequence_no,
            raw_text,
            depth,
            ..
        } => Some(ExecutionUnitInfo {
            node_id: node.id.0.clone(),
            sequence_no: *root_command_sequence_no,
            depth: *depth,
            command: raw_text.clone(),
        }),
        _ => None,
    }
}

fn imported_package_source_summary(sink: &ImportedPackageExecutionSinkEvidence) -> String {
    match sink.locator_kind {
        PackageLocatorKind::RegistryRef => format!(
            "{:?} package {} ({:?})",
            sink.package_manager, sink.locator, sink.locator_kind
        ),
        PackageLocatorKind::LocalPath
        | PackageLocatorKind::DirectUrl
        | PackageLocatorKind::VcsUrl
        | PackageLocatorKind::RequirementFile
        | PackageLocatorKind::UnknownDynamic => format!(
            "{:?} package {} ({:?})",
            sink.package_manager, sink.locator, sink.locator_kind
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{ImportedPackageExecutionGuardPass, collect_imported_package_sinks};
    use crate::{
        DecisionAssemblyPass, ExtractExecutionSemanticsPass, ExtractImportedPackageProvenancePass,
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, NodeKind, SessionGraph, SessionRead};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, EvidenceKind, ExecutionSemantics,
        PackageLocatorKind, PackageManagerKind, PolicyConfig, ProvenanceArtifact,
        ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuleAction, RuleId, RulePolicyEntry,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str, sequence_no: u64) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn runner_with_action(action: RuleAction) -> PassRunner {
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let _ = action;
        runner
    }

    fn run_with_policy(command: &str, action: RuleAction) -> RunnerContext {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::ImportedPackageExecution,
            RulePolicyEntry::new(action),
        );

        let mut ctx = RunnerContext::with_policy(sample_request(command, 3), policy);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        runner_with_action(action).run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn modeled_graph() -> (RunnerContext, SessionGraph, NodeId) {
        let ctx = run_with_policy("pip install numpy", RuleAction::Observe);
        let base = SessionGraph::new();
        let summary = SessionSummary::new();
        let staged = StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations());
        let mut graph = SessionGraph::new();
        for node in staged.graph().nodes() {
            graph.add_node(node.clone());
        }
        for edge in staged.graph().edges() {
            graph.add_edge(edge.clone()).unwrap();
        }
        let source = super::graph_backed_execution_resolve_records(&ctx)[0]
            .source_node_id()
            .clone();
        (ctx, graph, source)
    }

    fn consume(kind: ProvenanceConsumeKind) -> ProvenanceEdgeSemantics {
        ProvenanceEdgeSemantics::Consume {
            consume_kind: kind,
            slot_name: None,
            normalized_command_name: None,
            domain_label: None,
        }
    }

    #[test]
    fn only_imported_package_logic_consumption_is_an_execution_source() {
        let (ctx, mut graph, source) = modeled_graph();
        let target = NodeId::new("test:additional-package");
        graph.add_node(GraphNode::new(
            target.clone(),
            NodeKind::ProvenanceArtifact {
                artifact: ProvenanceArtifact::ImportedPackage {
                    manager: PackageManagerKind::Pip,
                    locator: "https://example.test/pkg".into(),
                    locator_kind: PackageLocatorKind::DirectUrl,
                    source_endpoint: Some("https://example.test/pkg".into()),
                    source_path: None,
                    version: 1,
                },
            },
        ));
        for kind in [
            ProvenanceConsumeKind::PackageLocator,
            ProvenanceConsumeKind::NetworkEndpoint,
        ] {
            graph
                .add_edge(Edge::with_semantics(
                    source.clone(),
                    target.clone(),
                    EdgeKind::Consumes,
                    consume(kind),
                ))
                .unwrap();
        }
        graph
            .add_edge(Edge::new(
                source.clone(),
                target.clone(),
                EdgeKind::Consumes,
            ))
            .unwrap();
        graph
            .add_edge(Edge::with_semantics(
                source.clone(),
                target.clone(),
                EdgeKind::Produces,
                consume(ProvenanceConsumeKind::ImportedPackageLogic),
            ))
            .unwrap();
        let sinks = collect_imported_package_sinks(&ctx, &graph);
        assert_eq!(sinks.len(), 1, "{sinks:?}");
        assert_eq!(sinks[0].locator, "numpy");

        for _ in 0..2 {
            graph
                .add_edge(Edge::with_semantics(
                    source.clone(),
                    target.clone(),
                    EdgeKind::Consumes,
                    consume(ProvenanceConsumeKind::ImportedPackageLogic),
                ))
                .unwrap();
        }
        let sinks = collect_imported_package_sinks(&ctx, &graph);
        assert_eq!(sinks.len(), 2, "{sinks:?}");
        assert_eq!(
            sinks
                .iter()
                .filter(|s| s.locator_kind == PackageLocatorKind::DirectUrl)
                .count(),
            1
        );
    }

    #[test]
    fn package_edges_do_not_trigger_the_guard_without_the_execution_flag() {
        let (ctx, mut graph, source) = modeled_graph();
        assert_eq!(collect_imported_package_sinks(&ctx, &graph).len(), 1);
        graph.add_node(GraphNode::new(
            super::execution_semantics_node_id(&source),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("pip", "download_only"),
            },
        ));
        assert!(collect_imported_package_sinks(&ctx, &graph).is_empty());
    }

    #[test]
    fn imported_package_execution_guard_observes_registry_ref_by_default() {
        let mut ctx = RunnerContext::new(sample_request("apt-get install curl", 3));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("registry_ref")
        }));
        assert!(
            ctx.evidence
                .iter()
                .any(|evidence| matches!(evidence.kind, EvidenceKind::ImportedPackageExecution(_)))
        );
    }

    #[test]
    fn imported_package_execution_guard_requires_approval_for_vcs_url() {
        let ctx = run_with_policy(
            "pip install git+https://example.test/pkg.git",
            RuleAction::NeedApproval,
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("vcs_url")
        }));
    }

    #[test]
    fn imported_package_execution_guard_requires_approval_for_direct_url_by_default() {
        let mut ctx = RunnerContext::new(sample_request(
            "pip install https://example.test/pkg.whl",
            3,
        ));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("direct_url")
        }));
    }

    #[test]
    fn imported_package_execution_guard_observes_local_path_by_default() {
        let mut ctx = RunnerContext::new(sample_request("pip install ./dist/pkg.whl", 3));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("local_path")
        }));
    }

    #[test]
    fn imported_package_execution_guard_observes_requirement_file_by_default() {
        let mut ctx = RunnerContext::new(sample_request("pip install -r requirements.txt", 3));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("requirement_file")
        }));
    }

    #[test]
    fn imported_package_execution_guard_requires_approval_for_unknown_dynamic_by_default() {
        let mut ctx = RunnerContext::new(sample_request("pip install \"$PKG\"", 3));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("unknown_dynamic")
        }));
    }

    #[test]
    fn imported_package_execution_guard_observes_shell_payload_wrapped_install() {
        let mut ctx = RunnerContext::new(sample_request("bash -lc 'pip install requests'", 3));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert!(ctx.evidence.iter().any(|evidence| match &evidence.kind {
            EvidenceKind::ImportedPackageExecution(imported) => {
                imported.sink.command == "pip install requests" && imported.sink.depth == 1
            }
            _ => false,
        }));
    }

    #[test]
    fn imported_package_execution_guard_observes_xargs_shell_payload_wrapped_install() {
        let mut ctx = RunnerContext::new(sample_request(
            r#"printf 'requests\n' | xargs bash -lc 'pip install "$0"'"#,
            3,
        ));
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut runner = PassRunner::new();
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
        runner.register_session_analysis_pass(ImportedPackageExecutionGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);

        assert!(ctx.evidence.iter().any(|evidence| match &evidence.kind {
            EvidenceKind::ImportedPackageExecution(imported) => {
                imported.sink.depth == 2
                    && imported.sink.package_manager == caushell_types::PackageManagerKind::Pip
                    && imported.sink.locator == "requests"
                    && imported.sink.locator_kind == caushell_types::PackageLocatorKind::RegistryRef
                    && imported.sink.command.contains("install")
            }
            _ => false,
        }));
    }
}
