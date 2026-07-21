use caushell_graph::{EdgeKind, GraphRead, NodeKind};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, ExecutionRiskSubtype, FindingEnforcementClass, ImportedPackageExecutionSinkEvidence,
    PackageLocatorKind, ProvenanceArtifact, RuleId, RulePolicy,
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

    for record in graph_backed_execution_resolve_records(ctx) {
        let Some(execution_info) = execution_unit_info(graph, record.source_node_id()) else {
            continue;
        };
        if execution_info.sequence_no != ctx.request().sequence_no {
            continue;
        }

        let Some(artifact) = imported_package_artifact_for_sink(graph, record.source_node_id())
        else {
            continue;
        };

        sinks.push(ImportedPackageExecutionSinkEvidence {
            node_id: execution_info.node_id,
            sequence_no: execution_info.sequence_no,
            depth: execution_info.depth,
            command: execution_info.command,
            package_manager: artifact.manager,
            risk_subtype: ExecutionRiskSubtype::ImportedPackage,
            source_class: RulePolicy::imported_package_source_class_for_locator_kind(
                artifact.locator_kind,
            ),
            locator: artifact.locator,
            locator_kind: artifact.locator_kind,
        });
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportedPackageArtifactInfo {
    manager: caushell_types::PackageManagerKind,
    locator: String,
    locator_kind: PackageLocatorKind,
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

fn imported_package_artifact_for_sink(
    graph: &dyn GraphRead,
    source_node_id: &caushell_graph::NodeId,
) -> Option<ImportedPackageArtifactInfo> {
    let semantics_node_id = execution_semantics_node_id(source_node_id);
    graph.get_node(&semantics_node_id)?;

    for edge in graph.outgoing_edges(source_node_id) {
        if edge.kind != EdgeKind::Consumes {
            continue;
        }

        let Some(node) = graph.get_node(&edge.to) else {
            continue;
        };

        let NodeKind::ProvenanceArtifact { artifact } = &node.kind else {
            continue;
        };

        let ProvenanceArtifact::ImportedPackage {
            manager,
            locator,
            locator_kind,
            ..
        } = artifact
        else {
            continue;
        };

        return Some(ImportedPackageArtifactInfo {
            manager: *manager,
            locator: locator.clone(),
            locator_kind: *locator_kind,
        });
    }

    None
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
    use super::ImportedPackageExecutionGuardPass;
    use crate::{
        DecisionAssemblyPass, ExtractExecutionSemanticsPass, ExtractImportedPackageProvenancePass,
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, EvidenceKind, PolicyConfig, RuleAction, RuleId,
        RulePolicyEntry, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
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
    fn imported_package_execution_guard_requires_approval_for_local_path_by_default() {
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

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::ImportedPackageExecution
                && finding.message.contains("local_path")
        }));
    }

    #[test]
    fn imported_package_execution_guard_requires_approval_for_requirement_file_by_default() {
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

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
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
                imported.sink.command == "pip install \"requests\"" && imported.sink.depth == 2
            }
            _ => false,
        }));
    }
}
