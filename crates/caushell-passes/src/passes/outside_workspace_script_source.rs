use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{Evidence, PathTrustScope, ProvenanceConsumeKind, RuleId};

use crate::support::{
    collect_outside_workspace_path_consumes, decision_for_rule_action, push_unique_reason,
};

pub struct OutsideWorkspaceScriptSourcePass;

impl SessionAnalysisPass for OutsideWorkspaceScriptSourcePass {
    fn name(&self) -> &'static str {
        "outside_workspace_script_source"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let request = ctx.request().clone();
        let trusted_sets = ctx
            .policy()
            .rule_policy
            .trusted_sets_for(RuleId::OutsideWorkspaceScriptSource)
            .to_vec();
        let Some(path_facts) = collect_outside_workspace_path_consumes(
            caushell_query::QuerySession::from_session(&staged_session),
            &request,
            &ctx.policy().path_trust_sets,
            &trusted_sets,
            ProvenanceConsumeKind::ScriptSource,
            PathTrustScope::ScriptSourceExecute,
        ) else {
            return;
        };

        let rule_action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::OutsideWorkspaceScriptSource);
        let normalized_workspace_root = path_facts.normalized_workspace_root.clone();
        let mut reasons = Vec::new();

        for path in path_facts.consumes {
            push_unique_reason(
                &mut reasons,
                format!(
                    "script source path {} for slot {} in command {} is outside workspace root {}",
                    path.path,
                    path.slot_name.as_deref().unwrap_or("<unknown>"),
                    path.normalized_command_name
                        .as_deref()
                        .unwrap_or("<unknown>"),
                    normalized_workspace_root
                ),
            );

            if let Some(write) = path.latest_prior_write {
                ctx.add_evidence(Evidence::prior_path_write(
                    RuleId::OutsideWorkspaceScriptSource,
                    &path.path,
                    write.sequence_no,
                    &write.raw_text,
                ));
                push_unique_reason(
                    &mut reasons,
                    format!(
                        "script source path {} was previously written at sequence {} by command {}",
                        path.path, write.sequence_no.0, write.raw_text,
                    ),
                );
            }
        }

        for reason in reasons {
            ctx.add_finding(RuleId::OutsideWorkspaceScriptSource, reason.clone());

            if let Some(decision) = decision_for_rule_action(rule_action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::OutsideWorkspaceScriptSource,
                    decision,
                    reason,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::OutsideWorkspaceScriptSourcePass;
    use crate::{
        DecisionAssemblyPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, Evidence, Finding, PathResolution,
        PathTrustGrant, PathTrustScope, PathTrustSet, PolicyConfig, ProvenanceArtifact,
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind, ResolvedPathPurpose,
        ResolvedPathRole, RuleAction, RuleId, RulePolicyEntry, RuntimeMetadata, SessionId,
        SessionSummary, ShellKind,
    };

    fn sample_request(
        command: &str,
        cwd: &str,
        home: Option<&str>,
        workspace_root: Option<&str>,
    ) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new(cwd.to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: home.map(str::to_string),
            workspace_root: workspace_root.map(str::to_string),
        }
    }

    fn policy_with_rule(action: RuleAction) -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(action),
        );
        policy
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass(
        policy: PolicyConfig,
        command: &str,
        cwd: &str,
        home: Option<&str>,
        workspace_root: Option<&str>,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_analysis_pass(OutsideWorkspaceScriptSourcePass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx =
            RunnerContext::with_policy(sample_request(command, cwd, home, workspace_root), policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn session_with_prior_write(
        path: &str,
        command: &str,
        sequence_no: u64,
    ) -> SessionView<'static> {
        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new(format!("command:sess-1:{sequence_no}")),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(sequence_no),
            command,
            "/tmp/project/work",
            ShellKind::Bash,
        );
        let _ = graph.add_path_fact(
            NodeId::new(format!("path:{path}")),
            PathResolution::Concrete {
                path: path.to_string(),
            },
            ResolvedPathRole::Write,
            Some(ResolvedPathPurpose::GenericOperand),
            "redirect_target_0",
            None,
        );
        let _ = graph.add_edge(Edge::new(
            NodeId::new(format!("command:sess-1:{sequence_no}")),
            NodeId::new(format!("path:{path}")),
            EdgeKind::Writes,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new(format!("artifact:path-content:{path}")),
            ProvenanceArtifact::PathContent {
                path: path.to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new(format!("command:sess-1:{sequence_no}")),
            NodeId::new(format!("artifact:path-content:{path}")),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                }),
            },
        ));

        let graph = Box::leak(Box::new(graph));
        let summary = Box::leak(Box::new(SessionSummary::default()));
        SessionView::new(graph, summary)
    }

    #[test]
    fn outside_workspace_script_source_skips_when_script_stays_within_workspace() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash ./scripts/build.sh",
            "/tmp/project",
            Some("/home/alice"),
            Some("/tmp/project"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_script_source_requires_approval_for_untrusted_path() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash ../shared/build.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::OutsideWorkspaceScriptSource,
                "script source path /tmp/project/shared/build.sh for slot script_path in command bash is outside workspace root /tmp/project/work"
            )]
        );
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::OutsideWorkspaceScriptSource
        );
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
    }

    #[test]
    fn outside_workspace_script_source_consumes_derived_execution_units() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "sudo bash ../shared/build.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::OutsideWorkspaceScriptSource,
                "script source path /tmp/project/shared/build.sh for slot script_path in command bash is outside workspace root /tmp/project/work"
            )]
        );
    }

    #[test]
    fn outside_workspace_script_source_reports_prior_session_write_provenance() {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_analysis_pass(OutsideWorkspaceScriptSourcePass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let session =
            session_with_prior_write("/tmp/shared/build.sh", "echo hi > ../../shared/build.sh", 3);
        let mut ctx = RunnerContext::with_policy(
            CheckRequest {
                session_id: SessionId::new("sess-1"),
                sequence_no: CommandSequenceNo::new(10),
                command: "bash ../../shared/build.sh".to_string(),
                shell_state_before: caushell_types::ShellStateSnapshot::new(
                    "/tmp/project/work".to_string(),
                ),
                shell_kind: ShellKind::Bash,
                runtime: RuntimeMetadata {
                    runtime_name: "claude_code".to_string(),
                    tool_name: Some("Bash".to_string()),
                    shell_runtime_capabilities:
                        caushell_types::ShellRuntimeCapabilities::persistent_shell(),
                },
                home: Some("/home/alice".to_string()),
                workspace_root: Some("/tmp/project/work".to_string()),
            },
            policy_with_rule(RuleAction::Observe),
        );

        runner.run(session, &mut ctx);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert_eq!(ctx.findings.len(), 2);
        assert!(ctx.evidence.contains(&Evidence::prior_path_write(
            RuleId::OutsideWorkspaceScriptSource,
            "/tmp/shared/build.sh",
            CommandSequenceNo::new(3),
            "echo hi > ../../shared/build.sh",
        )));
        assert_eq!(
            ctx.evidence
                .iter()
                .filter(|evidence| evidence.rule_id == RuleId::OutsideWorkspaceScriptSource)
                .count(),
            1
        );
        assert_eq!(
            ctx.evidence
                .iter()
                .find(|evidence| evidence.rule_id == RuleId::OutsideWorkspaceScriptSource)
                .expect("expected prior write evidence"),
            &Evidence::prior_path_write(
                RuleId::OutsideWorkspaceScriptSource,
                "/tmp/shared/build.sh",
                CommandSequenceNo::new(3),
                "echo hi > ../../shared/build.sh",
            )
        );
        assert_eq!(
            ctx.findings[1],
            Finding::new(
                RuleId::OutsideWorkspaceScriptSource,
                "script source path /tmp/shared/build.sh was previously written at sequence 3 by command echo hi > ../../shared/build.sh"
            )
        );
    }

    #[test]
    fn outside_workspace_script_source_can_observe_without_escalating() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::Observe),
            "bash ../shared/build.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert_eq!(ctx.findings.len(), 1);
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_script_source_respects_full_trust_set() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "system_scripts".to_string(),
            PathTrustSet::new(
                vec!["/opt/trusted-scripts".to_string()],
                PathTrustGrant::Full,
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["system_scripts".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash /opt/trusted-scripts/setup.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_script_source_respects_scoped_trust_set() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "system_scripts".to_string(),
            PathTrustSet::new(
                vec!["/opt/trusted-scripts".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::ScriptSourceExecute]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["system_scripts".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash /opt/trusted-scripts/setup.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_script_source_does_not_treat_write_only_trust_set_as_executable() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "write_only".to_string(),
            PathTrustSet::new(
                vec!["/opt/trusted-scripts".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::Write]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["write_only".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash /opt/trusted-scripts/setup.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
    }

    #[test]
    fn outside_workspace_script_source_expands_home_relative_trust_root() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "user_scripts".to_string(),
            PathTrustSet::new(
                vec!["~/.local/share/trusted-scripts".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::ScriptSourceExecute]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["user_scripts".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash ~/.local/share/trusted-scripts/setup.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_script_source_skips_when_workspace_root_is_missing() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash /opt/trusted-scripts/setup.sh",
            "/tmp/project/work",
            Some("/home/alice"),
            None,
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }
}
