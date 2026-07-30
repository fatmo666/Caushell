use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{Evidence, PathTrustScope, ProvenanceConsumeKind, RuleId};

use crate::support::{
    collect_outside_workspace_path_consumes, decision_for_rule_action, push_unique_reason,
};

pub struct OutsideWorkspaceStartupConfigPass;

impl SessionAnalysisPass for OutsideWorkspaceStartupConfigPass {
    fn name(&self) -> &'static str {
        "outside_workspace_startup_config"
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
            .trusted_sets_for(RuleId::OutsideWorkspaceStartupConfig)
            .to_vec();
        let Some(path_facts) = collect_outside_workspace_path_consumes(
            caushell_query::QuerySession::from_session(&staged_session),
            &request,
            &ctx.policy().path_trust_sets,
            &trusted_sets,
            ProvenanceConsumeKind::StartupConfigSource,
            PathTrustScope::StartupConfigLoad,
        ) else {
            return;
        };

        let rule_action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::OutsideWorkspaceStartupConfig);
        let normalized_workspace_root = path_facts.normalized_workspace_root.clone();
        let mut reasons = Vec::new();

        for path in path_facts.consumes {
            ctx.add_evidence(Evidence::outside_workspace_path(
                RuleId::OutsideWorkspaceStartupConfig,
                &path.path,
                path.slot_name.as_deref().unwrap_or("<unknown>"),
                path.normalized_command_name
                    .as_deref()
                    .unwrap_or("<unknown>"),
                normalized_workspace_root.clone(),
            ));
            push_unique_reason(
                &mut reasons,
                format!(
                    "startup config path {} for slot {} in command {} is outside workspace root {}",
                    path.path,
                    path.slot_name.as_deref().unwrap_or("<unknown>"),
                    path.normalized_command_name
                        .as_deref()
                        .unwrap_or("<unknown>"),
                    normalized_workspace_root
                ),
            );
        }

        for reason in reasons {
            ctx.add_finding(RuleId::OutsideWorkspaceStartupConfig, reason.clone());

            if let Some(decision) = decision_for_rule_action(rule_action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::OutsideWorkspaceStartupConfig,
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

    use super::OutsideWorkspaceStartupConfigPass;
    use crate::{
        DecisionAssemblyPass, ExtractImplicitStartupConfigPass, ExtractPathFactsPass,
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, Evidence, Finding, PathTrustGrant,
        PathTrustScope, PathTrustSet, PolicyConfig, RuleAction, RuleId, RulePolicyEntry,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
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

    fn sample_request_with_env(
        command: &str,
        cwd: &str,
        home: Option<&str>,
        workspace_root: Option<&str>,
        inherited_environment: std::collections::BTreeMap<String, String>,
    ) -> CheckRequest {
        let mut request = sample_request(command, cwd, home, workspace_root);
        request.shell_state_before = inherited_environment.into_iter().fold(
            caushell_types::ShellStateSnapshot::new(cwd.to_string())
                .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly),
            |snapshot, (name, value)| snapshot.with_exact_scalar_variable(name, value, true),
        );
        request
    }

    fn policy_with_rule(action: RuleAction) -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
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
        runner.register_session_transform_pass(ExtractImplicitStartupConfigPass);
        runner.register_session_analysis_pass(OutsideWorkspaceStartupConfigPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx =
            RunnerContext::with_policy(sample_request(command, cwd, home, workspace_root), policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn run_pass_with_request(policy: PolicyConfig, request: CheckRequest) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_transform_pass(ExtractImplicitStartupConfigPass);
        runner.register_session_analysis_pass(OutsideWorkspaceStartupConfigPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::with_policy(request, policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn outside_workspace_startup_config_skips_when_config_stays_within_workspace() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash --rcfile ./team.rc -c 'echo ok'",
            "/tmp/project",
            Some("/home/alice"),
            Some("/tmp/project"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_startup_config_requires_approval_for_untrusted_path() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash --rcfile ../shared/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::OutsideWorkspaceStartupConfig,
                "startup config path /tmp/project/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project/work"
            )]
        );
        assert!(ctx.evidence.contains(&Evidence::outside_workspace_path(
            RuleId::OutsideWorkspaceStartupConfig,
            "/tmp/project/shared/team.rc",
            "startup_config",
            "bash",
            "/tmp/project/work",
        )));
        assert_eq!(ctx.decision_proposals.len(), 1);
        assert_eq!(
            ctx.decision_proposals[0].rule_id,
            RuleId::OutsideWorkspaceStartupConfig
        );
        assert_eq!(ctx.decision_proposals[0].decision, Decision::NeedApproval);
    }

    #[test]
    fn outside_workspace_startup_config_consumes_derived_execution_units() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "sudo bash --rcfile ../shared/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::OutsideWorkspaceStartupConfig,
                "startup config path /tmp/project/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project/work"
            )]
        );
    }

    #[test]
    fn outside_workspace_startup_config_requires_approval_for_bash_env_path() {
        let request = sample_request_with_env(
            r#"bash -c 'echo ok'"#,
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
            std::collections::BTreeMap::from([(
                "BASH_ENV".to_string(),
                "../shared/team.rc".to_string(),
            )]),
        );

        let ctx = run_pass_with_request(policy_with_rule(RuleAction::NeedApproval), request);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(
            ctx.findings,
            vec![Finding::new(
                RuleId::OutsideWorkspaceStartupConfig,
                "startup config path /tmp/project/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project/work"
            )]
        );
    }

    #[test]
    fn outside_workspace_startup_config_can_observe_without_escalating() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::Observe),
            "bash --rcfile ../shared/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert_eq!(ctx.findings.len(), 1);
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_startup_config_respects_full_trust_set() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "system_configs".to_string(),
            PathTrustSet::new(vec!["/opt/trusted-rc".to_string()], PathTrustGrant::Full),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["system_configs".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash --rcfile /opt/trusted-rc/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_startup_config_respects_scoped_trust_set() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "system_configs".to_string(),
            PathTrustSet::new(
                vec!["/opt/trusted-rc".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::StartupConfigLoad]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["system_configs".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash --rcfile /opt/trusted-rc/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_startup_config_does_not_treat_script_scope_as_config_scope() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "scripts_only".to_string(),
            PathTrustSet::new(
                vec!["/opt/trusted-rc".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::ScriptSourceExecute]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["scripts_only".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash --rcfile /opt/trusted-rc/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.decision_proposals.len(), 1);
    }

    #[test]
    fn outside_workspace_startup_config_expands_home_relative_trust_root() {
        let mut policy = policy_with_rule(RuleAction::NeedApproval);
        policy.path_trust_sets.insert(
            "user_configs".to_string(),
            PathTrustSet::new(
                vec!["~/.config/trusted-shell".to_string()],
                PathTrustGrant::Scoped {
                    scopes: BTreeSet::from([PathTrustScope::StartupConfigLoad]),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceStartupConfig,
            RulePolicyEntry::new(RuleAction::NeedApproval)
                .with_trust_sets(vec!["user_configs".to_string()]),
        );

        let ctx = run_pass(
            policy,
            "bash --rcfile ~/.config/trusted-shell/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            Some("/tmp/project/work"),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn outside_workspace_startup_config_skips_when_workspace_root_is_missing() {
        let ctx = run_pass(
            policy_with_rule(RuleAction::NeedApproval),
            "bash --rcfile /opt/trusted-rc/team.rc -c 'echo ok'",
            "/tmp/project/work",
            Some("/home/alice"),
            None,
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }
}
