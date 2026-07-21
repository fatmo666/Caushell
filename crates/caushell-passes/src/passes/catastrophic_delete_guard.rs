use caushell_profile::ResolveInvocationArtifactResult;
use caushell_query::QuerySession;
use caushell_runner::{EffectiveCwd, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{FindingEnforcementClass, RuleId};
use std::collections::BTreeSet;

use crate::support::{
    CommandSinkReasonBuckets, collect_block_device_destructive_reasons,
    collect_block_device_session_reasons, collect_command_sink_reason_buckets_with_optional_cwd,
    collect_execution_unit_scoped_reason_buckets, decision_for_rule_action,
};

pub struct CatastrophicDeleteGuardPass;

impl SessionAnalysisPass for CatastrophicDeleteGuardPass {
    fn name(&self) -> &'static str {
        "catastrophic_delete_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let cwd = _session
            .summary()
            .current_working_directory()
            .map(|cwd| cwd.path.as_str())
            .unwrap_or_else(|| ctx.request().shell_state_before.cwd());
        let home = ctx.request().home.as_deref();
        let mut floor_reasons = BTreeSet::new();
        let mut path_metadata_mutation_reasons = BTreeSet::new();
        let mut path_relocation_reasons = BTreeSet::new();
        let mut partition_layout_mutation_reasons = BTreeSet::new();
        let mut partition_table_session_reasons = BTreeSet::new();
        let mut partition_table_mutation_reasons = BTreeSet::new();
        let mut partition_table_state_mutation_reasons = BTreeSet::new();

        for record in ctx.execution_unit_resolve_records() {
            let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
                continue;
            };

            for record_cwd in
                effective_cwd_options(ctx.effective_cwd_for_node(&record.source_node_id), cwd)
            {
                let CommandSinkReasonBuckets {
                    floor_reasons: record_floor_reasons,
                    path_metadata_mutation_reasons: record_path_metadata_mutation_reasons,
                    path_relocation_reasons: record_path_relocation_reasons,
                    partition_layout_mutation_reasons: record_partition_layout_mutation_reasons,
                    partition_table_session_reasons: record_partition_table_session_reasons,
                    partition_table_mutation_reasons: record_partition_table_mutation_reasons,
                    partition_table_state_mutation_reasons:
                        record_partition_table_state_mutation_reasons,
                } = collect_command_sink_reason_buckets_with_optional_cwd(
                    resolved,
                    record_cwd,
                    home,
                    &record.bindings,
                );

                floor_reasons.extend(record_floor_reasons);
                path_metadata_mutation_reasons.extend(record_path_metadata_mutation_reasons);
                path_relocation_reasons.extend(record_path_relocation_reasons);
                partition_layout_mutation_reasons.extend(record_partition_layout_mutation_reasons);
                partition_table_session_reasons.extend(record_partition_table_session_reasons);
                partition_table_mutation_reasons.extend(record_partition_table_mutation_reasons);
                partition_table_state_mutation_reasons
                    .extend(record_partition_table_state_mutation_reasons);
            }
        }

        let CommandSinkReasonBuckets {
            floor_reasons: execution_unit_scope_floor_reasons,
            path_relocation_reasons: execution_unit_scope_path_relocation_reasons,
            ..
        } = collect_execution_unit_scoped_reason_buckets(ctx.execution_unit_resolve_records());
        floor_reasons.extend(execution_unit_scope_floor_reasons);
        path_relocation_reasons.extend(execution_unit_scope_path_relocation_reasons);

        floor_reasons.extend(collect_block_device_destructive_reasons(
            ctx,
            QuerySession::from_session(&staged_session),
        ));
        partition_table_session_reasons.extend(collect_block_device_session_reasons(
            ctx,
            QuerySession::from_session(&staged_session),
        ));

        for reason in floor_reasons {
            ctx.add_finding_with_class(
                RuleId::CatastrophicFileSystemDelete,
                reason,
                FindingEnforcementClass::HardDenyFloor,
            );
        }

        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPathMetadataMutation,
            path_metadata_mutation_reasons,
        );
        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPathRelocation,
            path_relocation_reasons,
        );
        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPartitionLayoutMutation,
            partition_layout_mutation_reasons,
        );
        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPartitionTableSession,
            partition_table_session_reasons,
        );
        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPartitionTableMutation,
            partition_table_mutation_reasons,
        );
        emit_policy_findings_and_proposals(
            self.name(),
            ctx,
            RuleId::CatastrophicPartitionTableStateMutation,
            partition_table_state_mutation_reasons,
        );
    }
}

fn effective_cwd_options<'a>(
    effective: Option<&'a EffectiveCwd>,
    fallback_cwd: &'a str,
) -> Vec<Option<&'a str>> {
    let mut options = Vec::new();
    match effective {
        Some(cwd) if cwd.is_unreachable() => {}
        Some(cwd) => {
            for known in cwd.known_cwds() {
                push_unique_cwd_option(&mut options, Some(known));
            }
            if cwd.has_unknown() || options.is_empty() {
                push_unique_cwd_option(&mut options, None);
            }
        }
        None => push_unique_cwd_option(&mut options, Some(fallback_cwd)),
    }
    options
}

fn push_unique_cwd_option<'a>(options: &mut Vec<Option<&'a str>>, option: Option<&'a str>) {
    if !options.contains(&option) {
        options.push(option);
    }
}

fn emit_policy_findings_and_proposals(
    source_pass: &str,
    ctx: &mut RunnerContext,
    rule_id: RuleId,
    reasons: BTreeSet<String>,
) {
    if reasons.is_empty() {
        return;
    }

    let action = ctx.policy().rule_policy.action_for(rule_id);

    for reason in reasons {
        ctx.add_finding(rule_id, reason.clone());
        if let Some(decision) = decision_for_rule_action(action) {
            ctx.propose_decision(source_pass, rule_id, decision, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CatastrophicDeleteGuardPass;
    use crate::{
        ComputeEffectiveCwdPass, DecisionAssemblyPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::{Edge, EdgeKind};
    use caushell_graph::{GraphNode, NodeId, NodeKind, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, DerivedInvocationOrigin,
        FindingEnforcementClass, PolicyConfig, RuleId, RuntimeMetadata, SemanticExpansionPolicy,
        SessionId, SessionSummary, ShellKind,
    };
    use caushell_types::{
        ProvenanceArtifact, ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind,
        ResolvedPathPurpose, ResolvedPathRole,
    };

    fn sample_request(shell_kind: ShellKind, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind,
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

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass_with(command: &str, policy: PolicyConfig) -> RunnerContext {
        run_pass_with_session_and_shell_kind(SessionGraph::new(), ShellKind::Bash, command, policy)
    }

    fn run_pass_with_session_and_shell_kind(
        graph: SessionGraph,
        shell_kind: ShellKind,
        command: &str,
        policy: PolicyConfig,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_analysis_pass(CatastrophicDeleteGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::with_policy(sample_request(shell_kind, command), policy);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn run_pass_with_request_and_graph(
        request: CheckRequest,
        graph: SessionGraph,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_analysis_pass(CatastrophicDeleteGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::with_policy(request, PolicyConfig::default());

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn graph_with_known_payload_file(path: &str, producer_raw_text: &str) -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            producer_raw_text,
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new(format!("artifact:path-content:{path}")),
            ProvenanceArtifact::PathContent {
                path: path.to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:1"),
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

        graph
    }

    fn run_pass(command: &str) -> RunnerContext {
        run_pass_with(command, PolicyConfig::default())
    }

    fn run_pass_with_cwd(command: &str, cwd: &str) -> RunnerContext {
        let mut request = sample_request(ShellKind::Bash, command);
        request.shell_state_before = caushell_types::ShellStateSnapshot::new(cwd.to_string());
        run_pass_with_request_and_graph(request, SessionGraph::new())
    }

    fn assert_has_finding(
        ctx: &RunnerContext,
        rule_id: RuleId,
        enforcement_class: FindingEnforcementClass,
        fragments: &[&str],
    ) {
        assert!(
            ctx.findings.iter().any(|finding| {
                finding.rule_id == rule_id
                    && finding.enforcement_class == enforcement_class
                    && fragments
                        .iter()
                        .all(|fragment| finding.message.contains(fragment))
            }),
            "expected finding for {:?} with fragments {:?}, got {:?}",
            rule_id,
            fragments,
            ctx.findings
        );
    }

    fn assert_has_proposal(ctx: &RunnerContext, rule_id: RuleId, decision: Decision) {
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|proposal| { proposal.rule_id == rule_id && proposal.decision == decision }),
            "expected proposal {:?} for {:?}, got {:?}",
            decision,
            rule_id,
            ctx.decision_proposals
        );
    }

    fn assert_de_floored_surface_requires_approval(
        command: &str,
        rule_id: RuleId,
        fragments: &[&str],
    ) {
        let ctx = run_pass(command);

        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_has_finding(&ctx, rule_id, FindingEnforcementClass::Normal, fragments);
        assert_has_proposal(&ctx, rule_id, Decision::NeedApproval);
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == RuleId::CatastrophicFileSystemDelete
                    || finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no floor finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_root_in_default_mode() {
        let ctx = run_pass("rm -rf /");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(
            ctx.findings[0].enforcement_class,
            FindingEnforcementClass::HardDenyFloor
        );
        assert!(ctx.findings[0].message.contains("delete target /"));
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_system_root_in_default_mode() {
        let ctx = run_pass("rm -rf /usr");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(
            ctx.findings[0].enforcement_class,
            FindingEnforcementClass::HardDenyFloor
        );
        assert!(ctx.findings[0].message.contains("delete target /usr"));
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_root_with_dot_segments_in_default_mode() {
        let ctx = run_pass("rm -rf /./");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.message.contains("delete target /./")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_system_root_with_parent_segments_in_default_mode() {
        let ctx = run_pass("rm -rf /usr/../usr/.");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.message.contains("delete target /usr/../usr/.")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_root_with_leading_parent_segments_in_default_mode() {
        for command in [
            "rm -rf /..",
            "rm -rf /../",
            "rm -rf /../../etc/..",
            "rm -rf /usr/../../",
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_system_root_child_globs_in_default_mode() {
        for command in [
            "rm -rf /etc/*",
            "rm -rf /usr/*",
            "rm -rf /var/*",
            "rm -rf /boot/*",
            "rm -rf /usr/../etc/*",
            "rm -rf ///etc///*",
            r#"rm -rf /"etc"/*"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_system_root_name_patterns_in_default_mode() {
        for command in [
            "rm -rf /u*",
            "rm -rf /et?",
            "rm -rf /[e]tc",
            "rm -rf /{etc,usr}",
            "rm -rf /u*/*",
            "rm -rf /{etc,usr}/*",
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_allows_quoted_system_root_child_globs() {
        for command in [
            r#"rm -rf '/etc/*'"#,
            r#"rm -rf "/usr/*""#,
            r#"rm -rf '/u*'"#,
            r#"rm -rf "/{etc,usr}""#,
            r#"rm -rf /etc/"*""#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Allow),
                "expected allow for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                !ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                }),
                "expected no catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_handles_shell_escaped_system_root_paths() {
        for command in [
            r#"rm -rf /\e\t\c"#,
            r#"rm -rf /etc\/*"#,
            r#"rm -rf \/usr/*"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_allows_escaped_system_root_child_glob_star() {
        let ctx = run_pass(r#"rm -rf /etc/\*"#);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                    && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no catastrophic delete finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_relative_paths_resolving_to_system_roots() {
        for (cwd, command) in [
            ("/", "rm -rf etc"),
            ("/etc", "rm -rf ."),
            ("/etc", "rm -rf ./"),
            ("/usr/bin", "rm -rf .."),
            ("/etc", "rm -rf *"),
            ("/etc", "rm -rf ./*"),
            ("/etc", "rm -rf ../*"),
        ] {
            let ctx = run_pass_with_cwd(command, cwd);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command} in {cwd}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command} in {cwd}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_uses_effective_cwd_after_static_cd() {
        for command in [
            "cd / && rm -rf etc",
            "cd /; rm -rf etc",
            "cd /etc && rm -rf .",
            "cd /usr/bin && rm -rf ..",
            "pushd / >/dev/null && rm -rf etc",
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_does_not_leak_subshell_cd_to_following_command() {
        let ctx = run_pass_with_cwd("(cd /tmp/project); rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_preserves_original_cwd_after_control_flow_cd() {
        let ctx = run_pass_with_cwd("if false; then cd /tmp/project; fi; rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_preserves_original_cwd_when_sequence_cd_may_fail() {
        let ctx = run_pass_with_cwd("cd /no-such; rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_preserves_and_list_failure_after_sequence() {
        let ctx = run_pass_with_cwd("cd /no-such && true; rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_uses_or_list_success_after_sequence() {
        let ctx = run_pass_with_cwd("cd / || echo fail; rm -rf etc", "/tmp/project");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_unreachable_or_rhs_after_guaranteed_cd() {
        let ctx = run_pass_with_cwd("cd /tmp/project || rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_allows_relative_delete_after_static_cd_to_project() {
        let ctx = run_pass_with_cwd("cd /tmp/project && rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_allows_relative_delete_after_known_workspace_cd_sequence() {
        let ctx = run_pass_with_cwd("cd /tmp/project; rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_uses_function_expansion_cwd_for_following_command() {
        let ctx = run_pass("f(){ cd /; }; f; rm -rf etc");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_relative_delete_after_function_cd_to_workspace() {
        let ctx = run_pass_with_cwd("f(){ cd /tmp/project; }; f; rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_uses_sourced_script_cwd_for_following_command() {
        let mut request =
            sample_request(ShellKind::Bash, "source /tmp/project/script.sh; rm -rf etc");
        request.sequence_no = CommandSequenceNo::new(2);
        let graph =
            graph_with_known_payload_file("/tmp/project/script.sh", "printf 'cd /\\n' > script.sh");
        let ctx = run_pass_with_request_and_graph(request, graph);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_relative_delete_after_sourced_script_cd_to_workspace() {
        let mut request =
            sample_request(ShellKind::Bash, "source /tmp/project/script.sh; rm -rf etc");
        request.sequence_no = CommandSequenceNo::new(2);
        request.shell_state_before = caushell_types::ShellStateSnapshot::new("/".to_string());
        let graph = graph_with_known_payload_file(
            "/tmp/project/script.sh",
            "printf 'cd /tmp/project\\n' > script.sh",
        );
        let ctx = run_pass_with_request_and_graph(request, graph);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_uses_env_chdir_for_dispatch_child() {
        let ctx = run_pass("env --chdir=/ rm -rf etc");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_relative_delete_after_env_chdir_to_project() {
        let ctx = run_pass_with_cwd("env --chdir=/tmp/project rm -rf etc", "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_does_not_reuse_initial_cwd_after_dynamic_cd() {
        let ctx = run_pass_with_cwd(r#"cd "$TARGET" && rm -rf etc"#, "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow because relative cwd is unknown, got findings: {:?}",
            ctx.findings
        );
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                    && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no hard floor finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_still_denies_absolute_target_after_dynamic_cd() {
        let ctx = run_pass_with_cwd(r#"cd "$TARGET" && rm -rf /"#, "/tmp/project");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target /")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_uses_effective_cwd_for_block_device_redirection() {
        let ctx = run_pass("cd / && printf x > dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("raw block-device overwrite target dev/sda")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_relative_redirection_after_dynamic_cd() {
        let ctx = run_pass_with_cwd(r#"cd "$TARGET" && printf x > dev/sda"#, "/");

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow because relative cwd is unknown, got findings: {:?}",
            ctx.findings
        );
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                    && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no hard floor finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_uses_effective_cwd_for_static_fdisk_payload_target() {
        let ctx = run_pass("cd / && fdisk dev/sda <<'EOF'\ng\nw\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_home_paths_resolving_to_system_roots() {
        for command in ["rm -rf ~/../../etc", "rm -rf ~/../../etc/*"] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_same_request_static_variable_delete_target() {
        for command in [
            r#"TARGET=/; rm -rf "$TARGET""#,
            r#"TARGET=/etc; rm -rf "$TARGET""#,
            r#"TARGET=/etc; rm -rf "$TARGET"/*"#,
            r#"TARGET=/usr; rm -rf "$TARGET"/*"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_same_request_static_positional_delete_target() {
        for command in [
            r#"set -- /; rm -rf --no-preserve-root "$1""#,
            r#"set -- / /tmp; rm -rf --no-preserve-root "$@""#,
            r#"set -- /; rm -rf --no-preserve-root "$*""#,
            r#"TARGET=/; set -- "$TARGET"; rm -rf --no-preserve-root "$1""#,
            r#"set -- /etc; rm -rf "$1"/*"#,
            r#"set -- /etc; rm -rf "$@"/*"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target")
                }),
                "expected catastrophic delete finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_does_not_reuse_cleared_positional_target() {
        let ctx = run_pass(r#"set -- /; set --; rm -rf --no-preserve-root "$1""#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_default_parameter_expansion_root_target() {
        let ctx = run_pass(r#"TARGET_ROOT=; rm -rf --no-preserve-root "${TARGET_ROOT:-/}""#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(
            ctx.findings.iter().any(|finding| {
                finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                    && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                    && finding.message.contains("delete target")
            }),
            "expected catastrophic delete finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_catastrophic_project_delete() {
        let ctx = run_pass("rm -rf ./target");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_mv_root_to_dev_null_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "mv / /dev/null",
            RuleId::CatastrophicPathRelocation,
            &["move source /", "mv"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_mv_system_root_to_tmp_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "mv /etc /tmp/etc-backup",
            RuleId::CatastrophicPathRelocation,
            &["move source /etc", "mv"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mv_project_directory_in_default_mode() {
        let ctx = run_pass("mv ./build ./build.old");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_mv_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "mv / /dev/null",
            RuleId::CatastrophicPathRelocation,
            &["move source /", "mv"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_777_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod -R 777 /",
            RuleId::CatastrophicPathMetadataMutation,
            &["grant all-users rwx", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_0777_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod -R 0777 /",
            RuleId::CatastrophicPathMetadataMutation,
            &["grant all-users rwx", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_a_rwx_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod -R a+rwx /",
            RuleId::CatastrophicPathMetadataMutation,
            &["grant all-users rwx", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_ugo_rwx_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod -R ugo+rwx /",
            RuleId::CatastrophicPathMetadataMutation,
            &["grant all-users rwx", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_symbolic_world_writable_system_root() {
        assert_de_floored_surface_requires_approval(
            "chmod -R o+w /etc",
            RuleId::CatastrophicPathMetadataMutation,
            &["world-writable", "target /etc"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chmod_a_w_usr_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod --recursive a+w /usr",
            RuleId::CatastrophicPathMetadataMutation,
            &["world-writable", "target /usr"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chown_root_root_on_root() {
        assert_de_floored_surface_requires_approval(
            "chown -R root:root /",
            RuleId::CatastrophicPathMetadataMutation,
            &["root ownership", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chown_group_root_on_etc() {
        assert_de_floored_surface_requires_approval(
            "chown -R :root /etc",
            RuleId::CatastrophicPathMetadataMutation,
            &["root ownership", "target /etc"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_recursive_chgrp_root_on_usr() {
        assert_de_floored_surface_requires_approval(
            "chgrp -R root /usr",
            RuleId::CatastrophicPathMetadataMutation,
            &["root ownership", "target /usr"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_recursive_chmod_add_x() {
        let ctx = run_pass("chmod +x script.sh");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_recursive_chown_root_root_on_root() {
        let ctx = run_pass("chown root:root /");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chown_non_root_owner() {
        let ctx = run_pass("chown -R fatmo:staff /");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chgrp_non_root_group() {
        let ctx = run_pass("chgrp -R staff /");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_recursive_chmod_on_root() {
        let ctx = run_pass("chmod 777 /");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_recursive_chmod_non_catastrophic_file() {
        let ctx = run_pass("chmod 755 /tmp/x");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chmod_non_catastrophic_mode() {
        let ctx = run_pass("chmod -R 755 ./dist");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chmod_docs_mode_644() {
        let ctx = run_pass("chmod -R 644 ./docs");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chmod_symbolic_non_catastrophic_mode() {
        let ctx = run_pass("chmod -R a+rX ./bin");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_chmod_reference_mode() {
        let ctx = run_pass("chmod --reference=/tmp/mode ./x");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_recursive_chmod_dynamic_mode() {
        let ctx = run_pass("chmod -R \"$MODE\" /");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_recursive_chmod_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chmod -R 777 /",
            RuleId::CatastrophicPathMetadataMutation,
            &["grant all-users rwx", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_recursive_chown_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "chown -R root:root /",
            RuleId::CatastrophicPathMetadataMutation,
            &["root ownership", "target /"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_dd_to_block_device_in_default_mode() {
        let ctx = run_pass("dd if=payload.img of=/dev/sda bs=4M");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via dd")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_dd_to_normalized_block_device_in_default_mode() {
        let ctx = run_pass("dd if=payload.img of=/dev/./sda bs=4M");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/./sda via dd")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_dd_to_mdraid_in_default_mode() {
        let ctx = run_pass("dd if=payload.img of=/dev/md0 bs=4M");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/md0 via dd")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_mkfs_to_block_device_in_default_mode() {
        let ctx = run_pass("mkfs.ext4 /dev/nvme0n1p1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/nvme0n1p1 via mkfs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_mkfs_to_normalized_block_device_in_default_mode() {
        let ctx = run_pass("mkfs.ext4 /dev/../dev/nvme0n1p1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/../dev/nvme0n1p1 via mkfs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_patterns_in_default_mode() {
        for (command, expected) in [
            (
                "wipefs -a /dev/sd?",
                "filesystem signature wipe target /dev/sd? via wipefs",
            ),
            (
                "mkfs.ext4 /dev/nvme*n1",
                "destructive block-device target /dev/nvme*n1 via mkfs",
            ),
            (
                "wipefs -a /dev/[s]d?",
                "filesystem signature wipe target /dev/[s]d? via wipefs",
            ),
            (
                "mkfs.ext4 /d?v/sd?",
                "destructive block-device target /d?v/sd? via mkfs",
            ),
            (
                "shred /dev/mapper/*",
                "raw block-device overwrite target /dev/mapper/* via shred",
            ),
            (
                "cat payload.img > /dev/disk/by-id/*",
                "raw block-device overwrite target /dev/disk/by-id/* via shell redirection",
            ),
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains(expected)
                }),
                "expected block-device pattern finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_block_device_patterns() {
        for command in [
            "wipefs -a /tmp/sd?",
            "mkfs.ext4 ./dev/sd?",
            "wipefs -a /proc/sd?",
            "cat payload.img > /dev/not-a-block-pattern/*",
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Allow),
                "expected allow for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.is_empty(),
                "unexpected findings for {command}: {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mkfs_double_verbose_dry_run() {
        let ctx = run_pass("mkfs -V -V -t ext4 /dev/nvme0n1p1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_partition_table_destruction_in_default_mode() {
        let ctx = run_pass("sgdisk --zap-all /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via sgdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sgdisk_partition_delete_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --delete=2 /dev/sda",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via sgdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sgdisk_mbr_to_gpt_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --mbrtogpt /dev/sda",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via sgdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sgdisk_randomize_guids_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --randomize-guids /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sgdisk_sort_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --sort /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sgdisk_attribute_show() {
        let ctx = run_pass("sgdisk -A 4:show /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sgdisk_attribute_set_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk -A 4:set:2 /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sgdisk_pretend_attribute_set() {
        let ctx = run_pass("sgdisk --pretend -A 4:set:2 /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sgdisk_pretend_change_name() {
        let ctx = run_pass("sgdisk --pretend --change-name=1:root /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_cfdisk_partition_editor_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "cfdisk /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "cfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cfdisk_read_only_inspection() {
        let ctx = run_pass("cfdisk -r /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_cfdisk_partition_editor_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "cfdisk /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "cfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_gdisk_partition_editor_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "gdisk /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "gdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_gdisk_list_mode() {
        let ctx = run_pass("gdisk -l /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_mkfs_bfs_to_block_device_in_default_mode() {
        let ctx = run_pass("mkfs.bfs /dev/sda1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/sda1 via mkfs.bfs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_mkfs_minix_to_block_device_in_default_mode() {
        let ctx = run_pass("mkfs.minix /dev/sda1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/sda1 via mkfs.minix")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mkfs_cramfs_image_build() {
        let ctx = run_pass("mkfs.cramfs ./rootfs rootfs.cramfs");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_wrapped_block_device_overwrite_in_default_mode() {
        let ctx = run_pass("sudo dd if=payload.img of=/dev/sda bs=4M");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via dd")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_dispatch_derived_block_device_overwrite_in_default_mode() {
        let ctx = run_pass(r#"sudo sh -c 'dd if=payload.img of=/dev/sda bs=4M'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via dd")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_shell_redirection_to_normalized_block_device() {
        let ctx = run_pass("cat payload.img > /dev/./sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/./sda via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_does_not_replay_history_execution_units() {
        let mut graph = SessionGraph::new();
        graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:1:0:0"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(1),
                origin: DerivedInvocationOrigin::Dispatch {
                    source_command_index: 0,
                    dispatch_index: 0,
                    command_slot: "command".to_string(),
                },
                derived_command_index: 0,
                raw_text: "cat payload.img > /dev/sda".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Sh,
                depth: 1,
            },
        ));

        let ctx = run_pass_with_session_and_shell_kind(
            graph,
            ShellKind::Bash,
            "pwd",
            PolicyConfig::default(),
        );

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == RuleId::CatastrophicFileSystemDelete
                    || finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no replayed catastrophic history finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_wrapped_interactive_parted_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sudo parted /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "parted"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_find_root_exec_rm_in_default_mode() {
        let ctx = run_pass(r#"find / -type f -exec rm -f {} \;"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("dispatch-scoped destructive child command rm")
                && finding.message.contains("catastrophic search root /")
                && finding.message.contains("via find")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_find_system_root_child_glob_exec_rm() {
        for (command, root_fragment) in [
            (r#"find /etc/* -type f -exec rm -f {} \;"#, "/etc/*"),
            (r#"find /u*/* -type f -exec rm -f {} \;"#, "/usr/*"),
            (r#"find /{etc,usr}/* -type f -exec rm -f {} \;"#, "/etc/*"),
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                        && finding
                            .message
                            .contains("dispatch-scoped destructive child command rm")
                        && finding
                            .message
                            .contains(&format!("catastrophic search root {root_fragment}"))
                        && finding.message.contains("via find")
                }),
                "expected catastrophic find finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_find_system_root_child_glob_delete() {
        let ctx = run_pass(r#"find /usr/../etc/* -delete"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target /usr/../etc/*")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_quoted_find_system_root_child_glob() {
        let ctx = run_pass(r#"find '/etc/*' -delete"#);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_find_block_device_exec_mkfs() {
        let ctx = run_pass(r#"find /dev -maxdepth 1 -type b -name 'sd?' -exec mkfs.ext4 -F {} +"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("dispatch-scoped destructive block-device child command mkfs.ext4")
                && finding
                    .message
                    .contains("block-device search target /dev/sd?")
                && finding.message.contains("via find")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_find_non_block_device_type_exec_mkfs_placeholder() {
        let ctx = run_pass(r#"find /dev -maxdepth 1 -type f -name 'sd?' -exec mkfs.ext4 -F {} +"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_find_var_log_exec_rm_in_default_mode() {
        let ctx = run_pass(r#"find /var/log -type f -exec rm -f {} \;"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf '/\n' | xargs rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_quoted_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf "'/'\n" | xargs rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_backslash_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf '\\/\n' | xargs rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_null_delimited_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf '/\0' | xargs -0 rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_delimited_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf 'safe,/' | xargs -d , rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_attached_and_inline_options() {
        for command in [
            r#"printf 'safe,/' | xargs -d, rm -rf"#,
            r#"printf 'safe,/' | xargs --delimiter=, rm -rf"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target / in command rm")
                }),
                "expected xargs hard deny for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_replace_token_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf '/\n' | xargs -I{} rm -rf {}"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_replace_token_sh_c_positional_rm_root() {
        let ctx =
            run_pass(r#"printf '%s\n' / | xargs -I{} sh -c 'rm -rf --no-preserve-root "$1"' _ {}"#);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Deny),
            "expected deny, got findings: {:?}",
            ctx.findings
        );
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_max_args_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf 'safe\n/\n' | xargs -n 1 bash -lc 'rm -rf "$0"'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_max_lines_rm_root_in_default_mode() {
        let ctx = run_pass(r#"printf 'safe\n/\n' | xargs -L 1 bash -lc 'rm -rf "$0"'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_xargs_empty_stdin_rm_root_without_r() {
        let ctx = run_pass(r#"printf '' | xargs rm -rf /"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_allows_pipeline_xargs_empty_stdin_rm_root_with_r() {
        let ctx = run_pass(r#"printf '' | xargs -r rm -rf /"#);

        assert_eq!(
            ctx.final_decision,
            Some(Decision::Allow),
            "expected allow, got findings: {:?}",
            ctx.findings
        );
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == RuleId::CatastrophicFileSystemDelete
                    && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
            }),
            "expected no catastrophic xargs finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_allows_pipeline_xargs_interactive_prompt_rm_root() {
        for command in [
            r#"printf '/\n' | xargs -p rm -rf"#,
            r#"printf '/\n' | xargs --interactive rm -rf"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Allow),
                "expected allow for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                !ctx.findings.iter().any(|finding| {
                    finding.rule_id == RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                }),
                "expected no catastrophic xargs finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_allows_pipeline_xargs_eof_marker_before_root() {
        for command in [
            r#"printf 'STOP\n/\n' | xargs -E STOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs -ESTOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs -eSTOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs --eof=STOP rm -rf"#,
        ] {
            let ctx = run_pass(command);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Allow),
                "expected allow for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                !ctx.findings.iter().any(|finding| {
                    finding.rule_id == RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                }),
                "expected no catastrophic xargs finding for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_cat_known_file_into_xargs_rm_root() {
        let mut request = sample_request(ShellKind::Bash, r#"cat payload.txt | xargs rm -rf"#);
        request.sequence_no = CommandSequenceNo::new(2);
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf '/\\n' > payload.txt",
        );
        let ctx = run_pass_with_request_and_graph(request, graph);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_xargs_arg_file_rm_root() {
        let mut request = sample_request(ShellKind::Bash, r#"xargs -a payload.txt rm -rf"#);
        request.sequence_no = CommandSequenceNo::new(2);
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf '/\\n' > payload.txt",
        );
        let ctx = run_pass_with_request_and_graph(request, graph);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_xargs_attached_and_inline_arg_file_rm_root() {
        for command in [
            r#"xargs -apayload.txt rm -rf"#,
            r#"xargs --arg-file=payload.txt rm -rf"#,
        ] {
            let mut request = sample_request(ShellKind::Bash, command);
            request.sequence_no = CommandSequenceNo::new(2);
            let graph = graph_with_known_payload_file(
                "/tmp/project/payload.txt",
                "printf '/\\n' > payload.txt",
            );
            let ctx = run_pass_with_request_and_graph(request, graph);

            assert_eq!(
                ctx.final_decision,
                Some(Decision::Deny),
                "expected deny for {command}, got findings: {:?}",
                ctx.findings
            );
            assert!(
                ctx.findings.iter().any(|finding| {
                    finding.rule_id == RuleId::CatastrophicFileSystemDelete
                        && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                        && finding.message.contains("delete target / in command rm")
                }),
                "expected xargs arg-file hard deny for {command}, got {:?}",
                ctx.findings
            );
        }
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_cat_process_substitution_into_xargs_rm_root() {
        let ctx = run_pass(r#"cat <(printf '/\n') | xargs rm -rf"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_pipeline_xargs_mv_root_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"printf '/\n' | xargs mv -t /tmp"#,
            RuleId::CatastrophicPathRelocation,
            &["move source /", "in command mv"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_does_not_reuse_history_stdout_for_xargs() {
        let mut request = sample_request(
            ShellKind::Bash,
            r#"printf 'report.txt\n' | xargs mv -t /tmp"#,
        );
        request.sequence_no = CommandSequenceNo::new(2);

        let mut graph = SessionGraph::new();
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "printf '/\\n'",
            "/tmp/project",
            ShellKind::Bash,
        );

        let ctx = run_pass_with_request_and_graph(request, graph);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(
            !ctx.findings.iter().any(|finding| {
                finding.rule_id == RuleId::CatastrophicFileSystemDelete
                    || finding.rule_id == RuleId::CatastrophicPathRelocation
            }),
            "expected no catastrophic xargs finding, got {:?}",
            ctx.findings
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_find_root_exec_mv_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"find / -type f -exec mv {} /tmp/trash \;"#,
            RuleId::CatastrophicPathRelocation,
            &[
                "dispatch-scoped relocation child command mv",
                "catastrophic search root /",
                "via find",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_find_root_exec_mv_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"find / -type f -exec mv {} /tmp/trash \;"#,
            RuleId::CatastrophicPathRelocation,
            &[
                "dispatch-scoped relocation child command mv",
                "catastrophic search root /",
                "via find",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_find_etc_exec_rename_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"find /etc -type f -exec rename foo bar {} \;"#,
            RuleId::CatastrophicPathRelocation,
            &[
                "dispatch-scoped relocation child command rename",
                "catastrophic search root /etc",
                "via find",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_find_root_exec_shell_mv_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"find / -type f -exec sh -c 'mv "$1" /tmp/trash' sh {} \;"#,
            RuleId::CatastrophicPathRelocation,
            &[
                "dispatch-scoped relocation child command mv",
                "catastrophic search root /",
                "via find",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_find_root_delete_in_default_mode() {
        let ctx = run_pass(r#"find / -delete"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.message.contains(
                    "delete target / in command find is a catastrophic filesystem root delete",
                )
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_find_var_log_delete_in_default_mode() {
        let ctx = run_pass(r#"find /var/log -delete"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_nested_find_root_exec_rm_in_default_mode() {
        let ctx = run_pass(r#"bash -c 'find / -type f -exec rm -f {} \;'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("dispatch-scoped destructive child command rm")
                && finding.message.contains("catastrophic search root /")
                && finding.message.contains("via find")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_mv_root_from_command_substitution_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"mv $(printf /etc) /tmp/etc-backup"#,
            RuleId::CatastrophicPathRelocation,
            &["move source /etc", "in command mv"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_rm_root_from_process_substitution_backed_command_substitution()
     {
        let ctx = run_pass(r#"rm -rf $(cat <(printf '/\n'))"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding.message.contains("delete target / in command rm")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_in_default_mode() {
        let ctx = run_pass("cat payload.img > /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_bare_block_device_output_redirection_in_default_mode() {
        let ctx = run_pass("> /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_to_nvme_in_default_mode() {
        let ctx = run_pass("echo hi >/dev/nvme0n1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.message.contains(
                    "raw block-device overwrite target /dev/nvme0n1 via shell redirection",
                )
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_to_mmc_in_default_mode() {
        let ctx = run_pass("base64 -d disk.b64 > /dev/mmcblk0");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.message.contains(
                    "raw block-device overwrite target /dev/mmcblk0 via shell redirection",
                )
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_to_dm_in_default_mode() {
        let ctx = run_pass("cat payload.img > /dev/dm-0");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/dm-0 via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_to_mdraid_in_default_mode()
    {
        let ctx = run_pass("cat payload.img > /dev/md0");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/md0 via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_with_ampersand_operator() {
        let ctx = run_pass("echo hi &> /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_block_device_output_redirection_with_ampersand_append_operator()
     {
        let ctx = run_pass("echo hi &>> /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via shell redirection")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_cp_to_block_device_in_default_mode() {
        let ctx = run_pass("cp /dev/zero /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via cp")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cp_target_directory_non_directory_error_shape() {
        let ctx = run_pass("cp -t /dev/sda payload.img");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cp_attributes_only_to_block_device_path() {
        let ctx = run_pass("cp --attributes-only payload.img /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cp_hard_link_to_block_device_path() {
        let ctx = run_pass("cp -l payload.img /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cp_symbolic_link_to_block_device_path() {
        let ctx = run_pass("cp -s payload.img /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_tee_to_block_device_in_default_mode() {
        let ctx = run_pass("tee /dev/sda < /dev/zero > /dev/null");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via tee")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_install_to_block_device_under_current_floor_model() {
        let ctx = run_pass("install payload.img /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_install_target_directory_non_directory_error_shape() {
        let ctx = run_pass("install -t /dev/sda payload.img");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_wipefs_in_default_mode() {
        let ctx = run_pass("wipefs -a /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("filesystem signature wipe target /dev/sda via wipefs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_wipefs_mdraid_in_default_mode() {
        let ctx = run_pass("wipefs -a /dev/md0");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("filesystem signature wipe target /dev/md0 via wipefs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_wipefs_offset_target_in_default_mode() {
        let ctx = run_pass("wipefs -o 0x438 /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("filesystem signature wipe target /dev/sda via wipefs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_wipefs_no_act_preview() {
        let ctx = run_pass("wipefs -a -n /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_wipefs_listing() {
        let ctx = run_pass("wipefs /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_regular_file_output_redirection() {
        let ctx = run_pass("echo hi > ./disk.img");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_descriptor_duplication_redirection() {
        let ctx = run_pass("echo hi 2>&1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_read_only_block_device_redirection() {
        let ctx = run_pass("cat < /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_mkswap_in_default_mode() {
        let ctx = run_pass("mkswap /dev/sda2");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/sda2 via mkswap")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_mke2fs_in_default_mode() {
        let ctx = run_pass("mke2fs /dev/sda1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/sda1 via mke2fs")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mke2fs_no_create_inspection_mode() {
        let ctx = run_pass("mke2fs -n /dev/sda1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_shred_block_device_in_default_mode() {
        let ctx = run_pass("shred /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("raw block-device overwrite target /dev/sda via shred")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_shred_regular_file_overwrite() {
        let ctx = run_pass("shred ./payload.bin");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_shred_regular_file_remove_mode() {
        let ctx = run_pass("shred -u ./payload.bin");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_truncate_short_size_block_device() {
        let ctx = run_pass("truncate -s 0 /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_truncate_long_size_block_device() {
        let ctx = run_pass("truncate --size=0 /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_truncate_regular_file() {
        let ctx = run_pass("truncate -s 0 ./build.log");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_cmake_build_dir_block_device_shape() {
        let ctx = run_pass("cmake -S . -B /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_split_prefix_block_device_shape() {
        let ctx = run_pass("split -b 1M big.bin /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_csplit_prefix_block_device_shape() {
        let ctx = run_pass("csplit -f /dev/sda input.txt /END/");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mypy_report_directory_block_device_shape() {
        let ctx = run_pass("mypy --html-report /dev/sda src");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mypy_junit_xml_block_device_under_current_floor_model() {
        let ctx = run_pass("mypy --junit-xml /dev/sda src");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mknod_block_device_path_creation() {
        let ctx = run_pass("mknod /dev/sda b 8 0");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_mkfifo_block_device_path_creation() {
        let ctx = run_pass("mkfifo /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_link_block_device_path_creation() {
        let ctx = run_pass("link payload.img /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_blkdiscard_in_default_mode() {
        let ctx = run_pass("blkdiscard --secure /dev/nvme0n1");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("destructive block-device target /dev/nvme0n1 via blkdiscard")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_delete_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --delete /dev/sda 1",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via sfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_sfdisk_listing() {
        let ctx = run_pass("sfdisk --json /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_backup_flag() {
        let ctx = run_pass("sfdisk --backup /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_sfdisk_stdin_session_in_default_mode() {
        let ctx = run_pass("sfdisk /dev/sda <<'EOF'\nlabel: gpt\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via sfdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_no_act_stdin_session() {
        let ctx = run_pass("sfdisk --no-act /dev/sda <<'EOF'\nlabel: gpt\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_partno_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk -N 2 /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "sfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_no_act_partno_session() {
        let ctx = run_pass("sfdisk --no-act -N 2 /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sfdisk_partno_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk -N 2 /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "sfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sfdisk_delete_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --delete /dev/sda 1",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via sfdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_part_label_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --part-label /dev/sda 1 rootfs",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_part_type_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --part-type /dev/sda 1 0fc63daf-8483-4772-8e79-3d69d8477de4",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_part_uuid_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --part-uuid /dev/sda 1 11111111-2222-3333-4444-555555555555",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_activate_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --activate /dev/sda 1",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_disk_id_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --disk-id /dev/sda 0x1234abcd",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_part_attrs_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --part-attrs /dev/sda 1 RequiredPartition",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_sfdisk_reorder_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --reorder /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sfdisk_part_label_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sfdisk --part-label /dev/sda 1 rootfs",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sfdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sgdisk_attribute_set_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk -A 4:set:2 /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sgdisk_mbr_to_gpt_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --mbrtogpt /dev/sda",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via sgdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sgdisk_randomize_guids_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --randomize-guids /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_sgdisk_sort_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "sgdisk --sort /dev/sda",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via sgdisk",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_activate_without_partition_numbers() {
        let ctx = run_pass("sfdisk --activate /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_part_label_inspection() {
        let ctx = run_pass("sfdisk --part-label /dev/sda 1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_part_type_inspection() {
        let ctx = run_pass("sfdisk --part-type /dev/sda 1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_part_uuid_inspection() {
        let ctx = run_pass("sfdisk --part-uuid /dev/sda 1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_part_attrs_inspection() {
        let ctx = run_pass("sfdisk --part-attrs /dev/sda 1");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_sfdisk_disk_id_inspection() {
        let ctx = run_pass("sfdisk --disk-id /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_fdisk_listing() {
        let ctx = run_pass("fdisk -l /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_fdisk_list_details() {
        let ctx = run_pass("fdisk --list-details /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_fdisk_get_size_with_bytes() {
        let ctx = run_pass("fdisk --bytes -s /dev/sda");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_parted_print() {
        let ctx = run_pass("parted /dev/sda print");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_scripted_parted_print() {
        let ctx = run_pass("parted --script /dev/sda print");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_parted_help_command() {
        let ctx = run_pass("parted /dev/sda help");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_parted_quit_command() {
        let ctx = run_pass("parted /dev/sda quit");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_parted_select_command() {
        let ctx = run_pass("parted /dev/sda select /dev/sdb");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_ignores_non_destructive_parted_unit_command() {
        let ctx = run_pass("parted /dev/sda unit s");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_scripted_parted_mutation_in_default_mode() {
        let ctx = run_pass("parted --script /dev/sda mklabel gpt");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via parted")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_parted_metadata_mutation_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "parted /dev/sda name 1 rootfs",
            RuleId::CatastrophicPartitionTableStateMutation,
            &[
                "partition table state mutation target /dev/sda",
                "via parted",
            ],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_parted_partition_create_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "parted /dev/sda mkpart primary ext4 1MiB 100MiB",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via parted"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_parted_partition_create_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "parted /dev/sda mkpart primary ext4 1MiB 100MiB",
            RuleId::CatastrophicPartitionLayoutMutation,
            &["partition layout mutation target /dev/sda", "via parted"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_interactive_parted_session_in_default_mode()
    {
        assert_de_floored_surface_requires_approval(
            "parted /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "parted"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_interactive_parted_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "parted /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "parted"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_interactive_fdisk_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_interactive_fdisk_session_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_denies_scripted_fdisk_heredoc_mutation_in_default_mode() {
        let ctx = run_pass("fdisk /dev/sda <<'EOF'\ng\nw\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_scripted_fdisk_mutation_to_normalized_block_device() {
        let ctx = run_pass("fdisk /dev/./sda <<'EOF'\ng\nw\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_scripted_fdisk_herestring_mutation_in_default_mode() {
        let ctx = run_pass(r#"fdisk /dev/sda <<<$'g\nw\n'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_fdisk_herestring_raw_string_line_escapes() {
        let ctx = run_pass(r#"fdisk /dev/sda <<<'g\nw\n'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_scripted_fdisk_boot_flag_toggle_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\na\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_scripted_fdisk_compatibility_toggle_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\nc\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_scripted_fdisk_units_change_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\nu\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_scripted_fdisk_expert_disk_id_change_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\nx\ni\n0x1234\nr\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_scripted_fdisk_expert_geometry_change_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\nx\nh\n1\nr\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_scripted_fdisk_heredoc_inspect_only_payload() {
        let ctx = run_pass("fdisk /dev/sda <<'EOF'\np\nq\nEOF");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_fdisk_mutation_in_default_mode() {
        let ctx = run_pass(r#"printf 'o\nw\n' | fdisk /dev/sda"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_uses_policy_depth_for_static_payload_hard_deny() {
        let command = r#"printf 'o\nw\n' | fdisk /dev/sda"#;
        let default_ctx = run_pass(command);

        assert_eq!(default_ctx.final_decision, Some(Decision::Deny));
        assert!(default_ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));

        let depth_zero_policy = PolicyConfig {
            semantic_expansion: SemanticExpansionPolicy {
                max_nested_parse_depth: 0,
            },
            ..PolicyConfig::default()
        };
        let depth_zero_ctx = run_pass_with(command, depth_zero_policy);

        assert!(!depth_zero_ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_fdisk_mutation_via_printf_percent_s_in_default_mode()
     {
        let ctx = run_pass(
            r#"printf '%s' 'o
w
' | fdisk /dev/sda"#,
        );

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_fdisk_mutation_via_echo_e_in_default_mode() {
        let ctx = run_pass(r#"echo -e 'o\nw\n' | fdisk /dev/sda"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_process_substitution_fdisk_mutation_in_default_mode() {
        let ctx = run_pass(r#"fdisk /dev/sda < <(printf 'g\nw\n')"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via fdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_pipeline_sfdisk_table_rewrite_in_default_mode() {
        let ctx = run_pass(r#"printf 'label: gpt\n' | sfdisk /dev/sda"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via sfdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_denies_process_substitution_sfdisk_table_rewrite() {
        let ctx = run_pass(r#"sfdisk /dev/sda < <(printf 'label: gpt\n')"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicFileSystemDelete
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
                && finding
                    .message
                    .contains("partition table destruction target /dev/sda via sfdisk")
        }));
    }

    #[test]
    fn catastrophic_delete_guard_ignores_pipeline_fdisk_inspect_only_payload() {
        let ctx = run_pass(r#"printf 'p\nq\n' | fdisk /dev/sda"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_pipeline_fdisk_boot_flag_toggle_in_default_mode() {
        assert_de_floored_surface_requires_approval(
            r#"printf 'a\nw\n' | fdisk /dev/sda"#,
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_de_floors_process_substitution_fdisk_boot_flag_toggle() {
        assert_de_floored_surface_requires_approval(
            r#"fdisk /dev/sda < <(printf 'a\nw\n')"#,
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_pipeline_fdisk_boot_flag_toggle_in_default_mode()
     {
        assert_de_floored_surface_requires_approval(
            r#"printf 'a\nw\n' | fdisk /dev/sda"#,
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }

    #[test]
    fn catastrophic_delete_guard_ignores_pipeline_fdisk_inspect_only_payload_via_echo_e() {
        let ctx = run_pass(r#"echo -e 'p\nq\n' | fdisk /dev/sda"#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_delete_guard_requires_approval_for_scripted_fdisk_boot_flag_toggle_in_default_mode()
     {
        assert_de_floored_surface_requires_approval(
            "fdisk /dev/sda <<'EOF'\na\nw\nEOF",
            RuleId::CatastrophicPartitionTableSession,
            &["partition table session target /dev/sda", "fdisk"],
        );
    }
}
