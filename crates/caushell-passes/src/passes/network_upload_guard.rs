use caushell_query::{NetworkEndpointQuery, endpoint_has_loopback_scope};
use caushell_runner::{PendingMutation, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, EvidenceKind, NetworkUploadEvidence, ProvenanceArtifact, ProvenanceEndpointUsage,
    RuleId,
};

pub struct NetworkUploadGuardPass;

impl SessionAnalysisPass for NetworkUploadGuardPass {
    fn name(&self) -> &'static str {
        "network_upload_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        // Current extracted facts are the candidate gate. Unrelated commands
        // never query historical endpoints or revisit profile selection.
        if !ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddProvenanceArtifact {
                    artifact: ProvenanceArtifact::NetworkEndpoint {
                        usage: ProvenanceEndpointUsage::UploadTarget,
                        ..
                    },
                    ..
                } | PendingMutation::AddProvenanceArtifact {
                    artifact: ProvenanceArtifact::NetworkEndpoint { .. },
                    semantics: caushell_types::ProvenanceEdgeSemantics::Consume {
                        domain_label: Some(
                            caushell_types::ProvenanceDomainLabel::EndpointInputScope { .. }
                        ),
                        ..
                    },
                    ..
                }
            )
        }) {
            return;
        }
        let nodes: Vec<_> = ctx
            .execution_unit_resolve_records()
            .iter()
            .map(|record| record.source_node_id.clone())
            .collect();
        let mut flagged = std::collections::BTreeSet::new();
        let uploads: Vec<_> = NetworkEndpointQuery::for_execution_units(
            staged.graph(),
            &nodes,
            ctx.request().sequence_no,
        )
        .into_iter()
        .filter(|endpoint| {
            endpoint.usage == ProvenanceEndpointUsage::UploadTarget
                || endpoint.input_scope.is_some()
        })
        .filter(|endpoint| !endpoint_has_loopback_scope(endpoint.endpoint, endpoint.kind)
            || NetworkEndpointQuery::has_nonlocal_transport_target(staged.graph(), endpoint.execution_node_id))
        .filter_map(|endpoint| {
            let key = (
                endpoint.execution_node_id.clone(),
                endpoint.endpoint.to_string(),
            );
            if flagged.contains(&key) {
                return None;
            }
            let (local_source, unresolved) =
                if endpoint.usage == ProvenanceEndpointUsage::UploadTarget {
                    (None, None)
                } else {
                    match NetworkEndpointQuery::local_request_source(
                        staged.graph(),
                        &endpoint,
                        ctx.policy().runtime_taint.max_hops,
                        ctx.policy().runtime_taint.max_visited_nodes,
                    ) {
                        Ok(Some(source)) => (Some(source), None),
                        Ok(None) => return None,
                        Err(reason) => (None, Some(reason)),
                    }
                };
            let operation = if unresolved.is_some() {
                "sends request data whose file origin cannot be resolved within the analysis budget"
            } else if local_source.is_some() {
                "sends local request data"
            } else {
                "uploads data"
            };
            flagged.insert(key);
            Some((
                format!(
                    "{} {} to {}; the destination or its declared transport route is not statically confined to loopback",
                    endpoint.command, operation, endpoint.endpoint
                ),
                NetworkUploadEvidence {
                    node_id: endpoint.execution_node_id.0.clone(),
                    command: endpoint.command.into(),
                    endpoint: endpoint.endpoint.into(),
                    endpoint_kind: endpoint.kind,
                    local_source,
                    lineage_unresolved: unresolved.is_some(),
                },
            ))
        })
        .collect();
        let action = ctx.policy().rule_policy.action_for(RuleId::NetworkUpload);
        for (reason, evidence) in uploads {
            ctx.add_evidence(Evidence {
                rule_id: RuleId::NetworkUpload,
                summary: reason.clone(),
                kind: EvidenceKind::NetworkUpload(evidence),
            });
            ctx.add_finding(RuleId::NetworkUpload, reason.clone());
            if let Some(decision) = crate::support::decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::NetworkUpload, decision, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::PassRunner;
    use caushell_types::*;

    fn request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("generic-upload"),
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
        }
    }

    #[test]
    fn declarations_not_command_names_control_upload_approval() {
        let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-transfer}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: transfer
    parameters:
      - {name: destination, semantic: {kind: endpoint, endpoint_kind: url, usage: upload_target}, binding: {kind: next_positional}, cardinality: required_one}
    effects: [{kind: network_endpoint, target: {kind: slot, name: destination}}]
modifiers:
  - id: route
    matcher: {kind: any_flag, flags: [--route]}
    parameters:
      - {name: route, semantic: {kind: endpoint, endpoint_kind: url, usage: transport_target}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
    effects: [{kind: network_endpoint, target: {kind: slot, name: route}}]
"#).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        runner.register_session_transform_pass(crate::ExtractEndpointProvenancePass);
        runner.register_session_analysis_pass(NetworkUploadGuardPass);
        runner.register_final_decision_pass(crate::DecisionAssemblyPass);
        for (command, expected) in [
            (
                "arbitrary-transfer https://example.test/",
                Decision::NeedApproval,
            ),
            ("arbitrary-transfer http://localhost/", Decision::Allow),
            (
                "arbitrary-transfer --route http://outside.test/ http://localhost/",
                Decision::NeedApproval,
            ),
            (
                "arbitrary-transfer --route http://localhost:80/ http://localhost/",
                Decision::Allow,
            ),
            ("arbitrary-transfer \"$DEST\"", Decision::NeedApproval),
            (
                "arbitrary-transfer https://example.test/ --unknown",
                Decision::NeedApproval,
            ),
        ] {
            let mut ctx = RunnerContext::new(request(command));
            runner.run(
                SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
                &mut ctx,
            );
            assert_eq!(ctx.final_decision, Some(expected), "{command}: {ctx:#?}");
        }
    }

    #[test]
    fn no_candidate_returns_without_producing_a_finding() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request("ls ."));
        NetworkUploadGuardPass.run(
            SessionView::new(&graph, &summary),
            SessionView::new(&graph, &summary),
            &mut ctx,
        );
        assert!(ctx.findings.is_empty());
        assert!(ctx.evidence.is_empty());
    }
}
