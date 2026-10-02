use caushell_runner::{PendingMutation, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{Evidence, EvidenceKind, NetworkListenerExposureEvidence, RuleId};

pub struct NetworkListenerGuardPass;

impl SessionAnalysisPass for NetworkListenerGuardPass {
    fn name(&self) -> &'static str {
        "network_listener_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        // Fast gate over this request's already-extracted facts. No profile
        // reparse, historical graph scan, DNS or runtime socket inspection.
        if !ctx.pending_mutations().iter().any(|mutation| {
            matches!(mutation,
            PendingMutation::AddExecutionSemantics { semantics, .. }
                if semantics.network_listeners.iter().any(|listener| !listener.has_local_scope()))
        }) {
            return;
        }
        let current = ctx.request().sequence_no;
        let facts = caushell_query::ExecutionSemanticsQuery::new()
            .after_sequence(caushell_types::CommandSequenceNo::new(
                current.0.saturating_sub(1),
            ))
            .before_sequence(current.next())
            .execute(caushell_query::QuerySession::from_session(&staged));
        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::NetworkListenerExposure);
        for fact in facts.semantics() {
            for listener in fact.network_listeners() {
                if listener.has_local_scope() {
                    continue;
                }
                let reason =
                    format!("listener is not statically confined to loopback: {listener:?}");
                ctx.add_evidence(Evidence {
                    rule_id: RuleId::NetworkListenerExposure,
                    summary: reason.clone(),
                    kind: EvidenceKind::NetworkListenerExposure(NetworkListenerExposureEvidence {
                        node_id: fact.source().node_id().0.clone(),
                        command: fact.source().raw_text().into(),
                        listener: listener.clone(),
                    }),
                });
                ctx.add_finding(RuleId::NetworkListenerExposure, reason.clone());
                if let Some(decision) = crate::support::decision_for_rule_action(action) {
                    ctx.propose_decision(
                        self.name(),
                        RuleId::NetworkListenerExposure,
                        decision,
                        reason,
                    );
                }
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

    #[test]
    fn listener_policy_depends_on_declared_semantics_not_command_name() {
        let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: demo-listener}
forms:
  - id: run
    effects:
      - kind: listen_network
        target: {kind: network_listener, host: {slot: bind, default_value: '127.0.0.1'}}
modifiers:
  - id: bind
    matcher: {kind: any_flag, flags: ['--bind']}
    parameters:
      - {name: bind, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: optional_many}
"#;
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
                .unwrap(),
        ));
        runner.register_session_transform_pass(crate::ExtractExecutionSemanticsPass);
        runner.register_session_analysis_pass(NetworkListenerGuardPass);
        runner.register_final_decision_pass(crate::DecisionAssemblyPass);
        for (command, expected) in [
            ("demo-listener", Decision::Allow),
            ("demo-listener --bind=0.0.0.0", Decision::NeedApproval),
        ] {
            let request = CheckRequest {
                session_id: SessionId::new("generic-listener"),
                sequence_no: CommandSequenceNo::new(1),
                command: command.into(),
                shell_state_before: ShellStateSnapshot::new("/work"),
                shell_kind: ShellKind::Bash,
                runtime: RuntimeMetadata {
                    runtime_name: "test".into(),
                    tool_name: None,
                    shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
                },
                home: None,
                workspace_root: Some("/work".into()),
            };
            let mut ctx = RunnerContext::new(request);
            runner.run(
                SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
                &mut ctx,
            );
            assert_eq!(ctx.final_decision, Some(expected));
        }
    }
}
