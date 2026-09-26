use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::RuleId;

use crate::support::{decision_for_rule_action, graph_backed_execution_resolve_records};

/// Requests approval before a command signals or resumes another process/job.
pub struct ProcessControlGuardPass;

impl SessionAnalysisPass for ProcessControlGuardPass {
    fn name(&self) -> &'static str {
        "process_control_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        // Most commands have no process-control effect. Keep the common path cheap;
        // graph-backed records below ensure stale or unresolved candidates do not fire.
        let has_control_candidate = ctx.execution_unit_resolve_records().iter().any(|record| {
            matches!(&record.result, ResolveInvocationArtifactResult::Resolved(resolved)
                if resolved.bound.effects.iter().any(|effect| effect.kind == EffectKind::ControlProcess))
        });
        if !has_control_candidate {
            return;
        }

        let reasons: Vec<_> = graph_backed_execution_resolve_records(ctx)
            .into_iter()
            .filter_map(|record| {
                let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                    return None;
                };
                resolved.bound.effects.iter().any(|effect| effect.kind == EffectKind::ControlProcess)
                    .then(|| format!(
                        "{} ({}) has a resolved process-control effect; process control requires approval unless policy overrides this rule",
                        resolved.normalized_command_name, resolved.bound.form_id.as_str()
                    ))
            })
            .collect();
        let action = ctx.policy().rule_policy.action_for(RuleId::ProcessControl);
        for reason in reasons {
            ctx.add_finding(RuleId::ProcessControl, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::ProcessControl, decision, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DecisionAssemblyPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::PassRunner;
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RulePolicyEntry,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
        ShellStateSnapshot,
    };

    fn run(command: &str, registry: ProfileRegistry, action: RuleAction) -> RunnerContext {
        let request = CheckRequest {
            session_id: SessionId::new("process-test"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: ShellStateSnapshot::new("/workspace".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some("/workspace".into()),
        };
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::ProcessControl, RulePolicyEntry::new(action));
        let mut ctx = RunnerContext::with_policy(request, policy);
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        // The guard consumes resolved effects, not optional derived action metadata.
        runner.register_session_analysis_pass(ProcessControlGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn controls_require_approval_and_policy_can_observe_or_deny() {
        for command in [
            "kill 1234",
            "kill -9 1234",
            "kill -s TERM 1234",
            "kill \"$pid\"",
            "pkill -f service",
            "killall service",
            "fg %1",
            "bg %1",
        ] {
            for (action, decision) in [
                (RuleAction::NeedApproval, Decision::NeedApproval),
                (RuleAction::Observe, Decision::Allow),
                (RuleAction::Deny, Decision::Deny),
            ] {
                let ctx = run(command, ProfileRegistry::built_in().unwrap(), action);
                assert_eq!(ctx.final_decision, Some(decision), "{command}, {action:?}");
                assert!(
                    ctx.findings
                        .iter()
                        .any(|f| f.rule_id == RuleId::ProcessControl),
                    "{command}"
                );
            }
        }
    }

    #[test]
    fn probes_and_unrelated_commands_skip_process_findings() {
        for command in [
            "echo ok",
            "kill -0 1234",
            "kill -s 0 1234",
            "kill -n 0 1234",
            "kill --signal 0 1234",
            "kill -l",
            "kill -l TERM",
            "kill -L",
            "kill --list",
            "pkill -0 service",
            "pkill -0 -f service",
            "killall -0 service",
            "killall -s 0 service",
            "killall --signal=0 service",
            "killall -l",
            "killall -l service",
        ] {
            let ctx = run(
                command,
                ProfileRegistry::built_in().unwrap(),
                RuleAction::NeedApproval,
            );
            assert!(
                !ctx.findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::ProcessControl),
                "{command}"
            );
            if command != "echo ok" {
                assert!(
                    ctx.execution_unit_resolve_records()
                        .iter()
                        .any(|record| matches!(
                            record.result,
                            ResolveInvocationArtifactResult::Resolved(_)
                        )),
                    "{command} must resolve rather than skip by accident"
                );
            }
        }
    }

    #[test]
    fn unsupported_probe_options_are_not_resolved_as_readonly() {
        for command in [
            "kill -0 --timeout 1000 TERM 1234",
            "pkill -0 --unknown service",
            "killall -0 --unknown service",
        ] {
            let ctx = run(
                command,
                ProfileRegistry::built_in().unwrap(),
                RuleAction::NeedApproval,
            );
            assert!(
                ctx.execution_unit_resolve_records()
                    .iter()
                    .all(|record| !matches!(
                        record.result,
                        ResolveInvocationArtifactResult::Resolved(_)
                    )),
                "{command}"
            );
        }
    }

    #[test]
    fn unprojected_control_records_do_not_trigger_the_guard() {
        let resolved = run(
            "kill 1234",
            ProfileRegistry::built_in().unwrap(),
            RuleAction::NeedApproval,
        );
        let mut ctx = RunnerContext::new(resolved.request().clone());
        ctx.set_execution_unit_resolve_records(resolved.execution_unit_resolve_records().to_vec());
        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        ProcessControlGuardPass.run(
            SessionView::new(&graph, &summary),
            SessionView::new(&graph, &summary),
            &mut ctx,
        );
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }

    #[test]
    fn custom_control_effect_does_not_require_known_command_name_or_extracted_semantics() {
        let profile = load_command_profile_from_str(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: control-tool
forms:
  - id: control
    effects:
      - kind: control_process
        target:
          kind: slot
          name: targets
    parameters:
      - name: targets
        semantic:
          kind: process_target
          target_kind: unknown
          broad_match: false
        binding:
          kind: remaining_positionals
        cardinality: required_many
"#,
        )
        .unwrap();
        let ctx = run(
            "control-tool 1234",
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
            RuleAction::NeedApproval,
        );
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert_eq!(ctx.findings.len(), 1);
    }
}
