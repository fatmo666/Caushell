use caushell_profile::{
    BoundInvocation, EffectKind, EffectTarget, ResolveInvocationArtifactResult, SemanticType,
};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Decision, Evidence, EvidenceKind, NonShellScriptExecutionEvidence, RuleAction, RuleId,
};
use std::collections::BTreeSet;

pub struct NonShellScriptGuardPass;

fn execution_sources(bound: &BoundInvocation) -> BTreeSet<(String, String)> {
    let mut sources = BTreeSet::new();
    for effect in &bound.effects {
        if effect.kind == EffectKind::DispatchCommand
            && let EffectTarget::Dispatch(target) = &effect.target
            && let Some(runtime) = &target.module_runtime
        {
            sources.insert((runtime.clone(), "module".into()));
        }
        if effect.kind != EffectKind::ExecutePayload {
            continue;
        }
        let semantics = match &effect.target {
            EffectTarget::Slot(slot) => bound
                .bound_parameters
                .iter()
                .filter(|p| {
                    p.name == *slot && !p.values.is_empty() && !p.semantic_values_are_inapplicable()
                })
                .map(|p| &p.semantic)
                .collect::<Vec<_>>(),
            EffectTarget::ImplicitInput(source) => bound
                .bound_implicit_inputs
                .iter()
                .filter(|p| p.source == *source)
                .map(|p| &p.semantic)
                .collect(),
            _ => Vec::new(),
        };
        for semantic in semantics {
            if let SemanticType::Payload(payload) = semantic
                && !payload.language.is_shell()
            {
                sources.insert((
                    payload.language.as_str().into(),
                    payload.source.as_str().into(),
                ));
            }
        }
    }
    sources
}

impl SessionAnalysisPass for NonShellScriptGuardPass {
    fn name(&self) -> &'static str {
        "non_shell_script_guard"
    }

    fn run(&self, _session: SessionView<'_>, _staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let executions = ctx
            .execution_unit_resolve_records()
            .iter()
            .flat_map(|record| {
                let bound = match &record.result {
                    ResolveInvocationArtifactResult::Resolved(r) => Some(&r.bound),
                    ResolveInvocationArtifactResult::SelectionError { partial_bound, .. } => {
                        partial_bound.as_ref()
                    }
                    _ => None,
                };
                bound
                    .into_iter()
                    .flat_map(execution_sources)
                    .map(|(language, source)| NonShellScriptExecutionEvidence {
                        node_id: record.source_node_id.0.clone(),
                        command: record.rendered_command_text.clone(),
                        language,
                        source,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let decision = match ctx
            .policy()
            .rule_policy
            .action_for(RuleId::NonShellScriptExecution)
        {
            RuleAction::Deny => Decision::Deny,
            RuleAction::Observe | RuleAction::NeedApproval => Decision::NeedApproval,
        };
        for execution in executions {
            let reason = format!(
                "{} script execution requires approval ({})",
                execution.language, execution.source
            );
            ctx.add_evidence(Evidence {
                rule_id: RuleId::NonShellScriptExecution,
                summary: reason.clone(),
                kind: EvidenceKind::NonShellScriptExecution(execution),
            });
            ctx.add_finding(RuleId::NonShellScriptExecution, reason.clone());
            ctx.propose_decision(
                self.name(),
                RuleId::NonShellScriptExecution,
                decision,
                reason,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::{PassRunner, SessionView};
    use caushell_types::*;

    #[test]
    fn policy_follows_declared_execution_not_command_name_or_code_spelling() {
        let profiles = [
            ("program-runner", "python", true),
            ("text-reader", "python", false),
            ("shell-runner", "bash", true),
        ]
        .into_iter()
        .map(|(name, language, execute)| {
            let effect = if execute {
                "effects: [{kind: execute_payload, target: {kind: slot, name: body}}]"
            } else {
                ""
            };
            load_command_profile_from_str(&format!(
                r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
forms:
  - id: run
    parameters:
      - name: body
        semantic: {{kind: payload, language: {language}, source: inline_string, recursive: false}}
        binding: {{kind: next_positional}}
        cardinality: required_one
    {effect}
"#
            ))
            .unwrap()
        })
        .collect();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(profiles).unwrap(),
        ));
        runner.register_session_analysis_pass(NonShellScriptGuardPass);
        runner.register_final_decision_pass(crate::DecisionAssemblyPass);
        for (command, expected) in [
            ("program-runner 'pass'", Decision::NeedApproval),
            ("program-runner ''", Decision::NeedApproval),
            ("text-reader 'python3 -c pass'", Decision::Allow),
            ("shell-runner 'echo ok'", Decision::Allow),
        ] {
            let mut shell = ShellStateSnapshot::new("/workspace");
            shell.observability.variables = ShellStateKnowledge::Complete;
            shell.observability.aliases = ShellStateKnowledge::Complete;
            shell.observability.functions = ShellStateKnowledge::Complete;
            let mut ctx = RunnerContext::new(CheckRequest {
                session_id: SessionId::new("declarations"),
                sequence_no: CommandSequenceNo(1),
                command: command.into(),
                shell_state_before: shell,
                shell_kind: ShellKind::Bash,
                home: None,
                workspace_root: Some("/workspace".into()),
                runtime: RuntimeMetadata {
                    runtime_name: "test".into(),
                    tool_name: None,
                    shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
                },
            });
            let graph = SessionGraph::new();
            let summary = SessionSummary::new();
            runner.run(SessionView::new(&graph, &summary), &mut ctx);
            assert_eq!(ctx.final_decision, Some(expected), "{command}");
        }
    }
}
