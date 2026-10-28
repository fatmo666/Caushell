use caushell_profile::{
    BoundInvocation, EffectKind, EffectTarget, PayloadSource, ResolveInvocationArtifactResult,
    SemanticType,
};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Decision, Evidence, EvidenceKind, NonShellScriptExecutionEvidence, RuleAction, RuleId,
};
use std::collections::BTreeSet;

pub struct NonShellScriptGuardPass;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ExecutionSource {
    language: String,
    source: String,
    file_slot: Option<String>,
}

fn execution_sources(bound: &BoundInvocation) -> BTreeSet<ExecutionSource> {
    let mut sources = BTreeSet::new();
    for effect in &bound.effects {
        if effect.kind == EffectKind::DispatchCommand
            && let EffectTarget::Dispatch(target) = &effect.target
            && let Some(runtime) = &target.module_runtime
        {
            sources.insert(ExecutionSource {
                language: runtime.clone(),
                source: "module".into(),
                file_slot: None,
            });
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
                .map(|p| (&p.semantic, Some(p.name.as_str())))
                .collect::<Vec<_>>(),
            EffectTarget::ImplicitInput(source) => bound
                .bound_implicit_inputs
                .iter()
                .filter(|p| p.source == *source)
                .map(|p| (&p.semantic, None))
                .collect(),
            _ => Vec::new(),
        };
        for (semantic, slot) in semantics {
            if let SemanticType::Payload(payload) = semantic
                && !payload.language.is_shell()
            {
                sources.insert(ExecutionSource {
                    language: payload.language.as_str().into(),
                    source: payload.source.as_str().into(),
                    file_slot: slot
                        .filter(|_| payload.source == PayloadSource::ScriptFileRef)
                        .map(str::to_owned),
                });
            }
        }
    }
    sources
}

impl SessionAnalysisPass for NonShellScriptGuardPass {
    fn name(&self) -> &'static str {
        "non_shell_script_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
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
                    .map(|source| {
                        (
                            NonShellScriptExecutionEvidence {
                                node_id: record.source_node_id.0.clone(),
                                command: record.rendered_command_text.clone(),
                                language: source.language,
                                source: source.source,
                            },
                            source.file_slot,
                        )
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
        let file_checks =
            if decision != Decision::Deny && executions.iter().any(|(_, slot)| slot.is_some()) {
                crate::support::file_execution_checks(
                    ctx,
                    caushell_query::QuerySession::from_session(&staged),
                )
            } else {
                Vec::new()
            };
        for (execution, file_slot) in executions {
            // This is existing file-execution authority, not a proof of the
            // program's body. Match the exact owning execution unit AND slot;
            // one file grant cannot cover a sibling inline/module/stdin input.
            // Other passes still enforce tainted execution, gaps and Deny.
            if decision != Decision::Deny
                && file_slot.as_ref().is_some_and(|slot| {
                    file_checks.iter().any(|check| {
                        check.source.0 == execution.node_id
                            && check.slot == *slot
                            && check.exempt
                            && check.has_resolved_file_target
                    })
                })
            {
                continue;
            }
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

    fn run_file_contract(command: &str, second_source: &str, path_facts: bool) -> RunnerContext {
        let parameters = [("first", "script_file_ref"), ("second", second_source)]
            .into_iter()
            .map(|(name, source)| {
                let projection = if source == "script_file_ref" {
                    format!("structured_projection: {{branches: [], fallback: {{name: {name}_path, semantic: {{kind: path, role: read, purpose: script_source}}}}}}")
                } else {
                    String::new()
                };
                format!(r#"
      - name: {name}
        semantic: {{kind: payload, language: opaque, source: {source}, recursive: true}}
        binding: {{kind: next_positional}}
        cardinality: required_one
        {projection}
"#)
            }).collect::<String>();
        let profile = load_command_profile_from_str(&format!(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: custom-file-runner}}
forms:
  - id: run
    parameters:
{parameters}
    effects:
      - {{kind: read_path, path_access: content_open, target: {{kind: slot, name: first_path}}}}
      - {{kind: execute_payload, target: {{kind: slot, name: first}}}}
      - {{kind: execute_payload, target: {{kind: slot, name: second}}}}
{second_read}
"#,
            second_read = if second_source == "script_file_ref" {
            "      - {kind: read_path, path_access: content_open, target: {kind: slot, name: second_path}}"
            } else {
                ""
            }
        ))
        .unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        if path_facts {
            runner.register_session_transform_pass(crate::ExtractPathFactsPass);
            runner.register_session_transform_pass(crate::ResolvePathTargetsPass);
        }
        runner.register_session_analysis_pass(NonShellScriptGuardPass);
        runner.register_final_decision_pass(crate::DecisionAssemblyPass);
        let mut shell = ShellStateSnapshot::new("/workspace");
        shell.observability.variables = ShellStateKnowledge::Complete;
        shell.observability.aliases = ShellStateKnowledge::Complete;
        shell.observability.functions = ShellStateKnowledge::Complete;
        let mut ctx = RunnerContext::new(CheckRequest {
            session_id: SessionId::new("file-contract"),
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
        crate::test_support::supply_filesystem(&mut ctx);
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn file_authority_follows_generic_contract_slots_not_language_names() {
        for (command, expected) in [
            ("custom-file-runner ./a /tmp/b", Decision::Allow),
            ("custom-file-runner ./a /outside/b", Decision::NeedApproval),
            ("custom-file-runner /outside/a ./b", Decision::NeedApproval),
            (
                "custom-file-runner ./a \"$UNKNOWN\"",
                Decision::NeedApproval,
            ),
        ] {
            let ctx = run_file_contract(command, "script_file_ref", true);
            assert_eq!(
                ctx.final_decision,
                Some(expected),
                "{command}: {:?}",
                ctx.findings
            );
        }
        let ctx = run_file_contract("custom-file-runner ./a ./b", "inline_string", true);
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    }

    #[test]
    fn declared_file_inputs_without_target_proof_still_require_approval() {
        let ctx = run_file_contract("custom-file-runner ./a ./b", "script_file_ref", false);
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    }

    #[test]
    fn non_file_stream_targets_do_not_authorize_an_opaque_body() {
        let ctx = run_file_contract(
            "custom-file-runner <(producer) <(producer)",
            "script_file_ref",
            true,
        );
        assert!(ctx.pending_mutations().iter().any(|m| matches!(m,
            caushell_runner::PendingMutation::AddPathTargetFact { fact, .. }
            if fact.operation == PathTargetOperation::ExecuteFile
            && matches!(fact.resolution, SemanticResolution::NotApplicable { .. })
        )));
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
    }

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
