//! Byte recovery and effect completeness are distinct obligations. This pass
//! may retire only its consumer's native-byte gap after strict argv binding
//! and the existing target resolver have accounted for every child effect.
//! Policy guards still decide whether those effects are authorized.
use std::collections::BTreeMap;

use caushell_profile::{
    BoundInvocation, BoundValue, CommandProfile, Effect, EffectKind, EffectTarget,
    OptionScopePolicy, PayloadSource, ProfileRegistry, ProfileSourceKind,
    ResolveInvocationArtifactResult, ResolvedInvocationArtifact, SemanticType, argument_structure,
    bind_invocation, select_invocation,
};
use caushell_query::QuerySession;
use caushell_runner::{
    ExecutionUnitOriginKind, ExecutionUnitResolveRecord, RunnerContext, SessionAnalysisPass, SessionView,
};
use caushell_types::{
    Decision, EvidenceKind, FilesystemObservationSource, ImplicitInputSource,
    NativeBoundEffectsProof, NativeInputDecodeEvidence, NativeInputEffectEvidence,
    NativePathEffectReference, PathResolution, PathTargetFact, PathTargetOperation, RuleId,
    RuntimeArgumentDomain, SemanticResolution, StreamRecordEncoding,
};

pub struct ValidateNativeEffectsPass {
    registry: ProfileRegistry,
}
impl ValidateNativeEffectsPass {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self { registry }
    }
}

fn modeled(
    invocation: &caushell_profile::BoundInvocation,
    effect: &Effect,
    metadata_route_proved: bool,
) -> bool {
    if effect.state_operation.is_some()
        || effect.repository_operation.is_some()
        || effect.database_operation.is_some()
        || effect.terminal_session_operation.is_some()
        || effect.shell_job_operation.is_some()
        || effect.interactive_escape_surface.is_some()
        || (!effect.extensions.is_empty()
            && !(metadata_route_proved
                && crate::path::checked_metadata_mutation_for_target(invocation, effect).is_some()))
    {
        return false;
    }
    // Only an explicit empty semantic projection proves a slot effect absent.
    // Missing slots and unknown values remain applicable. Use the same query
    // as the path resolver; do not infer absence from an empty operand vector.
    if crate::path::path_target_is_inapplicable(invocation, &effect.target) {
        return effect.resource_namespace.is_none();
    }
    if super::resolve_path_targets::path_mutation_kind(effect.kind).is_some() {
        return effect.filesystem_namespace_impact()
            == caushell_profile::FilesystemNamespaceImpact::PathMutation;
    }
    matches!(
        effect.kind,
        EffectKind::ReadPath
            | EffectKind::TargetPath
            | EffectKind::ConsumeStdin
            | EffectKind::TransformData
    ) && effect.filesystem_namespace_impact()
        == caushell_profile::FilesystemNamespaceImpact::Neutral
}

fn resolved(fact: &PathTargetFact) -> bool {
    if fact.observations.is_empty()
        || fact
            .observations
            .iter()
            .any(|o| o.source == FilesystemObservationSource::Unavailable)
    {
        return false;
    }
    match &fact.resolution {
        SemanticResolution::Resolved {
            value: PathResolution::Concrete { path },
        } => !path.is_empty(),
        SemanticResolution::Resolved {
            value:
                PathResolution::BoundedPathSet {
                    roots,
                    may_escape: false,
                },
        } => !roots.is_empty(),
        _ => false,
    }
}

/// In a leading-options interpreter, a fixed script operand ends option
/// ownership before the appended xargs fields. Keep the file authorization
/// and all other effects; this proves nothing about what the script does.
fn fixed_script_binding(
    ctx: &RunnerContext,
    session: QuerySession<'_>,
    facts: &[&PathTargetFact],
    child: &ExecutionUnitResolveRecord,
    profile: &CommandProfile,
    invocation: &ResolvedInvocationArtifact,
) -> Option<(BoundInvocation, String, NativePathEffectReference)> {
    let argv = &invocation.materialized_projection.invocation;
    let [file, tail] = argv.args.as_slice() else {
        return None;
    };
    if profile.trust.source != ProfileSourceKind::BuiltIn
        || !matches!(profile.primary_name(), "perl" | "python")
        || profile.option_scope != OptionScopePolicy::LeadingOptions
        || invocation.bound.form_id.as_str() != "script_file"
        || !invocation.bound.applied_modifiers.is_empty()
        || !invocation.bound.configured_inputs.is_empty()
        || !invocation.bound.configured_execution_sources.is_empty()
        || invocation.bound.operation_semantics_unresolved
        || !invocation.bound.residuals.is_empty()
        || file.implicit_input_source.is_some()
        || tail.implicit_input_source != Some(ImplicitInputSource::StdinData)
        || tail.node_kind != "runtime_argument_list"
        || !argument_structure(file)
            .exact_value()
            .is_some_and(|value| !value.is_empty() && !value.starts_with('-'))
    {
        return None;
    }
    // Already decoded shell operands also carry the runtime-data bit. The
    // dispatch record identifies which bytes actually came from xargs stdin.
    let [input] = child.inherited_scope.native_argument_inputs.as_slice() else {
        return None;
    };
    let tail_range = tail.span.start_byte..tail.span.end_byte;
    if !input.origin.stdin
        || input.consumer_node_id != child.source_node_id
        || input.origin.producer_node_id != child.parent_execution_node_id
        || input.origin.data_ranges.as_slice() != [tail_range]
        || !input.projections.is_empty()
        || file.span.end_byte > tail.span.start_byte
    {
        return None;
    }
    let mut scripts = invocation.bound.effects.iter().filter_map(|effect| {
        let (EffectKind::ExecutePayload, EffectTarget::Slot(slot)) = (&effect.kind, &effect.target)
        else {
            return None;
        };
        Some(slot)
    });
    let script = scripts.next()?;
    if scripts.next().is_some() {
        return None;
    }
    let parameter = invocation
        .bound
        .bound_parameters
        .iter()
        .find(|p| &p.name == script)?;
    if !matches!(&parameter.semantic, SemanticType::Payload(p)
            if p.source == PayloadSource::ScriptFileRef && !p.language.is_shell())
        || !matches!(parameter.values.as_slice(), [BoundValue::Argument { span, .. }]
            if span == &file.span)
        || invocation.bound.bound_parameters.iter().any(|p| {
            p.values
                .iter()
                .any(|value| matches!(value, BoundValue::ImplicitInput { .. }))
                && p.semantic != SemanticType::PlainValue
        })
    {
        return None;
    }
    if !invocation.bound.bound_parameters.iter().any(|p| {
        p.semantic == SemanticType::PlainValue
            && p.values.iter().any(|value| {
                matches!(value, BoundValue::ImplicitInput {
                    source: caushell_profile::ImplicitInputSource::StdinData, origin: Some(origin), ..
                } if origin.span == tail.span && !origin.single_field)
            })
    }) {
        return None;
    }
    let mut prefix = argv.clone();
    prefix.args.truncate(1);
    let selection = select_invocation(profile, &prefix).ok()?;
    let rebound = bind_invocation(profile, &prefix, &selection);
    if rebound.form_id != invocation.bound.form_id
        || rebound.effects != invocation.bound.effects
        || rebound.operation_semantics_unresolved
        || !rebound.residuals.is_empty()
    {
        return None;
    }
    let checks = crate::support::file_execution_checks(ctx, session);
    let check = checks.iter().find(|check| {
        check.source == child.source_node_id
            && check.slot == script.as_str()
            && check.exempt
            && check.file_targets_resolved
    })?;
    let mut script_facts = facts.iter().filter(|fact| {
        fact.source_node_id == child.source_node_id.0
            && check.slots.contains(&fact.slot_name)
            && fact.operation == PathTargetOperation::ExecuteFile
    });
    let fact = script_facts.next()?;
    if script_facts.next().is_some() || !resolved(fact) {
        return None;
    }
    Some((
        rebound,
        script.as_str().to_owned(),
        NativePathEffectReference {
            source_node_id: fact.source_node_id.clone(),
            effect_key: fact.effect_key.clone(),
            slot_name: fact.slot_name.clone(),
        },
    ))
}

/// A batched native find action retains the argv boundary of the one input
/// field inside the callback. For a strictly bound reader, namespace
/// effects then close even if the producer's input bytes remain unknown.
fn closed_find_dispatch(
    registry: &ProfileRegistry,
    records: &[ExecutionUnitResolveRecord],
    child: &ExecutionUnitResolveRecord,
    invocation: &ResolvedInvocationArtifact,
) -> bool {
    use caushell_profile::{ArgumentFieldCount, CommandLookupDomain};
    use super::symbolic_native_inputs::{read_effect, strictly_bound_invocation};
    use caushell_types::NativeArgvEffectEnvelope;

    let bound = &invocation.bound;
    let [region] = bound.argument_regions.as_slice() else {
        return false;
    };
    if invocation.normalized_command_name != "find"
        || bound.form_id.as_str() != "exec_command"
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || region.id != "exec"
        || !matches!(child.bindings.command_lookup_domain(), CommandLookupDomain::External)
        || !registry.lookup("find").profile.is_some_and(|p| p.trust.source == ProfileSourceKind::BuiltIn)
        || !bound.effects.iter().all(|effect| {
            (read_effect(effect) && modeled(bound, effect, false))
                || (effect.kind == EffectKind::DispatchCommand
                    && matches!(&effect.target, EffectTarget::Dispatch(_))
                    && effect.extensions.is_empty())
        })
    {
        return false;
    }
    let args = &invocation.materialized_projection.invocation.args;
    let exact = |index, word: &str| {
        args.get(index)
            .is_some_and(|arg| argument_structure(arg).exact_value() == Some(word))
    };
    let mut dynamic = args.iter().enumerate()
        .filter(|(_, arg)| argument_structure(arg).exact_value().is_none());
    let Some((index, arg)) = dynamic.next() else {
        return false;
    };
    if dynamic.next().is_some()
        || index <= region.command_index
        || index >= region.end_index.saturating_sub(1)
        || region.end_index.checked_add(1) != Some(args.len())
        || !exact(region.end_index, "+")
        || !exact(region.end_index - 1, "{}")
        || !exact(region.command_index, "diff")
        || caushell_profile::native_diff_anchor(arg).is_none()
        || argument_structure(arg).fields != ArgumentFieldCount::ExactlyOne
    {
        return false;
    }
    let [input] = child.inherited_scope.native_argument_inputs.as_slice() else {
        return false;
    };
    if !input.origin.stdin
        || input.consumer_node_id != child.source_node_id
        || input.origin.producer_node_id != child.parent_execution_node_id
        || input.origin.data_ranges.as_slice() != [arg.span.start_byte..arg.span.end_byte]
        || !input.projections.is_empty()
    {
        return false;
    }
    let mut descendants = records.iter().filter(|r| r.parent_execution_node_id == child.source_node_id);
    let Some(leaf) = descendants.next() else {
        return false;
    };
    let ResolveInvocationArtifactResult::Resolved(compare) = &leaf.result else {
        return false;
    };
    let Some(profile) = registry.lookup("diff").profile else {
        return false;
    };
    if descendants.next().is_some()
        || records.iter().any(|r| r.parent_execution_node_id == leaf.source_node_id)
        || leaf.origin_kind != ExecutionUnitOriginKind::Dispatch
        || compare.normalized_command_name != "diff"
        || compare.bound.form_id.as_str() != "compare_paths"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !matches!(leaf.bindings.command_lookup_domain(), CommandLookupDomain::External)
        || !caushell_profile::native_effect_contract_is_closed_in_domain(
            profile, NativeArgvEffectEnvelope::ContentRead, leaf.bindings.command_lookup_domain(),
        )
        || !compare.bound.bound_parameters.iter().any(|parameter| {
            parameter.name.as_str() == "anchor_operand"
                && matches!(parameter.values.as_slice(), [BoundValue::ImplicitInput {
                    source: caushell_profile::ImplicitInputSource::StdinData,
                    origin: Some(origin), ..
                }] if origin.span == arg.span && origin.single_field)
        })
    {
        return false;
    }
    strictly_bound_invocation(profile, compare).is_some_and(|strict| {
        strict.effects == compare.bound.effects
            && strict.effects.iter().all(|effect| read_effect(effect) && modeled(&strict, effect, false))
    })
}

fn prove(
    ctx: &RunnerContext,
    session: QuerySession<'_>,
    registry: &ProfileRegistry,
    facts: &[&PathTargetFact],
    node: &str,
    gap: &NativeInputDecodeEvidence,
    checks: &mut usize,
) -> Option<NativeBoundEffectsProof> {
    let records = ctx.execution_unit_resolve_records();
    *checks = checks
        .saturating_add(records.len().saturating_mul(2))
        .saturating_add(facts.len());
    if *checks > 65_536 {
        return None;
    }
    let parent = records.iter().find(|r| r.source_node_id.0 == node)?;
    let ResolveInvocationArtifactResult::Resolved(parent) = &parent.result else {
        return None;
    };
    if parent.bound.operation_semantics_unresolved
        || !parent.bound.residuals.is_empty()
        || parent
            .bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "arg_file")
    {
        return None;
    }
    let children = records
        .iter()
        .filter(|r| r.source_node_id.0 != node && r.parent_execution_node_id.0 == node)
        .collect::<Vec<_>>();
    if children.is_empty() {
        return None;
    }
    let mut references = Vec::new();
    for child in children {
        *checks = checks.saturating_add(records.len()).saturating_add(1);
        if *checks > 65_536 || child.origin_kind != ExecutionUnitOriginKind::StaticXargs {
            return None;
        }
        let ResolveInvocationArtifactResult::Resolved(invocation) = &child.result else {
            return None;
        };
        if records.iter().any(|r| r.parent_execution_node_id == child.source_node_id) {
            *checks = checks.saturating_add(records.len().saturating_mul(2));
            if *checks > 65_536
                || parent.normalized_command_name != "xargs"
                || !["null_delimited", "replace_token"].into_iter().all(|required| {
                    parent.bound.applied_modifiers.iter().any(|flag| flag.as_str() == required)
                })
                || !closed_find_dispatch(registry, records, child, invocation)
            {
                return None;
            }
            continue;
        }
        // A rejected empty snapshot keeps the static child. Its argv must
        // still carry the separately proved NUL path domain from stdin.
        let metadata_route_proved = gap.rejected_candidate_encoding == Some(StreamRecordEncoding::Nul)
            || (gap.empty_nul_path_snapshot
                && invocation.materialized_projection.invocation.args.iter().any(|arg| {
                    arg.implicit_input_source == Some(ImplicitInputSource::StdinData)
                        && matches!(&arg.runtime_argument_domain,
                            Some(RuntimeArgumentDomain::PathSet { roots, may_escape: false, .. })
                                if !roots.is_empty())
                }));
        let profile = registry
            .lookup(&invocation.normalized_command_name)
            .profile?;
        let (rebound, script_reference) = match fixed_script_binding(
            ctx,
            session,
            facts,
            child,
            profile,
            invocation,
        ) {
            Some((rebound, script_slot, reference)) => (rebound, Some((script_slot, reference))),
            None => (
                super::symbolic_native_inputs::strictly_bound_invocation(profile, invocation)?,
                None,
            ),
        };
        let covered = |bound: &BoundInvocation, effect: &Effect| {
            modeled(bound, effect, metadata_route_proved)
                || script_reference.as_ref().is_some_and(|(script_slot, _)| {
                    effect.kind == EffectKind::ExecutePayload
                        && matches!(&effect.target, EffectTarget::Slot(slot) if slot.as_str() == script_slot)
                })
        };
        if rebound.effects != invocation.bound.effects
            || invocation
                .bound
                .effects
                .iter()
                .any(|effect| !covered(&invocation.bound, effect))
            || rebound
                .effects
                .iter()
                .any(|effect| !covered(&rebound, effect))
        {
            return None;
        }
        references.extend(script_reference.map(|(_, reference)| reference));
        for (index, effect) in invocation.bound.effects.iter().enumerate() {
            let Some(operation) = super::resolve_path_targets::path_mutation_kind(effect.kind)
            else {
                continue;
            };
            let key = format!("effect:{index}");
            let metadata = (!effect.extensions.is_empty())
                .then(|| crate::path::checked_metadata_mutation_for_target(&rebound, effect))
                .flatten();
            let mut matched = false;
            for fact in facts {
                *checks += 1;
                if *checks > 65_536 {
                    return None;
                }
                if fact.source_node_id != child.source_node_id.0 || fact.effect_key != key {
                    continue;
                }
                matched = true;
                let absent =
                    crate::path::path_target_is_inapplicable(&invocation.bound, &effect.target)
                        && matches!(fact.resolution, SemanticResolution::NotApplicable { .. });
                if fact.operation != operation
                    || !(absent || resolved(fact))
                    || metadata.as_ref().is_some_and(|expected| {
                        fact.metadata_mutation.as_ref() != Some(expected)
                    })
                {
                    return None;
                }
                references.push(NativePathEffectReference {
                    source_node_id: fact.source_node_id.clone(),
                    effect_key: fact.effect_key.clone(),
                    slot_name: fact.slot_name.clone(),
                });
            }
            if !matched {
                return None;
            }
        }
    }
    references.sort_by(|a, b| {
        (&a.source_node_id, &a.effect_key, &a.slot_name).cmp(&(
            &b.source_node_id,
            &b.effect_key,
            &b.slot_name,
        ))
    });
    references.dedup();
    Some(NativeBoundEffectsProof {
        argument_ownership_complete: true,
        path_targets: references,
    })
}

impl SessionAnalysisPass for ValidateNativeEffectsPass {
    fn name(&self) -> &'static str {
        "validate_native_effects"
    }
    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        if !super::resolve_path_targets::namespace_operations_complete(ctx, true) {
            return;
        }
        // The policy guards consume these same staged facts. Never consult an
        // independent filesystem snapshot to override their unresolved targets.
        let session = QuerySession::from_session(&staged);
        let facts = caushell_query::PathTargetQuery::new(ctx.request().sequence_no).execute(session);
        let gaps = ctx
            .evidence
            .iter()
            .filter_map(|e| match &e.kind {
                EvidenceKind::NativeInputDecode(g) if !g.complete && g.gap.is_some() => {
                    Some((g.node_id.clone(), g.clone()))
                }
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        let mut checks = 0;
        for (node, gap) in gaps {
            let owner = super::observed_native_inputs::gap_source(&node);
            if !ctx.decision_proposals.iter().any(|p| {
                p.source_pass == owner
                    && p.rule_id == RuleId::SelectionError
                    && p.decision == Decision::NeedApproval
            }) {
                continue;
            }
            let Some(proof) = prove(
                ctx,
                session,
                &self.registry,
                &facts,
                &node,
                &gap,
                &mut checks,
            ) else {
                continue;
            };
            let children = ctx
                .execution_unit_resolve_records()
                .iter()
                .filter(|r| r.source_node_id.0 != node && r.parent_execution_node_id.0 == node)
                .map(|r| r.source_node_id.0.clone())
                .collect();
            retire_byte_gap(ctx, &owner);
            super::observed_native_inputs::emit_proof(
                ctx,
                NativeInputEffectEvidence {
                    control_envelope: false,
                    effect_envelope: None,
                    bound_effects: Some(proof),
                    node_id: node,
                    producer_node_id: gap.producer_node_id,
                    child_node_ids: children,
                    observation_gap: gap.gap.unwrap(),
                },
            );
        }
    }
}

fn retire_byte_gap(ctx: &mut RunnerContext, owner: &str) {
    ctx.decision_proposals.retain(|p| {
        !(p.source_pass == owner
            && p.rule_id == RuleId::SelectionError
            && p.decision == Decision::NeedApproval)
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use caushell_profile::{
        BoundInvocation, BoundParameter, CommandName, EffectTarget, FormId, SemanticType, SlotName,
    };
    use caushell_types::*;
    #[test]
    fn an_empty_projection_is_absence_but_a_missing_or_unknown_slot_is_not() {
        let mut bound =
            BoundInvocation::new(CommandName::new("anonymous"), FormId::new("selected"));
        let effect = Effect::new(EffectKind::ExecutePayload).for_slot("optional_code");
        assert!(!modeled(&bound, &effect, false));
        let p = BoundParameter::new(SlotName::new("optional_code"), SemanticType::PlainValue);
        bound.bound_parameters.push(p);
        assert!(!modeled(&bound, &effect, false));
        bound.bound_parameters[0].projected_values = Some(vec![]);
        assert!(modeled(&bound, &effect, false));
        let mut annotated = effect.clone();
        annotated
            .extensions
            .insert("unknown_operation".into(), serde_json::json!(true));
        assert!(!modeled(&bound, &annotated, true));
        assert!(!modeled(
            &bound,
            &Effect {
                target: EffectTarget::None,
                ..effect
            },
            false,
        ));
    }
    #[test]
    fn equal_gap_messages_do_not_merge_consumer_or_guard_ownership() {
        let mut ctx = RunnerContext::new(CheckRequest {
            session_id: SessionId::new("owners"),
            sequence_no: CommandSequenceNo(1),
            command: "true".into(),
            shell_state_before: ShellStateSnapshot::new("/work"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/work".into()),
            runtime: RuntimeMetadata {
                runtime_name: "tests".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        });
        let owner = super::super::observed_native_inputs::gap_source("consumer-a");
        let other = super::super::observed_native_inputs::gap_source("consumer-b");
        for (source, rule, decision) in [
            (
                owner.clone(),
                RuleId::SelectionError,
                Decision::NeedApproval,
            ),
            (
                other.clone(),
                RuleId::SelectionError,
                Decision::NeedApproval,
            ),
            (owner.clone(), RuleId::SelectionError, Decision::Deny),
            (
                "another_guard".into(),
                RuleId::SelectionError,
                Decision::NeedApproval,
            ),
            (owner.clone(), RuleId::FileDeletion, Decision::NeedApproval),
        ] {
            ctx.propose_decision(source, rule, decision, "identical diagnostic");
        }
        retire_byte_gap(&mut ctx, &owner);
        assert_eq!(ctx.decision_proposals.len(), 4);
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|p| p.source_pass == other)
        );
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|p| p.decision == Decision::Deny)
        );
        assert!(
            ctx.decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::FileDeletion)
        );
    }
}
