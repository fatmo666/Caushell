//! Byte recovery and effect completeness are distinct obligations. This pass
//! may retire only its consumer's native-byte gap after strict argv binding
//! and the existing target resolver have accounted for every child effect.
//! Policy guards still decide whether those effects are authorized.
use std::collections::BTreeMap;

use caushell_profile::{Effect, EffectKind, ProfileRegistry, ResolveInvocationArtifactResult};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Decision, EvidenceKind, FilesystemObservationSource, NativeBoundEffectsProof,
    NativeInputEffectEvidence, NativePathEffectReference, PathResolution, PathTargetFact, RuleId,
    SemanticResolution, StreamRecordEncoding,
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
    rejected_nul_records: bool,
) -> bool {
    if effect.state_operation.is_some()
        || effect.repository_operation.is_some()
        || effect.database_operation.is_some()
        || effect.terminal_session_operation.is_some()
        || effect.shell_job_operation.is_some()
        || effect.interactive_escape_surface.is_some()
        || (!effect.extensions.is_empty()
            && !(rejected_nul_records
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

fn prove(
    ctx: &RunnerContext,
    registry: &ProfileRegistry,
    facts: &[&PathTargetFact],
    node: &str,
    rejected_nul_records: bool,
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
        if *checks > 65_536
            || child.origin_kind != ExecutionUnitOriginKind::StaticXargs
            || records
                .iter()
                .any(|r| r.parent_execution_node_id == child.source_node_id)
        {
            return None;
        }
        let ResolveInvocationArtifactResult::Resolved(invocation) = &child.result else {
            return None;
        };
        if invocation
            .bound
            .effects
            .iter()
            .any(|e| !modeled(&invocation.bound, e, rejected_nul_records))
        {
            return None;
        }
        let profile = registry
            .lookup(&invocation.normalized_command_name)
            .profile?;
        let rebound =
            super::symbolic_native_inputs::strictly_bound_invocation(profile, invocation)?;
        if rebound.effects != invocation.bound.effects
            || rebound
                .effects
                .iter()
                .any(|e| !modeled(&rebound, e, rejected_nul_records))
        {
            return None;
        }
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
        let facts = caushell_query::PathTargetQuery::new(ctx.request().sequence_no)
            .execute(caushell_query::QuerySession::from_session(&staged));
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
            // Mutating annotations require a known pathname route. A rejected
            // NUL decode may leave bounded effects; a missing observation or
            // unsupported record format cannot establish that route.
            let rejected_nul_records =
                gap.rejected_candidate_encoding == Some(StreamRecordEncoding::Nul);
            let Some(proof) = prove(
                ctx,
                &self.registry,
                &facts,
                &node,
                rejected_nul_records,
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
