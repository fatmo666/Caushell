use crate::path::{ExecutableFileReference, unmodeled_executable_path};
use crate::support::ExecutionResolveRecordRef;
use caushell_profile::{
    DispatchCommandSource, EffectKind, EffectTarget, Residual, ResidualKind, ResidualSurface,
    ResolveInvocationArtifactResult,
};
use caushell_runner::{
    ExecutionUnitOriginKind, ExecutionUnitResolveRecord, NestedPayloadParentRef,
    NestedPayloadRecord, NestedPayloadResolution,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate(
    records: &mut [ExecutionUnitResolveRecord],
    payloads: &[NestedPayloadRecord],
) {
    let modeled = payloads
        .iter()
        .filter(|p| matches!(p.resolution, NestedPayloadResolution::ModeledLanguage))
        .filter_map(|p| match &p.parent_ref {
            NestedPayloadParentRef::DerivedInvocation { node_id } => Some(node_id.clone()),
            NestedPayloadParentRef::RootCommand { command_index } => records
                .iter()
                .find(|r| {
                    r.origin_kind == ExecutionUnitOriginKind::TopLevel
                        && r.command_ref.command_index == *command_index
                })
                .map(|r| r.source_node_id.clone()),
        })
        .collect::<BTreeSet<_>>();
    if modeled.is_empty() && !records.iter().any(|record| matches!(&record.result,
        ResolveInvocationArtifactResult::Resolved(r) if r.bound.effects.iter().any(|e|
            e.kind == EffectKind::DispatchCommand && matches!(&e.target,
                EffectTarget::Dispatch(t) if matches!(t.command, DispatchCommandSource::CommandString { .. }))))) {
        return;
    }
    let parents = records
        .iter()
        // Top-level execution records use a self-reference as their anchor.
        .filter(|r| r.parent_execution_node_id != r.source_node_id)
        .map(|r| (r.source_node_id.clone(), r.parent_execution_node_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut incomplete = BTreeMap::new();
    let mut owners = Vec::new();
    for record in records.iter() {
        let unresolved = match &record.result {
            ResolveInvocationArtifactResult::Resolved(r) => {
                r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty()
            }
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => {
                !(record
                    .bindings
                    .function_binding(normalized_command_name)
                    .is_some()
                    && records.iter().any(|child| {
                        child.parent_execution_node_id == record.source_node_id
                            && child.origin_kind == ExecutionUnitOriginKind::FunctionExpansion
                    }))
            }
            _ => true,
        };
        // A gap in an invocation belongs to its parent when describing
        // incomplete children. The invocation already carries its own gap.
        if unresolved && let Some(parent) = parents.get(&record.source_node_id) {
            let unprofiled_file = matches!(
                unmodeled_executable_path(ExecutionResolveRecordRef::relative_to_supplied_base(record)),
                Some(ExecutableFileReference::Known(_))
            );
            owners.push((parent.clone(), unprofiled_file));
        }
    }
    for payload in payloads {
        if matches!(
            payload.resolution,
            NestedPayloadResolution::Parsed { .. } | NestedPayloadResolution::ModeledLanguage
        ) {
            continue;
        }
        let owner = match &payload.parent_ref {
            NestedPayloadParentRef::DerivedInvocation { node_id } => Some(node_id.clone()),
            NestedPayloadParentRef::RootCommand { command_index } => records
                .iter()
                .find(|r| {
                    r.origin_kind == ExecutionUnitOriginKind::TopLevel
                        && r.command_ref.command_index == *command_index
                })
                .map(|r| r.source_node_id.clone()),
        };
        if let Some(owner) = owner {
            // A payload that could not be analyzed may have no child
            // invocation record. Attribute that gap directly to its owner.
            owners.push((owner, false));
        }
    }
    for (mut node, unprofiled_file) in owners {
        let mut visited = BTreeSet::new();
        while visited.insert(node.clone()) {
            *incomplete.entry(node.clone()).or_insert(false) |= unprofiled_file;
            let Some(parent) = parents.get(&node) else {
                break;
            };
            node = parent.clone();
        }
    }
    for record in records {
        let ResolveInvocationArtifactResult::Resolved(r) = &mut record.result else {
            continue;
        };
        let child_gap = incomplete.get(&record.source_node_id);
        if child_gap.is_none() && r.bound.residuals.is_empty() {
            continue;
        }
        let dispatches_payload = modeled.contains(&record.source_node_id)
            || r.bound.effects.iter().any(|effect| {
                effect.kind == EffectKind::DispatchCommand
                    && matches!(&effect.target, EffectTarget::Dispatch(target)
                        if matches!(target.command, DispatchCommandSource::CommandString { .. }))
            });
        if !dispatches_payload {
            continue;
        }
        // Keep the existing conservative verdict for any unresolved
        // dispatch, while identifying only actual descendant/payload gaps.
        r.bound.operation_semantics_unresolved = true;
        if let Some(&unprofiled_file) = child_gap {
            let reason = if unprofiled_file {
                "native child analysis is incomplete: an explicit executable path has no registered profile"
            } else {
                "native child analysis is incomplete"
            };
            r.bound.residuals.push(Residual::new(
                ResidualKind::UnboundPayload,
                ResidualSurface::Payload,
                reason,
            ));
        }
    }
}
