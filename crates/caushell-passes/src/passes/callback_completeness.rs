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
    if !records.iter().any(|record| matches!(&record.result,
        ResolveInvocationArtifactResult::Resolved(r) if r.bound.effects.iter().any(|e|
            e.kind == EffectKind::DispatchCommand && matches!(&e.target,
                EffectTarget::Dispatch(t) if matches!(t.command, DispatchCommandSource::CommandString { .. }))))) {
        return;
    }
    let parents = records
        .iter()
        .map(|r| (r.source_node_id.clone(), r.parent_execution_node_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut incomplete = BTreeSet::new();
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
        if unresolved {
            owners.push(record.source_node_id.clone());
        }
    }
    for payload in payloads {
        if matches!(payload.resolution, NestedPayloadResolution::Parsed { .. }) {
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
            owners.push(owner);
        }
    }
    for mut node in owners {
        let mut visited = BTreeSet::new();
        while visited.insert(node.clone()) {
            incomplete.insert(node.clone());
            let Some(parent) = parents.get(&node) else {
                break;
            };
            node = parent.clone();
        }
    }
    for record in records {
        if !incomplete.contains(&record.source_node_id) {
            continue;
        }
        let ResolveInvocationArtifactResult::Resolved(r) = &mut record.result else {
            continue;
        };
        if r.bound.effects.iter().any(|e| e.kind == EffectKind::DispatchCommand && matches!(&e.target,
            EffectTarget::Dispatch(t) if matches!(t.command, DispatchCommandSource::CommandString { .. }))) {
            r.bound.operation_semantics_unresolved = true;
            r.bound.residuals.push(Residual::new(ResidualKind::UnboundPayload, ResidualSurface::Payload,
                "native callback analysis is incomplete"));
        }
    }
}
