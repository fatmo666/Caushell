use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{
    ExecutionUnitOriginKind, ExecutionUnitResolveRecord, NestedPayloadParentRef,
    NestedPayloadResolution, RunnerContext,
};

pub(crate) fn endpoint_is_loopback(
    ctx: &RunnerContext,
    source: &caushell_graph::NodeId,
    endpoint: Option<&str>,
    kind: caushell_types::ProvenanceEndpointKind,
) -> bool {
    let Some(endpoint) = endpoint else {
        return false;
    };
    if owner_namespace_is_proved(ctx, source)
        && let Some(resolved) = ctx
            .resource_authority()
            .and_then(|s| s.resolve_target(endpoint))
    {
        return caushell_query::endpoint_has_loopback_scope(&resolved.endpoint, kind);
    }
    caushell_query::endpoint_has_loopback_scope(endpoint, kind)
}

pub(crate) fn owner_namespace_is_proved(
    ctx: &RunnerContext,
    source: &caushell_graph::NodeId,
) -> bool {
    let records = ctx.execution_unit_resolve_records();
    let mut current = source;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..64 {
        if !visited.insert(current) {
            return false;
        }
        let Some(record) = records
            .iter()
            .find(|record| record.source_node_id == *current)
        else {
            return false;
        };
        let bound = match &record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => Some(&resolved.bound),
            ResolveInvocationArtifactResult::SelectionError { partial_bound, .. } => {
                partial_bound.as_ref()
            }
            _ => None,
        };
        if bound.is_some_and(|bound| {
            bound.operation_semantics_unresolved
                || bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ExecuteRemoteCommand)
        }) {
            return false;
        }
        if record.origin_kind == ExecutionUnitOriginKind::TopLevel {
            return true;
        }
        let Some(parent) = records
            .iter()
            .find(|parent| parent.source_node_id == record.parent_execution_node_id)
            .or_else(|| parsed_payload_owner(ctx, record))
        else {
            return record.origin_kind == ExecutionUnitOriginKind::FunctionExpansion
                && record.depth == 1
                && ctx.parsed_command().is_some_and(|parsed| {
                    parsed.commands.iter().enumerate().any(|(index, command)| {
                        crate::support::source_node_id_for_command(
                            ctx.request(),
                            parsed,
                            index,
                            command,
                        ) == record.parent_execution_node_id
                    })
                });
        };
        if matches!(
            record.origin_kind,
            ExecutionUnitOriginKind::Dispatch | ExecutionUnitOriginKind::StaticXargs
        ) {
            let ResolveInvocationArtifactResult::Resolved(resolved) = &parent.result else {
                return false;
            };
            let dispatches: Vec<_> = resolved
                .bound
                .effects
                .iter()
                .filter(|effect| effect.kind == EffectKind::DispatchCommand)
                .collect();
            if resolved.bound.operation_semantics_unresolved
                || dispatches.is_empty()
                || dispatches.iter().any(|effect| {
                    effect.resource_namespace
                        != Some(caushell_profile::ResourceNamespaceTransfer::SameExecutor)
                })
            {
                return false;
            }
        }
        current = &parent.source_node_id;
    }
    false
}

/// Script-file/stdin payloads have a synthetic payload container as their
/// parent, rather than an invocation record. Follow only the exact, completely
/// parsed container back to its declared owner. Do not infer ownership from a
/// node-name prefix, command spelling, or a matching endpoint.
fn parsed_payload_owner<'a>(
    ctx: &'a RunnerContext,
    record: &ExecutionUnitResolveRecord,
) -> Option<&'a ExecutionUnitResolveRecord> {
    if record.origin_kind != ExecutionUnitOriginKind::NestedPayload {
        return None;
    }
    let payload = ctx.nested_payload_records().iter().find(|payload| {
        crate::support::nested_payload_node_id(
            &ctx.request().session_id,
            ctx.request().sequence_no,
            payload.record_id.0,
        ) == record.parent_execution_node_id
            && payload.depth == record.depth
            && payload.root_command_index == record.root_command_index
            && matches!(&payload.resolution, NestedPayloadResolution::Parsed { parsed, .. }
                if *parsed == record.parsed_scope)
    })?;
    let parent =
        ctx.execution_unit_resolve_records()
            .iter()
            .find(|parent| match &payload.parent_ref {
                NestedPayloadParentRef::RootCommand { command_index } => {
                    parent.origin_kind == ExecutionUnitOriginKind::TopLevel
                        && parent.command_ref.command_index == *command_index
                }
                NestedPayloadParentRef::DerivedInvocation { node_id } => {
                    parent.source_node_id == *node_id
                }
            })?;
    // The caller will still check remote execution, unresolved operation scope,
    // dispatch namespace contracts, cycles and every ancestor of this owner.
    matches!(parent.result, ResolveInvocationArtifactResult::Resolved(_)).then_some(parent)
}
