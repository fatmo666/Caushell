//! Legacy payload reports consume the same canonical invocation as guards.
//! Refresh unresolved inline parameter candidates only after complete native
//! binding. File/stdin/configuration sources and depth failures are independent.
use super::*;
use std::collections::BTreeSet;

pub(super) fn refresh_legacy_inline_payloads(
    payloads: &mut Vec<NestedPayloadRecord>,
    canonical_payloads: &[NestedPayloadRecord],
    records: &[ExecutionUnitResolveRecord],
    refined_nodes: &BTreeSet<String>,
    max_depth: u8,
) {
    if refined_nodes.is_empty() {
        return;
    }
    let parent = |payload: &NestedPayloadRecord| -> Option<&ExecutionUnitResolveRecord> {
        match &payload.parent_ref {
            NestedPayloadParentRef::DerivedInvocation { node_id } => {
                records.iter().find(|r| r.source_node_id == *node_id)
            }
            NestedPayloadParentRef::RootCommand { command_index } => records.iter().find(|r| {
                r.origin_kind == ExecutionUnitOriginKind::TopLevel
                    && r.command_ref.command_index == *command_index
            }),
        }
    };
    payloads.retain_mut(|payload| {
        if payload.candidate.candidate.source != PayloadSource::InlineString
            || !matches!(
                payload.candidate.candidate.origin,
                RecursivePayloadOrigin::Parameter { .. }
            )
            || matches!(
                payload.resolution,
                NestedPayloadResolution::Parsed { .. }
                    | NestedPayloadResolution::ModeledLanguage
                    | NestedPayloadResolution::TruncatedByDepthBudget { .. }
            )
            || payload.depth > max_depth
        {
            return true;
        }
        let Some(record) = parent(payload) else {
            return true;
        };
        if !refined_nodes.contains(&record.source_node_id.0) {
            return true;
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            return true;
        };
        if resolved.bound.operation_semantics_unresolved || !resolved.bound.residuals.is_empty() {
            return true;
        }
        let origin = &payload.candidate.candidate.origin;
        let candidates = collect_recursive_payload_candidates(&resolved.bound);
        let mut matching = candidates
            .into_iter()
            .filter(|c| c.source == PayloadSource::InlineString && c.origin == *origin);
        let Some(candidate) = matching.next() else {
            // The fully rebound native grammar no longer has this execution
            // source (e.g. a finite sed program has no e command). No policy
            // exception is involved; its modeled read/write effects remain.
            return false;
        };
        // Ambiguous source identity must not select one convenient callback.
        if matching.next().is_some() {
            return true;
        }
        if canonical_payloads.iter().any(|p| {
            parent(p).is_some_and(|r| r.source_node_id == record.source_node_id)
                && p.candidate.candidate.source == candidate.source
                && p.candidate.candidate.origin == candidate.origin
        }) {
            return false;
        }
        let materialized = materialize_recursive_payload_candidate(&candidate, &record.bindings);
        let parsed = parse_recursive_payload_candidate(&materialized.candidate);
        let cwd = payload.execution_cwd.clone();
        *payload = NestedPayloadRecord::from_parse_result(
            payload.record_id,
            payload.parent_ref.clone(),
            payload.root_command_index,
            payload.depth,
            record.bindings.clone(),
            materialized,
            parsed,
        );
        payload.execution_cwd = cwd;
        true
    });
}
