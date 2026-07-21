use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::NodeId;
use caushell_profile::ResolveInvocationArtifactResult;
use caushell_runner::{ExecutionUnitResolveRecord, PendingMutation, RunnerContext};

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecutionResolveRecordRef<'a>(&'a ExecutionUnitResolveRecord);

impl<'a> ExecutionResolveRecordRef<'a> {
    pub(crate) fn source_node_id(&self) -> &'a NodeId {
        &self.0.source_node_id
    }

    pub(crate) fn command_index(&self) -> usize {
        self.0.command_ref.command_index
    }

    pub(crate) fn parsed_scope(&self) -> &'a caushell_parse::ParsedCommandArtifact {
        &self.0.parsed_scope
    }

    pub(crate) fn result(&self) -> &'a ResolveInvocationArtifactResult {
        &self.0.result
    }

    pub(crate) fn bindings(&self) -> &'a caushell_profile::SessionBindings {
        &self.0.bindings
    }
}

pub(crate) fn graph_backed_execution_resolve_records(
    ctx: &RunnerContext,
) -> Vec<ExecutionResolveRecordRef<'_>> {
    let staged_execution_unit_node_ids = staged_execution_unit_node_ids(ctx);
    ctx.execution_unit_resolve_records()
        .iter()
        .filter(|record| staged_execution_unit_node_ids.contains(&record.source_node_id))
        .map(ExecutionResolveRecordRef)
        .collect()
}

pub(crate) fn resolved_execution_records_for_local_analysis(
    ctx: &RunnerContext,
) -> Vec<ExecutionResolveRecordRef<'_>> {
    ctx.execution_unit_resolve_records()
        .iter()
        .map(ExecutionResolveRecordRef)
        .collect()
}

pub(crate) fn normalized_command_names_by_source_node(
    ctx: &RunnerContext,
) -> BTreeMap<NodeId, String> {
    graph_backed_execution_resolve_records(ctx)
        .into_iter()
        .filter_map(|record| {
            let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                return None;
            };

            Some((
                record.source_node_id().clone(),
                resolved.normalized_command_name.clone(),
            ))
        })
        .collect()
}

fn staged_execution_unit_node_ids(ctx: &RunnerContext) -> BTreeSet<NodeId> {
    ctx.pending_mutations()
        .iter()
        .filter_map(|mutation| match mutation {
            PendingMutation::AddTopLevelCommandInvocation { node_id, .. }
            | PendingMutation::AddDerivedInvocation { node_id, .. } => Some(node_id.clone()),
            _ => None,
        })
        .collect()
}
