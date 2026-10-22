use std::collections::{BTreeMap, BTreeSet};

use caushell_runner::{CwdPathContext, PendingMutation, RunnerContext};
use caushell_types::{
    PathResolution, PathTargetAccess, PathTargetOperation, ProvenanceVariableValueState,
    ResolvedPathPurpose, SemanticGapKind, SemanticResolution,
};

use super::{Input, absolute_spelling, new_input, target_spelling, unresolved};
use crate::path::{
    collect_path_facts, effective_cwd_cases, normalize_shell_path, project_path_at_cwd,
};
use crate::support::{
    bound_invocation, collect_implicit_startup_config_candidates, file_execution_references,
    graph_backed_execution_resolve_records, implicit_startup_path_fact_index,
    implicit_startup_slot_name, opens_only_non_file_inputs,
};

fn operation(purpose: ResolvedPathPurpose) -> Option<PathTargetOperation> {
    match purpose {
        ResolvedPathPurpose::ScriptSource => Some(PathTargetOperation::ExecuteFile),
        ResolvedPathPurpose::InProcessCode => Some(PathTargetOperation::LoadCode),
        ResolvedPathPurpose::StartupConfig => Some(PathTargetOperation::StartupConfig),
        _ => None,
    }
}

pub(super) fn collect(ctx: &RunnerContext) -> Vec<Input> {
    let cwd = ctx.request().shell_state_before.cwd();
    let records = graph_backed_execution_resolve_records(ctx);
    let by_source: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.source_node_id(), *record))
        .collect();
    let mut inputs = Vec::new();
    let mut candidate_paths = BTreeMap::new();
    let implicit = collect_implicit_startup_config_candidates(ctx);
    let implicit_nodes: BTreeSet<_> = implicit
        .iter()
        .map(|candidate| {
            crate::path::path_fact_node_id(
                &candidate.source_node_id,
                implicit_startup_path_fact_index(
                    candidate.command_index,
                    &candidate.environment_name,
                ),
                implicit_startup_slot_name(),
                &candidate.resolution,
            )
        })
        .collect();

    for mutation in ctx.pending_mutations() {
        let PendingMutation::AddPathFact {
            source_node_id,
            node_id,
            resolution,
            purpose: Some(purpose),
            slot_name,
            ..
        } = mutation
        else {
            continue;
        };
        let Some(operation) = operation(*purpose) else {
            continue;
        };
        if implicit_nodes.contains(node_id) {
            continue;
        }
        let record = by_source.get(source_node_id).copied();
        if operation == PathTargetOperation::LoadCode
            && record
                .and_then(|r| bound_invocation(r.result()))
                .is_some_and(|bound| {
                    !bound.effects.iter().any(|effect| {
                        effect.kind == caushell_profile::EffectKind::LoadInProcessCode
                    })
                })
        {
            continue;
        }
        let home = record.and_then(|record| {
            record
                .bindings()
                .tilde_home_with_default(ctx.request().home.as_deref())
        });
        let paths = candidate_paths
            .entry(source_node_id.clone())
            .or_insert_with(|| {
                record
                    .map(|record| collect_path_facts(&[record], cwd, home))
                    .unwrap_or_default()
            });
        let candidate = paths
            .iter()
            .find(|path| path.slot_name == *slot_name && path.resolution == *resolution);
        let semantic_slot = candidate
            .and_then(|path| path.semantic_slot.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(slot_name);
        let cwd_dependent = candidate.is_some_and(|path| path.cwd_dependent);
        let mut spellings = BTreeSet::new();
        if let Some(record) = record {
            for case in record.cwd_cases(cwd) {
                if let CwdPathContext::Exact(base) = case {
                    if let Some(spelling) =
                        target_spelling(record, semantic_slot, resolution, base, home)
                    {
                        spellings.insert(spelling);
                    }
                }
            }
            // Descriptor paths retain the pathname spelling at their opening site.
            let descriptor_routed = paths.iter().any(|path| {
                path.slot_name == *slot_name
                    && path.resolution.concrete_path().is_some_and(|path| {
                        caushell_query::IoTargetQuery::descriptor_alias(path).is_some()
                    })
            });
            if spellings.is_empty() && descriptor_routed {
                for opening in &records {
                    for case in effective_cwd_cases(
                        ctx.effective_cwd_for_node(opening.source_node_id()),
                        cwd,
                    ) {
                        let CwdPathContext::Exact(base) = case else {
                            continue;
                        };
                        for path in crate::path::collect_redirection_path_facts(
                            opening.parsed_scope(),
                            base,
                            home,
                            Some(opening.bindings()),
                        ) {
                            if path.resolution == *resolution
                                && let Some(spelling) =
                                    super::redirection_spelling(&path, base, home)
                            {
                                spellings.insert(spelling);
                            }
                        }
                    }
                }
            }
        }
        let spellings: Vec<_> = if spellings.is_empty() {
            vec![None]
        } else {
            spellings.into_iter().map(Some).collect()
        };
        for spelling in spellings {
            let mut input = new_input(
                ctx,
                source_node_id,
                format!("consume:{}", node_id.0),
                slot_name.clone(),
                operation,
                PathTargetAccess::Follow,
                resolution.clone(),
                spelling,
            );
            input.cwd_dependent = cwd_dependent;
            if record
                .and_then(|record| bound_invocation(record.result()))
                .is_some_and(|bound| bound.operation_semantics_unresolved)
            {
                input.pending_resolution = false;
                input.fact.resolution = unresolved(
                    SemanticGapKind::UnresolvedOperation,
                    "invocation has unresolved operation semantics",
                );
            }
            inputs.push(input);
        }
    }

    for candidate in implicit {
        let text = match &candidate.environment_state {
            ProvenanceVariableValueState::ExactScalar { value }
            | ProvenanceVariableValueState::RuntimeProduced { value, .. } => Some(value.as_str()),
            _ => None,
        };
        for case in effective_cwd_cases(ctx.execution_cwd_for_node(&candidate.source_node_id), cwd)
        {
            let cwd_dependent = text.is_none_or(|text| !text.starts_with('/'));
            let spelling = text.map(|text| absolute_spelling(text, case.resolution_base(cwd)));
            let lexical = match (&spelling, text) {
                (Some(spelling), Some(_)) if candidate.resolution.concrete_path().is_some() => {
                    PathResolution::Concrete {
                        path: normalize_shell_path(spelling),
                    }
                }
                _ => PathResolution::UnsupportedDynamicText {
                    text: "startup configuration source is unresolved".into(),
                },
            };
            let mut input = new_input(
                ctx,
                &candidate.source_node_id,
                format!("startup-env:{}", candidate.environment_name),
                implicit_startup_slot_name().into(),
                PathTargetOperation::StartupConfig,
                PathTargetAccess::Follow,
                project_path_at_cwd(lexical, cwd_dependent, case),
                spelling,
            );
            input.cwd_dependent = cwd_dependent;
            inputs.push(input);
        }
    }

    for reference in file_execution_references(ctx) {
        let record = by_source.get(&reference.source).copied();
        let channel =
            record.is_some_and(|record| opens_only_non_file_inputs(ctx, record, &reference.slots));
        let slots = if reference.slots.is_empty() {
            BTreeSet::from([reference.slot])
        } else {
            reference.slots
        };
        if channel {
            for input in inputs.iter_mut().filter(|input| {
                input.fact.operation == PathTargetOperation::ExecuteFile
                    && input.fact.source_node_id == reference.source.0
                    && slots.contains(&input.fact.slot_name)
            }) {
                input.pending_resolution = false;
                input.fact.resolution = SemanticResolution::NotApplicable {
                    reason: "execution input uses a non-filesystem channel".into(),
                };
            }
        }
        for slot in slots {
            if inputs.iter().any(|input| {
                input.fact.operation == PathTargetOperation::ExecuteFile
                    && input.fact.source_node_id == reference.source.0
                    && input.fact.slot_name == slot
            }) {
                continue;
            }
            let mut input = new_input(
                ctx,
                &reference.source,
                format!("execution-ref:{slot}"),
                slot,
                PathTargetOperation::ExecuteFile,
                PathTargetAccess::Follow,
                PathResolution::UnsupportedDynamicText {
                    text: "execution-file reference has no target record".into(),
                },
                None,
            );
            input.pending_resolution = false;
            if channel {
                input.fact.resolution = SemanticResolution::NotApplicable {
                    reason: "execution input uses a non-filesystem channel".into(),
                };
            }
            inputs.push(input);
        }
    }

    for declaration in crate::support::declared_path_consumptions(ctx) {
        if inputs.iter().any(|input| {
            input.fact.source_node_id == declaration.source.0
                && input.fact.operation == declaration.operation
                && input.fact.slot_name == declaration.slot
        }) {
            continue;
        }
        let mut input = new_input(
            ctx,
            &declaration.source,
            format!("declared-consume:{}", declaration.slot),
            declaration.slot,
            declaration.operation,
            PathTargetAccess::Follow,
            PathResolution::UnsupportedDynamicText {
                text: "declared file input has no target record".into(),
            },
            None,
        );
        input.pending_resolution = false;
        inputs.push(input);
    }
    inputs
}
