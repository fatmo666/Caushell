//! Join execution-file references to their own graph-backed path facts.
//! No language/command allowlist and no interpretation of code as a path.
use super::{
    ExecutionResolveRecordRef, bound_invocation, execution_content_io_target,
    graph_backed_execution_resolve_records, slot_uses_content_open,
};
use caushell_graph::NodeId;
use caushell_profile::{EffectKind, EffectTarget, PathPurpose, PayloadSource, SemanticType};
use caushell_query::{IoTarget, PathFactsQuery, QuerySession};
use caushell_runner::{PathExemption, PathOperation, RunnerContext};
use caushell_types::{
    NestedPayloadContextEvidence, NestedPayloadOriginEvidence, NestedPayloadParentEvidence,
    NestedPayloadSourceEvidence, ResolvedPathPurpose, RuleId,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct FileExecutionCheck {
    pub source: NodeId,
    pub slot: String,
    pub exempt: bool,
    pub reason: String,
}
pub(crate) fn file_execution_checks(
    ctx: &RunnerContext,
    session: QuerySession<'_>,
) -> Vec<FileExecutionCheck> {
    // Most shell actions have no executable file input. Do not construct the
    // staged-node/path indexes for commands without an execution effect.
    if !ctx.execution_unit_resolve_records().iter().any(|r| {
        bound_invocation(&r.result).is_some_and(|b| {
            b.effects.iter().any(|e| {
                matches!(
                    (&e.kind, &e.target),
                    (EffectKind::ExecutePayload, EffectTarget::Slot(_))
                )
            })
        })
    }) {
        return Vec::new();
    }
    let records = graph_backed_execution_resolve_records(ctx);
    let mut candidates = Vec::new();
    for record in records {
        let Some(bound) = bound_invocation(record.result()) else {
            continue;
        };
        for effect in &bound.effects {
            let (EffectKind::ExecutePayload, EffectTarget::Slot(slot)) =
                (&effect.kind, &effect.target)
            else {
                continue;
            };
            let Some(parameter) = bound.bound_parameters.iter().find(|p| p.name == *slot) else {
                continue;
            };
            let file_ref = match &parameter.semantic {
                SemanticType::Payload(p) => p.source == PayloadSource::ScriptFileRef,
                SemanticType::Path(p) => p.purpose == Some(PathPurpose::ScriptSource),
                _ => false,
            };
            if !file_ref {
                continue;
            }
            let slots: BTreeSet<_> = bound.bound_parameters.iter().filter(|p| {
                matches!(&p.semantic, SemanticType::Path(s) if s.purpose == Some(PathPurpose::ScriptSource))
                && (p.name == *slot || p.structured_source.as_ref() == Some(slot))
            }).map(|p| p.name.as_str().to_owned()).collect();
            if opens_only_non_file_inputs(ctx, record, &slots) {
                continue;
            }
            candidates.push((
                record.source_node_id().clone(),
                slot.as_str().to_owned(),
                slots,
            ));
        }
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    let facts = PathFactsQuery::new()
        .purpose(ResolvedPathPurpose::ScriptSource)
        .used_by_root_sequence(ctx.request().sequence_no)
        .execute(session);
    let mut index: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for fact in facts.facts() {
        for usage in fact.used_by() {
            index
                .entry((
                    usage.execution_unit().node_id().clone(),
                    fact.slot_name().to_owned(),
                ))
                .or_default()
                .push(fact.resolution());
        }
    }
    let policy = ctx.path_exemption_policy();
    candidates
        .into_iter()
        .map(|(source, slot, slots)| {
            let targets: Vec<_> = slots
                .iter()
                .flat_map(|s| {
                    index
                        .get(&(source.clone(), s.clone()))
                        .into_iter()
                        .flatten()
                })
                .collect();
            let complete = !slots.is_empty()
                && slots.iter().all(|s| {
                    index
                        .get(&(source.clone(), s.clone()))
                        .is_some_and(|facts| !facts.is_empty())
                });
            let assessments: Vec<PathExemption> = targets
                .iter()
                .map(|r| {
                    policy.check(
                        r,
                        PathOperation::ExecuteFile,
                        RuleId::OutsideWorkspaceScriptSource,
                    )
                })
                .collect();
            let exempt = complete && assessments.iter().all(|a| a.is_exempt());
            let reason = if !complete {
                format!(
                    "execution-file reference {slot} at {} has no proven filesystem target",
                    source.0
                )
            } else {
                format!(
                    "execution-file reference {slot} at {} has path assessments {:?}",
                    source.0, assessments
                )
            };
            FileExecutionCheck {
                source,
                slot,
                exempt,
                reason,
            }
        })
        .collect()
}

fn opens_only_non_file_inputs(
    ctx: &RunnerContext,
    record: ExecutionResolveRecordRef<'_>,
    slots: &BTreeSet<String>,
) -> bool {
    let Some(bound) = bound_invocation(record.result()) else {
        return false;
    };
    if slots.is_empty()
        || slots
            .iter()
            .any(|slot| !slot_uses_content_open(bound, slot, EffectKind::ReadPath))
    {
        return false;
    }
    let cwd = ctx.request().shell_state_before.cwd();
    let home = record
        .bindings()
        .tilde_home_with_default(ctx.request().home.as_deref());
    let paths = crate::path::collect_path_facts(&[record], cwd, home);
    slots.iter().all(|slot| {
        let mut seen = false;
        for path in paths.iter().filter(|p| {
            p.slot_name == *slot
                && p.purpose == Some(PathPurpose::ScriptSource)
                && p.role == caushell_profile::PathRole::Read
        }) {
            seen = true;
            for entry_cwd in crate::path::effective_cwd_cases(
                ctx.effective_cwd_for_node(record.source_node_id()),
                cwd,
            ) {
                if matches!(
                    execution_content_io_target(
                        ctx,
                        record.source_node_id(),
                        record.parsed_scope(),
                        record.command_index(),
                        None,
                        &path.resolution,
                        path.cwd_dependent,
                        entry_cwd.resolution_base(cwd),
                        home
                    ),
                    IoTarget::Path { .. }
                ) {
                    return false;
                }
            }
        }
        seen
    })
}
pub(crate) fn file_reference_is_exempt(
    context: &NestedPayloadContextEvidence,
    checks: &[FileExecutionCheck],
    ctx: &RunnerContext,
) -> bool {
    if context.source != NestedPayloadSourceEvidence::ScriptFileRef {
        return false;
    }
    let NestedPayloadOriginEvidence::Parameter { slot_name } = &context.origin else {
        return false;
    };
    let source = match &context.parent_ref {
        NestedPayloadParentEvidence::DerivedInvocation { node_id } => {
            Some(NodeId::new(node_id.clone()))
        }
        NestedPayloadParentEvidence::RootCommand { command_index } => ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|r| {
                r.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    && r.command_ref.command_index == *command_index
            })
            .map(|r| r.source_node_id.clone()),
    };
    checks
        .iter()
        .any(|c| c.exempt && c.slot == *slot_name && source.as_ref() == Some(&c.source))
}
