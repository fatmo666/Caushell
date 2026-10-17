//! Join execution-file references to their own graph-backed path facts.
//! No language/command allowlist and no interpretation of code as a path.
use super::{bound_invocation, graph_backed_execution_resolve_records};
use caushell_graph::NodeId;
use caushell_profile::{EffectKind, EffectTarget, PathPurpose, PayloadSource, SemanticType};
use caushell_query::{PathFactsQuery, QuerySession};
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
