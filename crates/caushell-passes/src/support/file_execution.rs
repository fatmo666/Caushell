//! Join execution-file references to their own graph-backed path facts.
//! No language/command allowlist and no interpretation of code as a path.
use super::{
    ExecutionResolveRecordRef, bound_invocation, execution_content_io_target,
    graph_backed_execution_resolve_records, slot_uses_content_open,
};
use caushell_graph::NodeId;
use caushell_profile::{EffectKind, EffectTarget, PathPurpose, PayloadSource, SemanticType};
use caushell_query::{IoTarget, PathTargetQuery, QuerySession};
use caushell_runner::{PathOperation, RunnerContext};
use caushell_types::{
    NestedPayloadContextEvidence, NestedPayloadOriginEvidence, NestedPayloadParentEvidence,
    NestedPayloadSourceEvidence, PathTargetOperation, RuleId, SemanticResolution,
};
use std::collections::BTreeSet;

pub(crate) struct FileExecutionCheck {
    pub source: NodeId,
    pub slot: String,
    pub exempt: bool,
    pub reason: String,
}
pub(crate) struct FileExecutionReference {
    pub source: NodeId,
    pub slot: String,
    pub slots: BTreeSet<String>,
}

pub(crate) fn file_execution_references(ctx: &RunnerContext) -> Vec<FileExecutionReference> {
    // Most shell actions have no executable file input. Do not construct the
    // staged-node/path indexes for commands without an execution effect.
    if !ctx.execution_unit_resolve_records().iter().any(|r| {
        crate::path::unmodeled_executable_path(ExecutionResolveRecordRef::new(r)).is_some()
            || bound_invocation(&r.result).is_some_and(|b| {
                b.effects.iter().any(|e| {
                    matches!(
                        (&e.kind, &e.target),
                        (
                            EffectKind::ExecutePayload | EffectKind::SourceScriptIntoCurrentShell,
                            EffectTarget::Slot(_)
                        )
                    )
                })
            })
    }) {
        return Vec::new();
    }
    let records = graph_backed_execution_resolve_records(ctx);
    let mut candidates = Vec::new();
    for record in records {
        if crate::path::unmodeled_executable_path(record).is_some() {
            let slot = crate::path::EXECUTABLE_FILE_SLOT.to_owned();
            candidates.push((
                record.source_node_id().clone(),
                slot.clone(),
                BTreeSet::from([slot]),
            ));
        }
        let Some(bound) = bound_invocation(record.result()) else {
            continue;
        };
        for effect in &bound.effects {
            let (
                EffectKind::ExecutePayload | EffectKind::SourceScriptIntoCurrentShell,
                EffectTarget::Slot(slot),
            ) = (&effect.kind, &effect.target)
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
    candidates
        .into_iter()
        .map(|(source, slot, slots)| FileExecutionReference {
            source,
            slot,
            slots,
        })
        .collect()
}

pub(crate) fn file_execution_checks(
    ctx: &RunnerContext,
    session: QuerySession<'_>,
) -> Vec<FileExecutionCheck> {
    let references = file_execution_references(ctx);
    if references.is_empty() {
        return Vec::new();
    }
    let facts = PathTargetQuery::new(ctx.request().sequence_no).execute(session);
    references
        .into_iter()
        .map(|reference| {
            let slots = if reference.slots.is_empty() {
                BTreeSet::from([reference.slot.clone()])
            } else {
                reference.slots
            };
            let complete = slots.iter().all(|slot| {
                facts.iter().any(|fact| {
                    fact.operation == PathTargetOperation::ExecuteFile
                        && fact.source_node_id == reference.source.0
                        && fact.slot_name == *slot
                })
            });
            let exempt = complete
                && facts
                    .iter()
                    .filter(|fact| {
                        fact.operation == PathTargetOperation::ExecuteFile
                            && fact.source_node_id == reference.source.0
                            && slots.contains(&fact.slot_name)
                    })
                    .all(|fact| {
                        matches!(&fact.resolution, SemanticResolution::NotApplicable { .. })
                            || ctx.target_path_policy().is_some_and(|policy| {
                                policy
                                    .check_target(
                                        fact,
                                        PathOperation::ExecuteFile,
                                        RuleId::OutsideWorkspaceScriptSource,
                                    )
                                    .is_exempt()
                            })
                    });
            FileExecutionCheck {
                reason: format!(
                    "execution-file reference {} at {} has {} target-scope proof",
                    reference.slot,
                    reference.source.0,
                    if exempt { "a complete" } else { "no complete" }
                ),
                source: reference.source,
                slot: reference.slot,
                exempt,
            }
        })
        .collect()
}

pub(crate) fn opens_only_non_file_inputs(
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
        if bound.bound_parameters.iter().find(|parameter| parameter.name.as_str() == slot.as_str()).is_some_and(|parameter|
            !parameter.values.is_empty() && parameter.values.iter().all(|value| matches!(value,
                caushell_profile::BoundValue::Argument { node_kind, .. } if node_kind == "process_substitution"))) {
            return true;
        }
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
                let target = execution_content_io_target(
                        ctx,
                        record.source_node_id(),
                        record.parsed_scope(),
                        record.command_index(),
                        None,
                        &path.resolution,
                        path.cwd_dependent,
                        entry_cwd.resolution_base(cwd),
                        home
                    );
                let file_or_unknown = match target {
                    IoTarget::Path { .. } | IoTarget::UnknownDescriptor { .. } => true,
                    IoTarget::InheritedDescriptor { descriptor } => descriptor != "0" || !super::pipeline_has_upstream(record.parsed_scope(), record.command_index()),
                    _ => false,
                };
                if file_or_unknown {
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
