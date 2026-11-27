use std::collections::BTreeMap;

use caushell_parse::{CommandFact, ParsedCommandArtifact, SourceSpan, StatementTerminator};
use caushell_profile::{
    DispatchWorkingDirectory, PathnamePattern, ResolveInvocationArtifactResult, argument_structure,
};
use caushell_runner::{
    DirectoryReadBudget, ExecutionUnitOriginKind, ExecutionUnitResolveRecord, RunnerContext,
};
use caushell_types::{
    DirectoryTreeEvidence, ImplicitInputSource, PathNamespaceEffect, PathResolution,
    PathTargetOperation, RuntimeArgumentDomain, SemanticResolution, ShellKind,
};

use super::{
    Input, directory_tree,
    namespace_state::{self, Baseline},
};
use crate::path::namespace::NamespaceResolver;

pub(super) fn guarded_by_success(
    parsed: Option<&ParsedCommandArtifact>,
    setup: &ExecutionUnitResolveRecord,
    successor: &ExecutionUnitResolveRecord,
) -> bool {
    let Some(parsed) = parsed else { return false };
    let (Some(setup), Some(successor)) = (
        foreground_command(parsed, setup),
        foreground_command(parsed, successor),
    ) else {
        return false;
    };
    has_success_guard(parsed, setup, successor)
}

/// Prove a local ordering between occurrences, not between all executions of
/// the two nodes. This can annotate a closed namespace proof but cannot remove
/// overlaps across loop iterations from the mutation graph.
pub(super) fn guarded_in_same_iteration(
    setup: &ExecutionUnitResolveRecord,
    successor: &ExecutionUnitResolveRecord,
) -> bool {
    if setup.origin_kind != successor.origin_kind
        || !matches!(
            setup.origin_kind,
            ExecutionUnitOriginKind::TopLevel | ExecutionUnitOriginKind::ShellCommandStringPayload
        )
        || setup.parent_execution_node_id != successor.parent_execution_node_id
        || setup.parsed_scope.for_loops.is_empty()
        || setup.parsed_scope != successor.parsed_scope
    {
        return false;
    }
    let parsed = &setup.parsed_scope;
    let (Some(setup), Some(successor)) = (
        command_in_frame(parsed, setup),
        command_in_frame(parsed, successor),
    ) else {
        return false;
    };
    let enclosing_iteration = |command: &CommandFact| {
        parsed
            .for_loops
            .iter()
            .enumerate()
            .filter(|(_, iteration)| {
                iteration.shell_scope_span.is_none()
                    && contains(&iteration.body_span, &command.span)
            })
            .min_by_key(|(_, iteration)| iteration.span.end_byte - iteration.span.start_byte)
            .map(|(index, _)| index)
    };
    enclosing_iteration(setup).is_some_and(|i| enclosing_iteration(successor) == Some(i))
        && has_success_guard(parsed, setup, successor)
}

fn has_success_guard(
    parsed: &ParsedCommandArtifact,
    setup: &CommandFact,
    successor: &CommandFact,
) -> bool {
    parsed.status_conditions.iter().any(|condition| {
        condition.success
            && condition.shell_scope_span.is_none()
            && condition.command_span == setup.span
            && setup.span.end_byte <= successor.span.start_byte
            && contains(&condition.guarded_region, &successor.span)
    })
}

fn contains(outer: &SourceSpan, inner: &SourceSpan) -> bool {
    outer.start_byte <= inner.start_byte && inner.end_byte <= outer.end_byte
}

fn foreground_command<'a>(
    parsed: &'a ParsedCommandArtifact,
    record: &ExecutionUnitResolveRecord,
) -> Option<&'a CommandFact> {
    if record.origin_kind != ExecutionUnitOriginKind::TopLevel {
        return None;
    }
    command_in_frame(parsed, record).filter(|command| command.control_flow_span.is_none())
}

fn command_in_frame<'a>(
    parsed: &'a ParsedCommandArtifact,
    record: &ExecutionUnitResolveRecord,
) -> Option<&'a CommandFact> {
    parsed.commands.iter().find(|command| {
        command.span == record.command_ref.span
            && command.shell_scope_span.is_none()
            && !command.in_pipeline
            && command.terminator != Some(StatementTerminator::Background)
    })
}

/// Preserve the directory created by a foreground mkdir before a matching
/// transfer, while still closing the transfer's destination namespace.
pub(super) fn prove_transfers(
    ctx: &RunnerContext,
    inputs: &[Input],
    baselines: &mut [Baseline],
    records: &BTreeMap<&str, &ExecutionUnitResolveRecord>,
    resolver: &mut NamespaceResolver,
    budget: &mut DirectoryReadBudget,
    evidence: &mut Vec<DirectoryTreeEvidence>,
) -> BTreeMap<String, String> {
    let mut setups = BTreeMap::<_, Vec<usize>>::new();
    for (index, input) in inputs.iter().enumerate() {
        if input.namespace_effect != Some(PathNamespaceEffect::DirectoryCreate)
            || input.fact.slot_name != "directory_paths"
        {
            continue;
        }
        let Some(path) = input.fact.lexical.concrete_path() else {
            continue;
        };
        let Some(ResolveInvocationArtifactResult::Resolved(command)) = records
            .get(input.fact.source_node_id.as_str())
            .map(|r| &r.result)
        else {
            continue;
        };
        if command.normalized_command_name == "mkdir"
            && command
                .bound
                .applied_modifiers
                .iter()
                .any(|m| m.as_str() == "parents")
            && namespace_state::scope_preservation(
                input,
                &baselines[index],
                input,
                &baselines[index],
            )
            .is_some()
        {
            setups.entry(path).or_default().push(index);
        }
    }
    let mut proven = BTreeMap::new();
    if setups.is_empty() {
        return proven;
    }
    let mut comparisons = 0;
    for (index, input) in inputs.iter().enumerate() {
        if input.fact.operation != PathTargetOperation::Write {
            continue;
        }
        let Some(path) = input.fact.lexical.concrete_path() else {
            continue;
        };
        let Some(candidates) = setups.get(path) else {
            continue;
        };
        let Some(transfer) = records.get(input.fact.source_node_id.as_str()) else {
            continue;
        };
        let exact_target = matches!(&baselines[index].0, SemanticResolution::Resolved { value }
            if value.concrete_path() == Some(path));
        let (successor, bounded_move) = match input.fact.slot_name.as_str() {
            "destination_path"
                if input
                    .fact
                    .spelling
                    .as_deref()
                    .is_some_and(|p| p.ends_with('/')) =>
            {
                let bounded_move = bounded_glob_move(transfer, input, &baselines[index], path);
                if !bounded_move && !(exact_target && literal_transfer(transfer)) {
                    continue;
                }
                (*transfer, bounded_move)
            }
            "destination_directory" if exact_target => {
                comparisons += ctx.dispatch_projection_records().len();
                if comparisons > 65536 {
                    return proven;
                }
                let Some(find) = direct_find_transfer(ctx, records, transfer) else {
                    continue;
                };
                if input.namespace_effect == Some(PathNamespaceEffect::EntryRelocation) {
                    comparisons += inputs.len();
                    if comparisons > 65536 {
                        return proven;
                    }
                    if !disjoint_move_sources(inputs, baselines, input, path) {
                        continue;
                    }
                }
                (find, false)
            }
            _ => continue,
        };
        for &setup_index in candidates {
            comparisons += 1;
            if comparisons > 65536 {
                return proven;
            }
            let setup_node = &inputs[setup_index].fact.source_node_id;
            if !guarded_by_success(
                ctx.parsed_command(),
                records[setup_node.as_str()],
                successor,
            ) {
                continue;
            }
            if bounded_move {
                // The relocation pass has already checked the complete source
                // and destination family. Only the execution order is new.
                proven.insert(input.fact.source_node_id.clone(), setup_node.clone());
                break;
            }
            let mut family = input.clone();
            family.fact.lexical = PathResolution::BoundedPathSet {
                roots: vec![path.into()],
                may_escape: false,
            };
            let (resolution, proof) = directory_tree::resolve(
                &family,
                resolver,
                ctx.filesystem_view(),
                budget,
                ctx.request().shell_state_before.cwd(),
            );
            // A directory operand can write existing entries beneath it.
            // Preserve a failed namespace check instead of using the operand
            // directory's own resolved path as proof for those entries.
            baselines[index] = resolution;
            if proof.complete && proof.roots == [path] {
                proven.insert(input.fact.source_node_id.clone(), setup_node.clone());
            }
            evidence.push(proof);
            break;
        }
    }
    proven
}

fn direct_find_transfer<'a>(
    ctx: &RunnerContext,
    records: &BTreeMap<&str, &'a ExecutionUnitResolveRecord>,
    transfer: &ExecutionUnitResolveRecord,
) -> Option<&'a ExecutionUnitResolveRecord> {
    let ResolveInvocationArtifactResult::Resolved(child) = &transfer.result else {
        return None;
    };
    if transfer.origin_kind != ExecutionUnitOriginKind::Dispatch
        || !matches!(child.normalized_command_name.as_str(), "cp" | "mv")
        || child.bound.form_id.as_str() != "target_directory"
        || child.bound.operation_semantics_unresolved
        || !child.bound.residuals.is_empty()
    {
        return None;
    }
    let parent = *records.get(transfer.parent_execution_node_id.0.as_str())?;
    let ResolveInvocationArtifactResult::Resolved(find) = &parent.result else {
        return None;
    };
    if parent.origin_kind != ExecutionUnitOriginKind::TopLevel
        || find.normalized_command_name != "find"
    {
        return None;
    }
    // The child has synthetic spans. Use the parent's shell condition after
    // identifying the exact native callback, including its working directory.
    let projection = &ctx
        .dispatch_projection_records()
        .iter()
        .find(|record| record.source_node_id == parent.source_node_id)?
        .projection;
    let [callback] = projection.resolved.as_slice() else {
        return None;
    };
    let [flag, directory, source] = callback.argv.as_slice() else {
        return None;
    };
    (projection.unresolved.is_empty()
        && callback.dispatch_index == transfer.origin_index
        && callback.command.slot.as_str() == "exec_command"
        && callback.working_directory == DispatchWorkingDirectory::Inherit
        && flag.runtime_data
        && matches!(flag.text.as_str(), "-t" | "--target-directory")
        && directory.runtime_data
        && source.implicit_input_source == Some(ImplicitInputSource::DispatchOutput)
        && matches!(&source.runtime_argument_domain,
            Some(RuntimeArgumentDomain::PathSet { roots, may_escape: false, .. })
                if !roots.is_empty() && roots.iter().all(|p| !p.is_empty() && !p.starts_with('-'))))
    .then_some(parent)
}

fn disjoint_move_sources(
    inputs: &[Input],
    baselines: &[Baseline],
    destination: &Input,
    path: &str,
) -> bool {
    let mut sources = inputs.iter().zip(baselines).filter(|(input, _)| {
        input.fact.source_node_id == destination.fact.source_node_id
            && input.fact.operation == PathTargetOperation::MoveSource
    });
    let Some((_, baseline)) = sources.next() else {
        return false;
    };
    sources.next().is_none()
        && matches!(&baseline.0, SemanticResolution::Resolved {
            value: PathResolution::BoundedPathSet { roots, may_escape: false },
        } if !roots.is_empty() && roots.iter().all(|root|
            !caushell_query::path_is_within_root(root, path)
                && !caushell_query::path_is_within_root(path, root)))
}

fn literal_transfer(record: &ExecutionUnitResolveRecord) -> bool {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return false;
    };
    let bound = &resolved.bound;
    let supported = match (
        resolved.normalized_command_name.as_str(),
        bound.form_id.as_str(),
    ) {
        ("cp", "ordinary_file_copy" | "default_copy_replacing_destination") => {
            bound.applied_modifiers.iter().all(|m| {
                matches!(
                    m.as_str(),
                    "backup_short" | "backup_default" | "force" | "preserve_short"
                )
            })
        }
        ("mv", "default_move") => bound.applied_modifiers.is_empty(),
        _ => false,
    };
    supported
        && !bound.operation_semantics_unresolved
        && bound.residuals.is_empty()
        && resolved
            .materialized_projection
            .invocation
            .args
            .iter()
            .all(|arg| argument_structure(arg).exact_value().is_some())
}

fn bounded_glob_move(
    record: &ExecutionUnitResolveRecord,
    destination: &Input,
    baseline: &Baseline,
    path: &str,
) -> bool {
    let Some(scope) = &destination.relocation_scope else {
        return false;
    };
    let Some((parent, name)) = path.rsplit_once('/') else {
        return false;
    };
    if parent != scope.root
        || !name.is_ascii()
        || scope.ordinary_source.is_some()
        || scope.disjoint_destination.is_some()
        || !matches!(&baseline.0, SemanticResolution::Resolved {
            value: PathResolution::BoundedPathSet { roots, may_escape: false },
        } if roots == &[path])
    {
        return false;
    }

    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return false;
    };
    let bound = &resolved.bound;
    if record.shell_kind != ShellKind::Bash
        || resolved.normalized_command_name != "mv"
        || bound.form_id.as_str() != "default_move"
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
    {
        return false;
    }

    let [options @ .., separator, glob, directory] =
        resolved.materialized_projection.invocation.args.as_slice()
    else {
        return false;
    };
    let verbose_or_empty = match options {
        [] => true,
        [option] => matches!(
            argument_structure(option).exact_value(),
            Some("-v" | "--verbose")
        ),
        _ => false,
    };
    // A variable-width source is data after --. With zero matches under
    // nullglob, only the directory operand remains and mv cannot move it.
    if !verbose_or_empty
        || argument_structure(separator).exact_value() != Some("--")
        || !argument_structure(directory)
            .exact_value()
            .is_some_and(|v| v.ends_with('/'))
    {
        return false;
    }
    let Ok(Some(pattern)) = PathnamePattern::from_argument(glob, record.shell_kind) else {
        return false;
    };
    !pattern.absolute
        && pattern.supports_option_independent_match_bound()
        && matches!(pattern.components.as_slice(), [component] if !component.matches(name, true, true))
}
