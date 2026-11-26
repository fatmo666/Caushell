use std::collections::BTreeMap;

use caushell_parse::{CommandFact, ParsedCommandArtifact, StatementTerminator};
use caushell_profile::{PathnamePattern, ResolveInvocationArtifactResult, argument_structure};
use caushell_runner::{
    DirectoryReadBudget, ExecutionUnitOriginKind, ExecutionUnitResolveRecord, RunnerContext,
};
use caushell_types::{
    DirectoryTreeEvidence, PathNamespaceEffect, PathResolution, PathTargetOperation,
    SemanticResolution, ShellKind,
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
    parsed.status_conditions.iter().any(|condition| {
        condition.success
            && condition.shell_scope_span.is_none()
            && condition.command_span == setup.span
            && setup.span.end_byte <= successor.span.start_byte
            && condition.guarded_region.start_byte <= successor.span.start_byte
            && successor.span.end_byte <= condition.guarded_region.end_byte
    })
}

fn foreground_command<'a>(
    parsed: &'a ParsedCommandArtifact,
    record: &ExecutionUnitResolveRecord,
) -> Option<&'a CommandFact> {
    if record.origin_kind != ExecutionUnitOriginKind::TopLevel {
        return None;
    }
    parsed.commands.iter().find(|command| {
        command.span == record.command_ref.span
            && command.shell_scope_span.is_none()
            && command.control_flow_span.is_none()
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
        if input.fact.operation != PathTargetOperation::Write
            || input.fact.slot_name != "destination_path"
            || !input
                .fact
                .spelling
                .as_deref()
                .is_some_and(|p| p.ends_with('/'))
        {
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
        let bounded_move = bounded_glob_move(transfer, input, &baselines[index], path);
        if !bounded_move
            && !(matches!(&baselines[index].0, SemanticResolution::Resolved { value }
                if value.concrete_path() == Some(path))
                && literal_transfer(transfer))
        {
            continue;
        }
        for &setup_index in candidates {
            comparisons += 1;
            if comparisons > 65536 {
                return proven;
            }
            let setup_node = &inputs[setup_index].fact.source_node_id;
            if !guarded_by_success(ctx.parsed_command(), records[setup_node.as_str()], transfer) {
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
