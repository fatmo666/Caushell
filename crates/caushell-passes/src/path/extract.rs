use caushell_graph::{EdgeKind, NodeId};
use caushell_parse::{ParsedCommandArtifact, RedirectionFact, RedirectionKind, SourceSpan};
use caushell_profile::{
    BoundArgumentMaterialization, BoundInvocation, BoundParameter, BoundValue, DerivedPathSource,
    DerivedPathTarget, Effect, EffectKind, EffectTarget, MutationScopeTarget, PathPurpose,
    PathRole, ResolveInvocationArtifactResult, ResolvedInvocationArtifact, SemanticType,
    SemanticValueRef, SemanticValueResolution, SlotName, StructuredValueContext,
    ToolConventionPathTarget, ValueMaterialization, parse_owner_group_spec,
};
use caushell_types::{
    DerivedPathBasis, DerivedPathRule, DerivedPathUnresolvedReason, InProcessCodeLoadKind,
    MutationScopeResolution, OwnerGroupSpec, PathMetadataMutation, PathMetadataMutationKind,
    PathResolution, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceDomainLabel,
    ProvenanceEdgeSemantics, ProvenanceProduceKind, RepositoryWorktreeScopeResolution,
    ResolvedMutationScopeOperation, ResolvedPathPurpose, ResolvedPathRole,
};

use super::configured::resolve_configured_path;
use super::normalize::{
    join_shell_path, normalize_shell_path, path_is_within_root, resolve_path_operand,
};
use crate::support::{ExecutionResolveRecordRef, is_file_write_redirection_operator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathFactCandidate {
    pub source_node_id: NodeId,
    pub command_index: usize,
    pub slot_name: String,
    /// Original bound parameter for a direct slot target. Graph identity may
    /// differ when an effect adds a role. Computed paths have no slot alias:
    /// their source slot's access semantics do not describe the new target.
    pub semantic_slot: Option<SlotName>,
    pub normalized_command_name: String,
    pub resolution: PathResolution,
    pub cwd_dependent: bool,
    pub role: PathRole,
    pub purpose: Option<PathPurpose>,
    pub metadata_mutation: Option<PathMetadataMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectionPathFactCandidate {
    pub fact: RedirectionFact,
    pub redirection_index: usize,
    pub slot_name: String,
    pub resolution: PathResolution,
    pub cwd_dependent: bool,
    pub role: PathRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationScopeFactCandidate {
    pub source_node_id: NodeId,
    pub command_index: usize,
    pub effect_index: usize,
    pub slot_name: String,
    pub normalized_command_name: String,
    pub resolution: MutationScopeResolution,
    pub operation: ResolvedMutationScopeOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationTargetCandidate {
    pub operation: EffectKind,
    pub slot_name: String,
    pub resolution: PathResolution,
    pub cwd_dependent: bool,
    pub implicit_incidental_cache: bool,
}

pub(crate) fn path_operand_depends_on_cwd(
    text: &str,
    _quoted: bool,
    _node_kind: &str,
    materialization: Option<&ValueMaterialization>,
) -> bool {
    let effective_text = match materialization {
        Some(ValueMaterialization::ResolvedExactScalar { value, .. })
        | Some(ValueMaterialization::ResolvedRuntimeProduced { value, .. }) => value.as_str(),
        _ => text,
    };
    !(effective_text.starts_with('/') || effective_text == "~" || effective_text.starts_with("~/"))
}

fn bound_path_operand_depends_on_cwd(
    text: &str,
    quoted: bool,
    node_kind: &str,
    materialization: &BoundArgumentMaterialization,
    projection_materialization: Option<&ValueMaterialization>,
) -> bool {
    if matches!(
        materialization,
        BoundArgumentMaterialization::RuntimeData
            | BoundArgumentMaterialization::ResolvedExactScalar { .. }
            | BoundArgumentMaterialization::ResolvedRuntimeProduced { .. }
    ) {
        return !text.starts_with('/');
    }
    path_operand_depends_on_cwd(text, quoted, node_kind, projection_materialization)
}

fn runtime_input_path_depends_on_cwd(
    domain: Option<&caushell_types::RuntimeArgumentDomain>,
) -> bool {
    !matches!(
        domain,
        Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, .. })
            if !roots.is_empty() && roots.iter().all(|root| root.starts_with('/'))
    )
}

fn runtime_input_path_resolution<S: std::fmt::Debug>(
    source: &S,
    domain: Option<&caushell_types::RuntimeArgumentDomain>,
    cwd: &str,
) -> PathResolution {
    match domain {
        Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, may_escape }) => {
            PathResolution::BoundedPathSet {
                roots: roots
                    .iter()
                    .map(|root| lexical_path_from_argv(root, cwd))
                    .collect(),
                may_escape: *may_escape,
            }
        }
        Some(caushell_types::RuntimeArgumentDomain::Unbounded) | None => {
            PathResolution::UnsupportedDynamicText {
                text: format!("path operand depends on runtime input {source:?}"),
            }
        }
    }
}

fn lexical_path_from_argv(text: &str, cwd: &str) -> String {
    if text.starts_with('/') {
        normalize_shell_path(text)
    } else {
        join_shell_path(cwd, text)
    }
}

/// Projected values are argv data, not shell source. Resolve them lexically;
/// the original-value branch retains the existing resolution and provenance.
fn semantic_path_resolution(
    value: SemanticValueRef<'_>,
    resolved: Option<&ResolvedInvocationArtifact>,
    cwd: &str,
    home: Option<&str>,
) -> (PathResolution, bool) {
    match value {
        SemanticValueRef::Projected { source, value } => match &value.resolution {
            SemanticValueResolution::Known(text) => (
                PathResolution::Concrete {
                    path: lexical_path_from_argv(text, cwd),
                },
                !text.starts_with('/'),
            ),
            SemanticValueResolution::Unknown(reason) => (
                PathResolution::UnsupportedDynamicText {
                    text: format!("unresolved value projection ({reason:?}) from {source:?}"),
                },
                true,
            ),
        },
        SemanticValueRef::Original(BoundValue::Argument {
            text,
            quoted,
            node_kind,
            span,
            materialization,
            ..
        }) => {
            let projection_materialization =
                resolved.and_then(|resolved| arg_materialization_for_span(resolved, span));
            let resolution = if resolved.is_some() {
                resolve_bound_path_resolution(
                    text,
                    *quoted,
                    node_kind,
                    cwd,
                    home,
                    materialization,
                    projection_materialization,
                )
            } else {
                resolve_path_resolution(text, *quoted, node_kind, cwd, home, None)
            };
            (
                resolution,
                bound_path_operand_depends_on_cwd(
                    text,
                    *quoted,
                    node_kind,
                    materialization,
                    projection_materialization,
                ),
            )
        }
        SemanticValueRef::Original(BoundValue::ImplicitInput { source, domain }) => (
            runtime_input_path_resolution(source, domain.as_ref(), cwd),
            runtime_input_path_depends_on_cwd(domain.as_ref()),
        ),
    }
}

fn semantic_value_text(value: SemanticValueRef<'_>) -> &str {
    match value {
        SemanticValueRef::Projected { value, .. } => match &value.resolution {
            SemanticValueResolution::Known(text) => text,
            SemanticValueResolution::Unknown(_) => "",
        },
        SemanticValueRef::Original(BoundValue::Argument { text, .. }) => text,
        SemanticValueRef::Original(BoundValue::ImplicitInput { .. }) => "",
    }
}

fn path_target_is_inapplicable(invocation: &BoundInvocation, target: &EffectTarget) -> bool {
    let slot_is_inapplicable = |slot: &SlotName| {
        bound_parameter(invocation, slot.as_str())
            .is_some_and(BoundParameter::semantic_values_are_inapplicable)
    };
    match target {
        EffectTarget::Slot(slot) => slot_is_inapplicable(slot),
        EffectTarget::DerivedPath(target) => {
            std::iter::once(&target.source).chain(target.root.iter()).any(|source| {
                matches!(source, DerivedPathSource::Slot(slot) if slot_is_inapplicable(slot))
            })
        }
        _ => false,
    }
}

fn slot_has_value_projection(invocation: &BoundInvocation, slot: &SlotName) -> bool {
    bound_parameter(invocation, slot.as_str()).is_some_and(|p| p.projected_values.is_some())
}

fn slot_depends_on_cwd(
    invocation: &BoundInvocation,
    slot: &SlotName,
    resolved: &ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    let Some(parameter) = bound_parameter(invocation, slot.as_str()) else {
        return true;
    };
    let mut values = parameter.semantic_values().peekable();
    values.peek().is_none()
        || values.any(|value| semantic_path_resolution(value, Some(resolved), cwd, home).1)
}

fn projected_derived_target_depends_on_cwd(
    target: &DerivedPathTarget,
    resolved: &ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    match target.root.as_ref().unwrap_or(&target.source) {
        DerivedPathSource::Slot(slot) => {
            slot_depends_on_cwd(&resolved.bound, slot, resolved, cwd, home)
        }
        DerivedPathSource::ToolConventionRoot { convention } => {
            tool_convention_roots_for_convention(&resolved.bound, convention)
                .any(|target| !target.path.starts_with('/'))
        }
    }
}

fn projected_mutation_scope_depends_on_cwd(
    target: &MutationScopeTarget,
    resolved: &ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    match target {
        MutationScopeTarget::RepositoryWorktree { root, subtree, .. } => {
            if !root
                .iter()
                .chain(subtree.iter())
                .any(|slot| slot_has_value_projection(&resolved.bound, slot))
            {
                return false;
            }
            root.as_ref()
                .is_none_or(|slot| slot_depends_on_cwd(&resolved.bound, slot, resolved, cwd, home))
                || subtree.as_ref().is_some_and(|slot| {
                    slot_depends_on_cwd(&resolved.bound, slot, resolved, cwd, home)
                })
        }
    }
}

pub(crate) fn collect_effect_mutation_targets(
    record: ExecutionResolveRecordRef<'_>,
    cwd: &str,
    home: Option<&str>,
) -> Vec<MutationTargetCandidate> {
    let (bound, resolved, command_name) = match record.result() {
        ResolveInvocationArtifactResult::Resolved(resolved) => (
            &resolved.bound,
            Some(resolved),
            resolved.normalized_command_name.as_str(),
        ),
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            partial_bound: Some(bound),
            ..
        } => (bound, None, normalized_command_name.as_str()),
        _ => return Vec::new(),
    };

    let mut targets = Vec::new();
    for (effect_index, effect) in bound.effects.iter().enumerate() {
        if !matches!(
            effect.kind,
            EffectKind::WritePath
                | EffectKind::DeletePath
                | EffectKind::MovePath
                | EffectKind::ChangeMode
                | EffectKind::ChangeOwner
                | EffectKind::ChangeGroup
                | EffectKind::MetadataMutation
        ) {
            continue;
        }

        // A generic metadata mutation may describe shell state (for example `set`),
        // not a filesystem target. No path-bearing target means this guard has
        // nothing to classify.
        if effect.kind == EffectKind::MetadataMutation
            && matches!(effect.target, EffectTarget::None)
        {
            continue;
        }

        // A proven nonmatching key means this path effect is inapplicable,
        // unlike a missing/unresolved operand that still needs the fallback.
        if path_target_is_inapplicable(bound, &effect.target) {
            continue;
        }

        let start = targets.len();
        match &effect.target {
            EffectTarget::ConfiguredPath(target) => {
                if let Some(path) = resolve_configured_path(bound, target, cwd, home, Some(record))
                {
                    targets.push(MutationTargetCandidate {
                        operation: effect.kind,
                        slot_name: format!("configured_path_{effect_index}"),
                        resolution: path.resolution,
                        cwd_dependent: path.cwd_dependent,
                        implicit_incidental_cache: path.implicit_incidental_cache,
                    });
                }
                // An absent optional configured output is inapplicable, not an
                // unresolved mutation requiring the generic fallback.
                continue;
            }
            EffectTarget::Slot(slot) => {
                if let Some(parameter) = bound_parameter(bound, slot.as_str()) {
                    for value in parameter.semantic_values() {
                        let (resolution, cwd_dependent) =
                            semantic_path_resolution(value, resolved, cwd, home);
                        targets.push(MutationTargetCandidate {
                            implicit_incidental_cache: false,
                            operation: effect.kind,
                            slot_name: slot.as_str().to_string(),
                            cwd_dependent,
                            resolution,
                        });
                    }
                }
            }
            EffectTarget::ToolConventionPath(target) => {
                targets.push(MutationTargetCandidate {
                    implicit_incidental_cache: false,
                    operation: effect.kind,
                    slot_name: tool_convention_slot_name(effect_index, &target.convention),
                    resolution: resolve_tool_convention_path(target, cwd),
                    cwd_dependent: false,
                });
            }
            EffectTarget::DerivedPath(target) => {
                let mut derived = Vec::new();
                collect_derived_target_path_facts(
                    record,
                    command_name,
                    bound,
                    resolved,
                    effect_index,
                    target,
                    PathRole::Target,
                    cwd,
                    home,
                    &mut derived,
                );
                let cwd_dependent = resolved
                    .map(|resolved| {
                        projected_derived_target_depends_on_cwd(target, resolved, cwd, home)
                    })
                    .unwrap_or(true);
                targets.extend(derived.into_iter().map(|path| MutationTargetCandidate {
                    implicit_incidental_cache: false,
                    operation: effect.kind,
                    slot_name: path.slot_name,
                    resolution: path.resolution,
                    cwd_dependent,
                }));
            }
            EffectTarget::MutationScope(scope) => {
                let (slot_name, scope_resolution) =
                    resolve_mutation_scope_target(scope, bound, cwd, home, true);
                let resolution = match scope_resolution {
                    MutationScopeResolution::RepositoryWorktree { root, scope, .. } => {
                        match scope {
                            RepositoryWorktreeScopeResolution::WholeWorktree => root,
                            RepositoryWorktreeScopeResolution::Subtree { path } => path,
                        }
                    }
                };
                targets.push(MutationTargetCandidate {
                    implicit_incidental_cache: false,
                    operation: effect.kind,
                    slot_name,
                    resolution,
                    cwd_dependent: resolved
                        .map(|resolved| {
                            projected_mutation_scope_depends_on_cwd(scope, resolved, cwd, home)
                        })
                        .unwrap_or(true),
                });
            }
            EffectTarget::ImplicitInput(_)
            | EffectTarget::VariableName(_)
            | EffectTarget::Dispatch(_)
            | EffectTarget::None
            | EffectTarget::NetworkListener(_) => {}
        }

        if targets.len() == start {
            targets.push(MutationTargetCandidate {
                implicit_incidental_cache: false,
                operation: effect.kind,
                slot_name: format!("effect_{effect_index}"),
                resolution: PathResolution::UnsupportedDynamicText {
                    text: format!("unresolved mutation target for {:?}", effect.kind),
                },
                cwd_dependent: true,
            });
        }
    }
    targets
}

pub(crate) fn collect_path_facts(
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<PathFactCandidate> {
    let mut paths = Vec::new();

    for &record in records {
        for option in record.cwd_options(cwd) {
            let start = paths.len();
            let resolution_cwd = option.unwrap_or(cwd);
            match record.result() {
                ResolveInvocationArtifactResult::Resolved(resolved) => {
                    collect_resolved_record_path_facts(
                        record,
                        resolved,
                        resolution_cwd,
                        home,
                        &mut paths,
                    );
                }
                ResolveInvocationArtifactResult::SelectionError {
                    normalized_command_name,
                    partial_bound: Some(bound),
                    ..
                } => {
                    collect_selection_error_path_facts(
                        record,
                        normalized_command_name,
                        bound,
                        resolution_cwd,
                        home,
                        &mut paths,
                    );
                }
                ResolveInvocationArtifactResult::MissingCommandName { .. }
                | ResolveInvocationArtifactResult::NoProfile { .. }
                | ResolveInvocationArtifactResult::SelectionError {
                    partial_bound: None,
                    ..
                } => {}
            }
            if option.is_none() {
                for path in &mut paths[start..] {
                    if path.cwd_dependent {
                        path.resolution = PathResolution::UnsupportedDynamicText {
                            text: format!("{} depends on unresolved execution cwd", path.slot_name),
                        };
                    }
                }
            }
        }
    }

    paths
}

pub(crate) fn collect_mutation_scope_facts(
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<MutationScopeFactCandidate> {
    let mut scopes = Vec::new();

    for &record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        for option in record.cwd_options(cwd) {
            collect_resolved_record_mutation_scope_facts(
                record,
                resolved,
                option.unwrap_or(cwd),
                home,
                option.is_some(),
                &mut scopes,
            );
        }
    }

    scopes
}

pub(crate) fn collect_redirection_path_facts(
    parsed_command: &ParsedCommandArtifact,
    cwd: &str,
    home: Option<&str>,
) -> Vec<RedirectionPathFactCandidate> {
    let mut paths = Vec::new();

    for (redirection_index, redirection) in parsed_command.redirections.iter().enumerate() {
        let Some((role, slot_name, resolution)) =
            redirection_path_fact(redirection, redirection_index, cwd, home)
        else {
            continue;
        };

        paths.push(RedirectionPathFactCandidate {
            fact: redirection.clone(),
            redirection_index,
            slot_name,
            resolution,
            cwd_dependent: redirection.target.as_ref().is_none_or(|target| {
                path_operand_depends_on_cwd(&target.text, target.quoted, &target.node_kind, None)
            }),
            role,
        });
    }

    paths
}

fn collect_resolved_record_path_facts(
    record: ExecutionResolveRecordRef<'_>,
    resolved: &ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
    out: &mut Vec<PathFactCandidate>,
) {
    for parameter in &resolved.bound.bound_parameters {
        for value in parameter.semantic_values() {
            let Some((role, purpose)) =
                path_semantics_for_parameter_value(&parameter.semantic, semantic_value_text(value))
            else {
                continue;
            };
            let (resolution, cwd_dependent) =
                semantic_path_resolution(value, Some(resolved), cwd, home);

            out.push(PathFactCandidate {
                source_node_id: record.source_node_id().clone(),
                command_index: record.command_index(),
                slot_name: parameter.name.as_str().to_string(),
                semantic_slot: Some(parameter.name.clone()),
                normalized_command_name: resolved.normalized_command_name.clone(),
                resolution,
                cwd_dependent,
                role,
                purpose,
                metadata_mutation: metadata_mutation_for_path_slot(
                    &resolved.bound,
                    parameter.name.as_str(),
                ),
            });
        }
    }

    collect_effect_target_path_facts(
        record,
        &resolved.normalized_command_name,
        &resolved.bound,
        Some(resolved),
        cwd,
        home,
        out,
    );
}

fn collect_selection_error_path_facts(
    record: ExecutionResolveRecordRef<'_>,
    normalized_command_name: &str,
    bound: &caushell_profile::BoundInvocation,
    cwd: &str,
    home: Option<&str>,
    out: &mut Vec<PathFactCandidate>,
) {
    for parameter in &bound.bound_parameters {
        for value in parameter.semantic_values() {
            let Some((role, purpose)) =
                path_semantics_for_parameter_value(&parameter.semantic, semantic_value_text(value))
            else {
                continue;
            };
            let (resolution, cwd_dependent) = semantic_path_resolution(value, None, cwd, home);

            out.push(PathFactCandidate {
                source_node_id: record.source_node_id().clone(),
                command_index: record.command_index(),
                slot_name: parameter.name.as_str().to_string(),
                semantic_slot: Some(parameter.name.clone()),
                normalized_command_name: normalized_command_name.to_string(),
                resolution,
                cwd_dependent,
                role,
                purpose,
                metadata_mutation: metadata_mutation_for_path_slot(bound, parameter.name.as_str()),
            });
        }
    }

    collect_effect_target_path_facts(record, normalized_command_name, bound, None, cwd, home, out);
}

fn collect_resolved_record_mutation_scope_facts(
    record: ExecutionResolveRecordRef<'_>,
    resolved: &ResolvedInvocationArtifact,
    cwd: &str,
    home: Option<&str>,
    cwd_known: bool,
    out: &mut Vec<MutationScopeFactCandidate>,
) {
    for (effect_index, effect) in resolved.bound.effects.iter().enumerate() {
        let Some(operation) = mutation_scope_operation_for_effect(effect.kind) else {
            continue;
        };

        let EffectTarget::MutationScope(target) = &effect.target else {
            continue;
        };

        let (slot_name, resolution) =
            resolve_mutation_scope_target(target, &resolved.bound, cwd, home, cwd_known);

        out.push(MutationScopeFactCandidate {
            source_node_id: record.source_node_id().clone(),
            command_index: record.command_index(),
            effect_index,
            slot_name,
            normalized_command_name: resolved.normalized_command_name.clone(),
            resolution,
            operation,
        });
    }
}

fn resolve_mutation_scope_target(
    target: &MutationScopeTarget,
    invocation: &BoundInvocation,
    cwd: &str,
    home: Option<&str>,
    cwd_known: bool,
) -> (String, MutationScopeResolution) {
    match target {
        MutationScopeTarget::RepositoryWorktree {
            root,
            path_set,
            subtree,
        } => {
            let root_resolution = root
                .as_ref()
                .and_then(|slot| {
                    first_path_resolution_for_slot(invocation, slot, cwd, home, cwd_known)
                })
                .unwrap_or_else(|| {
                    if cwd_known {
                        PathResolution::Concrete {
                            path: normalize_shell_path(cwd),
                        }
                    } else {
                        PathResolution::UnsupportedDynamicText {
                            text: "repository root depends on unresolved execution cwd".into(),
                        }
                    }
                });

            let scope = subtree
                .as_ref()
                .and_then(|slot| {
                    first_path_resolution_for_slot(invocation, slot, cwd, home, cwd_known)
                })
                .map(|path| RepositoryWorktreeScopeResolution::Subtree { path })
                .unwrap_or(RepositoryWorktreeScopeResolution::WholeWorktree);

            (
                subtree
                    .as_ref()
                    .or(root.as_ref())
                    .map(|slot| slot.as_str().to_string())
                    .unwrap_or_else(|| "repository_worktree".to_string()),
                MutationScopeResolution::RepositoryWorktree {
                    root: root_resolution,
                    path_set: *path_set,
                    scope,
                },
            )
        }
    }
}

fn first_path_resolution_for_slot(
    invocation: &BoundInvocation,
    slot: &SlotName,
    cwd: &str,
    home: Option<&str>,
    cwd_known: bool,
) -> Option<PathResolution> {
    let parameter = invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name == *slot)?;

    parameter.semantic_values().find_map(|value| match value {
        SemanticValueRef::Original(BoundValue::ImplicitInput { .. }) => None,
        _ => {
            let (resolution, dependent) = semantic_path_resolution(value, None, cwd, home);
            Some(if !cwd_known && dependent {
                PathResolution::UnsupportedDynamicText {
                    text: format!("{} depends on unresolved execution cwd", slot.as_str()),
                }
            } else {
                resolution
            })
        }
    })
}

fn collect_effect_target_path_facts(
    record: ExecutionResolveRecordRef<'_>,
    normalized_command_name: &str,
    invocation: &BoundInvocation,
    resolved: Option<&ResolvedInvocationArtifact>,
    cwd: &str,
    home: Option<&str>,
    out: &mut Vec<PathFactCandidate>,
) {
    for (effect_index, effect) in invocation.effects.iter().enumerate() {
        let Some(role) = path_role_for_effect(effect.kind).or_else(|| {
            (effect.kind == EffectKind::DeletePath
                && matches!(effect.target, EffectTarget::ConfiguredPath(_)))
            .then_some(PathRole::Target)
        }) else {
            continue;
        };

        if path_target_is_inapplicable(invocation, &effect.target) {
            continue;
        }

        match &effect.target {
            EffectTarget::ConfiguredPath(target) => {
                if let Some(path) =
                    resolve_configured_path(invocation, target, cwd, home, Some(record))
                {
                    out.push(PathFactCandidate {
                        source_node_id: record.source_node_id().clone(),
                        command_index: record.command_index(),
                        slot_name: format!("configured_path_{effect_index}"),
                        semantic_slot: None,
                        normalized_command_name: normalized_command_name.to_string(),
                        resolution: path.resolution,
                        cwd_dependent: path.cwd_dependent,
                        role,
                        purpose: target.purpose,
                        metadata_mutation: None,
                    });
                }
            }
            EffectTarget::ToolConventionPath(target) => out.push(PathFactCandidate {
                source_node_id: record.source_node_id().clone(),
                command_index: record.command_index(),
                slot_name: tool_convention_slot_name(effect_index, &target.convention),
                semantic_slot: None,
                normalized_command_name: normalized_command_name.to_string(),
                resolution: resolve_tool_convention_path(target, cwd),
                cwd_dependent: !target.path.starts_with('/'),
                role,
                purpose: target.purpose,
                metadata_mutation: None,
            }),
            EffectTarget::DerivedPath(target) => collect_derived_target_path_facts(
                record,
                normalized_command_name,
                invocation,
                resolved,
                effect_index,
                target,
                role,
                cwd,
                home,
                out,
            ),
            EffectTarget::Slot(slot) => {
                let Some(parameter) = bound_parameter(invocation, slot.as_str()) else {
                    continue;
                };
                let SemanticType::Path(path) = &parameter.semantic else {
                    continue;
                };
                // Parameters provide a base role, not an exclusive role. A
                // declared read/modify effect on the same file must also enter
                // the graph. Avoid duplicating the parameter's existing role.
                if path.role == role {
                    continue;
                }
                for value in parameter.semantic_values() {
                    let (resolution, cwd_dependent) =
                        semantic_path_resolution(value, resolved, cwd, home);
                    out.push(PathFactCandidate {
                        source_node_id: record.source_node_id().clone(),
                        command_index: record.command_index(),
                        slot_name: format!("{}_effect_{effect_index}", slot.as_str()),
                        semantic_slot: Some(slot.clone()),
                        normalized_command_name: normalized_command_name.into(),
                        resolution,
                        cwd_dependent,
                        role,
                        purpose: path.purpose,
                        metadata_mutation: metadata_mutation_for_path_slot(
                            invocation,
                            slot.as_str(),
                        ),
                    });
                }
            }
            EffectTarget::MutationScope(_)
            | EffectTarget::VariableName(_)
            | EffectTarget::ImplicitInput(_)
            | EffectTarget::Dispatch(_)
            | EffectTarget::None
            | EffectTarget::NetworkListener(_) => {}
        }
    }
}

fn collect_derived_target_path_facts(
    record: ExecutionResolveRecordRef<'_>,
    normalized_command_name: &str,
    invocation: &BoundInvocation,
    resolved: Option<&ResolvedInvocationArtifact>,
    effect_index: usize,
    target: &DerivedPathTarget,
    role: PathRole,
    cwd: &str,
    home: Option<&str>,
    out: &mut Vec<PathFactCandidate>,
) {
    let cwd_dependent = match target.root.as_ref().unwrap_or(&target.source) {
        DerivedPathSource::Slot(slot) => {
            bound_parameter(invocation, slot.as_str()).is_none_or(|parameter| {
                parameter
                    .semantic_values()
                    .any(|value| semantic_path_resolution(value, resolved, cwd, home).1)
            })
        }
        DerivedPathSource::ToolConventionRoot { convention } => {
            tool_convention_roots_for_convention(invocation, convention)
                .any(|target| !target.path.starts_with('/'))
        }
    };
    match (&target.source, &target.root) {
        (DerivedPathSource::Slot(source_slot_name), Some(root_source)) => {
            let Some(parameter) = bound_parameter(invocation, source_slot_name.as_str()) else {
                return;
            };

            let root_paths = resolve_derived_root_paths(invocation, root_source, cwd, home);
            if root_paths.is_empty() {
                return;
            }

            for value in parameter.semantic_values() {
                let Some(child_resolution) = derive_semantic_slot_path_resolution(
                    parameter,
                    value,
                    resolved,
                    cwd,
                    home,
                    source_slot_name.as_str(),
                    &target.rule,
                ) else {
                    continue;
                };

                for root_path in &root_paths {
                    let resolution = match root_path.concrete_path() {
                        Some(root) => compose_derived_path_under_root(&child_resolution, root),
                        // A projected unknown root must not erase the derived
                        // effect. Keep its uncertainty in the graph and guard.
                        None => PathResolution::UnsupportedDynamicText {
                            text: format!(
                                "derived target {:?} from {child_resolution:?} has unresolved root {root_path:?}",
                                target.rule
                            ),
                        },
                    };

                    out.push(PathFactCandidate {
                        source_node_id: record.source_node_id().clone(),
                        command_index: record.command_index(),
                        slot_name: derived_path_slot_name(effect_index),
                        semantic_slot: None,
                        normalized_command_name: normalized_command_name.to_string(),
                        resolution,
                        cwd_dependent,
                        role,
                        purpose: target.purpose,
                        metadata_mutation: None,
                    });
                }
            }
        }
        (DerivedPathSource::Slot(source_slot_name), None) => {
            let Some(parameter) = bound_parameter(invocation, source_slot_name.as_str()) else {
                return;
            };

            for value in parameter.semantic_values() {
                let Some(resolution) = derive_semantic_slot_path_resolution(
                    parameter,
                    value,
                    resolved,
                    cwd,
                    home,
                    source_slot_name.as_str(),
                    &target.rule,
                ) else {
                    continue;
                };

                out.push(PathFactCandidate {
                    source_node_id: record.source_node_id().clone(),
                    command_index: record.command_index(),
                    slot_name: derived_path_slot_name(effect_index),
                    semantic_slot: None,
                    normalized_command_name: normalized_command_name.to_string(),
                    resolution,
                    cwd_dependent,
                    role,
                    purpose: target.purpose,
                    metadata_mutation: None,
                });
            }
        }
        (DerivedPathSource::ToolConventionRoot { convention }, None) => {
            for root_target in tool_convention_roots_for_convention(invocation, convention) {
                let root_resolution = resolve_tool_convention_path(root_target, cwd);
                let basis = DerivedPathBasis::ToolConventionRoot {
                    path: root_resolution
                        .concrete_path()
                        .expect("tool convention targets always resolve to a concrete path")
                        .to_string(),
                    convention: convention.clone(),
                };
                let resolution = derive_path_resolution_from_concrete_source(
                    root_resolution,
                    basis,
                    &target.rule,
                );

                out.push(PathFactCandidate {
                    source_node_id: record.source_node_id().clone(),
                    command_index: record.command_index(),
                    slot_name: derived_path_slot_name(effect_index),
                    semantic_slot: None,
                    normalized_command_name: normalized_command_name.to_string(),
                    resolution,
                    cwd_dependent,
                    role,
                    purpose: target.purpose,
                    metadata_mutation: None,
                });
            }
        }
        (DerivedPathSource::ToolConventionRoot { .. }, Some(_)) => {}
    }
}

fn tool_convention_roots_for_convention<'a>(
    invocation: &'a BoundInvocation,
    convention: &str,
) -> impl Iterator<Item = &'a ToolConventionPathTarget> {
    invocation.effects.iter().filter_map(move |effect| {
        let EffectTarget::ToolConventionPath(target) = &effect.target else {
            return None;
        };

        (target.convention == convention).then_some(target)
    })
}

fn resolve_derived_root_paths(
    invocation: &BoundInvocation,
    root_source: &DerivedPathSource,
    cwd: &str,
    home: Option<&str>,
) -> Vec<PathResolution> {
    match root_source {
        DerivedPathSource::Slot(slot_name) => {
            let Some(parameter) = bound_parameter(invocation, slot_name.as_str()) else {
                return Vec::new();
            };

            parameter
                .semantic_values()
                .filter_map(|value| match value {
                    SemanticValueRef::Projected { .. } => {
                        Some(semantic_path_resolution(value, None, cwd, home).0)
                    }
                    SemanticValueRef::Original(BoundValue::Argument {
                        text,
                        quoted,
                        node_kind,
                        ..
                    }) => {
                        let resolution =
                            resolve_path_resolution(text, *quoted, node_kind, cwd, home, None);
                        resolution.concrete_path().is_some().then_some(resolution)
                    }
                    SemanticValueRef::Original(BoundValue::ImplicitInput { .. }) => None,
                })
                .collect()
        }
        DerivedPathSource::ToolConventionRoot { convention } => {
            tool_convention_roots_for_convention(invocation, convention)
                .map(|target| resolve_tool_convention_path(target, cwd))
                .collect()
        }
    }
}

fn bound_parameter<'a>(
    invocation: &'a BoundInvocation,
    slot_name: &str,
) -> Option<&'a BoundParameter> {
    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == slot_name)
}

fn path_semantics_for_parameter_value(
    semantic: &SemanticType,
    text: &str,
) -> Option<(PathRole, Option<PathPurpose>)> {
    match semantic {
        SemanticType::Path(path) => Some((path.role, path.purpose)),
        SemanticType::InProcessCodeLoad(load)
            if in_process_code_load_resolves_as_path(load.load_kind, text) =>
        {
            Some((PathRole::Read, Some(PathPurpose::InProcessCode)))
        }
        _ => None,
    }
}

fn in_process_code_load_resolves_as_path(load_kind: InProcessCodeLoadKind, text: &str) -> bool {
    match load_kind {
        InProcessCodeLoadKind::Path
        | InProcessCodeLoadKind::LibraryPath
        | InProcessCodeLoadKind::AgentPath => true,
        InProcessCodeLoadKind::Unknown => looks_like_explicit_path_operand(text),
        InProcessCodeLoadKind::ModuleName | InProcessCodeLoadKind::PluginName => false,
    }
}

fn looks_like_explicit_path_operand(text: &str) -> bool {
    text == "~"
        || text.starts_with("~/")
        || text.starts_with("./")
        || text.starts_with("../")
        || text.starts_with('/')
}

fn derive_semantic_slot_path_resolution(
    parameter: &BoundParameter,
    value: SemanticValueRef<'_>,
    resolved: Option<&ResolvedInvocationArtifact>,
    cwd: &str,
    home: Option<&str>,
    slot_name: &str,
    rule: &DerivedPathRule,
) -> Option<PathResolution> {
    if *rule == DerivedPathRule::SiblingFiles {
        let known = match value {
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(text) => Some(text.clone()),
                _ => None,
            },
            SemanticValueRef::Original(source) => match caushell_profile::project_value(
                &caushell_profile::ValueProjection::Identity,
                source,
            ) {
                Some(SemanticValueResolution::Known(text)) => Some(text),
                _ => None,
            },
        };
        if let Some(text) = known {
            // A basename is a prefix, not an existing path: `..` becomes
            // `.._report.csv`, so normalize its parent, not the prefix itself.
            let directory = text
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or(".");
            return Some(PathResolution::BoundedPathSet {
                roots: vec![lexical_path_from_argv(directory, cwd)],
                may_escape: false,
            });
        }
    }
    match value {
        SemanticValueRef::Original(BoundValue::Argument {
            text,
            quoted,
            node_kind,
            span,
            materialization: bound_materialization,
            ..
        }) => Some(derive_slot_target_path_resolution(
            parameter,
            text,
            *quoted,
            node_kind,
            cwd,
            home,
            resolved.and_then(|resolved| arg_materialization_for_span(resolved, span)),
            bound_materialization,
            slot_name,
            rule,
        )),
        SemanticValueRef::Original(BoundValue::ImplicitInput { source, domain }) => {
            let basis = DerivedPathBasis::PathOperand {
                raw: format!("runtime input {source:?}"),
                resolved_input_path: None,
                slot_name: slot_name.to_string(),
            };
            Some(match domain {
                Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, may_escape }) => {
                    derive_bounded_path_resolution(roots, *may_escape, basis, rule, cwd)
                }
                _ => PathResolution::DerivedUnresolved {
                    basis,
                    rule: rule.clone(),
                    reason: DerivedPathUnresolvedReason::UnsupportedRuntimeRule,
                },
            })
        }
        SemanticValueRef::Projected { source, .. } => {
            let source_resolution = semantic_path_resolution(value, resolved, cwd, home).0;
            let raw = match source {
                BoundValue::Argument { text, .. } => text.clone(),
                BoundValue::ImplicitInput { .. } => format!("{source:?}"),
            };
            let basis = DerivedPathBasis::PathOperand {
                raw,
                resolved_input_path: source_resolution.concrete_path().map(str::to_string),
                slot_name: slot_name.to_string(),
            };
            let spelling = match value {
                SemanticValueRef::Projected { value, .. } => match &value.resolution {
                    SemanticValueResolution::Known(text) => Some(text.as_str()),
                    _ => None,
                },
                _ => None,
            };
            Some(derive_path_resolution_from_spelling(
                source_resolution,
                basis,
                rule,
                spelling,
                cwd,
            ))
        }
    }
}

fn derive_slot_target_path_resolution(
    parameter: &BoundParameter,
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
    materialization: Option<&ValueMaterialization>,
    bound_materialization: &BoundArgumentMaterialization,
    slot_name: &str,
    rule: &DerivedPathRule,
) -> PathResolution {
    match &parameter.semantic {
        SemanticType::Path(_) | SemanticType::InProcessCodeLoad(_)
            if path_semantics_for_parameter_value(&parameter.semantic, text).is_some() =>
        {
            let source_resolution = resolve_bound_path_resolution(
                text,
                quoted,
                node_kind,
                cwd,
                home,
                bound_materialization,
                materialization,
            );
            let basis = DerivedPathBasis::PathOperand {
                raw: text.to_string(),
                resolved_input_path: source_resolution.concrete_path().map(str::to_string),
                slot_name: slot_name.to_string(),
            };

            // Filename transforms precede lexical normalization. In particular,
            // `./` + `.gz` names a child, not a sibling of the cwd, and literal
            // materialized `$`/`~` bytes must not undergo shell expansion again.
            let spelling = match materialization {
                Some(ValueMaterialization::ResolvedExactScalar { value, .. })
                | Some(ValueMaterialization::ResolvedRuntimeProduced { value, .. }) => {
                    Some(value.clone())
                }
                _ if !matches!(bound_materialization, BoundArgumentMaterialization::Literal) => {
                    Some(text.to_string())
                }
                _ => caushell_parse::decode_static_shell_argument(text, quoted, node_kind).map(
                    |word| {
                        if !quoted && (word == "~" || word.starts_with("~/")) {
                            home.map(|home| format!("{home}{}", &word[1..]))
                                .unwrap_or(word)
                        } else {
                            word
                        }
                    },
                ),
            };
            derive_path_resolution_from_spelling(
                source_resolution,
                basis,
                rule,
                spelling.as_deref(),
                cwd,
            )
        }
        SemanticType::Endpoint(endpoint)
            if endpoint.kind == caushell_profile::EndpointKind::Url =>
        {
            let basis = DerivedPathBasis::EndpointOperand {
                raw: text.to_string(),
                slot_name: slot_name.to_string(),
            };
            derive_path_resolution_from_endpoint_operand(text, cwd, materialization, basis, rule)
        }
        _ => PathResolution::DerivedUnresolved {
            basis: DerivedPathBasis::PathOperand {
                raw: text.to_string(),
                resolved_input_path: None,
                slot_name: slot_name.to_string(),
            },
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
        },
    }
}

fn suffix_transform(text: &str, rule: &DerivedPathRule) -> Option<String> {
    match rule {
        DerivedPathRule::AppendSuffix { suffix } => Some(format!("{text}{suffix}")),
        DerivedPathRule::StripSuffix { suffix } => text.strip_suffix(suffix).map(str::to_string),
        DerivedPathRule::ReplaceSuffix { from, to } => {
            text.strip_suffix(from).map(|stem| format!("{stem}{to}"))
        }
        _ => None,
    }
}

fn derive_path_resolution_from_spelling(
    source_resolution: PathResolution,
    basis: DerivedPathBasis,
    rule: &DerivedPathRule,
    spelling: Option<&str>,
    cwd: &str,
) -> PathResolution {
    if source_resolution.concrete_path().is_some()
        && let Some(spelling) = spelling
        && matches!(
            rule,
            DerivedPathRule::AppendSuffix { .. }
                | DerivedPathRule::StripSuffix { .. }
                | DerivedPathRule::ReplaceSuffix { .. }
        )
    {
        return match suffix_transform(spelling, rule).filter(|output| !output.is_empty()) {
            Some(output) => PathResolution::DerivedConcrete {
                path: lexical_path_from_argv(&output, cwd),
                basis,
                rule: rule.clone(),
            },
            None => PathResolution::DerivedUnresolved {
                basis,
                rule: rule.clone(),
                reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
            },
        };
    }
    derive_path_resolution_from_concrete_source(source_resolution, basis, rule)
}

/// A root bounds a set inclusively; it is NOT proof of an exact filename or
/// a directory-only/strict-descendant set. Preserve the raw root spelling for
/// append transforms, and widen to its parent when a transformed root or `..`
/// basename can leave that root. No filename, filesystem or tool-name probes.
fn derive_bounded_path_resolution(
    roots: &[String],
    may_escape: bool,
    basis: DerivedPathBasis,
    rule: &DerivedPathRule,
    cwd: &str,
) -> PathResolution {
    let unresolved = || PathResolution::DerivedUnresolved {
        basis: basis.clone(),
        rule: rule.clone(),
        reason: DerivedPathUnresolvedReason::UnsupportedRuntimeRule,
    };
    if roots.is_empty()
        || roots
            .iter()
            .any(|root| root.is_empty() || root.contains('\0'))
    {
        return unresolved();
    }
    let component = |s: &str| !s.contains(['/', '\0']);
    let preserves_root = match rule {
        DerivedPathRule::AppendSuffix { suffix }
            if component(suffix) && !suffix.is_empty() && suffix != "." && suffix != ".." =>
        {
            true
        }
        DerivedPathRule::StripSuffix { suffix } if component(suffix) && !suffix.is_empty() => false,
        DerivedPathRule::ReplaceSuffix { from, to }
            if component(from) && !from.is_empty() && component(to) =>
        {
            false
        }
        DerivedPathRule::SiblingFiles => false,
        DerivedPathRule::ChildUnder { relative_path }
            if !relative_path.starts_with('/')
                && !relative_path.contains('\0')
                && !relative_path.split('/').any(|part| part == "..") =>
        {
            return PathResolution::BoundedPathSet {
                roots: roots
                    .iter()
                    .map(|root| lexical_path_from_argv(root, cwd))
                    .collect(),
                may_escape,
            };
        }
        _ => return unresolved(),
    };
    let mut output_roots = Vec::with_capacity(roots.len());
    for spelling in roots {
        let root = lexical_path_from_argv(spelling, cwd);
        let bound = if preserves_root
            && (spelling.ends_with('/') || matches!(spelling.rsplit('/').next(), Some("." | "..")))
        {
            root
        } else {
            // Strip/replace can produce a special basename (`...gz` -> `..`).
            // Their parent bound is necessary even when the root is `.`.
            lexical_path_from_argv("..", &root)
        };
        if !output_roots.contains(&bound) {
            output_roots.push(bound);
        }
    }
    PathResolution::BoundedPathSet {
        roots: output_roots,
        may_escape,
    }
}

fn derive_path_resolution_from_concrete_source(
    source_resolution: PathResolution,
    basis: DerivedPathBasis,
    rule: &DerivedPathRule,
) -> PathResolution {
    if let PathResolution::BoundedPathSet { roots, may_escape } = &source_resolution {
        return derive_bounded_path_resolution(roots, *may_escape, basis, rule, "/");
    }
    let Some(source_path) = source_resolution.concrete_path() else {
        return PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
        };
    };

    match rule {
        DerivedPathRule::SiblingFiles => sibling_file_resolution(source_path, false),
        DerivedPathRule::AppendSuffix { suffix } => PathResolution::DerivedConcrete {
            path: format!("{source_path}{suffix}"),
            basis,
            rule: rule.clone(),
        },
        DerivedPathRule::StripSuffix { suffix } => match source_path.strip_suffix(suffix) {
            Some(stripped) => PathResolution::DerivedConcrete {
                path: normalize_shell_path(stripped),
                basis,
                rule: rule.clone(),
            },
            None => PathResolution::DerivedUnresolved {
                basis,
                rule: rule.clone(),
                reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
            },
        },
        DerivedPathRule::ReplaceSuffix { from, to } => match source_path.strip_suffix(from) {
            Some(stripped) => PathResolution::DerivedConcrete {
                path: normalize_shell_path(&format!("{stripped}{to}")),
                basis,
                rule: rule.clone(),
            },
            None => PathResolution::DerivedUnresolved {
                basis,
                rule: rule.clone(),
                reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
            },
        },
        DerivedPathRule::ArchiveMembers => PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnknownArchiveMembers,
        },
        DerivedPathRule::ChildUnder { relative_path } => {
            derive_path_resolution_under_root(source_path, relative_path, basis, rule)
        }
        DerivedPathRule::UrlBasename => PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedRuntimeRule,
        },
    }
}

fn sibling_file_resolution(source_path: &str, is_directory: bool) -> PathResolution {
    let root = if is_directory {
        source_path
    } else {
        source_path
            .rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .unwrap_or("/")
    };
    PathResolution::BoundedPathSet {
        roots: vec![root.to_string()],
        may_escape: false,
    }
}

fn derive_path_resolution_under_root(
    source_path: &str,
    relative_path: &str,
    basis: DerivedPathBasis,
    rule: &DerivedPathRule,
) -> PathResolution {
    if relative_path.starts_with('/') {
        return PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
        };
    }

    let path = join_shell_path(source_path, relative_path);
    if !path_is_within_root(&path, source_path) {
        return PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedOperandShape,
        };
    }

    PathResolution::DerivedConcrete {
        path,
        basis,
        rule: rule.clone(),
    }
}

fn compose_derived_path_under_root(
    child_resolution: &PathResolution,
    root_path: &str,
) -> PathResolution {
    match child_resolution {
        PathResolution::DerivedConcrete { path, basis, rule } => {
            let child_name = path.rsplit('/').next().unwrap_or(path);
            PathResolution::DerivedConcrete {
                path: join_shell_path(root_path, child_name),
                basis: basis.clone(),
                rule: rule.clone(),
            }
        }
        PathResolution::DerivedUnresolved {
            basis,
            rule,
            reason,
        } => PathResolution::DerivedUnresolved {
            basis: basis.clone(),
            rule: rule.clone(),
            reason: *reason,
        },
        PathResolution::Concrete { path } => PathResolution::Concrete {
            path: join_shell_path(root_path, path.rsplit('/').next().unwrap_or(path)),
        },
        PathResolution::ToolConvention { path, convention } => PathResolution::ToolConvention {
            path: join_shell_path(root_path, path.rsplit('/').next().unwrap_or(path)),
            convention: convention.clone(),
        },
        PathResolution::MissingBinding { variable_name } => PathResolution::MissingBinding {
            variable_name: variable_name.clone(),
        },
        PathResolution::UnsupportedDynamicBinding {
            variable_name,
            repr,
        } => PathResolution::UnsupportedDynamicBinding {
            variable_name: variable_name.clone(),
            repr: repr.clone(),
        },
        PathResolution::UnsupportedDynamicText { text } => {
            PathResolution::UnsupportedDynamicText { text: text.clone() }
        }
        PathResolution::HomeUnavailable { text } => {
            PathResolution::HomeUnavailable { text: text.clone() }
        }
        PathResolution::BoundedPathSet { may_escape, .. } => PathResolution::BoundedPathSet {
            // The declared output root relocates the derived name. Retaining
            // input roots would falsely certify a write to an external root.
            // A bounded name may include a special basename after stripping;
            // one parent covers that without inventing a concrete filename.
            roots: vec![lexical_path_from_argv("..", root_path)],
            may_escape: *may_escape,
        },
    }
}

fn derive_path_resolution_from_endpoint_operand(
    text: &str,
    cwd: &str,
    materialization: Option<&ValueMaterialization>,
    basis: DerivedPathBasis,
    rule: &DerivedPathRule,
) -> PathResolution {
    match rule {
        DerivedPathRule::UrlBasename => match endpoint_url_basename(text, materialization) {
            Some(basename) => PathResolution::DerivedConcrete {
                path: join_shell_path(cwd, &basename),
                basis,
                rule: rule.clone(),
            },
            None => PathResolution::DerivedUnresolved {
                basis,
                rule: rule.clone(),
                reason: endpoint_url_unresolved_reason(materialization),
            },
        },
        _ => PathResolution::DerivedUnresolved {
            basis,
            rule: rule.clone(),
            reason: DerivedPathUnresolvedReason::UnsupportedRuntimeRule,
        },
    }
}

fn endpoint_url_basename(
    text: &str,
    materialization: Option<&ValueMaterialization>,
) -> Option<String> {
    if matches!(
        materialization,
        Some(
            ValueMaterialization::MissingBinding { .. }
                | ValueMaterialization::UnsupportedDynamicBinding { .. }
                | ValueMaterialization::UnsupportedDynamicText { .. }
                | ValueMaterialization::UnsafeUnquotedScalar { .. }
                | ValueMaterialization::RequiresRuntimeInput { .. }
                | ValueMaterialization::RequiresImplicitInput { .. }
        )
    ) {
        return None;
    }

    let without_fragment = text.split('#').next().unwrap_or(text);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    let after_scheme = without_query
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(without_query);
    let path = after_scheme
        .split_once('/')
        .map(|(_, path)| path)
        .unwrap_or("");
    let basename = path.rsplit('/').next().unwrap_or("");

    if basename.is_empty() {
        None
    } else {
        Some(basename.to_string())
    }
}

fn endpoint_url_unresolved_reason(
    materialization: Option<&ValueMaterialization>,
) -> DerivedPathUnresolvedReason {
    match materialization {
        Some(
            ValueMaterialization::MissingBinding { .. }
            | ValueMaterialization::UnsupportedDynamicBinding { .. }
            | ValueMaterialization::UnsupportedDynamicText { .. }
            | ValueMaterialization::UnsafeUnquotedScalar { .. }
            | ValueMaterialization::RequiresRuntimeInput { .. }
            | ValueMaterialization::RequiresImplicitInput { .. },
        ) => DerivedPathUnresolvedReason::UnsupportedOperandShape,
        Some(
            ValueMaterialization::Static
            | ValueMaterialization::ResolvedExactScalar { .. }
            | ValueMaterialization::ResolvedRuntimeProduced { .. },
        )
        | None => DerivedPathUnresolvedReason::MissingUrlBasename,
    }
}

fn metadata_mutation_for_path_slot(
    invocation: &BoundInvocation,
    slot_name: &str,
) -> Option<PathMetadataMutation> {
    invocation
        .effects
        .iter()
        .filter(|effect| effect_targets_slot(effect, slot_name))
        .filter_map(|effect| metadata_mutation_for_effect(invocation, effect))
        .reduce(|mut current, next| {
            current.recursive |= next.recursive;
            for mutation_kind in next.mutation_kinds {
                if mutation_kind == PathMetadataMutationKind::Generic
                    && !current.mutation_kinds.is_empty()
                {
                    continue;
                }
                if mutation_kind != PathMetadataMutationKind::Generic {
                    current
                        .mutation_kinds
                        .retain(|kind| *kind != PathMetadataMutationKind::Generic);
                }
                if !current.mutation_kinds.contains(&mutation_kind) {
                    current.mutation_kinds.push(mutation_kind);
                }
            }
            if current.raw_operand.is_none() {
                current.raw_operand = next.raw_operand;
            }
            if current.owner_group.is_none() {
                current.owner_group = next.owner_group;
            }
            current
        })
}

fn effect_targets_slot(effect: &Effect, slot_name: &str) -> bool {
    matches!(&effect.target, EffectTarget::Slot(target) if target.as_str() == slot_name)
}

fn metadata_mutation_for_effect(
    invocation: &BoundInvocation,
    effect: &Effect,
) -> Option<PathMetadataMutation> {
    let operand_parameter = metadata_mutation_operand_parameter(invocation, effect);
    let raw_operand = operand_parameter.and_then(first_argument_text);
    let owner_group = operand_parameter.and_then(owner_group_spec_for_parameter);
    let mutation_kinds = metadata_mutation_kinds(effect.kind, owner_group.as_ref())?;
    let recursive = effect
        .extensions
        .get("metadata_mutation.recursive")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    Some(PathMetadataMutation {
        mutation_kinds,
        raw_operand,
        owner_group,
        recursive,
    })
}

fn metadata_mutation_kinds(
    kind: EffectKind,
    owner_group: Option<&OwnerGroupSpec>,
) -> Option<Vec<PathMetadataMutationKind>> {
    match kind {
        EffectKind::ChangeMode => Some(vec![PathMetadataMutationKind::ChangeMode]),
        EffectKind::ChangeOwner => Some(vec![PathMetadataMutationKind::ChangeOwner]),
        EffectKind::ChangeGroup => Some(vec![PathMetadataMutationKind::ChangeGroup]),
        EffectKind::MetadataMutation => {
            let mut kinds = Vec::new();

            if owner_group.is_some_and(|spec| spec.owner.is_some()) {
                kinds.push(PathMetadataMutationKind::ChangeOwner);
            }
            if owner_group.is_some_and(|spec| spec.group.is_some()) {
                kinds.push(PathMetadataMutationKind::ChangeGroup);
            }
            if kinds.is_empty() {
                kinds.push(PathMetadataMutationKind::Generic);
            }

            Some(kinds)
        }
        EffectKind::ReadPath
        | EffectKind::WritePath
        | EffectKind::DeletePath
        | EffectKind::MovePath
        | EffectKind::TargetPath
        | EffectKind::LoadConfig
        | EffectKind::ExecutePayload
        | EffectKind::SourceScriptIntoCurrentShell
        | EffectKind::SetCurrentWorkingDirectory
        | EffectKind::SetExecutionWorkingDirectory
        | EffectKind::ExecuteRemoteCommand
        | EffectKind::ExecuteHook
        | EffectKind::ExecuteConfigDefinedTask
        | EffectKind::DispatchCommand
        | EffectKind::ConsumeStdin
        | EffectKind::BindVariableFromRuntimeInput
        | EffectKind::TerminateCurrentShell
        | EffectKind::ShellJobOperation
        | EffectKind::PrivilegeModifier
        | EffectKind::NetworkEndpoint
        | EffectKind::ListenNetwork
        | EffectKind::TransformData
        | EffectKind::ImportPackage
        | EffectKind::ExecuteImportedPackageLogic
        | EffectKind::LoadInProcessCode
        | EffectKind::OpenInteractiveEscapeSurface
        | EffectKind::ControlProcess
        | EffectKind::RepositoryOperation
        | EffectKind::DatabaseOperation
        | EffectKind::TerminalSessionOperation => None,
    }
}

fn metadata_mutation_operand_parameter<'a>(
    invocation: &'a BoundInvocation,
    effect: &Effect,
) -> Option<&'a BoundParameter> {
    let slot_name = effect
        .extensions
        .get("metadata_mutation.raw_operand_slot")
        .and_then(|value| value.as_str())?;

    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == slot_name)
}

fn owner_group_spec_for_parameter(parameter: &BoundParameter) -> Option<OwnerGroupSpec> {
    match &parameter.semantic {
        SemanticType::StructuredValue(semantic)
            if semantic.context == StructuredValueContext::OwnerGroupSpec =>
        {
            first_argument_text(parameter).and_then(|text| parse_owner_group_spec(&text))
        }
        _ => None,
    }
}

fn first_argument_text(parameter: &BoundParameter) -> Option<String> {
    parameter.values.iter().find_map(|value| match value {
        BoundValue::Argument { text, .. } => Some(text.clone()),
        BoundValue::ImplicitInput { .. } => None,
    })
}

fn arg_materialization_for_span<'a>(
    resolved: &'a ResolvedInvocationArtifact,
    span: &SourceSpan,
) -> Option<&'a ValueMaterialization> {
    resolved
        .materialized_projection
        .invocation
        .args
        .iter()
        .zip(resolved.materialized_projection.arg_resolutions.iter())
        .find_map(|(arg, resolution)| (&arg.span == span).then_some(resolution))
}

fn resolve_bound_path_resolution(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
    materialization: &BoundArgumentMaterialization,
    projection_materialization: Option<&ValueMaterialization>,
) -> PathResolution {
    if matches!(
        materialization,
        BoundArgumentMaterialization::RuntimeData
            | BoundArgumentMaterialization::ResolvedExactScalar { .. }
            | BoundArgumentMaterialization::ResolvedRuntimeProduced { .. }
    ) {
        return PathResolution::Concrete {
            path: lexical_path_from_argv(text, cwd),
        };
    }
    resolve_path_resolution(
        text,
        quoted,
        node_kind,
        cwd,
        home,
        projection_materialization,
    )
}

fn resolve_path_resolution(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
    materialization: Option<&ValueMaterialization>,
) -> PathResolution {
    if let Some(path) = resolve_path_operand(text, quoted, node_kind, cwd, home) {
        return PathResolution::Concrete { path };
    }

    if home.is_none() && is_home_relative_operand(text, quoted, node_kind) {
        return PathResolution::HomeUnavailable {
            text: text.to_string(),
        };
    }

    match materialization {
        Some(ValueMaterialization::MissingBinding { variable_name }) => {
            PathResolution::MissingBinding {
                variable_name: variable_name.clone(),
            }
        }
        Some(ValueMaterialization::ResolvedExactScalar { value, .. }) => {
            if let Some(path) = resolve_path_operand(value, quoted, node_kind, cwd, home) {
                PathResolution::Concrete { path }
            } else {
                PathResolution::UnsupportedDynamicText {
                    text: value.clone(),
                }
            }
        }
        Some(ValueMaterialization::ResolvedRuntimeProduced { value, .. }) => {
            if let Some(path) = resolve_path_operand(value, quoted, node_kind, cwd, home) {
                PathResolution::Concrete { path }
            } else {
                PathResolution::UnsupportedDynamicText {
                    text: value.clone(),
                }
            }
        }
        Some(ValueMaterialization::UnsupportedDynamicBinding {
            variable_name,
            repr,
            ..
        }) => PathResolution::UnsupportedDynamicBinding {
            variable_name: variable_name.clone(),
            repr: repr.clone(),
        },
        Some(ValueMaterialization::UnsafeUnquotedScalar {
            variable_name,
            value,
            ..
        }) => PathResolution::UnsupportedDynamicBinding {
            variable_name: variable_name.clone(),
            repr: value.clone(),
        },
        Some(ValueMaterialization::UnsupportedDynamicText { text }) => {
            PathResolution::UnsupportedDynamicText { text: text.clone() }
        }
        Some(ValueMaterialization::RequiresRuntimeInput { .. })
        | Some(ValueMaterialization::RequiresImplicitInput { .. })
        | Some(ValueMaterialization::Static)
        | None => PathResolution::UnsupportedDynamicText {
            text: text.to_string(),
        },
    }
}

fn is_home_relative_operand(text: &str, quoted: bool, node_kind: &str) -> bool {
    !quoted && node_kind != "raw_string" && (text == "~" || text.starts_with("~/"))
}

fn path_role_for_effect(kind: EffectKind) -> Option<PathRole> {
    match kind {
        EffectKind::ReadPath => Some(PathRole::Read),
        EffectKind::WritePath => Some(PathRole::Write),
        EffectKind::TargetPath => Some(PathRole::Target),
        EffectKind::LoadConfig => Some(PathRole::Config),
        EffectKind::DeletePath
        | EffectKind::MovePath
        | EffectKind::ChangeMode
        | EffectKind::ChangeOwner
        | EffectKind::ChangeGroup
        | EffectKind::MetadataMutation
        | EffectKind::ExecutePayload
        | EffectKind::SourceScriptIntoCurrentShell
        | EffectKind::SetCurrentWorkingDirectory
        | EffectKind::SetExecutionWorkingDirectory
        | EffectKind::ExecuteRemoteCommand
        | EffectKind::ExecuteHook
        | EffectKind::ExecuteConfigDefinedTask
        | EffectKind::DispatchCommand
        | EffectKind::ConsumeStdin
        | EffectKind::BindVariableFromRuntimeInput
        | EffectKind::TerminateCurrentShell
        | EffectKind::ShellJobOperation
        | EffectKind::PrivilegeModifier
        | EffectKind::NetworkEndpoint
        | EffectKind::ListenNetwork
        | EffectKind::TransformData
        | EffectKind::ImportPackage
        | EffectKind::ExecuteImportedPackageLogic
        | EffectKind::LoadInProcessCode
        | EffectKind::OpenInteractiveEscapeSurface
        | EffectKind::ControlProcess
        | EffectKind::RepositoryOperation
        | EffectKind::DatabaseOperation
        | EffectKind::TerminalSessionOperation => None,
    }
}

fn mutation_scope_operation_for_effect(kind: EffectKind) -> Option<ResolvedMutationScopeOperation> {
    match kind {
        EffectKind::WritePath => Some(ResolvedMutationScopeOperation::Write),
        EffectKind::DeletePath => Some(ResolvedMutationScopeOperation::Delete),
        EffectKind::ReadPath
        | EffectKind::MovePath
        | EffectKind::ChangeMode
        | EffectKind::ChangeOwner
        | EffectKind::ChangeGroup
        | EffectKind::MetadataMutation
        | EffectKind::TargetPath
        | EffectKind::LoadConfig
        | EffectKind::ExecutePayload
        | EffectKind::SourceScriptIntoCurrentShell
        | EffectKind::SetCurrentWorkingDirectory
        | EffectKind::SetExecutionWorkingDirectory
        | EffectKind::ExecuteRemoteCommand
        | EffectKind::ExecuteHook
        | EffectKind::ExecuteConfigDefinedTask
        | EffectKind::DispatchCommand
        | EffectKind::ConsumeStdin
        | EffectKind::BindVariableFromRuntimeInput
        | EffectKind::TerminateCurrentShell
        | EffectKind::ShellJobOperation
        | EffectKind::PrivilegeModifier
        | EffectKind::NetworkEndpoint
        | EffectKind::ListenNetwork
        | EffectKind::TransformData
        | EffectKind::ImportPackage
        | EffectKind::ExecuteImportedPackageLogic
        | EffectKind::LoadInProcessCode
        | EffectKind::OpenInteractiveEscapeSurface
        | EffectKind::ControlProcess
        | EffectKind::RepositoryOperation
        | EffectKind::DatabaseOperation
        | EffectKind::TerminalSessionOperation => None,
    }
}

fn tool_convention_slot_name(effect_index: usize, convention: &str) -> String {
    let sanitized: String = convention
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();

    format!("tool_convention_path_{effect_index}_{sanitized}")
}

fn derived_path_slot_name(effect_index: usize) -> String {
    format!("derived_path_{effect_index}")
}

fn resolve_tool_convention_path(target: &ToolConventionPathTarget, cwd: &str) -> PathResolution {
    let path = if target.path.starts_with('/') {
        normalize_shell_path(&target.path)
    } else {
        join_shell_path(cwd, &target.path)
    };

    PathResolution::ToolConvention {
        path,
        convention: target.convention.clone(),
    }
}

fn redirection_path_fact(
    redirection: &RedirectionFact,
    redirection_index: usize,
    cwd: &str,
    home: Option<&str>,
) -> Option<(PathRole, String, PathResolution)> {
    // Here-strings carry data payload, not filesystem path targets.
    if redirection.kind != RedirectionKind::File {
        return None;
    }

    let operator = redirection.operator.as_deref()?;
    let target = redirection.target.as_ref()?;
    if target.node_kind == "process_substitution" {
        return None;
    }
    let role = path_role_for_redirection_operator(operator)?;
    let resolution = resolve_path_resolution(
        &target.text,
        target.quoted,
        &target.node_kind,
        cwd,
        home,
        None,
    );

    Some((
        role,
        format!("redirect_target_{redirection_index}"),
        resolution,
    ))
}

fn path_role_for_redirection_operator(operator: &str) -> Option<PathRole> {
    // We only materialize direct file flow here; descriptor duplication like `2>&1` is not a path fact.
    if matches!(operator, "<" | "<>") {
        return Some(PathRole::Read);
    }

    if is_file_write_redirection_operator(operator) {
        return Some(PathRole::Write);
    }

    None
}

pub(crate) fn edge_kind_for_path_role(role: PathRole) -> EdgeKind {
    match role {
        PathRole::Read | PathRole::Config => EdgeKind::Reads,
        PathRole::Write => EdgeKind::Writes,
        PathRole::MetadataMutation => EdgeKind::MutatesMetadata,
        PathRole::Target | PathRole::CwdAnchor => EdgeKind::Targets,
    }
}

pub(crate) fn edge_kind_for_mutation_scope_operation(
    operation: ResolvedMutationScopeOperation,
) -> EdgeKind {
    match operation {
        ResolvedMutationScopeOperation::Write => EdgeKind::Writes,
        ResolvedMutationScopeOperation::Delete => EdgeKind::Targets,
    }
}

pub(crate) fn resolved_path_role_for_profile_role(role: PathRole) -> ResolvedPathRole {
    match role {
        PathRole::Read => ResolvedPathRole::Read,
        PathRole::Write => ResolvedPathRole::Write,
        PathRole::MetadataMutation => ResolvedPathRole::MetadataMutation,
        PathRole::Target => ResolvedPathRole::Target,
        PathRole::Config => ResolvedPathRole::Config,
        PathRole::CwdAnchor => ResolvedPathRole::CwdAnchor,
    }
}

pub(crate) fn resolved_path_purpose_for_profile_purpose(
    purpose: PathPurpose,
) -> ResolvedPathPurpose {
    match purpose {
        PathPurpose::IncidentalCache => ResolvedPathPurpose::IncidentalCache,
        PathPurpose::GenericOperand => ResolvedPathPurpose::GenericOperand,
        PathPurpose::ScriptSource => ResolvedPathPurpose::ScriptSource,
        PathPurpose::InProcessCode => ResolvedPathPurpose::InProcessCode,
        PathPurpose::StartupConfig => ResolvedPathPurpose::StartupConfig,
        PathPurpose::ProjectConfig => ResolvedPathPurpose::ProjectConfig,
        PathPurpose::ToolConfig => ResolvedPathPurpose::ToolConfig,
        PathPurpose::TaskConfig => ResolvedPathPurpose::TaskConfig,
        PathPurpose::WorkingDirectory => ResolvedPathPurpose::WorkingDirectory,
    }
}

pub(crate) fn path_fact_node_id(
    source_node_id: &NodeId,
    source_index: usize,
    slot_name: &str,
    resolution: &PathResolution,
) -> NodeId {
    NodeId::new(format!(
        "resolved-path:{}:{source_index}:{slot_name}:{}",
        source_node_id.0,
        path_resolution_id_suffix(resolution),
    ))
}

pub(crate) fn mutation_scope_fact_node_id(
    source_node_id: &NodeId,
    source_index: usize,
    effect_index: usize,
    slot_name: &str,
    resolution: &MutationScopeResolution,
    operation: ResolvedMutationScopeOperation,
) -> NodeId {
    NodeId::new(format!(
        "mutation-scope:{}:{source_index}:{effect_index}:{slot_name}:{}:{}",
        source_node_id.0,
        mutation_scope_operation_id_suffix(operation),
        mutation_scope_resolution_id_suffix(resolution),
    ))
}

fn mutation_scope_operation_id_suffix(operation: ResolvedMutationScopeOperation) -> &'static str {
    match operation {
        ResolvedMutationScopeOperation::Write => "write",
        ResolvedMutationScopeOperation::Delete => "delete",
    }
}

fn mutation_scope_resolution_id_suffix(resolution: &MutationScopeResolution) -> String {
    match resolution {
        MutationScopeResolution::RepositoryWorktree {
            root,
            path_set,
            scope,
        } => format!(
            "repo-worktree:{}:{}:{}",
            path_resolution_id_suffix(root),
            repository_worktree_path_set_id_suffix(*path_set),
            repository_worktree_scope_id_suffix(scope)
        ),
    }
}

fn repository_worktree_path_set_id_suffix(
    path_set: caushell_types::RepositoryWorktreePathSet,
) -> &'static str {
    match path_set {
        caushell_types::RepositoryWorktreePathSet::Tracked => "tracked",
        caushell_types::RepositoryWorktreePathSet::PatchSelectedTracked => "patch-selected-tracked",
        caushell_types::RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees => {
            "registered-submodule-worktrees"
        }
        caushell_types::RepositoryWorktreePathSet::UntrackedOnly => "untracked-only",
        caushell_types::RepositoryWorktreePathSet::IgnoredOnly => "ignored-only",
        caushell_types::RepositoryWorktreePathSet::UntrackedAndIgnored => "untracked-and-ignored",
    }
}

fn repository_worktree_scope_id_suffix(scope: &RepositoryWorktreeScopeResolution) -> String {
    match scope {
        RepositoryWorktreeScopeResolution::WholeWorktree => "whole-worktree".to_string(),
        RepositoryWorktreeScopeResolution::Subtree { path } => {
            format!("subtree:{}", path_resolution_id_suffix(path))
        }
    }
}

fn path_resolution_id_suffix(resolution: &PathResolution) -> String {
    match resolution {
        PathResolution::Concrete { path } => path.clone(),
        PathResolution::ToolConvention { path, convention } => {
            format!("tool-convention:{convention}:{path}")
        }
        PathResolution::DerivedConcrete { path, basis, rule } => format!(
            "derived-concrete:{path}:{}:{}",
            derived_path_basis_id_suffix(basis),
            derived_path_rule_id_suffix(rule)
        ),
        PathResolution::DerivedUnresolved {
            basis,
            rule,
            reason,
        } => format!(
            "derived-unresolved:{}:{}:{}",
            derived_path_basis_id_suffix(basis),
            derived_path_rule_id_suffix(rule),
            derived_path_reason_id_suffix(*reason),
        ),
        PathResolution::MissingBinding { variable_name } => {
            format!("missing-binding:{variable_name}")
        }
        PathResolution::UnsupportedDynamicBinding {
            variable_name,
            repr,
        } => {
            format!("dynamic-binding:{variable_name}:{repr}")
        }
        PathResolution::UnsupportedDynamicText { text } => format!("dynamic-text:{text}"),
        PathResolution::HomeUnavailable { text } => format!("home-unavailable:{text}"),
        PathResolution::BoundedPathSet { roots, may_escape } => {
            format!("bounded-path-set:{}:{}", roots.join("|"), may_escape)
        }
    }
}

fn derived_path_basis_id_suffix(basis: &DerivedPathBasis) -> String {
    match basis {
        DerivedPathBasis::PathOperand {
            raw,
            resolved_input_path,
            slot_name,
        } => format!(
            "path-operand:{slot_name}:{raw}:{}",
            resolved_input_path.as_deref().unwrap_or("unresolved")
        ),
        DerivedPathBasis::EndpointOperand { raw, slot_name } => {
            format!("endpoint-operand:{slot_name}:{raw}")
        }
        DerivedPathBasis::ToolConventionRoot { path, convention } => {
            format!("tool-root:{convention}:{path}")
        }
        DerivedPathBasis::ConfigDerivedRoot {
            config_path,
            convention,
            key,
            value,
        } => format!("config-root:{convention}:{config_path}:{key}:{value}"),
    }
}

fn derived_path_rule_id_suffix(rule: &DerivedPathRule) -> String {
    match rule {
        DerivedPathRule::AppendSuffix { suffix } => format!("append-suffix:{suffix}"),
        DerivedPathRule::StripSuffix { suffix } => format!("strip-suffix:{suffix}"),
        DerivedPathRule::ReplaceSuffix { from, to } => {
            format!("replace-suffix:{from}:{to}")
        }
        DerivedPathRule::UrlBasename => "url-basename".to_string(),
        DerivedPathRule::ArchiveMembers => "archive-members".to_string(),
        DerivedPathRule::SiblingFiles => "sibling-files".to_string(),
        DerivedPathRule::ChildUnder { relative_path } => {
            format!("child-under:{relative_path}")
        }
    }
}

fn derived_path_reason_id_suffix(reason: DerivedPathUnresolvedReason) -> &'static str {
    match reason {
        DerivedPathUnresolvedReason::UnknownArchiveMembers => "unknown-archive-members",
        DerivedPathUnresolvedReason::MissingUrlBasename => "missing-url-basename",
        DerivedPathUnresolvedReason::MissingWorkspaceRoot => "missing-workspace-root",
        DerivedPathUnresolvedReason::UnsupportedOperandShape => "unsupported-operand-shape",
        DerivedPathUnresolvedReason::UnsupportedRuntimeRule => "unsupported-runtime-rule",
    }
}

pub(crate) fn provenance_path_artifact_node_id(path: &str) -> NodeId {
    NodeId::new(format!("artifact:path-content:{path}"))
}

pub(crate) fn provenance_artifact_for_path(path: &str) -> ProvenanceArtifact {
    ProvenanceArtifact::PathContent {
        path: path.to_string(),
        version: None,
    }
}

pub(crate) fn provenance_edge_for_path_fact(
    role: PathRole,
    purpose: Option<PathPurpose>,
    slot_name: &str,
    normalized_command_name: Option<&str>,
) -> Option<(EdgeKind, ProvenanceEdgeSemantics)> {
    let domain_label = Some(ProvenanceDomainLabel::Path {
        role: resolved_path_role_for_profile_role(role),
        purpose: purpose.map(resolved_path_purpose_for_profile_purpose),
    });

    if let Some(consume_kind) = provenance_consume_kind_for_path_fact(role, purpose) {
        return Some((
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind,
                slot_name: Some(slot_name.to_string()),
                normalized_command_name: normalized_command_name.map(str::to_string),
                domain_label,
            },
        ));
    }

    provenance_produce_kind_for_path_fact(role).map(|produce_kind| {
        (
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind,
                slot_name: Some(slot_name.to_string()),
                normalized_command_name: normalized_command_name.map(str::to_string),
                domain_label,
            },
        )
    })
}

fn provenance_consume_kind_for_path_fact(
    role: PathRole,
    purpose: Option<PathPurpose>,
) -> Option<ProvenanceConsumeKind> {
    match role {
        PathRole::Read => Some(match purpose {
            Some(PathPurpose::ScriptSource) => ProvenanceConsumeKind::ScriptSource,
            Some(PathPurpose::InProcessCode) => ProvenanceConsumeKind::InProcessCodeSource,
            Some(PathPurpose::StartupConfig) => ProvenanceConsumeKind::StartupConfigSource,
            Some(PathPurpose::ProjectConfig) => ProvenanceConsumeKind::ProjectConfigSource,
            Some(PathPurpose::ToolConfig) => ProvenanceConsumeKind::ToolConfigSource,
            Some(PathPurpose::TaskConfig) => ProvenanceConsumeKind::TaskDefinitionSource,
            _ => ProvenanceConsumeKind::PathRead,
        }),
        PathRole::Config => Some(match purpose {
            Some(PathPurpose::ProjectConfig) => ProvenanceConsumeKind::ProjectConfigSource,
            Some(PathPurpose::ToolConfig) => ProvenanceConsumeKind::ToolConfigSource,
            Some(PathPurpose::TaskConfig) => ProvenanceConsumeKind::TaskDefinitionSource,
            Some(PathPurpose::ScriptSource) => ProvenanceConsumeKind::ScriptSource,
            Some(PathPurpose::InProcessCode) => ProvenanceConsumeKind::InProcessCodeSource,
            Some(PathPurpose::StartupConfig)
            | Some(PathPurpose::IncidentalCache)
            | Some(PathPurpose::GenericOperand)
            | Some(PathPurpose::WorkingDirectory)
            | None => ProvenanceConsumeKind::StartupConfigSource,
        }),
        PathRole::Write | PathRole::MetadataMutation | PathRole::Target | PathRole::CwdAnchor => {
            None
        }
    }
}

fn provenance_produce_kind_for_path_fact(role: PathRole) -> Option<ProvenanceProduceKind> {
    match role {
        PathRole::Write => Some(ProvenanceProduceKind::PathWrite),
        PathRole::Read
        | PathRole::MetadataMutation
        | PathRole::Target
        | PathRole::Config
        | PathRole::CwdAnchor => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundArgumentMaterialization, PathResolution, ValueMaterialization,
        resolve_bound_path_resolution, runtime_input_path_resolution,
    };
    use caushell_profile::ImplicitInputSource;
    use caushell_types::RuntimeArgumentDomain;

    fn derived_basis() -> caushell_types::DerivedPathBasis {
        caushell_types::DerivedPathBasis::PathOperand {
            raw: "synthetic runtime paths".into(),
            resolved_input_path: None,
            slot_name: "inputs".into(),
        }
    }

    #[test]
    fn bounded_suffix_proofs_account_for_the_root_itself_and_raw_spelling() {
        use caushell_types::DerivedPathRule;
        for (raw, expected) in [
            (".", "/tmp/project"),
            ("./", "/tmp/project"),
            ("sub", "/tmp/project"),
            ("sub/", "/tmp/project/sub"),
            ("/tmp/project", "/tmp"),
            ("/tmp/project/", "/tmp/project"),
            ("..", "/tmp"),
        ] {
            let output = super::derive_bounded_path_resolution(
                &[raw.into()],
                false,
                derived_basis(),
                &DerivedPathRule::AppendSuffix {
                    suffix: ".pack".into(),
                },
                "/tmp/project",
            );
            assert_eq!(
                output,
                PathResolution::BoundedPathSet {
                    roots: vec![expected.into()],
                    may_escape: false
                },
                "{raw}"
            );
        }
    }

    #[test]
    fn bounded_strip_replace_and_sibling_rules_widen_to_parent() {
        use caushell_types::DerivedPathRule;
        for rule in [
            DerivedPathRule::StripSuffix {
                suffix: ".pack".into(),
            },
            DerivedPathRule::ReplaceSuffix {
                from: ".pack".into(),
                to: ".raw".into(),
            },
            DerivedPathRule::SiblingFiles,
        ] {
            assert_eq!(
                super::derive_bounded_path_resolution(
                    &[".".into(), "./".into()],
                    false,
                    derived_basis(),
                    &rule,
                    "/tmp/project"
                ),
                PathResolution::BoundedPathSet {
                    roots: vec!["/tmp".into()],
                    may_escape: false
                }
            );
            assert_eq!(
                super::derive_bounded_path_resolution(
                    &["sub".into()],
                    true,
                    derived_basis(),
                    &rule,
                    "/tmp/project"
                ),
                PathResolution::BoundedPathSet {
                    roots: vec!["/tmp/project".into()],
                    may_escape: true
                }
            );
        }
    }

    #[test]
    fn bounded_output_relocation_does_not_keep_input_roots() {
        for may_escape in [false, true] {
            let input = PathResolution::BoundedPathSet {
                roots: vec!["/tmp/project".into()],
                may_escape,
            };
            for (destination, expected) in [
                ("/opt/output", "/opt"),
                ("/tmp/project/output", "/tmp/project"),
            ] {
                assert_eq!(
                    super::compose_derived_path_under_root(&input, destination),
                    PathResolution::BoundedPathSet {
                        roots: vec![expected.into()],
                        may_escape
                    }
                );
            }
        }
    }

    #[test]
    fn bounded_rules_never_invent_empty_unknown_or_traversing_proofs() {
        use caushell_types::DerivedPathRule;
        for rule in [
            DerivedPathRule::AppendSuffix {
                suffix: "/../out".into(),
            },
            DerivedPathRule::AppendSuffix { suffix: ".".into() },
            DerivedPathRule::ReplaceSuffix {
                from: ".p".into(),
                to: "/../out".into(),
            },
            DerivedPathRule::ChildUnder {
                relative_path: "../out".into(),
            },
            DerivedPathRule::UrlBasename,
            DerivedPathRule::ArchiveMembers,
        ] {
            assert!(matches!(
                super::derive_bounded_path_resolution(
                    &[".".into()],
                    false,
                    derived_basis(),
                    &rule,
                    "/tmp/project"
                ),
                PathResolution::DerivedUnresolved { .. }
            ));
        }
        for roots in [vec![], vec!["".into()], vec!["bad\0root".into()]] {
            for rule in [
                DerivedPathRule::AppendSuffix {
                    suffix: ".pack".into(),
                },
                DerivedPathRule::ChildUnder {
                    relative_path: "out".into(),
                },
            ] {
                assert!(matches!(
                    super::derive_bounded_path_resolution(
                        &roots,
                        false,
                        derived_basis(),
                        &rule,
                        "/tmp/project"
                    ),
                    PathResolution::DerivedUnresolved { .. }
                ));
            }
        }
    }

    #[test]
    fn bounded_transforms_cover_finite_counterexamples_without_enumerating_at_runtime() {
        use caushell_types::DerivedPathRule;
        for raw in [
            ".",
            "./",
            "sub",
            "sub/",
            "..",
            "/tmp/project",
            "/tmp/project/",
            "/",
        ] {
            for rule in [
                DerivedPathRule::AppendSuffix {
                    suffix: ".pack".into(),
                },
                DerivedPathRule::StripSuffix {
                    suffix: ".pack".into(),
                },
                DerivedPathRule::ReplaceSuffix {
                    from: ".pack".into(),
                    to: ".raw".into(),
                },
            ] {
                let PathResolution::BoundedPathSet {
                    roots,
                    may_escape: false,
                } = super::derive_bounded_path_resolution(
                    &[raw.into()],
                    false,
                    derived_basis(),
                    &rule,
                    "/tmp/project",
                )
                else {
                    panic!("missing proof")
                };
                for tail in [
                    "",
                    "/x.pack",
                    "/.pack",
                    "/..pack",
                    "/...pack",
                    "/nested/x.pack",
                    "/nested/...pack",
                    "/.",
                    "/..",
                ] {
                    let input = format!("{raw}{tail}");
                    let original = super::lexical_path_from_argv(&input, "/tmp/project");
                    let root = super::lexical_path_from_argv(raw, "/tmp/project");
                    if !super::path_is_within_root(&original, &root) {
                        continue;
                    }
                    if let Some(output) =
                        super::suffix_transform(&input, &rule).filter(|s| !s.is_empty())
                    {
                        let output = super::lexical_path_from_argv(&output, "/tmp/project");
                        assert!(
                            roots
                                .iter()
                                .any(|root| super::path_is_within_root(&output, root)),
                            "{input} {rule:?} -> {output}, {roots:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exact_suffix_rules_transform_argv_before_normalization() {
        use caushell_types::DerivedPathRule;
        for (input, expected) in [
            (".", "/tmp/project/..pack"),
            ("./", "/tmp/project/.pack"),
            ("sub/..", "/tmp/project/sub/...pack"),
            ("/tmp/project/", "/tmp/project/.pack"),
        ] {
            let source = PathResolution::Concrete {
                path: super::lexical_path_from_argv(input, "/tmp/project"),
            };
            let output = super::derive_path_resolution_from_spelling(
                source,
                derived_basis(),
                &DerivedPathRule::AppendSuffix {
                    suffix: ".pack".into(),
                },
                Some(input),
                "/tmp/project",
            );
            assert_eq!(output.concrete_path(), Some(expected));
        }
        let source = PathResolution::Concrete {
            path: "/tmp/project/x.pack".into(),
        };
        assert!(matches!(
            super::derive_path_resolution_from_spelling(
                source,
                derived_basis(),
                &DerivedPathRule::StripSuffix {
                    suffix: ".pack".into()
                },
                Some("x.pack/"),
                "/tmp/project"
            ),
            PathResolution::DerivedUnresolved { .. }
        ));
    }

    #[test]
    fn materialized_argv_paths_keep_dollar_and_tilde_as_literal_bytes() {
        let resolution = resolve_bound_path_resolution(
            "$HOME/~/file",
            false,
            "word",
            "/workspace/project",
            Some("/home/user"),
            &BoundArgumentMaterialization::RuntimeData,
            Some(&ValueMaterialization::Static),
        );

        assert_eq!(
            resolution,
            PathResolution::Concrete {
                path: "/workspace/project/$HOME/~/file".to_string(),
            }
        );
    }

    #[test]
    fn runtime_path_domain_roots_are_lexically_joined_without_expansion() {
        let resolution = runtime_input_path_resolution(
            &ImplicitInputSource::StdinData,
            Some(&RuntimeArgumentDomain::PathSet {
                roots: vec!["$ROOT/~/out".to_string(), "/tmp/../var/data".to_string()],
                may_escape: false,
            }),
            "/workspace/project",
        );

        assert_eq!(
            resolution,
            PathResolution::BoundedPathSet {
                roots: vec![
                    "/workspace/project/$ROOT/~/out".to_string(),
                    "/var/data".to_string(),
                ],
                may_escape: false,
            }
        );
    }

    #[test]
    fn ordinary_implicit_path_evidence_keeps_unknown_input_unsupported() {
        let resolution = runtime_input_path_resolution(
            &ImplicitInputSource::StdinData,
            Some(&RuntimeArgumentDomain::Unbounded),
            "/workspace/project",
        );

        assert!(matches!(
            resolution,
            PathResolution::UnsupportedDynamicText { ref text }
                if text.contains("StdinData")
        ));
    }
}
