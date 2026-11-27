use caushell_graph::NodeId;
use caushell_profile::{
    BoundArgumentMaterialization, EffectKind, EffectTarget, FilesystemNamespaceImpact,
    SemanticValueRef, SemanticValueResolution,
};
use caushell_query::{IoTarget, IoTargetQuery};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    PathResolution, PathTargetAccess, PathTargetFact, PathTargetOperation, SemanticGapKind,
    SemanticResolution,
};

use crate::path::namespace::{NamespaceResolver, unresolved};
use crate::path::{
    collect_effect_mutation_targets, collect_redirection_path_facts, effective_cwd_cases,
    normalize_shell_path, path_target_is_inapplicable, project_path_at_cwd,
};
use crate::support::{
    bound_invocation, content_io_target, graph_backed_execution_resolve_records,
    is_file_write_redirection_operator, redirection_parent_command_index, slot_uses_content_open,
};

mod consumption;
mod directory_setup;
mod directory_tree;
mod entry_relocation;
mod namespace_state;
mod unzip_setup;

pub struct ResolvePathTargetsPass;

pub(crate) fn path_mutation_kind(kind: EffectKind) -> Option<PathTargetOperation> {
    Some(match kind {
        EffectKind::WritePath => PathTargetOperation::Write,
        EffectKind::DeletePath => PathTargetOperation::Delete,
        EffectKind::MovePath => PathTargetOperation::MoveSource,
        EffectKind::ChangeMode
        | EffectKind::ChangeOwner
        | EffectKind::ChangeGroup
        | EffectKind::MetadataMutation => PathTargetOperation::Metadata,
        _ => return None,
    })
}

#[derive(Clone)]
struct Input {
    fact: PathTargetFact,
    namespace_write: bool,
    pending_resolution: bool,
    direct_content_output: bool,
    cwd_dependent: bool,
    directory_anchor: Option<String>,
    namespace_effect: Option<caushell_types::PathNamespaceEffect>,
    move_from_dot_search: bool,
    relocation_scope: Option<entry_relocation::RelocationScope>,
}

impl SessionTransformPass for ResolvePathTargetsPass {
    fn name(&self) -> &'static str {
        "resolve_path_targets"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let mut inputs = collect_inputs(ctx);
        inputs.extend(consumption::collect(ctx));
        inputs.extend(entry_context_inputs(ctx));
        if inputs.is_empty() {
            return;
        }
        let mut resolver = NamespaceResolver::new(ctx.filesystem_view());
        let mut scope_observations = Vec::new();
        let policy = ctx.path_exemption_policy().map_roots(|root| {
            let (resolved, observations) = resolver.resolve(root, PathTargetAccess::Follow);
            scope_observations.extend(observations);
            match resolved {
                SemanticResolution::Resolved { value } => value.concrete_path().map(str::to_owned),
                _ => None,
            }
        });
        ctx.set_target_path_policy(policy);
        let records: std::collections::BTreeMap<_, _> = ctx
            .execution_unit_resolve_records()
            .iter()
            .map(|record| (record.source_node_id.0.as_str(), record))
            .collect();
        // Resolve the current namespace first. Abstract write dependencies are
        // separate from observations, and must not depend on iteration order.
        let mut baselines = Vec::with_capacity(inputs.len());
        let mut tree_evidence = Vec::new();
        let mut tree_budget = caushell_runner::DirectoryReadBudget::default();
        for index in 0..inputs.len() {
            if !inputs[index].pending_resolution {
                baselines.push((inputs[index].fact.resolution.clone(), Vec::new()));
                continue;
            }
            let spelling = inputs[index].fact.spelling.as_deref();
            let (resolution, mut observations) = if inputs[index].cwd_dependent
                && unproved_execution_directory(&records, &inputs[index].fact.source_node_id)
            {
                (
                    unresolved(
                        SemanticGapKind::UnresolvedOperation,
                        "execution directory has only a lexical parent-component resolution",
                    ),
                    Vec::new(),
                )
            } else if inputs[index].namespace_effect
                == Some(caushell_types::PathNamespaceEffect::DirectoryTreeWrite)
                || matches!(
                    inputs[index].fact.lexical,
                    PathResolution::BoundedPathSet {
                        may_escape: false,
                        ..
                    } | PathResolution::FileNamePrefix { .. }
                )
            {
                let (baseline, evidence) = directory_tree::resolve(
                    &inputs[index],
                    &mut resolver,
                    ctx.filesystem_view(),
                    &mut tree_budget,
                    ctx.request().shell_state_before.cwd(),
                );
                tree_evidence.push(evidence);
                baseline
            } else if let Some(spelling) = spelling {
                resolver.resolve(spelling, inputs[index].fact.access)
            } else {
                (
                    unresolved(
                        SemanticGapKind::UnknownTarget,
                        "target namespace cannot be proved from its lexical path bound",
                    ),
                    Vec::new(),
                )
            };
            if (inputs[index].namespace_effect
                == Some(caushell_types::PathNamespaceEffect::EntryRemoval)
                || (inputs[index].namespace_effect
                    == Some(caushell_types::PathNamespaceEffect::EntryRelocation)
                    && inputs[index].fact.operation == PathTargetOperation::MoveSource))
                && let SemanticResolution::Resolved {
                    value: PathResolution::Concrete { path },
                } = &resolution
            {
                // Entry lookup intentionally skips the leaf. An invariant
                // about removing an ordinary leaf needs its own current type
                // observation, from the same resolver/cache as its ancestors.
                let (_, leaf_observations) = resolver.resolve(path, PathTargetAccess::Follow);
                for observation in leaf_observations {
                    if !observations.contains(&observation) {
                        observations.push(observation);
                    }
                }
            }
            baselines.push((resolution, observations));
        }
        let closed_tree = namespace_operations_complete(ctx, true);
        let ordered_transfers = if closed_tree {
            tree_evidence.extend(entry_relocation::close_families(
                &mut inputs, &mut baselines, &mut resolver,
                ctx.filesystem_view(), &mut tree_budget,
                ctx.request().shell_state_before.cwd(),
                |node| ctx.parsed_command().is_some_and(|parsed| {
                    records.get(node).is_some_and(|record| {
                        directory_setup::foreground_command(parsed, record).is_some()
                    }) && parsed.commands.iter().all(|command| {
                        command.terminator != Some(caushell_parse::StatementTerminator::Background)
                    })
                }),
            ));
            directory_setup::prove_transfers(
                ctx, &inputs, &mut baselines, &records, &mut resolver, &mut tree_budget,
                &mut tree_evidence,
            )
        } else {
            std::collections::BTreeMap::new()
        };
        let namespace_writes: Vec<_> = inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.namespace_write && input.pending_resolution)
            .flat_map(|(index, _)| {
                let roots = match &baselines[index].0 {
                    SemanticResolution::Resolved {
                        value: PathResolution::Concrete { path },
                    } => vec![Some(path.clone())],
                    SemanticResolution::Resolved {
                        value:
                            PathResolution::BoundedPathSet {
                                roots,
                                may_escape: false,
                            },
                    } if !roots.is_empty() => roots.iter().cloned().map(Some).collect(),
                    SemanticResolution::Resolved {
                        value: PathResolution::FileNamePrefix { directory, .. },
                    } => vec![Some(directory.clone())],
                    _ => vec![None],
                };
                roots.into_iter().map(move |root| (index, root))
            })
            .collect();
        let mut comparisons = 0usize;
        let completes_before_writer = |target: &Input, writer: &Input| {
            unzip_setup::completes_before_unzip(
                target,
                writer,
                &records,
                ctx.parsed_command(),
            ) || target.namespace_effect == Some(caushell_types::PathNamespaceEffect::DirectoryCreate)
                && ordered_transfers.get(writer.fact.source_node_id.as_str())
                    == Some(&target.fact.source_node_id)
        };
        let stable_producers = if namespace_operations_complete(ctx, false) {
            namespace_state::stable_producers(
                &inputs,
                &baselines,
                &namespace_writes,
                &mut comparisons,
                closed_tree,
                &completes_before_writer,
            )
        } else {
            // An opaque sibling may have no declared mutation target at all.
            // It cannot participate in a closed abstract namespace proof.
            std::collections::BTreeSet::new()
        };
        let mut terminal_device = None;
        for index in 0..inputs.len() {
            if !inputs[index].pending_resolution {
                continue;
            }
            let (mut resolution, observations) = baselines[index].clone();
            let mut proofs = Vec::new();
            let entry_context = matches!(
                inputs[index].fact.operation,
                PathTargetOperation::WorkingDirectory | PathTargetOperation::WorkspaceRoot
            );
            let changed_by_sibling = !entry_context
                && namespace_writes.iter().any(|(other, root)| {
                    comparisons += 1;
                    if comparisons > 65536 {
                        return true;
                    }
                    if *other == index || completes_before_writer(&inputs[index], &inputs[*other]) {
                        return false;
                    }
                    let overlaps = namespace_state::overlaps(
                        &inputs[index],
                        &baselines[index],
                        &baselines[*other],
                        root.as_deref(),
                    );
                    if overlaps && stable_producers.contains(other) {
                        if let Some(mut proof) = namespace_state::scope_preservation(
                            &inputs[*other],
                            &baselines[*other],
                            &inputs[index],
                            &baselines[index],
                        ) {
                            if proof.effect == caushell_types::PathNamespaceEffect::DirectoryCreate
                                && inputs[index].fact.operation == PathTargetOperation::Write
                                && let (Some(setup), Some(consumer)) = (
                                    records.get(proof.producer_node_id.as_str()),
                                    records.get(inputs[index].fact.source_node_id.as_str()),
                                )
                            {
                                proof.same_iteration_success =
                                    directory_setup::guarded_in_same_iteration(setup, consumer);
                            }
                            proofs.push(proof);
                            return false;
                        }
                    }
                    overlaps
                });
            if comparisons > 65536 {
                resolution = unresolved(
                    SemanticGapKind::BudgetExceeded,
                    "namespace dependency budget exhausted",
                );
            } else if changed_by_sibling {
                resolution = unresolved(
                    SemanticGapKind::NamespaceMutation,
                    "another effect in this action may change a target path component",
                );
            } else if !closed_tree
                && matches!(
                    &resolution,
                    SemanticResolution::Resolved {
                        value: PathResolution::BoundedPathSet { .. } | PathResolution::FileNamePrefix { .. }
                    }
                )
            {
                // A current link-free snapshot is not a proof about an action
                // containing an opaque sibling, even if it declares no writes.
                resolution = unresolved(
                    SemanticGapKind::UnresolvedOperation,
                    "directory family cannot be closed over opaque action semantics",
                );
            }
            let input = &inputs[index];
            if input.direct_content_output
                && !input.cwd_dependent
                && ctx.assumes_protected_defaults()
                && let Some(spelling) = input.fact.spelling.as_deref()
                && spelling == IoTargetQuery::CONTROLLING_TERMINAL_PATH
                && let SemanticResolution::Resolved { value } = &resolution
                && let Some(IoTarget::ControllingTerminal) =
                    IoTargetQuery::controlling_terminal_output(
                        spelling,
                        value,
                        *terminal_device.get_or_insert_with(|| {
                            ctx.filesystem_view().has_controlling_terminal_device()
                        }),
                    )
            {
                resolution = SemanticResolution::NotApplicable {
                    reason: "content output to the verified Linux controlling-terminal device"
                        .into(),
                };
            }
            // Keep the existing directory-scope resolution for callers.
            // The lexical fact retains the basename family used above to
            // prove that unrelated entries cannot invalidate that resolution.
            inputs[index].fact.resolution = match resolution {
                SemanticResolution::Resolved {
                    value: PathResolution::FileNamePrefix { directory, .. },
                } => SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet {
                        roots: vec![directory],
                        may_escape: false,
                    },
                },
                other => other,
            };
            // A failed or budget-truncated proof must not leave a partial
            // certificate that could be mistaken for a complete namespace.
            if matches!(
                inputs[index].fact.resolution,
                SemanticResolution::Resolved { .. }
            ) {
                inputs[index].fact.namespace_proofs = proofs;
            }
            inputs[index].fact.observations = observations;
            inputs[index]
                .fact
                .observations
                .extend(scope_observations.iter().cloned());
            inputs[index]
                .fact
                .observations
                .sort_by(|a, b| a.path.cmp(&b.path));
            inputs[index]
                .fact
                .observations
                .dedup_by(|a, b| a.path == b.path && a.entry == b.entry);
        }
        for proof in tree_evidence {
            ctx.add_evidence(caushell_types::Evidence {
                rule_id: caushell_types::RuleId::OutsideWorkspaceMutation,
                summary: proof.gap.clone().unwrap_or_else(|| {
                    "link-free directory output family resolved without granting authority".into()
                }),
                kind: caushell_types::EvidenceKind::DirectoryTree(proof),
            });
        }
        for (index, input) in inputs.into_iter().enumerate() {
            ctx.stage_mutation(PendingMutation::AddPathTargetFact {
                node_id: NodeId::new(format!(
                    "path-target:{}:{}:{index}",
                    ctx.request().session_id.0,
                    ctx.request().sequence_no.0
                )),
                fact: input.fact,
            });
        }
    }
}

pub(super) fn namespace_operations_complete(ctx: &RunnerContext, whole_tree: bool) -> bool {
    use caushell_profile::ResolveInvocationArtifactResult as Result;
    ctx.unresolved_dispatch_records().is_empty()
        && graph_backed_execution_resolve_records(ctx)
            .into_iter()
            .all(|record| match record.result() {
                Result::Resolved(invocation) => {
                    !invocation.bound.operation_semantics_unresolved
                        && (!whole_tree
                            || !invocation.bound.effects.iter().any(|effect| {
                                effect.state_operation.is_some_and(|operation| {
                                    operation.operation
                                        == caushell_types::StateOperationKind::Opaque
                                })
                            }))
                }
                // Keep the existing single-leaf build/execute contract. A
                // known executable path cannot certify a closed directory tree.
                Result::NoProfile { normalized_command_name, .. } => {
                    let expanded_function = record.bindings().function_binding(normalized_command_name).is_some()
                        && ctx.execution_unit_resolve_records().iter().any(|child|
                            child.parent_execution_node_id == *record.source_node_id()
                                && child.origin_kind == caushell_runner::ExecutionUnitOriginKind::FunctionExpansion)
                        && !ctx.evidence.iter().any(|e| matches!(&e.kind,
                            caushell_types::EvidenceKind::ExecutionExpansionTruncated(t) if t.next_candidate_count > 0));
                    // A resolved function call is a structural parent. Its
                    // actual body units are checked by this same closure;
                    // opaque children and truncated recursion cannot qualify.
                    expanded_function || (!whole_tree
                        && matches!(
                            crate::path::unmodeled_executable_path(record),
                            Some(crate::path::ExecutableFileReference::Known(_))
                        ))
                }
                Result::MissingCommandName {
                    gap_kind: caushell_types::ResolveGapKind::MissingCommandName,
                } => record.command().is_some_and(|command| {
                    command.command_name.is_none() && command.tokens.is_empty()
                }),
                _ => false,
            })
}

fn entry_context_inputs(ctx: &RunnerContext) -> Vec<Input> {
    let Some(workspace) = ctx.request().workspace_root.as_deref() else {
        return Vec::new();
    };
    let source = caushell_runner::request_anchor_node_id(ctx.request());
    [
        (
            PathTargetOperation::WorkingDirectory,
            "cwd",
            ctx.request().shell_state_before.cwd(),
        ),
        (
            PathTargetOperation::WorkspaceRoot,
            "workspace_root",
            workspace,
        ),
    ]
    .into_iter()
    .map(|(operation, slot, spelling)| {
        new_input(
            ctx,
            &source,
            format!("entry-context:{slot}"),
            slot.into(),
            operation,
            PathTargetAccess::Follow,
            PathResolution::Concrete {
                path: normalize_shell_path(spelling),
            },
            Some(spelling.into()),
        )
    })
    .collect()
}

fn new_input(
    ctx: &RunnerContext,
    source: &NodeId,
    key: String,
    slot: String,
    operation: PathTargetOperation,
    access: PathTargetAccess,
    lexical: PathResolution,
    spelling: Option<String>,
) -> Input {
    let spelling = lexical.concrete_path().and(spelling);
    Input {
        fact: PathTargetFact {
            sequence_no: ctx.request().sequence_no,
            source_node_id: source.0.clone(),
            effect_key: key,
            slot_name: slot,
            operation,
            access,
            resolution: unresolved(
                SemanticGapKind::UnknownTarget,
                "target namespace has not been resolved",
            ),
            lexical,
            spelling,
            observations: Vec::new(),
            namespace_proofs: Vec::new(),
            metadata_mutation: None,
            implicit_incidental_cache: false,
        },
        namespace_write: operation.is_mutation()
            && operation != PathTargetOperation::Metadata
            && access != PathTargetAccess::Follow,
        pending_resolution: true,
        direct_content_output: false,
        cwd_dependent: false,
        directory_anchor: None,
        namespace_effect: None,
        move_from_dot_search: false,
        relocation_scope: None,
    }
}

fn collect_inputs(ctx: &RunnerContext) -> Vec<Input> {
    use caushell_profile::{BoundValue, ImplicitInputSource};
    use caushell_runner::{CwdPathContext, ExecutionUnitOriginKind};
    use caushell_types::RuntimeArgumentDomain;

    let cwd = ctx.request().shell_state_before.cwd();
    let find_parents: std::collections::BTreeSet<_> = ctx.execution_unit_resolve_records().iter()
        .filter(|r| r.origin_kind == ExecutionUnitOriginKind::TopLevel
            && matches!(&r.result, caushell_profile::ResolveInvocationArtifactResult::Resolved(result)
                if result.normalized_command_name.as_str() == "find"
                    && !result.bound.operation_semantics_unresolved))
        .map(|r| &r.source_node_id)
        .collect();
    let mut inputs = Vec::new();
    for record in graph_backed_execution_resolve_records(ctx) {
        let home = record
            .bindings()
            .tilde_home_with_default(ctx.request().home.as_deref());
        if let Some(bound) = bound_invocation(record.result()) {
            for case in
                effective_cwd_cases(ctx.execution_cwd_for_node(record.source_node_id()), cwd)
            {
                let base = case.resolution_base(cwd);
                let targets = collect_effect_mutation_targets(record, base, home);
                for (effect_index, effect) in bound.effects.iter().enumerate() {
                    let Some(operation) = path_mutation_kind(effect.kind) else {
                        continue;
                    };
                    if effect.kind == EffectKind::MetadataMutation
                        && matches!(effect.target, EffectTarget::None)
                    {
                        continue;
                    }
                    let start = inputs.len();
                    for target in targets.iter().filter(|t| t.effect_index == effect_index) {
                        let archive_members =
                            bound.bound_archive_members.contains_key(&effect_index);
                        let access = if archive_members {
                            PathTargetAccess::Follow
                        } else if matches!(
                            operation,
                            PathTargetOperation::Delete | PathTargetOperation::MoveSource
                        ) {
                            PathTargetAccess::Entry
                        } else if slot_uses_content_open(bound, &target.slot_name, effect.kind) {
                            PathTargetAccess::Follow
                        } else {
                            PathTargetAccess::Either
                        };
                        let mut lexical = project_path_at_cwd(
                            target.resolution.clone(),
                            target.cwd_dependent,
                            case,
                        );
                        let mut spelling =
                            target_spelling(record, &target.slot_name, &lexical, base, home);
                        let direct_content_output = operation == PathTargetOperation::Write
                            && access == PathTargetAccess::Follow
                            && !archive_members
                            && effect.namespace_effect.is_none()
                            && effect.path_access == Some(caushell_profile::PathAccessKind::ContentOpen)
                            && matches!(&effect.target, EffectTarget::Slot(_))
                            && matches!(
                                record.result(),
                                caushell_profile::ResolveInvocationArtifactResult::Resolved(_)
                            );
                        if ctx.assumes_protected_defaults()
                            && direct_content_output
                            && lexical.concrete_path() == Some(IoTargetQuery::CONTROLLING_TERMINAL_PATH)
                        {
                            spelling = target.terminal_operand_spelling.clone();
                        }
                        let mut not_applicable = false;
                        if access == PathTargetAccess::Follow
                            && lexical.concrete_path().is_some_and(|p| {
                                p == "/dev/null"
                                    || caushell_query::IoTargetQuery::descriptor_alias(p).is_some()
                            })
                        {
                            let shell_cases = effective_cwd_cases(
                                ctx.effective_cwd_for_node(record.source_node_id()),
                                cwd,
                            );
                            let shell_base = if let [caushell_runner::CwdPathContext::Exact(base)] =
                                &shell_cases[..]
                            {
                                Some(*base)
                            } else {
                                None
                            };
                            let io = content_io_target(
                                record.parsed_scope(),
                                Some(record.command_index()),
                                None,
                                &lexical,
                                target.cwd_dependent,
                                shell_base.unwrap_or(cwd),
                                home,
                                Some(record.bindings()),
                            );
                            match io_path(io) {
                                Some(path) => {
                                    lexical = if shell_base.is_none() {
                                        PathResolution::UnsupportedDynamicText { text: "descriptor path depends on an unresolved caller working directory".into() }
                                    } else {
                                        path
                                    };
                                    spelling = lexical.concrete_path().map(str::to_owned);
                                }
                                None => not_applicable = true,
                            }
                        }
                        let mut input = new_input(
                            ctx,
                            record.source_node_id(),
                            format!("effect:{effect_index}"),
                            target.slot_name.clone(),
                            operation,
                            access,
                            lexical,
                            spelling,
                        );
                        input.direct_content_output = direct_content_output;
                        input.fact.metadata_mutation = target.metadata_mutation.clone();
                        // A plugin/config/wrapper may execute arbitrary logic;
                        // its declaration is not a closed namespace transformer.
                        if matches!(
                            record.result(),
                            caushell_profile::ResolveInvocationArtifactResult::Resolved(_)
                        ) && !bound.operation_semantics_unresolved
                            && bound.effects.iter().all(|effect| {
                                match effect.kind {
                                    EffectKind::ReadPath
                                    | EffectKind::WritePath
                                    | EffectKind::MovePath
                                    | EffectKind::DeletePath
                                    | EffectKind::TransformData
                                    | EffectKind::ImportPackage => true,
                                    // Metadata references (such as touch -r) do
                                    // not rewrite the writer's namespace.
                                    EffectKind::TargetPath => effect.filesystem_namespace_impact()
                                        == FilesystemNamespaceImpact::Neutral,
                                    // A native configuration loader can participate only after
                                    // complete current-action parse evidence. Executable hooks
                                    // remain separate effects and fail this closed-effect test.
                                    EffectKind::LoadConfig => ctx.evidence.iter().any(|e| {
                                        matches!(&e.kind,
                                        caushell_types::EvidenceKind::ToolConfigParse(p)
                                        if p.node_id==record.source_node_id().0 && p.complete)
                                    }),
                                    _ => false,
                                }
                            })
                        {
                            input.namespace_effect = if matches!(
                                operation,
                                PathTargetOperation::MoveSource | PathTargetOperation::Delete
                            ) && effect.namespace_effect != Some(caushell_types::PathNamespaceEffect::EntryRelocation) {
                                Some(caushell_types::PathNamespaceEffect::EntryRemoval)
                            } else {
                                effect.namespace_effect
                            };
                            // These find callbacks run in the entry cwd. The
                            // only inclusive starting spelling is literally
                            // '.', which plain native mv cannot move.
                            input.move_from_dot_search = operation == PathTargetOperation::MoveSource
                                && bound.command_name.as_str() == "mv"
                                && bound.form_id.as_str() == "default_move"
                                && bound.applied_modifiers.is_empty()
                                && matches!(case, CwdPathContext::Exact(path) if path == cwd)
                                && record.variable_frame().is_some_and(|(parent, kind, _)|
                                    kind == ExecutionUnitOriginKind::Dispatch && find_parents.contains(&parent))
                                && matches!(&effect.target, EffectTarget::Slot(slot)
                                    if bound.bound_parameters.iter().any(|p| p.name == *slot
                                        && matches!(p.values.as_slice(), [BoundValue::ImplicitInput {
                                            source: ImplicitInputSource::DispatchOutput,
                                            domain: Some(RuntimeArgumentDomain::PathSet {
                                                roots, may_escape: false, ..
                                            }), ..
                                        }] if roots == &["."])));
                        }
                        if archive_members {
                            // The complete archive proof excludes link/special
                            // entries; these writes cannot redirect later members.
                            input.namespace_write = false;
                        }
                        input.cwd_dependent = target.cwd_dependent;
                        if matches!(
                            input.fact.lexical,
                            PathResolution::BoundedPathSet { .. }
                                | PathResolution::FileNamePrefix { .. }
                        ) && let caushell_runner::CwdPathContext::Exact(path)
                            | caushell_runner::CwdPathContext::Subtree(path) = case
                        {
                            input.directory_anchor = Some(path.to_owned());
                        }
                        input.fact.implicit_incidental_cache = target.implicit_incidental_cache;
                        if not_applicable {
                            input.pending_resolution = false;
                            input.fact.resolution = SemanticResolution::NotApplicable {
                                reason: "content channel has no filesystem mutation target".into(),
                            };
                        } else if bound.operation_semantics_unresolved {
                            input.pending_resolution = false;
                            input.fact.resolution = unresolved(
                                SemanticGapKind::UnresolvedOperation,
                                "invocation has unresolved operation semantics",
                            );
                        }
                        inputs.push(input);
                    }
                    if inputs.len() == start {
                        let lexical = PathResolution::UnsupportedDynamicText {
                            text: format!("effect {effect_index} has no target record"),
                        };
                        let mut input = new_input(
                            ctx,
                            record.source_node_id(),
                            format!("effect:{effect_index}"),
                            format!("effect_{effect_index}"),
                            operation,
                            PathTargetAccess::Either,
                            lexical,
                            None,
                        );
                        let absent = path_target_is_inapplicable(bound, &effect.target)
                            || matches!(effect.target, EffectTarget::ConfiguredPath(_))
                            || matches!(bound.bound_path_lists.get(&effect_index), Some(caushell_profile::BoundPathList::Paths(paths)) if paths.is_empty())
                            || bound
                                .bound_archive_members
                                .get(&effect_index)
                                .is_some_and(Vec::is_empty)
                            || (effect.path_access
                                == Some(caushell_profile::PathAccessKind::ContentOpen)
                                && matches!(&effect.target, EffectTarget::Slot(slot) if bound.bound_parameters.iter()
                                .find(|parameter| &parameter.name == slot).is_some_and(|parameter| !parameter.values.is_empty()
                                    && parameter.values.iter().all(|value| matches!(value,
                                        caushell_profile::BoundValue::Argument { node_kind, .. } if node_kind == "process_substitution")))));
                        input.pending_resolution = false;
                        input.fact.resolution = if bound.operation_semantics_unresolved {
                            unresolved(
                                SemanticGapKind::UnresolvedOperation,
                                "invocation has unresolved operation semantics",
                            )
                        } else if absent {
                            SemanticResolution::NotApplicable {
                                reason:
                                    "effect has no applicable filesystem target in this invocation"
                                        .into(),
                            }
                        } else {
                            unresolved(
                                SemanticGapKind::UnknownTarget,
                                "declared mutation effect produced no target",
                            )
                        };
                        inputs.push(input);
                    }
                }
            }
        }
        for case in effective_cwd_cases(ctx.effective_cwd_for_node(record.source_node_id()), cwd) {
            let base = case.resolution_base(cwd);
            for path in collect_redirection_path_facts(
                record.parsed_scope(),
                base,
                home,
                Some(record.bindings()),
            ) {
                if redirection_parent_command_index(record.parsed_scope(), &path.fact)
                    != Some(record.command_index())
                {
                    continue;
                }
                if !path
                    .fact
                    .operator
                    .as_deref()
                    .is_some_and(|op| is_file_write_redirection_operator(op) || op == "<>")
                {
                    continue;
                }
                let io = crate::support::redirection_io_target(
                    record.parsed_scope(),
                    Some(record.command_index()),
                    path.redirection_index,
                    &path.resolution,
                    path.cwd_dependent,
                    base,
                    home,
                    Some(record.bindings()),
                );
                let lexical = io_path(io);
                let spelling = if lexical.as_ref().and_then(PathResolution::concrete_path)
                    == path.resolution.concrete_path()
                {
                    redirection_spelling(&path, base, home)
                } else {
                    lexical
                        .as_ref()
                        .and_then(PathResolution::concrete_path)
                        .map(str::to_owned)
                };
                let mut input = new_input(
                    ctx,
                    record.source_node_id(),
                    format!("redirect:{}", path.redirection_index),
                    path.slot_name.clone(),
                    PathTargetOperation::Write,
                    PathTargetAccess::Follow,
                    project_path_at_cwd(
                        lexical.clone().unwrap_or_else(|| path.resolution.clone()),
                        path.cwd_dependent,
                        case,
                    ),
                    spelling,
                );
                if lexical.is_none() {
                    input.pending_resolution = false;
                    input.fact.resolution = SemanticResolution::NotApplicable {
                        reason: "redirection uses a non-filesystem channel".into(),
                    };
                }
                input.direct_content_output = path
                    .fact
                    .operator
                    .as_deref()
                    .is_some_and(is_file_write_redirection_operator);
                input.cwd_dependent = path.cwd_dependent;
                inputs.push(input);
            }
        }
    }
    for syntax in crate::support::shell_syntax_redirections(ctx) {
        if !syntax
            .path
            .fact
            .operator
            .as_deref()
            .is_some_and(|op| is_file_write_redirection_operator(op) || op == "<>")
        {
            continue;
        }
        let lexical = io_path(syntax.io);
        let cwd_dependent = syntax.path.cwd_dependent;
        let spelling = if lexical.as_ref().and_then(PathResolution::concrete_path)
            == syntax.path.resolution.concrete_path()
        {
            redirection_spelling(
                &syntax.path,
                syntax.exact_cwd.as_deref().unwrap_or(cwd),
                syntax.home.as_deref(),
            )
        } else {
            lexical
                .as_ref()
                .and_then(PathResolution::concrete_path)
                .map(str::to_owned)
        };
        let mut input = new_input(
            ctx,
            &syntax.source,
            format!("syntax-redirect:{}", syntax.path.redirection_index),
            syntax.path.slot_name,
            PathTargetOperation::Write,
            PathTargetAccess::Follow,
            lexical.clone().unwrap_or(syntax.path.resolution),
            spelling,
        );
        if lexical.is_none() {
            input.pending_resolution = false;
            input.fact.resolution = SemanticResolution::NotApplicable {
                reason: "redirection uses a non-filesystem channel".into(),
            };
        }
        input.direct_content_output = syntax
            .path
            .fact
            .operator
            .as_deref()
            .is_some_and(is_file_write_redirection_operator);
        input.cwd_dependent = cwd_dependent;
        inputs.push(input);
    }
    inputs
}

fn unproved_execution_directory(
    records: &std::collections::BTreeMap<&str, &caushell_runner::ExecutionUnitResolveRecord>,
    source: &str,
) -> bool {
    let mut source = source;
    let mut seen = std::collections::BTreeSet::new();
    while let Some(record) = records.get(source) {
        if !seen.insert(source.to_string()) {
            return true;
        }
        if let Some(bound) = bound_invocation(&record.result) {
            if bound.bound_parameters.iter().filter(|parameter| matches!(&parameter.semantic,
                caushell_profile::SemanticType::Path(path) if path.role == caushell_profile::PathRole::CwdAnchor))
                .flat_map(|parameter| parameter.semantic_values()).any(|value| match caushell_profile::project_semantic_value(&caushell_profile::ValueProjection::Identity, value) {
                    Some(SemanticValueResolution::Known(text)) => text.split('/').any(|component| component == ".."),
                    _ => true,
                }) { return true; }
        }
        if record.parent_execution_node_id.0 == source {
            break;
        }
        source = &record.parent_execution_node_id.0;
    }
    false
}

fn spelling_visits(path: &str, root: &str) -> bool {
    let mut prefix = String::new();
    path.split('/').filter(|part| !part.is_empty()).any(|part| {
        prefix.push('/');
        prefix.push_str(part);
        caushell_query::path_is_within_root(&normalize_shell_path(&prefix), root)
    })
}

fn io_path(io: IoTarget) -> Option<PathResolution> {
    match io {
        IoTarget::Path { resolution, .. } => Some(resolution),
        IoTarget::UnknownDescriptor { descriptor } => {
            Some(PathResolution::UnsupportedDynamicText {
                text: format!("unknown file descriptor {descriptor}"),
            })
        }
        IoTarget::InlineContent { .. } => Some(PathResolution::UnsupportedDynamicText {
            text: "write through inline content descriptor".into(),
        }),
        _ => None,
    }
}

fn absolute_spelling(value: &str, cwd: &str) -> String {
    if value.starts_with('/') {
        value.into()
    } else {
        format!("{}/{value}", cwd.trim_end_matches('/'))
    }
}

fn redirection_spelling(
    path: &crate::path::RedirectionPathFactCandidate,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    path.resolution.concrete_path()?;
    let target = path.fact.target.as_ref()?;
    let text = caushell_profile::materialize_shell_assignment_value(
        &target.text,
        target.quoted,
        &target.node_kind,
        &caushell_profile::SessionBindings::default(),
    )?;
    let text = if !target.quoted && text.starts_with('~') {
        crate::path::expand_home_path_spelling(&text, home)?
    } else {
        text
    };
    Some(absolute_spelling(&text, cwd))
}

fn target_spelling(
    record: crate::support::ExecutionResolveRecordRef<'_>,
    slot: &str,
    lexical: &PathResolution,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    let path = lexical.concrete_path()?;
    if slot == crate::path::EXECUTABLE_FILE_SLOT {
        let tilde_expansion = match record.result() {
            caushell_profile::ResolveInvocationArtifactResult::NoProfile {
                executable_word: Some(word),
                ..
            } => !word.runtime_data && word.text.starts_with('~'),
            _ => record.command().is_some_and(|command| {
                !command.command_name_runtime_data
                    && command
                        .command_name
                        .as_deref()
                        .is_some_and(|name| name.starts_with('~'))
            }),
        };
        return match crate::path::unmodeled_executable_path(record)? {
            crate::path::ExecutableFileReference::Known(text) => {
                let text = if tilde_expansion && text.starts_with('~') {
                    crate::path::expand_home_path_spelling(&text, home)?
                } else {
                    text
                };
                let spelling = absolute_spelling(&text, cwd);
                // Keep the spelling paired with the lexical fact from this
                // cwd alternative. Physical namespace resolution still uses
                // the original spelling, including `..` and symlinks.
                (normalize_shell_path(&spelling) == path).then_some(spelling)
            }
            _ => None,
        };
    }
    let bound = bound_invocation(record.result())?;
    if let Some(parameter) = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)
    {
        for value in parameter.semantic_values() {
            let text = match value {
                SemanticValueRef::Projected { value, .. } => match &value.resolution {
                    SemanticValueResolution::Known(text) => Some(text.clone()),
                    _ => None,
                },
                SemanticValueRef::Original(
                    source @ caushell_profile::BoundValue::Argument {
                        text,
                        quoted,
                        node_kind,
                        materialization,
                        ..
                    },
                ) => {
                    let text = if matches!(
                        materialization,
                        BoundArgumentMaterialization::RuntimeData
                            | BoundArgumentMaterialization::ResolvedExactScalar { .. }
                            | BoundArgumentMaterialization::ResolvedRuntimeProduced { .. }
                    ) {
                        Some(text.clone())
                    } else {
                        caushell_profile::materialize_shell_assignment_value(
                            text,
                            *quoted,
                            node_kind,
                            record.bindings(),
                        )
                    };
                    text.and_then(|text| {
                        if source.allows_shell_tilde_expansion() && text.starts_with('~') {
                            crate::path::expand_home_path_spelling(&text, home)
                        } else {
                            Some(text)
                        }
                    })
                }
                _ => None,
            };
            if let Some(text) = text {
                let spelling = absolute_spelling(&text, cwd);
                if normalize_shell_path(&spelling) == path {
                    return Some(spelling);
                }
            }
        }
        return None;
    }
    // A cwd-relative leaf transform does not carry its input's parent traversal.
    if matches!(lexical, PathResolution::DerivedConcrete { .. })
        && bound.effects.iter().enumerate().any(|(index, effect)| {
            crate::path::derived_path_slot_name(index) == slot
                && matches!(&effect.target, EffectTarget::DerivedPath(derived) if derived.root.is_none()
                    && matches!(derived.rule, caushell_types::DerivedPathRule::Basename | caushell_types::DerivedPathRule::UrlBasename))
        })
    {
        return Some(path.into());
    }
    // Other derived rules expose normalized paths, not an original spelling.
    if bound.bound_parameters.iter().flat_map(|parameter| parameter.semantic_values()).any(|value|
        matches!(caushell_profile::project_semantic_value(&caushell_profile::ValueProjection::Identity, value),
            Some(SemanticValueResolution::Known(text)) if text.split('/').any(|component| component == ".."))) { return None; }
    Some(path.into())
}
