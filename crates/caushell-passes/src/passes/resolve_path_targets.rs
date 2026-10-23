use caushell_graph::NodeId;
use caushell_profile::{
    BoundArgumentMaterialization, EffectKind, EffectTarget, SemanticValueRef,
    SemanticValueResolution,
};
use caushell_query::IoTarget;
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

struct Input {
    fact: PathTargetFact,
    namespace_write: bool,
    pending_resolution: bool,
    cwd_dependent: bool,
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
        let namespace_writes: Vec<_> = inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.namespace_write && input.pending_resolution)
            .map(|(index, input)| (index, input.fact.lexical.concrete_path().map(str::to_owned)))
            .collect();
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
        let mut comparisons = 0usize;
        for index in 0..inputs.len() {
            if !inputs[index].pending_resolution {
                continue;
            }
            let spelling = inputs[index].fact.spelling.as_deref();
            let (mut resolution, observations) = if inputs[index].cwd_dependent
                && unproved_execution_directory(&records, &inputs[index].fact.source_node_id)
            {
                (
                    unresolved(
                        SemanticGapKind::UnresolvedOperation,
                        "execution directory has only a lexical parent-component resolution",
                    ),
                    Vec::new(),
                )
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
                    if *other == index {
                        return false;
                    }
                    let Some(root) = root else {
                        return true;
                    };
                    spelling.is_some_and(|path| spelling_visits(path, root))
                        || observations.iter().any(|observation| {
                            caushell_query::path_is_within_root(&observation.path, root)
                        })
                        || inputs[index]
                            .fact
                            .lexical
                            .concrete_path()
                            .is_some_and(|path| caushell_query::path_is_within_root(path, root))
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
            }
            inputs[index].fact.resolution = resolution;
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
            metadata_mutation: None,
            implicit_incidental_cache: false,
        },
        namespace_write: operation.is_mutation()
            && operation != PathTargetOperation::Metadata
            && access != PathTargetAccess::Follow,
        pending_resolution: true,
        cwd_dependent: false,
    }
}

fn collect_inputs(ctx: &RunnerContext) -> Vec<Input> {
    let cwd = ctx.request().shell_state_before.cwd();
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
                        input.fact.metadata_mutation = target.metadata_mutation.clone();
                        if archive_members {
                            // The complete archive proof excludes link/special
                            // entries; these writes cannot redirect later members.
                            input.namespace_write = false;
                        }
                        input.cwd_dependent = target.cwd_dependent;
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
                Some(absolute_spelling(&text, cwd))
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
