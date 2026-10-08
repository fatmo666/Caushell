//! Project shell execution boundaries onto actual output artifacts, not onto
//! a parent command's undifferentiated inputs. No tool names or runtime probes.
use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::{EdgeKind, NodeId};
use caushell_parse::ParseStatus;
use caushell_query::IoTarget;
use caushell_runner::{
    ExecutionUnitOriginKind, ExecutionUnitResolveRecord, PendingMutation, RunnerContext,
};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, StreamDataDependency,
};

use super::{StreamSemanticsIndex, annotate_stream_output, graph_backed_execution_resolve_records};

fn is_shell_scope(kind: ExecutionUnitOriginKind) -> bool {
    matches!(
        kind,
        ExecutionUnitOriginKind::ShellCommandStringPayload
            | ExecutionUnitOriginKind::RecursivePayload
            | ExecutionUnitOriginKind::FunctionExpansion
            | ExecutionUnitOriginKind::NestedPayload
    )
}

fn scopes(ctx: &RunnerContext) -> BTreeMap<NodeId, Vec<&ExecutionUnitResolveRecord>> {
    let mut result = BTreeMap::<NodeId, Vec<_>>::new();
    for record in ctx
        .execution_unit_resolve_records()
        .iter()
        .filter(|r| is_shell_scope(r.origin_kind))
    {
        let parent = if record.origin_kind == ExecutionUnitOriginKind::NestedPayload {
            let Some(id) = ctx
                .pending_mutations()
                .iter()
                .find_map(|mutation| match mutation {
                    PendingMutation::AddNestedPayload {
                        node_id, record_id, ..
                    } if *node_id == record.parent_execution_node_id => Some(*record_id),
                    _ => None,
                })
            else {
                continue;
            };
            let Some(payload) = ctx
                .nested_payload_records()
                .iter()
                .find(|payload| payload.record_id.0 == id)
            else {
                continue;
            };
            if !matches!(
                payload.candidate.candidate.language,
                caushell_profile::PayloadLanguage::Bash
                    | caushell_profile::PayloadLanguage::Sh
                    | caushell_profile::PayloadLanguage::Dash
            ) {
                continue;
            }
            match &payload.parent_ref {
                caushell_runner::NestedPayloadParentRef::DerivedInvocation { node_id } => {
                    node_id.clone()
                }
                caushell_runner::NestedPayloadParentRef::RootCommand { command_index } => {
                    let Some(parsed) = ctx.parsed_command() else {
                        continue;
                    };
                    let Some(command) = parsed.commands.get(*command_index) else {
                        continue;
                    };
                    super::source_node_id_for_command(
                        ctx.request(),
                        parsed,
                        *command_index,
                        command,
                    )
                }
            }
        } else {
            record.parent_execution_node_id.clone()
        };
        result.entry(parent).or_default().push(record);
    }
    result
}

/// Resolve a statically inherited nonstandard FD only when its backing target
/// is concrete, closed or discarded. An alias to an ancestor's entry stream
/// requires that stream's identity; never confuse it with a later local FD
/// reassignment. Such aliases deliberately retain the existing unknown target.
pub(crate) fn inherited_shell_descriptor_target(
    ctx: &RunnerContext,
    source: &NodeId,
    descriptor: &str,
) -> Option<IoTarget> {
    if matches!(descriptor, "0" | "1" | "2") {
        return None;
    }
    let parent = scopes(ctx).into_iter().find_map(|(parent, children)| {
        children
            .iter()
            .any(|child| &child.source_node_id == source)
            .then_some(parent)
    })?;
    let (parsed, index) = execution_location(ctx, &parent)?;
    let cwd = ctx
        .known_effective_cwd_for_node(&parent)
        .unwrap_or(ctx.request().shell_state_before.cwd());
    let target = super::execution_content_io_target(
        ctx,
        &parent,
        parsed,
        index,
        None,
        &caushell_types::PathResolution::Concrete {
            path: format!("/dev/fd/{descriptor}"),
        },
        false,
        cwd,
        ctx.request().home.as_deref(),
    );
    match &target {
        IoTarget::Path {
            resolution,
            cwd_dependent,
        } if resolution.concrete_path().is_some()
            && (!cwd_dependent
                || ctx
                    .effective_cwd_for_node(&parent)
                    .is_none_or(|cwd| !cwd.has_unknown())) =>
        {
            Some(target)
        }
        IoTarget::Closed | IoTarget::Discard => Some(target),
        _ => None,
    }
}

pub(crate) fn execution_location<'a>(
    ctx: &'a RunnerContext,
    node: &NodeId,
) -> Option<(&'a caushell_parse::ParsedCommandArtifact, usize)> {
    ctx.execution_unit_resolve_records()
        .iter()
        .find(|r| &r.source_node_id == node)
        .map(|record| (&record.parsed_scope, record.command_ref.command_index))
        .or_else(|| {
            ctx.parsed_command().and_then(|parsed| {
                parsed
                    .commands
                    .iter()
                    .enumerate()
                    .find(|(index, command)| {
                        super::source_node_id_for_command(ctx.request(), parsed, *index, command)
                            == *node
                    })
                    .map(|(index, _)| (parsed, index))
            })
        })
        .or_else(|| {
            ctx.parsed_command_scopes().iter().find_map(|scope| {
                scope
                    .command_node_ids
                    .iter()
                    .position(|id| id == node)
                    .map(|index| (&scope.parsed, index))
            })
        })
}

/// Only a fully expanded, complete scope can replace the parent's broad
/// dependency by its actual child producers. Partial/truncated scopes retain
/// unknown dependencies and the existing resolution/expansion approval policy.
pub(crate) fn projected_shell_scope_parents(ctx: &RunnerContext) -> BTreeSet<NodeId> {
    let groups = scopes(ctx);
    if groups.is_empty() {
        return BTreeSet::new();
    }
    let graph_nodes: BTreeSet<_> = graph_backed_execution_resolve_records(ctx)
        .iter()
        .map(|record| record.source_node_id().clone())
        .collect();
    groups
        .into_iter()
        .filter_map(|(parent, children)| {
            let first = children.first()?;
            let indexes: BTreeSet<_> = children
                .iter()
                .map(|r| r.command_ref.command_index)
                .collect();
            (first.parsed_scope.status == ParseStatus::Complete
                && children.iter().all(|r| {
                    r.parsed_scope == first.parsed_scope
                        && graph_nodes.contains(&r.source_node_id)
                        && matches!(
                            r.result,
                            caushell_profile::ResolveInvocationArtifactResult::Resolved(_)
                        )
                })
                && indexes.len() == first.parsed_scope.commands.len()
                && indexes
                    .iter()
                    .copied()
                    .eq(0..first.parsed_scope.commands.len()))
            .then_some(parent)
        })
        .collect()
}

#[derive(Clone, PartialEq, Eq)]
struct Output {
    node: NodeId,
    artifact: ProvenanceArtifact,
    semantics: ProvenanceEdgeSemantics,
    target: IoTarget,
    scope_stdout: bool,
}

fn output(
    ctx: &RunnerContext,
    source: &NodeId,
    node: &NodeId,
    artifact: &ProvenanceArtifact,
    semantics: &ProvenanceEdgeSemantics,
) -> Option<Output> {
    let mut scope_stdout = false;
    let target = match artifact {
        ProvenanceArtifact::PathContent { path, .. } => IoTarget::Path {
            resolution: caushell_types::PathResolution::Concrete { path: path.clone() },
            cwd_dependent: false,
        },
        ProvenanceArtifact::PipelineStream { .. } | ProvenanceArtifact::TransformOutput { .. } => {
            IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            }
        }
        ProvenanceArtifact::CommandSubstitutionOutput { .. } => {
            scope_stdout = true;
            IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            }
        }
        ProvenanceArtifact::MaterializedValue { source_kind, .. }
            if source_kind == "dispatch_stdout" =>
        {
            IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            }
        }
        ProvenanceArtifact::DescriptorStream {
            descriptor,
            unresolved,
            ..
        } => {
            if *unresolved {
                IoTarget::UnknownDescriptor {
                    descriptor: descriptor.clone(),
                }
            } else {
                IoTarget::InheritedDescriptor {
                    descriptor: descriptor.clone(),
                }
            }
        }
        ProvenanceArtifact::ProcessSubstitutionChannel { operator, .. } if operator == "input" => {
            scope_stdout = true;
            IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            }
        }
        ProvenanceArtifact::ProcessSubstitutionChannel { .. } => {
            let record = ctx
                .execution_unit_resolve_records()
                .iter()
                .find(|r| &r.source_node_id == source)?;
            let index = (0..record.parsed_scope.redirections.len()).find(|&index| {
                crate::passes::redirection_process_substitution_artifact(ctx, source, index)
                    .is_some_and(|(id, _)| id == *node)
            })?;
            IoTarget::ProcessSubstitution {
                redirection_index: index,
            }
        }
        _ => return None,
    };
    Some(Output {
        node: node.clone(),
        artifact: artifact.clone(),
        semantics: semantics.clone(),
        target,
        scope_stdout,
    })
}

fn stdin_input(artifact: &ProvenanceArtifact, semantics: &ProvenanceEdgeSemantics) -> bool {
    matches!(
        semantics,
        ProvenanceEdgeSemantics::Consume {
            consume_kind: ProvenanceConsumeKind::PipelineInput
                | ProvenanceConsumeKind::StdinExplicit
                | ProvenanceConsumeKind::StdinImplicit,
            ..
        }
    ) || matches!(
        artifact,
        ProvenanceArtifact::RuntimeInput {
            source: caushell_types::RuntimeInputSource::StdinData
                | caushell_types::RuntimeInputSource::StdinPayload,
            ..
        }
    )
}

pub(crate) fn collect_shell_io_scope_mutations(
    ctx: &RunnerContext,
    streams: &StreamSemanticsIndex,
) -> Vec<PendingMutation> {
    let mut groups: Vec<_> = scopes(ctx).into_iter().collect();
    if groups.is_empty() {
        return Vec::new();
    }
    let records: BTreeMap<_, _> = ctx
        .execution_unit_resolve_records()
        .iter()
        .map(|r| (r.source_node_id.clone(), r))
        .collect();
    let graph_nodes: BTreeSet<_> = graph_backed_execution_resolve_records(ctx)
        .iter()
        .map(|r| r.source_node_id().clone())
        .collect();
    // Outside-in: a nested interpreter first receives the enclosing output
    // artifacts, then its own children are projected onto those same artifacts.
    groups.sort_by_key(|(_, children)| children.iter().map(|child| child.depth).min().unwrap_or(0));
    let mut outputs = BTreeMap::<NodeId, Vec<Output>>::new();
    let mut inputs = BTreeMap::<NodeId, Vec<(NodeId, ProvenanceArtifact)>>::new();
    let mut program_inputs = BTreeMap::<NodeId, Vec<(NodeId, ProvenanceArtifact)>>::new();
    let payload_slots: BTreeMap<_, BTreeSet<_>> = records
        .iter()
        .map(|(node, record)| {
            let slots = super::bound_invocation(&record.result)
                .into_iter()
                .flat_map(|bound| &bound.effects)
                .filter(|effect| effect.kind == caushell_profile::EffectKind::ExecutePayload)
                .filter_map(|effect| match &effect.target {
                    caushell_profile::EffectTarget::Slot(name) => Some(name.as_str()),
                    _ => None,
                })
                .collect();
            (node.clone(), slots)
        })
        .collect();
    let stdin_programs: BTreeSet<_> = records
        .iter()
        .filter_map(|(node, record)| {
            super::bound_invocation(&record.result)
                .is_some_and(|bound| {
                    bound.effects.iter().any(|effect| {
                        effect.kind == caushell_profile::EffectKind::ExecutePayload
                            && effect.target
                                == caushell_profile::EffectTarget::ImplicitInput(
                                    caushell_profile::ImplicitInputSource::StdinPayload,
                                )
                    })
                })
                .then_some(node.clone())
        })
        .collect();
    let mut explicit_stdin = BTreeSet::new();
    let mut unknown_descriptor_reads = BTreeSet::new();
    for mutation in ctx.pending_mutations() {
        if let PendingMutation::AddProvenanceArtifact {
            source_node_id,
            node_id,
            artifact,
            relation,
            semantics,
        } = mutation
        {
            if *relation == EdgeKind::Produces {
                if let Some(out) = output(ctx, source_node_id, node_id, artifact, semantics) {
                    outputs.entry(source_node_id.clone()).or_default().push(out);
                }
            } else if *relation == EdgeKind::Consumes {
                if matches!(
                    semantics,
                    ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        ..
                    }
                ) || stdin_programs.contains(source_node_id) && stdin_input(artifact, semantics)
                    || matches!(semantics, ProvenanceEdgeSemantics::Consume {consume_kind: ProvenanceConsumeKind::VariableExpansion | ProvenanceConsumeKind::CommandString,
                        slot_name: Some(slot), ..} if payload_slots.get(source_node_id).is_some_and(|slots| slots.contains(slot.as_str())))
                {
                    program_inputs
                        .entry(source_node_id.clone())
                        .or_default()
                        .push((node_id.clone(), artifact.clone()));
                }
                if stdin_input(artifact, semantics) {
                    inputs
                        .entry(source_node_id.clone())
                        .or_default()
                        .push((node_id.clone(), artifact.clone()));
                }
                if matches!(artifact, ProvenanceArtifact::DescriptorStream {descriptor, unresolved: false, ..} if descriptor == "0")
                {
                    explicit_stdin.insert(source_node_id.clone());
                }
                if matches!(
                    artifact,
                    ProvenanceArtifact::DescriptorStream {
                        unresolved: true,
                        ..
                    }
                ) {
                    unknown_descriptor_reads.insert(source_node_id.clone());
                }
            }
        }
    }
    let mut mutations = Vec::new();
    for (parent, children) in groups {
        let parent_outputs = outputs.get(&parent).cloned().unwrap_or_default();
        let parent_inputs = inputs.get(&parent).cloned().unwrap_or_default();
        let source_program = program_inputs.get(&parent).cloned().unwrap_or_default();
        for child in children {
            let node = &child.source_node_id;
            if !graph_nodes.contains(node)
                || ctx
                    .effective_cwd_for_node(node)
                    .is_some_and(|cwd| cwd.is_unreachable())
            {
                continue;
            }
            // Parsing a script/variable into commands does not erase the
            // program's byte origin. Literal arguments may originate there.
            for (id, artifact) in &source_program {
                mutations.push(PendingMutation::AddProvenanceArtifact {
                    source_node_id: node.clone(),
                    node_id: id.clone(),
                    artifact: artifact.clone(),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::CommandString,
                        slot_name: Some("scope_program".into()),
                        normalized_command_name: None,
                        domain_label: None,
                    },
                });
                program_inputs
                    .entry(node.clone())
                    .or_default()
                    .push((id.clone(), artifact.clone()));
            }
            // An internal pipeline supplies its own input. Local redirects,
            // closed FDs and ignored stdin must not import the parent's input.
            if (streams.inherits_stdin(node) && !streams.ignores_stdin(node))
                || explicit_stdin.contains(node)
                || unknown_descriptor_reads.contains(node)
            {
                for (id, artifact) in &parent_inputs {
                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id: node.clone(),
                        node_id: id.clone(),
                        artifact: artifact.clone(),
                        relation: EdgeKind::Consumes,
                        semantics: ProvenanceEdgeSemantics::Consume {
                            consume_kind: ProvenanceConsumeKind::StdinImplicit,
                            slot_name: Some("scope_stdin".into()),
                            normalized_command_name: None,
                            domain_label: None,
                        },
                    });
                    inputs
                        .entry(node.clone())
                        .or_default()
                        .push((id.clone(), artifact.clone()));
                }
            }
            for port in ["1", "2"] {
                let Some(target) = streams.output_target(node, port) else {
                    continue;
                };
                let inherited = match target {
                    IoTarget::InheritedDescriptor { descriptor } => descriptor.as_str(),
                    IoTarget::UnknownDescriptor { .. } => "unknown",
                    IoTarget::Path { .. } => "path",
                    _ => continue,
                };
                // Nonterminal stdout (including stderr duplicated to it) is
                // the INTERNAL pipe, not the shell scope's enclosing output.
                if inherited == "1" && streams.pipeline_nonterminal(node) {
                    continue;
                }
                if !matches!(inherited, "1" | "2" | "unknown" | "path") {
                    continue;
                }
                let destination = if inherited == "path" {
                    Some(target)
                } else {
                    streams.output_target(&parent, inherited)
                };
                for out in &parent_outputs {
                    if out.scope_stdout && streams.pipeline_nonterminal(&parent) {
                        continue;
                    }
                    if inherited != "unknown"
                        && !destination
                            .is_some_and(|d| super::stream_semantics::same_target(d, &out.target))
                    {
                        continue;
                    }
                    let mut semantics = out.semantics.clone();
                    // A parent's independence claim describes the parent,
                    // not the new child producer. Preserve only the underlying
                    // domain before applying this producer's own dependency.
                    if let ProvenanceEdgeSemantics::Produce { domain_label, .. } = &mut semantics {
                        if let Some(caushell_types::ProvenanceDomainLabel::StreamOutput {
                            domain,
                            ..
                        }) = domain_label
                        {
                            *domain_label = domain.take().map(|domain| *domain);
                        }
                    }
                    // Evaluate this particular port, not every input/output of
                    // either interpreter. Unknown routes remain conservative.
                    annotate_stream_output(
                        &mut semantics,
                        if inherited == "unknown" {
                            StreamDataDependency::Unknown
                        } else {
                            streams.dependency(node, target)
                        },
                    );
                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id: node.clone(),
                        node_id: out.node.clone(),
                        artifact: out.artifact.clone(),
                        relation: EdgeKind::Produces,
                        semantics: semantics.clone(),
                    });
                    let projected = Output {
                        target: target.clone(),
                        semantics,
                        scope_stdout: false,
                        ..out.clone()
                    };
                    let node_outputs = outputs.entry(node.clone()).or_default();
                    if !node_outputs.contains(&projected) {
                        node_outputs.push(projected);
                    }
                }
            }
        }
    }
    mutations
}
