use std::collections::VecDeque;

use caushell_profile::{NativePathOutputPlan, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    DirectoryEntryKind, DirectoryReadLimits, Evidence, EvidenceKind, FilesystemEntry,
    MAX_DIRECTORY_DEPTH, MAX_OBSERVED_STREAM_BYTES, MAX_OBSERVED_STREAM_RECORDS,
    ObservedStreamRecord, PathTargetAccess, RuleId, SemanticResolution, StdoutRecordsEvidence,
    StreamRecordOrder,
};

use super::discover_tool_config_inputs::possible_writes;
use crate::path::namespace::NamespaceResolver;
use crate::support::{ExecutionResolveRecordRef, graph_backed_execution_resolve_records};

pub struct ObserveStdoutRecordsPass;

impl SessionTransformPass for ObserveStdoutRecordsPass {
    fn name(&self) -> &'static str {
        "observe_stdout_records"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        if !ctx.execution_unit_resolve_records().iter().any(|record| {
            matches!(&record.result,ResolveInvocationArtifactResult::Resolved(r)
                if r.bound.stdout_records.as_ref().is_some_and(|c|c.native.is_some()))
        }) {
            return;
        }
        let snapshot = ctx.clone();
        let records = graph_backed_execution_resolve_records(&snapshot);
        for &record in &records {
            let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                continue;
            };
            let Some(plan) = resolved.native_stdout_record_plan() else {
                continue;
            };
            let mut output = StdoutRecordsEvidence {
                node_id: record.source_node_id().0.clone(),
                producer_node_id: record.source_node_id().0.clone(),
                session_id: ctx.request().session_id.0.clone(),
                sequence_no: ctx.request().sequence_no,
                cwd: None,
                complete: false,
                order: StreamRecordOrder::Unspecified,
                encoding: None,
                records: Vec::new(),
                namespace_observations: Vec::new(),
                directory_observations: Vec::new(),
                environment_observations: Vec::new(),
                forwarded_by: Vec::new(),
                gap: None,
            };
            let result = plan.and_then(|plan| observe(ctx, record, &records, &plan, &mut output));
            match result {
                Ok(()) => {
                    output.complete = true;
                    if output.records.len() <= 1 {
                        output.order = StreamRecordOrder::Exact;
                    }
                }
                Err(gap) => {
                    output.gap = Some(gap);
                    output.records.clear();
                }
            }
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: if output.complete {
                    "native stdout records observed".into()
                } else {
                    format!(
                        "native stdout records incomplete: {}",
                        output.gap.as_deref().unwrap_or_default()
                    )
                },
                kind: EvidenceKind::StdoutRecords(output),
            });
        }
        for &record in &records {
            let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                continue;
            };
            if !matches!(
                resolved.proven_stdout_records().map(|r| &r.projection),
                Some(caushell_profile::StdoutRecordProjection::Stdin)
            ) {
                continue;
            }
            let in_frame = |index| {
                records.iter().copied().find(|r| {
                    r.command_index() == index
                        && r.parsed_scope() == record.parsed_scope()
                        && r.variable_frame() == record.variable_frame()
                })
            };
            let Some((mut output, via)) = crate::support::stdin_observed_records(
                record.parsed_scope(),
                record.command_index(),
                64,
                |index| match in_frame(index)?.result() {
                    ResolveInvocationArtifactResult::Resolved(r) => Some(r.clone()),
                    _ => None,
                },
                |index| {
                    let node = in_frame(index)?.source_node_id();
                    ctx.evidence.iter().find_map(|e| match &e.kind {
                        EvidenceKind::StdoutRecords(r) if r.node_id == node.0 => Some(r.clone()),
                        _ => None,
                    })
                },
            ) else {
                continue;
            };
            for index in via {
                output
                    .forwarded_by
                    .push(in_frame(index).unwrap().source_node_id().0.clone());
            }
            output.node_id = record.source_node_id().0.clone();
            output.forwarded_by.push(output.node_id.clone());
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: "native stdout records forwarded".into(),
                kind: EvidenceKind::StdoutRecords(output),
            });
        }
    }
}

fn observe(
    ctx: &mut RunnerContext,
    record: ExecutionResolveRecordRef<'_>,
    records: &[ExecutionResolveRecordRef<'_>],
    plan: &NativePathOutputPlan,
    output: &mut StdoutRecordsEvidence,
) -> Result<(), String> {
    let command = record.command().ok_or("producer command is unavailable")?;
    output.encoding = Some(match plan.output.as_slice() {
        [caushell_profile::NativeRecordFormat::Line] => caushell_types::StreamRecordEncoding::Lines,
        [caushell_profile::NativeRecordFormat::Nul] => caushell_types::StreamRecordEncoding::Nul,
        _ => caushell_types::StreamRecordEncoding::NativeFormat,
    });
    let pipe_stdout = crate::support::collect_pipeline_groups(record.parsed_scope())
        .iter()
        .any(|g| {
            g.commands
                .iter()
                .position(|c| c.command_index == record.command_index())
                .is_some_and(|i| i + 1 < g.commands.len())
        });
    if output.encoding != Some(caushell_types::StreamRecordEncoding::Nul)
        && (!pipe_stdout
            || !crate::support::stdout_route_is_plain(
                record.parsed_scope(),
                record.command_index(),
            ))
    {
        return Err("producer stdout terminal mode is unobserved".into());
    }
    if plan.predicates.iter().any(|p| {
        matches!(
            p,
            caushell_profile::NativePathPredicate::Name {
                insensitive: true,
                ..
            } | caushell_profile::NativePathPredicate::Path {
                insensitive: true,
                ..
            }
        )
    }) {
        let mut bindings = record.bindings().clone();
        for (name, value) in
            caushell_profile::materialize_prefix_environment(command, record.bindings())
        {
            bindings.set_child_environment_value(&name, value);
        }
        observe_locale(&bindings, output)?;
    }
    if command.control_flow_span.is_some()
        || command.guarded
        || record.static_input_cwd_unproven()
        || command
            .command_name
            .as_deref()
            .is_some_and(|n| record.bindings().function_binding(n).is_some())
    {
        return Err("producer execution frame is incomplete".into());
    }
    let cases = record.cwd_options(ctx.request().shell_state_before.cwd());
    let cwd = match cases.as_slice() {
        [Some(cwd)] => cwd.to_string(),
        _ => return Err("producer cwd is unresolved".into()),
    };
    output.cwd = Some(cwd.clone());
    let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
    let others = records
        .iter()
        .filter(|r| r.source_node_id() != record.source_node_id())
        .copied()
        .collect::<Vec<_>>();
    if others.iter().any(|r| match r.result() {
        ResolveInvocationArtifactResult::Resolved(resolved) => {
            resolved.bound.operation_semantics_unresolved
                || !resolved.bound.residuals.is_empty()
                || resolved.bound.effects.iter().any(|e| {
                    !matches!(
                        e.kind,
                        caushell_profile::EffectKind::ReadPath
                            | caushell_profile::EffectKind::WritePath
                            | caushell_profile::EffectKind::DeletePath
                            | caushell_profile::EffectKind::MovePath
                            | caushell_profile::EffectKind::ChangeMode
                            | caushell_profile::EffectKind::ChangeOwner
                            | caushell_profile::EffectKind::ChangeGroup
                            | caushell_profile::EffectKind::MetadataMutation
                            | caushell_profile::EffectKind::SetCurrentWorkingDirectory
                            | caushell_profile::EffectKind::SetExecutionWorkingDirectory
                            | caushell_profile::EffectKind::ConsumeStdin
                            | caushell_profile::EffectKind::ConsumeAuxiliaryValue
                            | caushell_profile::EffectKind::ConsumeAuxiliaryEnvironment
                            | caushell_profile::EffectKind::NetworkEndpoint
                            | caushell_profile::EffectKind::TransformData
                    )
                })
        }
        _ => true,
    }) {
        return Err("other action effects may change the producer namespace".into());
    }
    let writes = possible_writes(ctx, &others, &mut namespace);
    // Shell redirections take effect before the producer runs.
    if record.parsed_scope().redirections.iter().any(|r| {
        r.operator
            .as_deref()
            .is_some_and(crate::support::is_file_write_redirection_operator)
    }) {
        return Err("producer namespace may change through a redirection".into());
    }
    let mut queue = VecDeque::new();
    for root in &plan.roots {
        let spelling = if root.starts_with('/') {
            root.clone()
        } else {
            format!("{}/{root}", cwd.trim_end_matches('/'))
        };
        let (resolution, observations) = namespace.resolve(&spelling, PathTargetAccess::Entry);
        output.namespace_observations.extend(observations);
        let path = match resolution {
            SemanticResolution::Resolved { value } => value.concrete_path().map(str::to_owned),
            _ => None,
        }
        .ok_or("producer root namespace is unresolved")?;
        if writes
            .iter()
            .any(|p| p.as_ref().is_none_or(|p| overlaps(p, &path)))
        {
            return Err("producer namespace may change within this action".into());
        }
        if ctx.filesystem_view().entry(&path) != FilesystemEntry::Directory {
            return Err("native root is not an observed directory".into());
        }
        queue.push_back((
            path,
            root.clone(),
            String::new(),
            0,
            DirectoryEntryKind::Directory,
            None,
        ));
    }
    let mut visited = 0usize;
    let mut bytes = 0usize;
    let mut path_bytes = 0usize;
    while let Some((path, spelling, relative, depth, kind, expected_identity)) = queue.pop_front() {
        visited += 1;
        if visited > MAX_OBSERVED_STREAM_RECORDS || depth > MAX_DIRECTORY_DEPTH {
            return Err("producer traversal budget exceeded".into());
        }
        let name = if relative.is_empty() {
            root_name(&spelling)
        } else {
            spelling.rsplit('/').next().unwrap_or(&spelling)
        };
        if plan
            .accepts(&spelling, name, kind, depth)
            .map_err(String::from)?
        {
            path_bytes = path_bytes
                .checked_add(spelling.len())
                .filter(|n| *n <= MAX_OBSERVED_STREAM_BYTES)
                .ok_or("producer path byte budget exceeded")?;
            let encoded = plan
                .encode(&spelling, &relative, name)
                .map_err(String::from)?;
            bytes = bytes
                .checked_add(encoded.len())
                .filter(|n| *n <= MAX_OBSERVED_STREAM_BYTES)
                .ok_or("producer byte budget exceeded")?;
            output.records.push(ObservedStreamRecord {
                path_spelling: spelling.clone(),
                bytes: encoded,
            });
        }
        if kind != DirectoryEntryKind::Directory {
            continue;
        }
        let read = ctx.read_directory(&path, depth);
        output.directory_observations.push(read.observation.clone());
        let entries = read
            .complete_entries(&path, DirectoryReadLimits::default())
            .ok_or("directory observation is incomplete")?;
        if expected_identity
            .as_ref()
            .is_some_and(|id| read.observation.identity.as_ref() != Some(id))
        {
            return Err("directory entry identity changed before traversal".into());
        }
        if plan.max_depth.is_some_and(|max| depth >= max) {
            continue;
        }
        for entry in entries {
            queue.push_back((
                join(&path, &entry.name),
                join(&spelling, &entry.name),
                join_relative(&relative, &entry.name),
                depth + 1,
                entry.kind,
                Some(entry.identity.clone()),
            ));
            if queue.len().saturating_add(visited) > MAX_OBSERVED_STREAM_RECORDS {
                return Err("producer traversal budget exceeded".into());
            }
        }
    }
    // A later subtree read must not certify a stale earlier root observation.
    for previous in output.directory_observations.clone() {
        let read = ctx.read_directory(&previous.path, 0);
        if read.observation != previous {
            return Err("directory changed during producer observation".into());
        }
    }
    let view = ctx.filesystem_view();
    if output
        .namespace_observations
        .iter()
        .any(|o| o.source != view.source() || view.entry(&o.path) != o.entry)
    {
        return Err("producer root namespace changed during observation".into());
    }
    Ok(())
}

fn root_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed.rsplit('/').next().unwrap_or(trimmed)
    }
}

fn observe_locale(
    bindings: &caushell_profile::SessionBindings,
    output: &mut StdoutRecordsEvidence,
) -> Result<(), String> {
    use caushell_profile::{EnvironmentValueRef as E, SessionValue};
    use caushell_types::{ShellEnvironmentSnapshot, ShellEnvironmentValue as V};
    for name in ["LC_ALL", "LC_CTYPE", "LANG"] {
        let value = match bindings.environment_value(name) {
            E::Absent => V::Absent,
            E::Present(
                SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. },
            ) => V::Present {
                value: value.clone(),
            },
            _ => V::Unknown,
        };
        output
            .environment_observations
            .push(ShellEnvironmentSnapshot {
                name: name.into(),
                value: value.clone(),
            });
        match value {
            V::Absent => {}
            V::Present { value } if value.is_empty() => {}
            V::Present { value }
                if matches!(value.as_str(), "C" | "POSIX" | "C.UTF-8" | "C.utf8") =>
            {
                return Ok(());
            }
            _ => return Err("native case folding locale is unobserved or unsupported".into()),
        }
    }
    Ok(())
}
fn join(path: &str, name: &str) -> String {
    if path.ends_with('/') {
        format!("{path}{name}")
    } else {
        format!("{path}/{name}")
    }
}
fn join_relative(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.into()
    } else {
        join(path, name)
    }
}
fn overlaps(a: &str, b: &str) -> bool {
    caushell_query::path_is_within_root(a, b) || caushell_query::path_is_within_root(b, a)
}
