use caushell_profile::{
    ArchiveExtraction, DerivedPathSource, EffectKind, EffectTarget, ProfileRegistry,
    ResolveInvocationArtifactResult, argument_structure, gnu_tar_extraction,
};
use caushell_runner::{
    FileContentRead, MAX_FILE_CONTENT_BYTES, RunnerContext, SessionTransformPass, SessionView,
};
use caushell_types::{
    ArchiveMembersEvidence, DerivedPathRule, Evidence, EvidenceKind, FileContentSource,
    FilesystemEntry, PathTargetAccess, RuleId, SemanticResolution,
};

use super::discover_tool_config_inputs::possible_writes;
use super::resolve_tool_configuration::known_content;
use crate::path::archive::tar_members;
use crate::path::namespace::NamespaceResolver;
use crate::support::{
    ExecutionResolveRecordRef, StaticFileContent, graph_backed_execution_resolve_records,
};

pub struct ResolveArchiveMembersPass {
    registry: ProfileRegistry,
}

impl ResolveArchiveMembersPass {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self { registry }
    }
}

impl SessionTransformPass for ResolveArchiveMembersPass {
    fn name(&self) -> &'static str {
        "resolve_archive_members"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        let records = graph_backed_execution_resolve_records(ctx);
        let mut updates = Vec::new();
        let mut remaining = 16usize;
        for &record in &records {
            let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
                continue;
            };
            if resolved.bound.archive_extraction != Some(ArchiveExtraction::GnuTar) {
                continue;
            }
            for (index, effect) in resolved.bound.effects.iter().enumerate() {
                let EffectTarget::DerivedPath(target) = &effect.target else {
                    continue;
                };
                if effect.kind != EffectKind::WritePath
                    || target.rule != DerivedPathRule::ArchiveMembers
                {
                    continue;
                }
                let DerivedPathSource::Slot(slot) = &target.source else {
                    continue;
                };
                // Empty alternative source slots have no applicable effect.
                if !resolved
                    .bound
                    .bound_parameters
                    .iter()
                    .any(|p| &p.name == slot && p.semantic_values().next().is_some())
                {
                    continue;
                }
                let mut evidence = ArchiveMembersEvidence {
                    node_id: record.source_node_id().0.clone(),
                    effect_index: index,
                    complete: false,
                    file: None,
                    namespace_observations: Vec::new(),
                    members: Vec::new(),
                    errors: Vec::new(),
                };
                let result = if remaining == 0 {
                    Err("archive observation budget exceeded".into())
                } else {
                    remaining -= 1;
                    prove(
                        session,
                        ctx,
                        &self.registry,
                        record,
                        &records,
                        &mut evidence,
                    )
                };
                let paths = match result {
                    Ok(paths) => {
                        evidence.complete = true;
                        Some(paths)
                    }
                    Err(error) => {
                        evidence.errors.push(error);
                        None
                    }
                };
                updates.push((record.source_node_id().clone(), index, paths, evidence));
            }
        }
        for (node, index, paths, evidence) in updates {
            if let Some(ResolveInvocationArtifactResult::Resolved(resolved)) =
                ctx.execution_result_mut(&node)
            {
                if let Some(paths) = paths {
                    resolved.bound.bound_archive_members.insert(index, paths);
                }
            }
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: if evidence.complete {
                    "archive member targets proved"
                } else {
                    "archive member targets incomplete"
                }
                .into(),
                kind: EvidenceKind::ArchiveMembers(evidence),
            });
        }
    }
}

fn prove(
    session: SessionView<'_>,
    ctx: &RunnerContext,
    registry: &ProfileRegistry,
    record: ExecutionResolveRecordRef<'_>,
    records: &[ExecutionResolveRecordRef<'_>],
    evidence: &mut ArchiveMembersEvidence,
) -> Result<Vec<String>, String> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        unreachable!()
    };
    if resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
        || resolved.materialized_projection.shell_expansion_unresolved
        || record.static_input_cwd_unproven()
    {
        return Err("archive invocation is incomplete".into());
    }
    let argv = resolved
        .materialized_projection
        .invocation
        .args
        .iter()
        .map(|arg| argument_structure(arg).exact_value().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or("archive argv is incomplete")?;
    let invocation = gnu_tar_extraction(&argv)?;
    let cases = record.cwd_options(&ctx.request().shell_state_before.cwd);
    let cwd = match cases.as_slice() {
        [Some(cwd)] => *cwd,
        _ => return Err("archive input directory is unresolved".into()),
    };
    let archive = spelling(cwd, &invocation.archive);
    let view = ctx.filesystem_view();
    let mut namespace = NamespaceResolver::new(view.clone());
    let (source_resolution, source_observations) =
        namespace.resolve(&archive, PathTargetAccess::Follow);
    evidence
        .namespace_observations
        .extend(source_observations.clone());
    let source = concrete(&source_resolution).ok_or("archive source namespace is unresolved")?;
    let others = records
        .iter()
        .filter(|other| other.source_node_id() != record.source_node_id())
        .copied()
        .collect::<Vec<_>>();
    let writes = possible_writes(ctx, &others, &mut namespace);
    if touches(&writes, &archive)
        || touches(&writes, source)
        || record.parsed_scope().redirections.iter().any(|r| {
            r.operator
                .as_deref()
                .is_some_and(crate::support::is_file_write_redirection_operator)
        })
    {
        return Err("archive content or namespace may change within this action".into());
    }
    let read = match known_content(session, ctx, registry, record, records, source) {
        StaticFileContent::Known(content) => FileContentRead::complete(
            FileContentSource::Graph,
            source,
            MAX_FILE_CONTENT_BYTES,
            None,
            content.into_bytes(),
        ),
        StaticFileContent::Unknown => {
            return Err("archive content has unresolved prior writes".into());
        }
        StaticFileContent::Unobserved => view.read_file(source, MAX_FILE_CONTENT_BYTES),
    };
    evidence.file = Some(read.observation.clone());
    let bytes = read
        .complete_bytes(source, MAX_FILE_CONTENT_BYTES)
        .ok_or("archive content observation is incomplete")?;
    if read
        .observation
        .identity
        .as_ref()
        .is_some_and(|id| id.size != bytes.len() as u64)
    {
        return Err("archive content identity disagrees with its bytes".into());
    }
    let mut fresh = NamespaceResolver::new(view.clone());
    let (after, observed) = fresh.resolve(&archive, PathTargetAccess::Follow);
    if after != source_resolution || observed != source_observations {
        return Err("archive namespace changed during observation".into());
    }
    evidence.members = tar_members(bytes)?;
    let mut directory = cwd.to_string();
    for operand in invocation.directories {
        directory = spelling(&directory, &operand);
        let (resolution, observations) = namespace.resolve(&directory, PathTargetAccess::Follow);
        let linked = observations
            .iter()
            .any(|o| matches!(o.entry, FilesystemEntry::Symlink { .. }));
        evidence.namespace_observations.extend(observations);
        directory = concrete(&resolution)
            .filter(|_| !linked)
            .ok_or("archive extraction directory is unresolved or linked")?
            .into();
    }
    let mut paths = Vec::new();
    let mut prior_files = Vec::<String>::new();
    for member in &mut evidence.members {
        if !matches!(member.typeflag, 0 | b'0' | b'5')
            || !member.link_name.is_empty()
            || member.typeflag == b'5' && member.size != 0
        {
            return Err(format!(
                "archive member {} has an unsupported type or link",
                member.order
            ));
        }
        if member.name.is_empty()
            || member.name.starts_with('/')
            || member.name.split('/').any(|c| c == "..")
        {
            return Err(format!(
                "archive member {} has an absolute or traversing name",
                member.order
            ));
        }
        let target = spelling(&directory, &member.name);
        let (resolution, observations) = namespace.resolve(&target, PathTargetAccess::Follow);
        let linked = observations
            .iter()
            .any(|o| matches!(o.entry, FilesystemEntry::Symlink { .. }));
        evidence.namespace_observations.extend(observations);
        let target = concrete(&resolution)
            .filter(|_| !linked)
            .ok_or("archive target namespace is unresolved or linked")?
            .to_owned();
        if touches(&writes, &target)
            || overlaps(&target, source)
            || prior_files
                .iter()
                .any(|path| target != *path && caushell_query::path_is_within_root(&target, path))
        {
            return Err("archive member overlaps an input or a changing namespace".into());
        }
        if member.typeflag != b'5' {
            prior_files.push(target.clone());
        }
        member.target = Some(target.clone());
        paths.push(target);
    }
    Ok(paths)
}

fn spelling(base: &str, value: &str) -> String {
    if value.starts_with('/') {
        value.into()
    } else {
        format!("{}/{value}", base.trim_end_matches('/'))
    }
}

fn concrete(value: &SemanticResolution<caushell_types::PathResolution>) -> Option<&str> {
    match value {
        SemanticResolution::Resolved { value } => value.concrete_path(),
        _ => None,
    }
}

fn overlaps(left: &str, right: &str) -> bool {
    caushell_query::path_is_within_root(left, right)
        || caushell_query::path_is_within_root(right, left)
}

fn touches(writes: &std::collections::BTreeSet<Option<String>>, path: &str) -> bool {
    writes.contains(&None) || writes.iter().flatten().any(|write| overlaps(write, path))
}
