use std::collections::BTreeSet;

use caushell_profile::{
    ArgumentFieldCount, BoundInvocation, ConfiguredPathMissing, ConfiguredPathTarget, Effect,
    EffectKind, EffectTarget, EnvironmentValueRef, ImplicitConfigFile, ImplicitConfigSource,
    PathPurpose, PathRole, ProfileRegistry, Residual, ResidualKind, ResidualSurface,
    ResolveInvocationArtifactResult, SessionValue, argument_structure, materialize_command_name,
    materialize_prefix_environment,
};
use caushell_runner::{RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    Evidence, EvidenceKind, FilesystemEntry, PathTargetAccess, RuleId, SemanticResolution,
    ToolConfigInputEvidence, ToolConfigInputStatus,
};

use crate::path::namespace::NamespaceResolver;
use crate::path::{collect_effect_mutation_targets, collect_redirection_path_facts};
use crate::support::{ExecutionResolveRecordRef, graph_backed_execution_resolve_records};

pub struct DiscoverToolConfigInputsPass {
    registry: ProfileRegistry,
}

impl DiscoverToolConfigInputsPass {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self { registry }
    }
}

impl SessionTransformPass for DiscoverToolConfigInputsPass {
    fn name(&self) -> &'static str {
        "discover_tool_config_inputs"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let records = graph_backed_execution_resolve_records(ctx);
        if !records.iter().any(|record| {
            command_name(record.result()).is_some_and(|name| {
                self.registry
                    .lookup(name)
                    .profile
                    .is_some_and(|p| !p.implicit_config_files.is_empty())
            })
        }) {
            return;
        }
        let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
        let active_search = records.iter().any(|record| {
            command_name(record.result())
                .and_then(|name| self.registry.lookup(name).profile)
                .is_some_and(|profile| {
                    profile
                        .implicit_config_files
                        .iter()
                        .any(|input| !disabled(input, *record))
                })
        });
        let writes = if active_search {
            possible_writes(ctx, &records, &mut namespace)
        } else {
            BTreeSet::new()
        };
        let mut discovered = Vec::new();
        for record in records {
            let Some(profile) =
                command_name(record.result()).and_then(|name| self.registry.lookup(name).profile)
            else {
                continue;
            };
            let Some(command) = record.command() else {
                continue;
            };
            let prefix = materialize_prefix_environment(command, record.bindings());
            for input in &profile.implicit_config_files {
                if disabled(input, record) {
                    discovered.push(evidence(
                        record,
                        input,
                        0,
                        "first_argument",
                        None,
                        ToolConfigInputStatus::Disabled,
                        Vec::new(),
                        "disabled before option parsing",
                    ));
                    continue;
                }
                for (index, source) in input.sources.iter().enumerate() {
                    let environment = |name: &str| {
                        prefix
                            .iter()
                            .rev()
                            .find(|(key, _)| key == name)
                            .map(|(_, value)| EnvironmentValueRef::Present(value))
                            .unwrap_or_else(|| record.bindings().environment_value(name))
                    };
                    let (origin, directory, suffix, suppressed) = match source {
                        ImplicitConfigSource::EnvironmentDirectory {
                            name,
                            suffix,
                            unless_environment_set,
                        } => {
                            let origin = if prefix.iter().any(|(key, _)| key == name) {
                                format!("command_prefix:{name}")
                            } else {
                                format!("environment:{name}")
                            };
                            let suppressed =
                                unless_environment_set.as_deref().is_some_and(|name| {
                                    matches!(environment(name), EnvironmentValueRef::Present(_))
                                });
                            (
                                origin,
                                scalar_environment(environment(name)),
                                suffix,
                                suppressed,
                            )
                        }
                        ImplicitConfigSource::AccountHome { suffix } => (
                            "account_home".into(),
                            ctx.request()
                                .home
                                .as_deref()
                                .filter(|home| home.starts_with('/') && !home.contains('\0'))
                                .map(str::to_owned)
                                .ok_or("account home is not observed"),
                            suffix,
                            false,
                        ),
                    };
                    if suppressed || matches!(&directory, Ok(directory) if directory.is_empty()) {
                        discovered.push(evidence(
                            record,
                            input,
                            index,
                            &origin,
                            None,
                            ToolConfigInputStatus::Absent,
                            Vec::new(),
                            "source is unset, empty or suppressed",
                        ));
                        continue;
                    }
                    let directory = match directory {
                        Ok(directory) => directory,
                        Err(detail) => {
                            discovered.push(evidence(
                                record,
                                input,
                                index,
                                &origin,
                                None,
                                ToolConfigInputStatus::Unknown,
                                Vec::new(),
                                detail,
                            ));
                            continue;
                        }
                    };
                    let spelling = format!("{}/{}", directory.trim_end_matches('/'), suffix);
                    let paths = if spelling.starts_with('/') {
                        vec![Some(spelling)]
                    } else {
                        record
                            .cwd_options(&ctx.request().shell_state_before.cwd)
                            .into_iter()
                            .map(|cwd| {
                                cwd.map(|cwd| format!("{}/{spelling}", cwd.trim_end_matches('/')))
                            })
                            .collect()
                    };
                    for path in paths {
                        let Some(path) = path else {
                            discovered.push(evidence(
                                record,
                                input,
                                index,
                                &origin,
                                None,
                                ToolConfigInputStatus::Unknown,
                                Vec::new(),
                                "configuration working directory is not fully known",
                            ));
                            continue;
                        };
                        let (resolution, observations) =
                            namespace.resolve(&path, PathTargetAccess::Follow);
                        let concrete = match &resolution {
                            SemanticResolution::Resolved { value } => value.concrete_path(),
                            _ => None,
                        };
                        let changed = writes.contains(&None)
                            || writes.iter().flatten().any(|write| {
                                overlaps(write, &path)
                                    || concrete.is_some_and(|path| overlaps(write, path))
                                    || observations.iter().any(|observation| {
                                        ancestor_or_same(write, &observation.path)
                                    })
                            });
                        let (status, detail) = if changed {
                            (
                                ToolConfigInputStatus::Unknown,
                                "configuration namespace may be changed within this action"
                                    .to_owned(),
                            )
                        } else if let SemanticResolution::Unresolved { gap } = &resolution {
                            (ToolConfigInputStatus::Unknown, gap.detail.clone())
                        } else if observations.iter().any(|observation| {
                            matches!(observation.entry, FilesystemEntry::Missing)
                        }) {
                            (
                                ToolConfigInputStatus::Absent,
                                "configuration path is absent".to_owned(),
                            )
                        } else {
                            (
                                ToolConfigInputStatus::Opaque,
                                "configuration may be loaded; contents are not understood"
                                    .to_owned(),
                            )
                        };
                        let resolved_path = concrete.map(str::to_owned);
                        let mut item = evidence(
                            record,
                            input,
                            index,
                            &origin,
                            Some(path),
                            status,
                            observations,
                            &detail,
                        );
                        item.resolved_path = resolved_path;
                        discovered.push(item);
                    }
                }
            }
        }
        for item in discovered {
            if matches!(
                item.status,
                ToolConfigInputStatus::Unknown | ToolConfigInputStatus::Opaque
            ) {
                let node = caushell_graph::NodeId::new(&item.node_id);
                if let Some(result) = ctx.execution_result_mut(&node) {
                    if let Some(bound) = bound_mut(result) {
                        attach_input(bound, &item);
                    }
                }
            }
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: format!("{} {}: {}", item.input_id, item.source, item.detail),
                kind: EvidenceKind::ToolConfigInput(item),
            });
        }
    }
}

fn command_name(result: &ResolveInvocationArtifactResult) -> Option<&str> {
    match result {
        ResolveInvocationArtifactResult::Resolved(resolved) => {
            Some(&resolved.normalized_command_name)
        }
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            ..
        } => Some(normalized_command_name),
        _ => None,
    }
}

fn bound_mut(result: &mut ResolveInvocationArtifactResult) -> Option<&mut BoundInvocation> {
    match result {
        ResolveInvocationArtifactResult::Resolved(resolved) => Some(&mut resolved.bound),
        ResolveInvocationArtifactResult::SelectionError { partial_bound, .. } => {
            partial_bound.as_mut()
        }
        _ => None,
    }
}

fn disabled(input: &ImplicitConfigFile, record: ExecutionResolveRecordRef<'_>) -> bool {
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        return false;
    };
    let Some(first) = resolved.materialized_projection.invocation.args.first() else {
        return false;
    };
    if argument_structure(first).fields != ArgumentFieldCount::ExactlyOne
        || first.implicit_input_source.is_some()
    {
        return false;
    }
    let value = if first.runtime_data {
        Some(first.text.clone())
    } else {
        materialize_command_name(&first.text, record.bindings())
    };
    value.is_some_and(|value| {
        let disable = &input.disabled_by_first_argument;
        disable.words.iter().any(|word| {
            if disable.case_insensitive_words {
                word.eq_ignore_ascii_case(&value)
            } else {
                word == &value
            }
        }) || disable
            .prefixes
            .iter()
            .any(|prefix| value.starts_with(prefix))
    })
}

fn scalar_environment(value: EnvironmentValueRef<'_>) -> Result<String, &'static str> {
    match value {
        EnvironmentValueRef::Absent => Ok(String::new()),
        EnvironmentValueRef::Present(
            SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. },
        ) if !value.contains('\0') => Ok(value.clone()),
        _ => Err("environment directory is not known"),
    }
}

fn evidence(
    record: ExecutionResolveRecordRef<'_>,
    input: &ImplicitConfigFile,
    index: usize,
    source: &str,
    path: Option<String>,
    status: ToolConfigInputStatus,
    observations: Vec<caushell_types::FilesystemObservation>,
    detail: &str,
) -> ToolConfigInputEvidence {
    ToolConfigInputEvidence {
        node_id: record.source_node_id().0.clone(),
        command: command_name(record.result()).unwrap_or_default().into(),
        input_id: input.id.clone(),
        source_index: index,
        source: source.into(),
        path,
        resolved_path: None,
        status,
        observations,
        detail: detail.into(),
    }
}

fn attach_input(bound: &mut BoundInvocation, input: &ToolConfigInputEvidence) {
    let target = EffectTarget::ConfiguredPath(ConfiguredPathTarget {
        sources: Vec::new(),
        only_when_sources_absent: false,
        environment: None,
        shell_variable: None,
        relative_to: None,
        unresolved_relative_base: false,
        expand_environment: false,
        expand_user: false,
        missing: ConfiguredPathMissing::Unknown,
        default_value: input.resolved_path.clone(),
        fallback_parent_slots: Vec::new(),
        purpose: Some(PathPurpose::ToolConfig),
    });
    for kind in [EffectKind::ReadPath, EffectKind::LoadConfig] {
        let mut effect = Effect::new(kind);
        effect.target = target.clone();
        if !bound.effects.contains(&effect) {
            bound.effects.push(effect);
        }
    }
    bound.operation_semantics_unresolved = true;
    bound.residuals.push(Residual::new(
        ResidualKind::UnboundControlSurface,
        ResidualSurface::Control,
        format!(
            "implicit configuration {} from {} {:?}: {}",
            input.input_id, input.source, input.path, input.detail
        ),
    ));
}

fn overlaps(left: &str, right: &str) -> bool {
    ancestor_or_same(left, right) || ancestor_or_same(right, left)
}

fn ancestor_or_same(parent: &str, path: &str) -> bool {
    parent == path
        || path
            .strip_prefix(parent.trim_end_matches('/'))
            .is_some_and(|tail| tail.starts_with('/'))
}

fn possible_writes(
    ctx: &RunnerContext,
    records: &[ExecutionResolveRecordRef<'_>],
    namespace: &mut NamespaceResolver,
) -> BTreeSet<Option<String>> {
    let mut writes = BTreeSet::new();
    for record in records {
        for cwd in record.cwd_options(&ctx.request().shell_state_before.cwd) {
            let base = cwd.unwrap_or(&ctx.request().shell_state_before.cwd);
            let mut paths =
                collect_effect_mutation_targets(*record, base, ctx.request().home.as_deref())
                    .into_iter()
                    .map(|target| (target.resolution, target.cwd_dependent))
                    .collect::<Vec<_>>();
            paths.extend(
                collect_redirection_path_facts(
                    record.parsed_scope(),
                    base,
                    ctx.request().home.as_deref(),
                    Some(record.bindings()),
                )
                .into_iter()
                .filter(|target| target.role == PathRole::Write)
                .map(|target| (target.resolution, target.cwd_dependent)),
            );
            for (resolution, cwd_dependent) in paths {
                let path = if cwd.is_none() && cwd_dependent {
                    None
                } else {
                    resolution.concrete_path()
                };
                writes.insert(path.map(str::to_owned));
                if let Some(path) = path {
                    let (resolution, _) = namespace.resolve(path, PathTargetAccess::Either);
                    writes.insert(match resolution {
                        SemanticResolution::Resolved { value } => {
                            value.concrete_path().map(str::to_owned)
                        }
                        _ => None,
                    });
                }
                if writes.len() > 4096 {
                    return BTreeSet::from([None]);
                }
            }
        }
    }
    writes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ComputeEffectiveCwdPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_runner::{FilesystemView, PassRunner};
    use caushell_types::*;
    use std::sync::Arc;

    struct Files;
    impl FilesystemView for Files {
        fn entry(&self, path: &str) -> FilesystemEntry {
            if path.ends_with("fixture.rc") {
                FilesystemEntry::File
            } else {
                FilesystemEntry::Directory
            }
        }
    }

    fn run(command: &str) -> RunnerContext {
        let profile = caushell_profile::load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: fixture}
implicit_config_files:
  - id: startup
    disabled_by_first_argument: {words: [--clean]}
    sources: [{kind: environment_directory, name: FIXTURE_HOME, suffix: fixture.rc}]
forms:
  - id: run
    parameters: [{name: args, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
"#).unwrap();
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry.clone()));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(DiscoverToolConfigInputsPass::new(registry));
        let mut ctx = RunnerContext::new(CheckRequest {
            session_id: SessionId::new("config-discovery"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace")
                .with_variable_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            home: Some("/home/test".into()),
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        });
        ctx.set_filesystem_view(Arc::new(Files));
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn declarations_drive_effects_for_an_unrelated_tool() {
        let ctx = run("FIXTURE_HOME=/settings fixture arg");
        let record = &ctx.execution_unit_resolve_records()[0];
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            panic!("{record:?}")
        };
        assert!(resolved.bound.operation_semantics_unresolved);
        assert!(resolved.bound.effects.iter().any(|effect| effect.kind == EffectKind::LoadConfig && matches!(&effect.target,
            EffectTarget::ConfiguredPath(target) if target.default_value.as_deref() == Some("/settings/fixture.rc") && target.purpose == Some(PathPurpose::ToolConfig))));
        assert!(ctx.execution_cwd_for_node(&record.source_node_id).is_some());
    }

    #[test]
    fn disable_and_unset_sources_do_not_add_effects() {
        for command in ["FIXTURE_HOME=/settings fixture --clean arg", "fixture arg"] {
            let ctx = run(command);
            let ResolveInvocationArtifactResult::Resolved(resolved) =
                &ctx.execution_unit_resolve_records()[0].result
            else {
                panic!("{ctx:?}")
            };
            assert!(!resolved.bound.operation_semantics_unresolved);
            assert!(resolved.bound.effects.is_empty());
        }
    }
}
