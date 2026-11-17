//! One native configuration source resolution, consumed by dispatch and paths.
mod repository;
use super::*;
use caushell_profile::{
    ConfiguredExecutionSource, ConfiguredExecutionValue, GitConfigEvent, GitConfigValue,
    GitConfiguration, git_boolean, parse_git_config_parameters, parse_git_configuration,
};
use caushell_runner::{FileContentRead, FilesystemView, MAX_FILE_CONTENT_BYTES};
use caushell_types::{
    FileContentSource, FileContentStatus, PathResolution, PathTargetAccess, SemanticResolution,
    ToolConfigParseEvidence,
};
use std::sync::Arc;

#[derive(Clone)]
enum Content {
    Absent,
    Known(String),
    Unknown(String),
}
struct Inputs<'a> {
    view: Arc<dyn FilesystemView>,
    visible: Box<dyn FnMut(&str) -> crate::support::StaticFileContent + 'a>,
    paths: Vec<PathResolution>,
    evidence: ToolConfigParseEvidence,
    stack: Vec<String>,
    remaining_files: usize,
    remaining_bytes: usize,
    home: Option<String>,
    convention: String,
    source_conventions: BTreeMap<String, String>,
}
impl Inputs<'_> {
    fn entry(&mut self, path: &str) -> caushell_types::FilesystemEntry {
        match (self.visible)(path) {
            crate::support::StaticFileContent::Known(_) => {
                return caushell_types::FilesystemEntry::File;
            }
            crate::support::StaticFileContent::Unknown => {
                return caushell_types::FilesystemEntry::Unavailable {
                    reason: "Git discovery namespace is changed or unknown".into(),
                };
            }
            crate::support::StaticFileContent::Unobserved => (),
        }
        let (resolution, observations) =
            crate::path::namespace::NamespaceResolver::new(self.view.clone())
                .resolve(path, PathTargetAccess::Follow);
        self.evidence
            .namespace_observations
            .extend(observations.clone());
        let SemanticResolution::Resolved { value } = resolution else {
            return caushell_types::FilesystemEntry::Unavailable {
                reason: "Git discovery path is unresolved".into(),
            };
        };
        let Some(path) = value.concrete_path() else {
            return caushell_types::FilesystemEntry::Unavailable {
                reason: "Git discovery path is not unique".into(),
            };
        };
        if observations
            .iter()
            .any(|o| matches!(o.entry, caushell_types::FilesystemEntry::Missing))
        {
            caushell_types::FilesystemEntry::Missing
        } else {
            self.view.entry(path)
        }
    }
    fn overlay(
        &mut self,
        state: &mut GitConfiguration,
        key: &str,
        value: Option<String>,
        source: &str,
    ) {
        let key_lower = key.to_ascii_lowercase();
        if key_lower == "include.path" {
            self.convention = "git.command_config".into();
            match value {
                Some(path) if path.starts_with('/') => self.file(state, &path, 0),
                Some(path) if path.starts_with("~/") && self.home.is_some() => {
                    let path =
                        crate::path::join_shell_path(self.home.as_deref().unwrap(), &path[2..]);
                    self.file(state, &path, 0);
                }
                _ => state.unresolved("Git command/environment include path unresolved"),
            }
        } else if key_lower.starts_with("includeif.") && key_lower.ends_with(".path") {
            state.unresolved("conditional Git command/environment include unresolved");
        } else {
            state.set(key, value, source);
        }
    }
    fn read(&mut self, path: &str) -> Content {
        if self.remaining_files == 0 {
            return Content::Unknown("Git input file budget exhausted".into());
        }
        self.remaining_files -= 1;
        let mut namespace = crate::path::namespace::NamespaceResolver::new(self.view.clone());
        let visible = (self.visible)(path);
        let read = match visible {
            crate::support::StaticFileContent::Known(text) => FileContentRead::complete(
                FileContentSource::Graph,
                path,
                MAX_FILE_CONTENT_BYTES,
                None,
                text.into_bytes(),
            ),
            crate::support::StaticFileContent::Unknown => FileContentRead::failed(
                FileContentSource::Graph,
                path,
                MAX_FILE_CONTENT_BYTES,
                FileContentStatus::Changed,
                "source-visible native input changed or is unknown",
            ),
            crate::support::StaticFileContent::Unobserved => {
                let (resolution, before) = namespace.resolve(path, PathTargetAccess::Follow);
                self.evidence.namespace_observations.extend(before.clone());
                let SemanticResolution::Resolved { value } = resolution else {
                    return Content::Unknown("Git input namespace unresolved".into());
                };
                let Some(concrete) = value.concrete_path() else {
                    return Content::Unknown("Git input namespace is not unique".into());
                };
                if before
                    .iter()
                    .any(|o| matches!(o.entry, caushell_types::FilesystemEntry::Missing))
                {
                    self.paths
                        .push(PathResolution::Concrete { path: path.into() });
                    self.evidence.files.push(
                        FileContentRead::failed(
                            FileContentSource::SuppliedView,
                            concrete,
                            MAX_FILE_CONTENT_BYTES,
                            FileContentStatus::Missing,
                            "observed absence",
                        )
                        .observation,
                    );
                    return Content::Absent;
                }
                let result = self.view.read_file(concrete, MAX_FILE_CONTENT_BYTES);
                let (after, observations) =
                    crate::path::namespace::NamespaceResolver::new(self.view.clone())
                        .resolve(path, PathTargetAccess::Follow);
                if after
                    != (SemanticResolution::Resolved {
                        value: value.clone(),
                    })
                    || before != observations
                {
                    return Content::Unknown("Git input namespace changed during read".into());
                }
                if result.observation.status == FileContentStatus::Missing {
                    return Content::Unknown(
                        "Git namespace and content observations disagree".into(),
                    );
                }
                if concrete != path {
                    self.paths.push(PathResolution::Concrete {
                        path: concrete.into(),
                    });
                    let bytes = result
                        .complete_bytes(concrete, MAX_FILE_CONTENT_BYTES)
                        .map(|v| v.to_vec());
                    self.evidence.files.push(result.observation.clone());
                    if let Some(bytes) = bytes {
                        return self.bytes(bytes);
                    }
                    return Content::Unknown("Git input content unavailable".into());
                }
                result
            }
        };
        self.paths
            .push(PathResolution::Concrete { path: path.into() });
        let bytes = read
            .complete_bytes(path, MAX_FILE_CONTENT_BYTES)
            .map(|v| v.to_vec());
        self.evidence.files.push(read.observation.clone());
        match bytes {
            Some(bytes) => self.bytes(bytes),
            None => Content::Unknown(format!("Git input {}: {:?}", path, read.observation.status)),
        }
    }
    fn bytes(&mut self, bytes: Vec<u8>) -> Content {
        if bytes.len() > self.remaining_bytes {
            return Content::Unknown("Git input byte budget exhausted".into());
        }
        self.remaining_bytes -= bytes.len();
        String::from_utf8(bytes)
            .map(Content::Known)
            .unwrap_or_else(|_| Content::Unknown("Git input is not UTF-8".into()))
    }
    fn file(&mut self, state: &mut GitConfiguration, path: &str, depth: usize) {
        if depth > 8 || self.stack.iter().any(|p| p == path) {
            state.unresolved("Git include depth/cycle unresolved");
            return;
        }
        match self.read(path) {
            Content::Absent => (),
            Content::Unknown(reason) => {
                self.evidence.errors.push(reason.clone());
                state.unresolved(reason);
            }
            Content::Known(text) => match parse_git_configuration(&text) {
                Err(reason) => {
                    self.evidence.errors.push(reason.clone());
                    state.unresolved(reason);
                }
                Ok(events) => {
                    self.source_conventions
                        .insert(path.into(), self.convention.clone());
                    self.stack.push(path.into());
                    for event in events {
                        match event {
                            GitConfigEvent::Value { key, value } => state.set(&key, value, path),
                            GitConfigEvent::Include {
                                path: include,
                                conditional,
                            } => {
                                if conditional {
                                    state.unresolved(
                                        "conditional Git include cannot be proved active/inactive",
                                    );
                                    continue;
                                }
                                let include = if let Some(tail) = include.strip_prefix("~/") {
                                    let Some(home) = &self.home else {
                                        state.unresolved("Git include home is unknown");
                                        continue;
                                    };
                                    crate::path::join_shell_path(home, tail)
                                } else if include.starts_with('~') {
                                    state.unresolved("Git named-user include home unresolved");
                                    continue;
                                } else if include.starts_with('/') {
                                    crate::path::normalize_shell_path(&include)
                                } else {
                                    crate::path::join_shell_path(
                                        path.rsplit_once('/').map_or(".", |(p, _)| p),
                                        &include,
                                    )
                                };
                                self.file(state, &include, depth + 1);
                            }
                        }
                    }
                    self.stack.pop();
                }
            },
        }
    }
}

fn cli_pairs(
    bound: &caushell_profile::BoundInvocation,
    environment: &crate::support::ExecutionEnvironment,
) -> Result<Vec<(String, Option<String>)>, String> {
    let mut items = Vec::new();
    for parameter in &bound.bound_parameters {
        let is_env = parameter.name.as_str() == "configuration_environment";
        if !is_env && parameter.name.as_str() != "configuration_overrides" {
            continue;
        }
        for value in &parameter.values {
            let caushell_profile::BoundValue::Argument { span, .. } = value else {
                return Err("Git command config argv unresolved".into());
            };
            let Some(caushell_profile::SemanticValueResolution::Known(text)) =
                caushell_profile::project_value(
                    &caushell_profile::ValueProjection::Identity,
                    value,
                )
            else {
                return Err("Git command config scalar unresolved".into());
            };
            let (key, value) = text
                .split_once('=')
                .map_or((text.as_str(), None), |(k, v)| (k, Some(v.to_owned())));
            let value = if is_env {
                Some(
                    environment
                        .scalar(
                            value
                                .as_deref()
                                .ok_or("Git config-env lacks environment name")?,
                        )?
                        .ok_or("Git config-env variable absent")?
                        .to_owned(),
                )
            } else {
                value
            };
            items.push((span.start_byte, key.to_owned(), value));
        }
    }
    items.sort_by_key(|x| x.0);
    if items.windows(2).any(|v| v[0].0 == v[1].0) {
        return Err("Git configuration argv order is not unique".into());
    }
    Ok(items.into_iter().map(|(_, k, v)| (k, v)).collect())
}
fn environment_pairs(
    state: &mut GitConfiguration,
    environment: &crate::support::ExecutionEnvironment,
    inputs: &mut Inputs<'_>,
) {
    match environment.scalar("GIT_CONFIG_COUNT") {
        Ok(None) => (),
        Ok(Some(n)) => match n.parse::<usize>() {
            Ok(n) if n <= 256 => {
                for i in 0..n {
                    match (
                        environment.scalar(&format!("GIT_CONFIG_KEY_{i}")),
                        environment.scalar(&format!("GIT_CONFIG_VALUE_{i}")),
                    ) {
                        (Ok(Some(key)), Ok(Some(value))) => inputs.overlay(
                            state,
                            key,
                            Some(value.into()),
                            "<Git environment key/value>",
                        ),
                        _ => state.unresolved("Git environment config pair unresolved"),
                    }
                }
            }
            _ => state.unresolved("Git environment config count invalid or over budget"),
        },
        Err(reason) => state.unresolved(reason),
    }
    match environment.scalar("GIT_CONFIG_PARAMETERS") {
        Ok(None) => (),
        Ok(Some(text)) => match parse_git_config_parameters(text) {
            Ok(pairs) => {
                for (k, v) in pairs {
                    inputs.overlay(state, &k, v, "<GIT_CONFIG_PARAMETERS>")
                }
            }
            Err(reason) => state.unresolved(reason),
        },
        Err(reason) => state.unresolved(reason),
    }
}
fn absolute(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        crate::path::normalize_shell_path(path)
    } else {
        crate::path::join_shell_path(base, path)
    }
}

// git_config_pathname/interpolate_path run before run-command's shell test.
// Unsupported installation/account interpolation stays unknown, never a
// guessed literal path whose observed absence would suppress execution.
fn native_pathname(path: &str, home: Option<&str>) -> Option<String> {
    if let Some(tail) = path.strip_prefix("~/") {
        home.filter(|h| !h.is_empty())
            .map(|h| format!("{h}/{tail}"))
    } else if path.starts_with('~') || path.starts_with("%(prefix)/") {
        None
    } else {
        Some(path.into())
    }
}

fn historical_nonexecutable(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    path: &str,
) -> bool {
    let history = caushell_query::ExecutionUnitHistoryQuery::new()
        .before_sequence(request.sequence_no)
        .execute(caushell_query::QuerySession::from_session(&session));
    let mut disabled = false;
    for unit in history
        .execution_units()
        .iter()
        .rev()
        .take(256)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let Ok(parsed) = caushell_parse::parse_command(unit.raw_text(), unit.shell_kind()) else {
            disabled = false;
            continue;
        };
        let cwd = caushell_runner::EffectiveCwd::known(
            unit.top_level()
                .map(|u| u.cwd_before())
                .unwrap_or(request.shell_state_before.cwd()),
        );
        let obs = source_scope_observations(
            registry,
            request,
            &parsed,
            parsed.commands.len().saturating_sub(1),
            &SessionBindings::new(),
        );
        let cwds = super::super::compute_effective_cwd::source_scope_execution_cwds(
            &parsed, request, &cwd, &obs,
        )
        .1;
        disabled = crate::support::git_hooks::hook_explicitly_nonexecutable(
            path,
            &parsed,
            parsed.commands.len(),
            &obs,
            &cwds,
            request.home.as_deref(),
            disabled,
        );
    }
    disabled
}

#[derive(PartialEq, Eq)]
enum IndexUse {
    Never,
    May,
    Index,
}

fn native_path_inside(path: &str, root: &str, inputs: &mut Inputs<'_>) -> Option<bool> {
    if !path.starts_with('/') {
        return None;
    }
    let mut ns = crate::path::namespace::NamespaceResolver::new(inputs.view.clone());
    let (base, observations) = ns.resolve(root, PathTargetAccess::Follow);
    inputs.evidence.namespace_observations.extend(observations);
    let SemanticResolution::Resolved { value: base } = base else {
        return None;
    };
    let root = base.concrete_path()?;
    let path = crate::path::normalize_shell_path(path);
    // Git considers a lexical worktree prefix inside before resolving symlinks
    // beneath it. Outside aliases are resolved only up to the first prefix that
    // reaches the worktree. Full realpath containment is a different question.
    if path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/'))) {
        return Some(true);
    }
    let mut prefix = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        prefix.push('/');
        prefix.push_str(part);
        if !matches!(
            (inputs.visible)(&prefix),
            crate::support::StaticFileContent::Unobserved
        ) {
            return None;
        }
        let (resolution, observations) = ns.resolve(&prefix, PathTargetAccess::Follow);
        let missing = observations
            .iter()
            .any(|o| matches!(o.entry, caushell_types::FilesystemEntry::Missing));
        inputs.evidence.namespace_observations.extend(observations);
        let SemanticResolution::Resolved { value } = resolution else {
            return None;
        };
        if value.concrete_path() == Some(root) {
            return Some(true);
        }
        // Missing prefixes either select no-index or fail before reading an
        // index. They cannot later cross a verified-missing prefix into a repo.
        if missing {
            return Some(false);
        }
    }
    Some(false)
}

fn diff_index_use(
    registry: &ProfileRegistry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    root: Option<&str>,
    inputs: &mut Inputs<'_>,
) -> IndexUse {
    let bound = &resolved.bound;
    if bound.subcommand_path != ["diff"] {
        return IndexUse::Index;
    }
    let Some(profile) = registry.lookup(&resolved.normalized_command_name).profile else {
        return IndexUse::May;
    };
    let Ok(selection) =
        caushell_profile::select_invocation(profile, &resolved.materialized_projection.invocation)
    else {
        return IndexUse::May;
    };
    let scope = selection.form_scope;
    let Some(raw) = resolved
        .materialized_projection
        .invocation
        .args
        .get(scope.start_index..scope.end_index)
        .and_then(|args| {
            args.iter()
                .map(|a| {
                    caushell_profile::argument_structure(a)
                        .exact_value()
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()
        })
    else {
        return IndexUse::May;
    };
    // Reproduce cmd_diff's pre-scan on native argv, not the operand projection:
    // that scan deliberately stops at the first non-option and does not skip
    // another option's operand. --no-index after -- is data.
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == "--" {
            i += 1;
            break;
        }
        if raw[i] == "--no-index" {
            return IndexUse::Never;
        }
        if !raw[i].starts_with('-') {
            break;
        }
        i += 1;
    }
    if raw.len() == i + 2 {
        let inside = root
            .map(|root| {
                raw[i..]
                    .iter()
                    .map(|p| native_path_inside(p, root, inputs))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if inside.contains(&Some(false)) {
            return IndexUse::Never;
        }
        if decoded_task_arguments(bound, "pathspecs").is_some()
            && inside.len() == 2
            && inside.iter().all(|v| *v == Some(true))
        {
            return IndexUse::Index;
        }
    }
    if decoded_task_arguments(bound, "revision_args").map_or_else(
        || decoded_task_arguments(bound, "pathspecs").is_none_or(|v| v.len() == 2),
        |v| v.len() >= 2,
    ) {
        IndexUse::May
    } else {
        IndexUse::Index
    }
}

fn last_owned_control(
    registry: &ProfileRegistry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    id: &str,
) -> Option<String> {
    let profile = registry.lookup(&resolved.normalized_command_name).profile?;
    let selection =
        caushell_profile::select_invocation(profile, &resolved.materialized_projection.invocation)
            .ok()?;
    selection
        .modifiers
        .iter()
        .find(|m| m.id.as_str() == id)?
        .option_flag_occurrences
        .as_ref()?
        .last()
        .map(|(_, flag)| flag.as_str().to_owned())
}

/// Called exactly once for each canonical invocation, before any source is
/// admitted. No command-name policy exception; native index/hook declarations
/// select the configuration consumer.
pub(super) fn refresh(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    ctx: &mut RunnerContext,
) {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result else {
        return;
    };
    if resolved.normalized_command_name != "git" || resolved.bound.native_configuration_resolved {
        return;
    }
    let hook_kind = crate::support::git_hooks::hook_kind(&resolved.bound);
    let declared_index = resolved.bound.effects.iter().any(
        |e| matches!(&e.target,EffectTarget::ToolConventionPath(t) if t.convention=="git.index"),
    );
    if !declared_index && hook_kind.is_none() {
        return;
    }
    let external_diff_enabled = last_owned_control(registry, resolved, "diff_external_control")
        .as_deref()
        != Some("--no-ext-diff");
    let textconv_enabled = last_owned_control(registry, resolved, "diff_textconv_control")
        .as_deref()
        != Some("--no-textconv");
    let bound = resolved.bound.clone();
    let command_index = program_command_index(entry);
    let parsed = &entry.parsed_scope;
    let observations = source_scope_observations(
        registry,
        request,
        parsed,
        command_index,
        program_scope_bindings(entry),
    );
    let (shells, cwds) = super::super::compute_effective_cwd::source_scope_execution_cwds(
        parsed,
        request,
        &context.entry_cwd,
        &observations,
    );
    let scope_observations = context
        .source_scopes
        .iter()
        .map(|scope| {
            let obs = source_scope_observations(
                registry,
                request,
                &scope.parsed,
                scope.before_command_index,
                &scope.bindings,
            );
            let cwds = super::super::compute_effective_cwd::source_scope_execution_cwds(
                &scope.parsed,
                request,
                &scope.entry_cwd,
                &obs,
            )
            .1;
            (obs, cwds)
        })
        .collect::<Vec<_>>();
    let mut cwd = shells.get(command_index).and_then(|c| {
        let k = c.known_cwds();
        (k.len() == 1 && !c.has_unknown() && c.bounded_roots().is_empty()).then(|| k[0].to_string())
    });
    let directories = decoded_task_arguments(&bound, "working_directory");
    if let Some(directories) = directories {
        for dir in directories {
            if !dir.is_empty() {
                cwd = if dir.starts_with('/') {
                    Some(crate::path::normalize_shell_path(&dir))
                } else {
                    cwd.as_ref().map(|b| absolute(b, &dir))
                };
            }
        }
    } else {
        cwd = None;
    }
    let environment = crate::support::ExecutionEnvironment::for_command(
        &entry.bindings,
        parsed,
        &entry.command_ref,
    );
    let home = environment.scalar("HOME").ok().flatten().map(str::to_owned);
    let count = ctx
        .evidence
        .iter()
        .filter_map(|e| {
            if let caushell_types::EvidenceKind::ToolConfigParse(e) = &e.kind {
                Some(e.files.len())
            } else {
                None
            }
        })
        .sum::<usize>();
    let mut inputs = Inputs {
        view: ctx.filesystem_view(),
        visible: Box::new(|p| {
            source_visible_file_content(
                registry,
                session,
                request,
                parsed,
                command_index,
                p,
                &observations,
                &cwds,
                &context.source_scopes,
            )
        }),
        paths: vec![],
        evidence: ToolConfigParseEvidence {
            unresolved_inputs: Vec::new(),
            node_id: entry.source_node_id.0.clone(),
            command: entry.rendered_command_text.clone(),
            complete: true,
            files: vec![],
            directories: vec![],
            namespace_observations: vec![],
            options: vec![],
            errors: vec![],
        },
        stack: vec![],
        remaining_files: 128usize.saturating_sub(count),
        remaining_bytes: 1048576,
        home,
        convention: String::new(),
        source_conventions: BTreeMap::new(),
    };
    let mut repository = repository::Repository::Unknown;
    if let Some(base) = &cwd {
        let mut candidates = scope_observations
            .iter()
            .filter_map(|(obs, cwds)| {
                crate::support::git_hooks::observed_repository_root(base, obs, cwds)
            })
            .collect::<Vec<_>>();
        candidates.extend(crate::support::git_hooks::observed_repository_root(
            base,
            &observations,
            &cwds,
        ));
        repository = if let Some(root) = candidates.into_iter().max_by_key(String::len) {
            repository::Repository::WorkTree(root)
        } else {
            repository::discover(&mut inputs, base)
        };
    }
    let mut root = match &repository {
        repository::Repository::WorkTree(root) => Some(root.clone()),
        _ => None,
    };
    let mut state = GitConfiguration::default();
    let mut named_inputs = Vec::new();
    let base = cwd.as_deref().unwrap_or(request.shell_state_before.cwd());
    let spelling = entry
        .parsed_scope
        .commands
        .get(command_index)
        .and_then(|c| c.command_name.as_deref());
    let native_layout = spelling.and_then(|spelling| {
        let layout = inputs.view.git_runtime(spelling)?;
        (layout.validate().is_ok()
            && entry.bindings.native_variant(spelling) == Some(layout.variant.as_str()))
        .then_some(layout)
    });
    if let Some(layout) = &native_layout {
        inputs
            .evidence
            .options
            .push(caushell_types::ToolConfigOptionEvidence {
                path: layout.system_config.clone(),
                line: 0,
                order: inputs.evidence.options.len(),
                option: "git.executor_native_layout".into(),
                argument_sha256: Some(caushell_runner::content_sha256(
                    serde_json::to_string(layout).unwrap().as_bytes(),
                )),
            });
    }
    for source in crate::support::git_hooks::git_nonlocal_config_sources(
        &environment,
        base,
        native_layout.as_ref().map(|l| l.system_config.as_str()),
    ) {
        named_inputs.push(caushell_profile::ConfiguredInputSource {
            id: source.slot_name.into(),
            path: source.resolution.clone(),
        });
        inputs.convention = source.convention.into();
        inputs
            .evidence
            .options
            .push(caushell_types::ToolConfigOptionEvidence {
                path: source
                    .resolution
                    .concrete_path()
                    .unwrap_or("<unresolved>")
                    .into(),
                line: 0, // Environment-selected source, not a config-file line.
                order: inputs.evidence.options.len(),
                option: format!("{}:{}", source.convention, source.slot_name),
                argument_sha256: None,
            });
        if let Some(path) = source.resolution.concrete_path() {
            inputs.file(&mut state, path, 0)
        } else {
            inputs.paths.push(source.resolution);
            state.unresolved("Git configuration environment source unresolved");
        }
    }
    let mut local = None;
    match environment.scalar("GIT_DIR") {
        Ok(Some(dir)) => {
            root = cwd.clone(); // Explicit GIT_DIR bypasses repository discovery.
            local = if dir.starts_with('/') {
                Some(crate::path::normalize_shell_path(dir))
            } else {
                cwd.as_ref().map(|b| absolute(b, dir))
            };
        }
        Ok(None) => {
            local = match &repository {
                repository::Repository::WorkTree(root) => {
                    Some(crate::path::join_shell_path(root, ".git"))
                }
                repository::Repository::Bare(dir) => Some(dir.clone()),
                _ => None,
            };
        }
        Err(reason) => state.unresolved(reason),
    }
    let mut common_dir = None;
    let mut resolved_gitdir = None;
    if let Some(mut gitdir) = local {
        if matches!(
            inputs.view.entry(&gitdir),
            caushell_types::FilesystemEntry::File
        ) {
            match inputs.read(&gitdir) {
                Content::Known(pointer) => match pointer
                    .trim()
                    .strip_prefix("gitdir: ")
                    .filter(|v| !v.is_empty() && !v.contains('\n'))
                {
                    Some(path) => {
                        gitdir = absolute(gitdir.rsplit_once('/').map_or(base, |(p, _)| p), path)
                    }
                    None => state.unresolved("Git directory pointer malformed"),
                },
                _ => state.unresolved("Git directory pointer unavailable"),
            }
        }
        common_dir = match environment.scalar("GIT_COMMON_DIR") {
            Ok(Some(path)) => cwd.as_ref().map(|cwd| absolute(cwd, path)),
            Ok(None) => match inputs.read(&crate::path::join_shell_path(&gitdir, "commondir")) {
                Content::Absent => Some(gitdir.clone()),
                Content::Known(path) if !path.trim().is_empty() && !path.trim().contains('\n') => {
                    Some(absolute(&gitdir, path.trim()))
                }
                _ => None,
            },
            Err(_) => None,
        };
        if let Some(common) = &common_dir {
            resolved_gitdir = Some(gitdir.clone());
            inputs.convention = "git.local_config".into();
            inputs.file(
                &mut state,
                &crate::path::join_shell_path(common, "config"),
                0,
            );
        } else {
            state.unresolved("Git common configuration directory unresolved");
        }
        match state.get("extensions.worktreeconfig") {
            GitConfigValue::Absent => (),
            GitConfigValue::Known { value, .. } => match git_boolean(value.as_deref()) {
                Some(true) => {
                    inputs.convention = "git.worktree_config".into();
                    inputs.file(
                        &mut state,
                        &crate::path::join_shell_path(&gitdir, "config.worktree"),
                        0,
                    )
                }
                Some(false) => (),
                None => state.unresolved("Git worktree configuration mode invalid"),
            },
            GitConfigValue::Unknown { reason } => state.unresolved(reason),
        }
    } else if !matches!(repository, repository::Repository::Absent)
        || environment.scalar("GIT_DIR") != Ok(None)
    {
        state.unresolved("Git repository/configuration location unresolved");
    }
    environment_pairs(&mut state, &environment, &mut inputs);
    let overrides = cli_pairs(&bound, &environment);
    match &overrides {
        Ok(pairs) => {
            for (k, v) in pairs {
                inputs.overlay(&mut state, k, v.clone(), "<Git command-line config>")
            }
        }
        Err(reason) => state.unresolved(reason.clone()),
    }
    // A helper executes from Git's work tree, not the caller's subdirectory.
    // Explicit environment/core selectors must not silently retain that cwd.
    match environment.scalar("GIT_WORK_TREE") {
        Ok(Some(path)) => root = cwd.as_ref().map(|cwd| absolute(cwd, path)),
        Ok(None) => match state.get("core.worktree") {
            GitConfigValue::Known {
                value: Some(path), ..
            } => {
                root = native_pathname(&path, inputs.home.as_deref())
                    .and_then(|path| resolved_gitdir.as_ref().map(|base| absolute(base, &path)))
            }
            GitConfigValue::Absent => (),
            _ => root = None,
        },
        Err(_) => root = None,
    }
    let no_repository = matches!(repository, repository::Repository::Absent)
        && environment.scalar("GIT_DIR") == Ok(None);
    let index_use = diff_index_use(registry, resolved, root.as_deref(), &mut inputs);
    let index = declared_index && !no_repository && index_use != IndexUse::Never;
    let mut sources = Vec::new();
    if index {
        let mut value = state.get("core.fsmonitor");
        if value == GitConfigValue::Absent {
            value = match environment.scalar("GIT_TEST_FSMONITOR") {
                Ok(None | Some("")) => GitConfigValue::Absent,
                Ok(Some(v)) => GitConfigValue::Known {
                    value: Some(v.into()),
                    source: "<GIT_TEST_FSMONITOR>".into(),
                },
                Err(reason) => GitConfigValue::Unknown { reason },
            };
        }
        let input=match value {
            GitConfigValue::Absent=>None,
            // The native environment fallback is a raw hook command, not a
            // boolean or git_config_pathname value (fsmonitor-settings.c).
            GitConfigValue::Known{value,source} if source=="<GIT_TEST_FSMONITOR>" =>
                Some((source, ConfiguredExecutionValue::Command{text:value.unwrap()})),
            GitConfigValue::Known{value,source}=>match git_boolean(value.as_deref()) {
                Some(false)=>None,
                Some(true)=>Some((source,ConfiguredExecutionValue::Unknown{detail:"Git built-in filesystem monitor service may start; runtime/platform capability is not proven".into()})),
                None=>Some((source,native_pathname(value.as_deref().unwrap(), inputs.home.as_deref())
                    .map(|text| ConfiguredExecutionValue::Command{text})
                    .unwrap_or_else(|| ConfiguredExecutionValue::Unknown{detail:"Git native pathname interpolation unresolved".into()}))),
            },
            GitConfigValue::Unknown{reason}=>Some(("<unresolved Git config>".into(),ConfiguredExecutionValue::Unknown{detail:reason})),
        };
        if let Some((config_source, mut value)) = input {
            // Two unresolved diff operands may be revisions rather than index
            // inputs. Keep a conditional source opaque, never invent execution.
            if bound.operation_semantics_unresolved
                || !bound.residuals.is_empty()
                || index_use == IndexUse::May
            {
                value=ConfiguredExecutionValue::Unknown{detail:"Git diff index use depends on unresolved native revision/path interpretation".into()};
            }
            sources.push(ConfiguredExecutionSource {
                id: "git-config:core.fsmonitor".into(),
                may_execute: true,
                config_source,
                value,
                cwd: root.clone(),
            });
        }
    }
    if bound.subcommand_path == ["diff"] {
        if external_diff_enabled {
            let mut values = Vec::new();
            match environment.scalar("GIT_EXTERNAL_DIFF") {
                Ok(Some(value)) => values.push((
                    "<GIT_EXTERNAL_DIFF>".to_owned(),
                    ConfiguredExecutionValue::Command { text: value.into() },
                )),
                Ok(None) => match state.get("diff.external") {
                    GitConfigValue::Absent => (),
                    GitConfigValue::Known {
                        value: Some(value),
                        source,
                    } => values.push((source, ConfiguredExecutionValue::Command { text: value })),
                    GitConfigValue::Known { .. } => values.push((
                        "<diff.external>".into(),
                        ConfiguredExecutionValue::Unknown {
                            detail: "Git external diff command has an invalid value".into(),
                        },
                    )),
                    GitConfigValue::Unknown { reason } => values.push((
                        "<unresolved Git config>".into(),
                        ConfiguredExecutionValue::Unknown { detail: reason },
                    )),
                },
                Err(reason) => values.push((
                    "<GIT_EXTERNAL_DIFF>".into(),
                    ConfiguredExecutionValue::Unknown { detail: reason },
                )),
            }
            for (config_source, value) in values {
                sources.push(ConfiguredExecutionSource {
                    id: "git-config:diff.external".into(),
                    may_execute: true,
                    config_source,
                    value,
                    cwd: if no_repository {
                        cwd.clone()
                    } else {
                        root.clone()
                    },
                });
            }
        }
        let drivers = state.configured_driver_keys();
        let driver_may_execute = drivers.iter().any(|k| {
            external_diff_enabled && k.ends_with(".command")
                || textconv_enabled && k.ends_with(".textconv")
        });
        if driver_may_execute || !state.is_complete() {
            sources.push(ConfiguredExecutionSource { id: "git-config:diff.driver".into(), may_execute: true,
                config_source: "<Git attribute-selected diff driver>".into(), cwd: root.clone(),
                value: ConfiguredExecutionValue::Unknown { detail: "Git attribute-selected external diff/textconv applicability is not proven; native driver configuration remains executable".into() } });
        }
    }
    if !no_repository
        && (bound.subcommand_path == ["diff"] || bound.subcommand_path == ["status"])
        && (!state.conversion_filter_keys().is_empty() || !state.is_complete())
    {
        sources.push(ConfiguredExecutionSource { id: "git-config:conversion_filter".into(), may_execute: true,
            config_source: "<Git attribute-selected conversion filter>".into(), cwd: root.clone(),
            value: ConfiguredExecutionValue::Unknown { detail: "Git conversion-filter applicability and protocol are not proven; disabling external diff/textconv does not attest all conversion sources".into() } });
    }
    if let Some(kind) = hook_kind {
        let (hook_root, config_source, convention) = match state.get("core.hookspath") {
            GitConfigValue::Absent => (
                common_dir
                    .as_ref()
                    .map(|r| crate::path::join_shell_path(r, "hooks")),
                common_dir
                    .as_ref()
                    .map(|r| crate::path::join_shell_path(r, "config"))
                    .unwrap_or_default(),
                "git.default_hooks".into(),
            ),
            GitConfigValue::Known {
                value: Some(path),
                source,
            } => {
                let hook_root = (!path.is_empty())
                    .then(|| native_pathname(&path, inputs.home.as_deref()))
                    .flatten()
                    .and_then(|path| {
                        if path.starts_with('/') {
                            Some(crate::path::normalize_shell_path(&path))
                        } else {
                            root.as_ref().map(|r| absolute(r, &path))
                        }
                    });
                let convention = inputs
                    .source_conventions
                    .get(&source)
                    .cloned()
                    .unwrap_or_else(|| "git.command_config".into());
                (hook_root, source, convention)
            }
            _ => (
                None,
                "<unresolved Git config>".into(),
                "git.unknown_config".into(),
            ),
        };
        if hook_root.as_deref() != Some("/dev/null") {
            for stage in crate::support::git_hooks::git_hook_stages(&bound, kind) {
                let path = hook_root.as_ref().map_or_else(
                    || PathResolution::UnsupportedDynamicText {
                        text: "Git hook configuration source is unresolved".into(),
                    },
                    |root| PathResolution::DerivedConcrete {
                        path: crate::path::join_shell_path(root, stage),
                        basis: caushell_types::DerivedPathBasis::ConfigDerivedRoot {
                            config_path: config_source.clone(),
                            convention: convention.clone(),
                            key: "core.hooksPath".into(),
                            value: root.clone(),
                        },
                        rule: caushell_types::DerivedPathRule::ChildUnder {
                            relative_path: stage.into(),
                        },
                    },
                );
                sources.push(ConfiguredExecutionSource {
                    id: format!("git-hook:{stage}"),
                    may_execute: true,
                    config_source: config_source.clone(),
                    value: ConfiguredExecutionValue::File {
                        path,
                        native_argv0: None,
                        hook_stage: Some(stage.into()),
                        body: None,
                    },
                    cwd: root.clone(),
                });
            }
        }
    }
    // Resolve file-backed programs once as source records. Consumers never
    // reopen their configuration or script bytes using a different snapshot.
    for source in &mut sources {
        if let ConfiguredExecutionValue::Command { text } = &source.value {
            let shell = text
                .chars()
                .any(|c| "|&;<>()$`\\\"' \t\n*?[#~=%".contains(c));
            if !shell && text.contains('/') {
                let path = if text.starts_with('/') {
                    PathResolution::Concrete {
                        path: crate::path::normalize_shell_path(text),
                    }
                } else {
                    source.cwd.as_deref().map_or_else(
                        || PathResolution::UnsupportedDynamicText {
                            text: "Git configured executable cwd unknown".into(),
                        },
                        |cwd| PathResolution::Concrete {
                            path: absolute(cwd, text),
                        },
                    )
                };
                source.value = ConfiguredExecutionValue::File {
                    path,
                    native_argv0: Some(text.clone()),
                    hook_stage: None,
                    body: None,
                };
            }
        }
    }
    for source in &mut sources {
        let ConfiguredExecutionValue::File {
            path,
            hook_stage,
            body,
            ..
        } = &mut source.value
        else {
            continue;
        };
        let Some(path) = path.concrete_path() else {
            continue;
        };
        let mut disabled = if hook_stage.is_some() {
            historical_nonexecutable(registry, session, request, path)
        } else {
            false
        };
        for (scope, (obs, cwds)) in context.source_scopes.iter().zip(&scope_observations) {
            disabled = crate::support::git_hooks::hook_explicitly_nonexecutable(
                path,
                &scope.parsed,
                scope.before_command_index,
                obs,
                cwds,
                request.home.as_deref(),
                disabled,
            );
        }
        if hook_stage.is_some()
            && crate::support::git_hooks::hook_explicitly_nonexecutable(
                path,
                parsed,
                command_index,
                &observations,
                &cwds,
                request.home.as_deref(),
                disabled,
            )
        {
            source.may_execute = false;
            continue;
        }
        match inputs.read(path) {
            Content::Absent => source.may_execute = false,
            Content::Known(text) => {
                *body = Some(text);
            }
            Content::Unknown(reason) => {
                inputs.evidence.errors.push(reason);
            }
        }
    }
    if inputs
        .evidence
        .namespace_observations
        .iter()
        .any(|o| o.source != inputs.view.source() || inputs.view.entry(&o.path) != o.entry)
    {
        state.unresolved("Git configuration/discovery namespace changed during resolution");
        sources.push(ConfiguredExecutionSource {
            id: "git-config:changed_snapshot".into(),
            config_source: "<Git configuration snapshot>".into(),
            may_execute: true,
            cwd: root.clone(),
            value: ConfiguredExecutionValue::Unknown {
                detail: "Git configuration/discovery namespace changed during resolution".into(),
            },
        });
    }
    if native_layout.as_ref().is_some_and(|layout| {
        spelling.and_then(|s| inputs.view.git_runtime(s)).as_ref() != Some(layout)
    }) {
        sources.push(ConfiguredExecutionSource {
            id: "git-config:changed_layout".into(),
            config_source: "<executor Git layout>".into(),
            may_execute: true,
            cwd: root.clone(),
            value: ConfiguredExecutionValue::Unknown {
                detail: "owning executor Git layout changed during resolution".into(),
            },
        });
    }
    inputs.evidence.unresolved_inputs = state.unresolved_reasons().to_vec();
    for source in &sources {
        if let ConfiguredExecutionValue::Unknown { detail } = &source.value {
            if !inputs.evidence.unresolved_inputs.contains(detail) {
                inputs.evidence.unresolved_inputs.push(detail.clone());
            }
        }
    }
    inputs.evidence.complete = state.is_complete()
        && inputs.evidence.errors.is_empty()
        && sources.iter().all(|source| {
            !source.may_execute
                || match &source.value {
                    ConfiguredExecutionValue::Unknown { .. } => false,
                    ConfiguredExecutionValue::File { path, body, .. } => {
                        path.concrete_path().is_some() && body.is_some()
                    }
                    ConfiguredExecutionValue::Command { .. } => true,
                }
        });
    if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
        if sources.iter().any(|s| s.may_execute) {
            resolved.bound.effects.push(caushell_profile::Effect::new(
                EffectKind::ExecuteConfigDefinedTask,
            ));
        }
        if bound.subcommand_path == ["diff"] && (index_use != IndexUse::Index || no_repository) {
            // Mode selection refines data effects too. A possible no-index
            // branch contributes file/stdin reads even when revision-vs-path
            // interpretation is still uncertain. Preserve that union, plus
            // the original index effect, rather than dropping either branch.
            if let Some(original) = bound
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == "revision_args")
                .or_else(|| {
                    bound
                        .bound_parameters
                        .iter()
                        .find(|p| p.name.as_str() == "pathspecs")
                })
            {
                let mut paths = original.clone();
                let recursive_or_unknown = original.values.iter().any(|v| {
                    match caushell_profile::project_value(
                        &caushell_profile::ValueProjection::Identity,
                        v,
                    ) {
                        Some(caushell_profile::SemanticValueResolution::Known(path))
                            if path == "-" =>
                        {
                            false
                        }
                        Some(caushell_profile::SemanticValueResolution::Known(path)) => {
                            let path = if path.starts_with('/') {
                                Some(path)
                            } else {
                                cwd.as_ref().map(|base| absolute(base, &path))
                            };
                            path.is_none_or(|path| {
                                !matches!(
                                    inputs.entry(&path),
                                    caushell_types::FilesystemEntry::File
                                        | caushell_types::FilesystemEntry::Missing
                                )
                            })
                        }
                        _ => true,
                    }
                });
                if recursive_or_unknown {
                    resolved.bound.operation_semantics_unresolved = true;
                    resolved.bound.residuals.push(caushell_profile::Residual::new(caushell_profile::ResidualKind::UnboundControlSurface,
                        caushell_profile::ResidualSurface::Control, "native no-index directory/unknown operand has unproved recursive data effects"));
                }

                let stdin = paths.values.iter().any(|v| matches!(caushell_profile::project_value(&caushell_profile::ValueProjection::Identity,v), Some(caushell_profile::SemanticValueResolution::Known(s)) if s == "-"));
                paths.values.retain(|v| !matches!(caushell_profile::project_value(&caushell_profile::ValueProjection::Identity,v), Some(caushell_profile::SemanticValueResolution::Known(s)) if s == "-"));
                paths.name = SlotName::new("native_diff_files");
                paths.semantic = SemanticType::Path(caushell_profile::PathSemantic {
                    role: PathRole::Read,
                    purpose: Some(PathPurpose::GenericOperand),
                });
                paths.structured_source = Some(original.name.clone());
                let mut read = caushell_profile::Effect::new(EffectKind::ReadPath);
                read.target = EffectTarget::Slot(paths.name.clone());
                resolved.bound.bound_parameters.push(paths);
                resolved.bound.effects.push(read);
                if stdin {
                    let mut consume = caushell_profile::Effect::new(EffectKind::ConsumeStdin);
                    consume.target = EffectTarget::ImplicitInput(
                        caushell_profile::ImplicitInputSource::StdinData,
                    );
                    resolved.bound.effects.push(consume);
                    resolved.bound.bound_implicit_inputs.push(
                        caushell_profile::BoundImplicitInput::new(
                            caushell_profile::ImplicitInputSource::StdinData,
                            SemanticType::PlainValue,
                        ),
                    );
                }
                if let Some(stream) = &mut resolved.bound.stream_contract {
                    stream.stdin_mode = caushell_profile::StreamInputMode::DeclaredEffects;
                    if sources.iter().all(|s| !s.may_execute) {
                        stream.stdout_dependency = caushell_types::StreamDataDependency::Inputs;
                    }
                }
            }
            if index_use == IndexUse::Never || no_repository {
                resolved.bound.effects.retain(|e| !matches!(&e.target, EffectTarget::ToolConventionPath(t) if e.kind == EffectKind::ReadPath && t.convention == "git.index"));
            }
        }
        resolved.bound.configured_execution_sources = sources;
        named_inputs.extend(inputs.paths.iter().enumerate().map(|(i, path)| {
            caushell_profile::ConfiguredInputSource {
                id: format!("git_configuration_input_{i}"),
                path: path.clone(),
            }
        }));
        resolved.bound.configured_inputs = named_inputs;
        resolved.bound.native_configuration_resolved = true;
    }
    ctx.add_evidence(caushell_types::Evidence {
        rule_id: caushell_types::RuleId::SelectionError,
        summary: "Git execution sources resolved at the canonical invocation".into(),
        kind: caushell_types::EvidenceKind::ToolConfigParse(inputs.evidence),
    });
}

pub(super) fn frontier_entries(
    _registry: &ProfileRegistry,
    _session: SessionView<'_>,
    _request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    context: &ProgramSourceContext,
    _ctx: &mut RunnerContext,
) -> Vec<FrontierEntry> {
    if !resolved.bound.native_configuration_resolved {
        return Vec::new();
    }
    let index = program_command_index(entry);
    let parsed = &entry.parsed_scope;
    let environment = crate::support::ExecutionEnvironment::for_command(
        &entry.bindings,
        parsed,
        &entry.command_ref,
    );
    let mut base_bindings =
        crate::support::command_environment_bindings(&entry.bindings, parsed, &entry.command_ref);
    base_bindings.enter_child_shell_environment();
    // Native helpers receive Git's own protocol/hook arguments, never the
    // caller shell's positional frame. Unmodeled protocol values stay data.
    base_bindings.forget_positional_parameters();
    // Git serializes -c/--config-env into the environment inherited by helpers.
    // An unresolved serialization remains unknown rather than disappearing.
    match (
        environment.scalar("GIT_CONFIG_PARAMETERS"),
        cli_pairs(&resolved.bound, &environment),
    ) {
        (Ok(inherited), Ok(pairs)) => {
            let mut text = inherited.unwrap_or("").to_owned();
            for (k, v) in pairs {
                if !text.is_empty() {
                    text.push(' ');
                }
                let item = v.map_or(k.clone(), |v| format!("{k}={v}"));
                text.push('\'');
                text.push_str(&item.replace('\'', "'\\''"));
                text.push('\'');
            }
            base_bindings.set_child_environment_value(
                "GIT_CONFIG_PARAMETERS",
                caushell_profile::SessionValue::exact_scalar(text),
            );
        }
        _ => base_bindings.set_child_environment_value(
            "GIT_CONFIG_PARAMETERS",
            caushell_profile::SessionValue::opaque_dynamic(
                "native Git configuration parameters unresolved",
            ),
        ),
    }
    let parent_ref = if entry.origin_kind == ExecutionUnitOriginKind::TopLevel {
        NestedPayloadParentRef::RootCommand {
            command_index: entry.command_ref.command_index,
        }
    } else {
        NestedPayloadParentRef::DerivedInvocation {
            node_id: entry.source_node_id.clone(),
        }
    };
    let scopes = extended_payload_source_scopes(
        &context.source_scopes,
        parsed,
        index,
        program_scope_bindings(entry),
        &context.entry_cwd,
    );
    let mut result = Vec::new();
    for source in &resolved.bound.configured_execution_sources {
        if !source.may_execute {
            continue;
        }
        let mut bindings = base_bindings.clone();
        let (language, input, payload_source, config_path, positional) = match &source.value {
            ConfiguredExecutionValue::Unknown { detail } => (
                PayloadLanguage::Opaque,
                RecursivePayloadInput::LiteralText {
                    text: detail.clone(),
                },
                PayloadSource::DynamicReference,
                source.config_source.clone(),
                None,
            ),
            ConfiguredExecutionValue::Command { text } => {
                // prepare_shell_cmd adds "$@" when native arguments are passed.
                // No metacharacters means direct execvp, not shell builtins.
                let shell = text
                    .chars()
                    .any(|c| "|&;<>()$`\\\"' \t\n*?[#~=%".contains(c));
                let code = if shell {
                    format!("{text} \"$@\"")
                } else {
                    format!(
                        "env -- {} \"$@\"",
                        crate::support::config_tasks::quote_task_argument(text)
                    )
                };
                bindings.forget_positional_parameters();
                bindings.set_shell_program_name(Some(
                    caushell_profile::SessionValue::exact_scalar(text),
                ));
                (
                    PayloadLanguage::Sh,
                    RecursivePayloadInput::LiteralText { text: code },
                    PayloadSource::InlineString,
                    source.config_source.clone(),
                    None,
                )
            }
            ConfiguredExecutionValue::File {
                path,
                native_argv0,
                hook_stage,
                body,
            } => {
                let spelling = path
                    .concrete_path()
                    .unwrap_or("<unresolved Git configured program>")
                    .to_owned();
                bindings.set_shell_program_name(
                    native_argv0
                        .as_ref()
                        .map(caushell_profile::SessionValue::exact_scalar),
                );
                let positional = hook_stage
                    .as_deref()
                    .filter(|s| {
                        matches!(
                            *s,
                            "pre-commit" | "post-commit" | "pre-applypatch" | "post-applypatch"
                        )
                    })
                    .map(|_| Vec::new());
                match body {
                    Some(body) => (
                        crate::support::git_hooks::hook_language(body),
                        RecursivePayloadInput::LiteralText { text: body.clone() },
                        PayloadSource::InlineString,
                        spelling,
                        positional,
                    ),
                    None => (
                        PayloadLanguage::Opaque,
                        RecursivePayloadInput::LiteralText {
                            text: "Git configured program content/cwd is unknown".into(),
                        },
                        PayloadSource::DynamicReference,
                        spelling,
                        positional,
                    ),
                }
            }
        };
        result.push(FrontierEntry {
            parent_ref: parent_ref.clone(),
            root_command_index: entry.root_command_index,
            depth: entry.depth.saturating_add(1),
            candidate: RecursivePayloadCandidate {
                language,
                source: payload_source,
                origin: RecursivePayloadOrigin::ConfigDefinedTask {
                    config_path,
                    task_name: source.id.clone(),
                },
                input,
            },
            bindings,
            positional_args: positional,
            scope_entry_cwd: source.cwd.as_deref().map_or(
                caushell_runner::EffectiveCwd::Unknown,
                caushell_runner::EffectiveCwd::known,
            ),
            source_scopes: scopes.clone(),
        });
    }
    result
}
