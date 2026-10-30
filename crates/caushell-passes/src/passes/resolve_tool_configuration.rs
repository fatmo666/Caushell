mod apt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use caushell_parse::{CommandToken, CommandTokenKind, SourceSpan};
use caushell_profile::{
    BoundInvocation, CommandProfile, ConfigurationSyntax, ConfiguredPathMissing,
    ConfiguredPathTarget, Effect, EffectKind, EffectTarget, ImplicitConfigSource,
    InvocationRuntimeContext, PathPurpose, ProfileRegistry, ResidualKind,
    ResolveInvocationArtifactResult, argument_structure, mark_configuration_pending,
    parse_configuration, resolve_invocation_artifact_with_bindings, root_option_ownership,
};
use caushell_query::QuerySession;
use caushell_runner::{
    EffectiveCwd, FileContentRead, FilesystemView, MAX_FILE_CONTENT_BYTES, RunnerContext,
    SessionTransformPass, SessionView, content_sha256,
};
use caushell_types::{
    Evidence, EvidenceKind, FileContentSource, FileContentStatus, PathTargetAccess, RuleId,
    ToolConfigInputStatus, ToolConfigOptionEvidence, ToolConfigParseEvidence,
};

use super::discover_tool_config_inputs::{
    possible_namespace_writes, possible_writes, possible_writes_excluding_effects,
};
use crate::path::namespace::NamespaceResolver;
use crate::support::{
    ExecutionResolveRecordRef, StaticFileContent, graph_backed_execution_resolve_records,
    static_file_content_before_scoped_command,
};

pub struct ResolveToolConfigurationPass {
    registry: ProfileRegistry,
}

impl ResolveToolConfigurationPass {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self { registry }
    }
}

impl SessionTransformPass for ResolveToolConfigurationPass {
    fn name(&self) -> &'static str {
        "resolve_tool_configuration"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        let records = graph_backed_execution_resolve_records(ctx);
        let mut inputs_by_node: BTreeMap<&str, Vec<&caushell_types::ToolConfigInputEvidence>> =
            BTreeMap::new();
        for evidence in &ctx.evidence {
            if let EvidenceKind::ToolConfigInput(input) = &evidence.kind {
                inputs_by_node
                    .entry(&input.node_id)
                    .or_default()
                    .push(input);
            }
        }
        if !records.iter().any(|r| {
            matches!(r.result(), ResolveInvocationArtifactResult::Resolved(r)
            if self.registry.lookup(&r.normalized_command_name).profile.is_some_and(|p|
                p.configuration_files.as_ref().is_some_and(|contract|
                    contract.syntax == ConfigurationSyntax::Apt || r.bound.applied_modifiers.iter().any(|id| id.as_str() == contract.modifier))))
        }) && !inputs_by_node.values().flatten().any(|input| {
            matches!(
                input.status,
                ToolConfigInputStatus::Unknown | ToolConfigInputStatus::Opaque
            )
        }) {
            return;
        }
        let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
        let writes = possible_writes(ctx, &records, &mut namespace);
        let namespace_writes = possible_namespace_writes(ctx, &records, &mut namespace);
        let mut updates = Vec::new();
        let mut remaining_requests: usize = 128;
        let mut remaining_bytes: usize = 1_048_576;
        for record in &records {
            let ResolveInvocationArtifactResult::Resolved(original) = record.result() else {
                continue;
            };
            let Some(profile) = self
                .registry
                .lookup(&original.normalized_command_name)
                .profile
            else {
                continue;
            };
            let Some(contract) = &profile.configuration_files else {
                continue;
            };
            let inputs = inputs_by_node
                .get(record.source_node_id().0.as_str())
                .into_iter()
                .flatten()
                .copied()
                .filter(|input| contract.implicit_search.as_deref() == Some(&input.input_id))
                .collect::<Vec<_>>();
            let explicit = original
                .bound
                .applied_modifiers
                .iter()
                .any(|id| id.as_str() == contract.modifier);
            let is_apt = contract.syntax == ConfigurationSyntax::Apt;
            if !is_apt
                && !explicit
                && inputs.iter().all(|input| {
                    matches!(
                        input.status,
                        ToolConfigInputStatus::Absent | ToolConfigInputStatus::Disabled
                    )
                })
            {
                continue;
            }
            let Some(command) = record.command() else {
                continue;
            };
            let cwds = record.cwd_options(&ctx.request().shell_state_before.cwd);
            let cwd = (cwds.len() == 1 && !record.static_input_cwd_unproven())
                .then(|| cwds[0])
                .flatten();
            // A native loader reads before its own operation, but after shell redirects.
            // Other execution units still invalidate config/content namespace facts.
            let apt_writes;
            let apt_namespace_writes;
            let (input_writes, input_namespace_writes) = if is_apt {
                apt_writes = possible_writes_excluding_effects(
                    ctx,
                    &records,
                    &mut namespace,
                    record.source_node_id(),
                    true,
                );
                apt_namespace_writes = possible_writes_excluding_effects(
                    ctx,
                    &records,
                    &mut namespace,
                    record.source_node_id(),
                    false,
                );
                (&apt_writes, &apt_namespace_writes)
            } else {
                (&writes, &namespace_writes)
            };
            let static_content =
                |path: &str| known_content(session, ctx, &self.registry, *record, &records, path);
            let mut expansion = Expansion {
                profile,
                view: ctx.filesystem_view(),
                cwd,
                writes: input_writes,
                namespace_writes: input_namespace_writes,
                static_content: &static_content,
                stack: Vec::new(),
                paths: Vec::new(),
                bytes: 0,
                requests: 0,
                request_limit: remaining_requests.min(32),
                byte_limit: remaining_bytes.min(262_144),
                tokens: Vec::new(),
                evidence: ToolConfigParseEvidence {
                    node_id: record.source_node_id().0.clone(),
                    command: original.normalized_command_name.clone(),
                    complete: false,
                    files: Vec::new(),
                    directories: Vec::new(),
                    namespace_observations: Vec::new(),
                    options: Vec::new(),
                    errors: Vec::new(),
                },
            };
            let apt_result = if is_apt {
                Some(apt::resolve(&mut expansion, *record))
            } else {
                None
            };
            if !is_apt
                && let Some(search) = contract
                    .implicit_search
                    .as_deref()
                    .and_then(|id| profile.implicit_config_files.iter().find(|i| i.id == id))
            {
                if inputs.is_empty() {
                    expansion.error("implicit configuration discovery is unavailable");
                    expansion.paths.push(None);
                } else if !inputs
                    .iter()
                    .any(|i| i.status == ToolConfigInputStatus::Disabled)
                {
                    for (index, source) in search.sources.iter().enumerate() {
                        let candidates = inputs
                            .iter()
                            .filter(|i| i.source_index == index)
                            .collect::<Vec<_>>();
                        if !candidates.is_empty()
                            && candidates
                                .iter()
                                .all(|i| i.status == ToolConfigInputStatus::Absent)
                        {
                            continue;
                        }
                        if candidates.len() != 1 {
                            expansion
                                .error("implicit configuration source is not uniquely resolved");
                            expansion.paths.push(None);
                            break;
                        }
                        let candidate = candidates[0];
                        if matches!(
                            source,
                            ImplicitConfigSource::EnvironmentDirectory {
                                selection_requires_version: true,
                                ..
                            }
                        ) {
                            expansion.error(
                                "implicit configuration selection requires tool-version evidence",
                            );
                            expansion.paths.push(candidate.resolved_path.clone());
                            break;
                        }
                        let Some(path) = candidate.path.as_deref() else {
                            expansion.error("implicit configuration path is unknown");
                            expansion.paths.push(None);
                            break;
                        };
                        if expansion.file(path, &command.span, 0, true) != InputOutcome::Missing {
                            break;
                        }
                    }
                }
            }
            let invocation = &original.materialized_projection.invocation;
            let argv = invocation
                .args
                .iter()
                .map(|arg| argument_structure(arg).exact_value().map(str::to_owned))
                .collect::<Option<Vec<_>>>();
            let ownership = root_option_ownership(profile, invocation);
            let result = if let Some(result) = apt_result {
                result
            } else if let (Some(argv), Some(ownership)) = (argv, ownership)
                && !ownership.ownership_unresolved
                && ownership.error.is_none()
                && !original.materialized_projection.shell_expansion_unresolved
            {
                let flags = profile
                    .modifiers
                    .iter()
                    .find(|m| m.id.as_str() == contract.modifier)
                    .map(|m| m.matcher.flag_names())
                    .unwrap_or_default();
                let mut index = 0;
                while index < argv.len() {
                    let flag = ownership
                        .flags
                        .iter()
                        .find(|(i, f)| *i == index && flags.contains(f));
                    let span = &invocation.args[index].span;
                    if let Some((_, flag)) = flag {
                        let word = &argv[index];
                        let mut attached = None;
                        if flag.as_str().starts_with("--") {
                            attached = word
                                .strip_prefix(&format!("{}=", flag.as_str()))
                                .map(str::to_owned);
                        } else if flag.as_str().len() == 2 {
                            let letter = flag.as_str().as_bytes()[1] as char;
                            if let Some(position) = word[1..].find(letter).map(|i| i + 1) {
                                if position > 1 {
                                    expansion.push(&word[..position], span);
                                }
                                if position + 1 < word.len() {
                                    attached = Some(word[position + 1..].into());
                                }
                            }
                        }
                        let path = attached.or_else(|| {
                            index += 1;
                            argv.get(index).cloned()
                        });
                        if let Some(path) = path {
                            expansion.file(&path, span, 0, false);
                        } else {
                            expansion.error("configuration option has no filename");
                        }
                    } else {
                        expansion.push(&argv[index], span);
                    }
                    index += 1;
                }
                let mut effective = command.clone();
                effective.command_name = Some(original.normalized_command_name.clone());
                effective.command_name_runtime_data = true;
                effective.tokens = std::mem::take(&mut expansion.tokens);
                let runtime = InvocationRuntimeContext {
                    shell_kind: invocation.shell_kind,
                    stdin_payload_available: invocation.stdin_payload_available,
                    interactive_session: invocation.interactive_session,
                };
                let mut result = resolve_invocation_artifact_with_bindings(
                    &self.registry,
                    &effective,
                    runtime,
                    record.bindings(),
                );
                if let Some(bound) = bound_mut(&mut result) {
                    let independent = original.bound.operation_semantics_unresolved
                        && (!original
                            .bound
                            .residuals
                            .iter()
                            .any(|r| r.kind == ResidualKind::ConfigurationInput)
                            || original
                                .bound
                                .residuals
                                .iter()
                                .any(|r| r.kind != ResidualKind::ConfigurationInput));
                    bound.operation_semantics_unresolved |= independent;
                    for residual in &original.bound.residuals {
                        if residual.kind != ResidualKind::ConfigurationInput
                            && !bound.residuals.contains(residual)
                        {
                            bound.residuals.push(residual.clone());
                        }
                    }
                }
                result
            } else {
                expansion.error("configuration argv ownership or bytes are unresolved");
                record.result().clone()
            };
            let mut result = result;
            if let Some(bound) = bound_mut(&mut result) {
                for path in &expansion.paths {
                    attach_file_effects(bound, path.clone());
                }
                if !expansion.evidence.errors.is_empty() {
                    mark_configuration_pending(bound, "configuration input is incomplete");
                }
            }
            expansion.evidence.complete = expansion.evidence.errors.is_empty();
            remaining_requests = remaining_requests.saturating_sub(expansion.requests);
            remaining_bytes = remaining_bytes.saturating_sub(expansion.bytes);
            updates.push((record.source_node_id().clone(), result, expansion.evidence));
        }
        for (node, result, evidence) in updates {
            if let Some(target) = ctx.execution_result_mut(&node) {
                *target = result;
            }
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: if evidence.complete {
                    "configuration options resolved"
                } else {
                    "configuration input incomplete"
                }
                .into(),
                kind: EvidenceKind::ToolConfigParse(evidence),
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputOutcome {
    Loaded,
    Missing,
    Unknown,
}

struct Expansion<'a> {
    profile: &'a CommandProfile,
    view: Arc<dyn FilesystemView>,
    cwd: Option<&'a str>,
    writes: &'a BTreeSet<Option<String>>,
    namespace_writes: &'a BTreeSet<Option<String>>,
    static_content: &'a dyn Fn(&str) -> StaticFileContent,
    stack: Vec<String>,
    paths: Vec<Option<String>>,
    bytes: usize,
    requests: usize,
    request_limit: usize,
    byte_limit: usize,
    tokens: Vec<CommandToken>,
    evidence: ToolConfigParseEvidence,
}

impl Expansion<'_> {
    fn error(&mut self, detail: impl Into<String>) {
        if self.evidence.errors.len() < 64 {
            self.evidence.errors.push(detail.into());
        }
    }

    fn push(&mut self, text: &str, span: &SourceSpan) {
        if self.tokens.len() >= 8192 {
            self.error("effective argv budget exceeded");
            return;
        }
        self.tokens.push(CommandToken {
            text: text.into(),
            implicit_input_source: None,
            runtime_argument_domain: None,
            runtime_data: true,
            quoted: false,
            node_kind: "runtime_word".into(),
            kind: if text == "--" {
                CommandTokenKind::DashDash
            } else if text.starts_with('-') {
                CommandTokenKind::Flag
            } else {
                CommandTokenKind::Arg
            },
            span: span.clone(),
            command_substitutions: Vec::new(),
        });
    }

    fn file(
        &mut self,
        name: &str,
        span: &SourceSpan,
        depth: usize,
        missing_ok: bool,
    ) -> InputOutcome {
        self.requests += 1;
        if name == "-"
            || depth >= 8
            || self.requests > self.request_limit
            || self.bytes >= self.byte_limit
        {
            self.error("configuration input is stdin or exceeds the expansion budget");
            self.paths.push(None);
            return InputOutcome::Unknown;
        }
        let path = if name.starts_with('/') {
            Some(name.into())
        } else {
            self.cwd
                .map(|cwd| format!("{}/{name}", cwd.trim_end_matches('/')))
        };
        let Some(path) = path else {
            self.error("configuration working directory is not uniquely known");
            self.paths.push(None);
            return InputOutcome::Unknown;
        };
        let (read, concrete) = self.read(&path);
        let bytes = read
            .complete_bytes(&concrete, MAX_FILE_CONTENT_BYTES)
            .map(<[u8]>::to_vec);
        let status = read.observation.status;
        self.evidence.files.push(read.observation);
        if status == FileContentStatus::Missing && missing_ok {
            return InputOutcome::Missing;
        }
        self.paths.push(Some(concrete.clone()));
        let Some(bytes) = bytes else {
            self.error(format!(
                "configuration content observation is {status:?}: {path}"
            ));
            return InputOutcome::Unknown;
        };
        self.bytes += bytes.len();
        if self.bytes > self.byte_limit || self.stack.contains(&concrete) {
            self.error("configuration expansion is cyclic or exceeds its byte budget");
            return InputOutcome::Unknown;
        }
        self.stack.push(concrete.clone());
        let parsed = parse_configuration(self.profile, &bytes);
        for error in parsed.errors {
            self.error(format!("{path}:{}: {}", error.line, error.detail));
        }
        for option in parsed.options {
            if self.evidence.options.len() >= 2048 {
                self.error("configuration option budget exceeded");
                break;
            }
            self.evidence.options.push(ToolConfigOptionEvidence {
                path: concrete.clone(),
                line: option.line,
                order: self.evidence.options.len(),
                option: option.option.clone(),
                argument_sha256: option
                    .argument
                    .as_ref()
                    .map(|v| content_sha256(v.as_bytes())),
            });
            let contract = self.profile.configuration_files.as_ref().unwrap();
            let nested = self
                .profile
                .modifiers
                .iter()
                .find(|m| m.id.as_str() == contract.modifier)
                .is_some_and(|m| {
                    m.matcher
                        .flag_names()
                        .iter()
                        .any(|f| f.as_str() == option.option)
                });
            if nested {
                if let Some(path) = option.argument {
                    self.file(&path, span, depth + 1, false);
                } else {
                    self.error("nested configuration filename is missing");
                }
            } else {
                self.push(&option.option, span);
                if let Some(argument) = option.argument {
                    self.push(&argument, span);
                }
            }
        }
        self.stack.pop();
        InputOutcome::Loaded
    }

    fn read(&mut self, path: &str) -> (FileContentRead, String) {
        let mut namespace = NamespaceResolver::new(self.view.clone());
        let (resolution, observations) = namespace.resolve(path, PathTargetAccess::Follow);
        let concrete = match &resolution {
            caushell_types::SemanticResolution::Resolved { value } => {
                value.concrete_path().map(str::to_owned)
            }
            _ => None,
        };
        self.evidence
            .namespace_observations
            .extend(observations.clone());
        let Some(concrete) = concrete else {
            return (
                failed(path, "configuration namespace is unresolved"),
                path.into(),
            );
        };
        if touches(self.namespace_writes, path) || touches(self.namespace_writes, &concrete) {
            return (
                failed(
                    &concrete,
                    "configuration namespace may change within this action",
                ),
                concrete,
            );
        }
        let content = (self.static_content)(&concrete);
        let read = match content {
            StaticFileContent::Known(content) => FileContentRead::complete(
                FileContentSource::Graph,
                &concrete,
                MAX_FILE_CONTENT_BYTES,
                None,
                content.into_bytes(),
            ),
            _ if touches(self.writes, path) || touches(self.writes, &concrete) => failed(
                &concrete,
                "configuration content may change within this action",
            ),
            _ => self.view.read_file(&concrete, MAX_FILE_CONTENT_BYTES),
        };
        if read.observation.status == FileContentStatus::Missing
            && observations
                .iter()
                .any(|o| o.path == concrete && o.entry == caushell_types::FilesystemEntry::File)
        {
            return (
                failed(&concrete, "configuration existence observations disagree"),
                concrete,
            );
        }
        let mut after = NamespaceResolver::new(self.view.clone());
        let (after_resolution, after_observations) = after.resolve(path, PathTargetAccess::Follow);
        if after_resolution != resolution || after_observations != observations {
            return (
                failed(
                    &concrete,
                    "configuration namespace changed during observation",
                ),
                concrete,
            );
        }
        (read, concrete)
    }
}

fn failed(path: &str, detail: &str) -> FileContentRead {
    FileContentRead::failed(
        FileContentSource::Unavailable,
        path,
        MAX_FILE_CONTENT_BYTES,
        FileContentStatus::Changed,
        detail,
    )
}

fn touches(writes: &BTreeSet<Option<String>>, path: &str) -> bool {
    writes.contains(&None)
        || writes.iter().flatten().any(|write| {
            write == path
                || path
                    .strip_prefix(write.trim_end_matches('/'))
                    .is_some_and(|s| s.starts_with('/'))
                || write
                    .strip_prefix(path.trim_end_matches('/'))
                    .is_some_and(|s| s.starts_with('/'))
        })
}

fn bound_mut(result: &mut ResolveInvocationArtifactResult) -> Option<&mut BoundInvocation> {
    match result {
        ResolveInvocationArtifactResult::Resolved(r) => Some(&mut r.bound),
        ResolveInvocationArtifactResult::SelectionError { partial_bound, .. } => {
            partial_bound.as_mut()
        }
        _ => None,
    }
}

fn attach_file_effects(bound: &mut BoundInvocation, path: Option<String>) {
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
        default_value: path,
        fallback_parent_slots: Vec::new(),
        fallback_parent_suffix: None,
        purpose: Some(PathPurpose::ToolConfig),
    });
    for kind in [EffectKind::ReadPath, EffectKind::LoadConfig] {
        let mut effect = Effect::new(kind);
        effect.target = target.clone();
        if !bound.effects.contains(&effect) {
            bound.effects.push(effect);
        }
    }
}

pub(super) fn known_content(
    session: SessionView<'_>,
    ctx: &RunnerContext,
    registry: &ProfileRegistry,
    record: ExecutionResolveRecordRef<'_>,
    records: &[ExecutionResolveRecordRef<'_>],
    path: &str,
) -> StaticFileContent {
    if record.command_index() > 256 || record.static_input_cwd_unproven() {
        return StaticFileContent::Unknown;
    }
    let mut observations = Vec::new();
    let mut cwds = Vec::new();
    for command in record
        .parsed_scope()
        .commands
        .iter()
        .take(record.command_index())
    {
        let matching = records
            .iter()
            .filter(|r| {
                r.parsed_scope() == record.parsed_scope()
                    && r.variable_frame() == record.variable_frame()
                    && r.command().is_some_and(|c| c.span == command.span)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return StaticFileContent::Unknown;
        }
        let prior = matching[0];
        observations.push((prior.result().clone(), prior.bindings().clone()));
        cwds.push(
            ctx.execution_cwd_for_node(prior.source_node_id())
                .cloned()
                .unwrap_or(EffectiveCwd::Unknown),
        );
    }
    static_file_content_before_scoped_command(
        QuerySession::new(session.graph(), session.summary()),
        registry,
        ctx.request(),
        record.parsed_scope(),
        record.command_index(),
        path,
        &observations,
        &cwds,
        None,
    )
}
