use std::path::{Component, Path};

use caushell_profile::{
    CommandProfile, EnvironmentValueRef, ImplicitConfigFile, ImplicitConfigSource, ProfileRegistry,
    ProfileSourceKind, ProtectedAccountDefaults, StaticOptionEnvironmentDefault,
};
use caushell_runner::RunnerContext;
use caushell_types::{
    CheckRequest, DEFAULT_TEMPORARY_PATH_ROOTS, Evidence, EvidenceKind, FilesystemObservation,
    PathResolution, PathTargetAccess, RuleId, SemanticResolution, SessionSummary,
    ShellEnvironmentSnapshot, ShellEnvironmentValue, ShellKind, ShellRuntimeCapabilities,
    ShellStateKnowledge, ToolConfigInputEvidence, ToolConfigInputStatus,
};

use crate::path::namespace::NamespaceResolver;
use crate::support::ExecutionEnvironment;

pub(super) fn seed_option_environment_defaults(
    registry: &ProfileRegistry,
    summary: &SessionSummary,
    ctx: &mut RunnerContext,
    request: &mut CheckRequest,
) {
    let state = &mut request.shell_state_before;
    if !ctx.assumes_protected_defaults()
        || request.shell_kind != ShellKind::Bash
        || request.runtime.shell_runtime_capabilities != ShellRuntimeCapabilities::request_only()
        || state.observability.variables != ShellStateKnowledge::Unknown
        || summary.shell_state_uncertainty().is_some()
    {
        return;
    }

    let direct = ctx.parsed_command().and_then(|parsed| {
        let [command] = parsed.commands.as_slice() else {
            return None;
        };
        if request.sequence_no != caushell_types::CommandSequenceNo(1)
            || summary.last_sequence_no().is_some()
            || parsed.status != caushell_parse::ParseStatus::Complete
            || command.command_name_runtime_data
            || command.shell_scope_span.is_some()
            || command.text.trim() != parsed.raw_command.trim()
        {
            return None;
        }
        let name = command.command_name.as_deref()?;
        registry.lookup(name).profile.map(CommandProfile::primary_name)
    });
    for profile in registry.profiles() {
        if profile.trust.source != ProfileSourceKind::BuiltIn {
            continue;
        }
        let Some(input) = &profile.option_environment else {
            continue;
        };
        match input.static_default {
            Some(StaticOptionEnvironmentDefault::Absent) => {}
            Some(StaticOptionEnvironmentDefault::AbsentForDirectInvocation)
                if direct == Some(profile.primary_name()) => {}
            _ => continue,
        }
        for name in input.names() {
            if summary.variable_binding(name).is_some()
                || state.environment.iter().any(|entry| entry.name == name)
                || state.variables.iter().any(|entry| entry.name == name)
            {
                continue;
            }
            // The entry assumption belongs to the private binding view.
            // Request-local assignments and observed state take precedence.
            state.environment.push(ShellEnvironmentSnapshot {
                name: name.into(),
                value: ShellEnvironmentValue::Absent,
            });
            ctx.add_evidence(Evidence {
                rule_id: RuleId::SelectionError,
                summary: format!("offline entry model assumes no inherited {name}"),
                kind: EvidenceKind::StaticOptionEnvironmentDefault { name: name.into() },
            });
        }
    }
}

pub(super) fn registered_defaults<'a>(
    profile: &CommandProfile,
    input: &'a ImplicitConfigFile,
) -> Option<&'a ProtectedAccountDefaults> {
    if profile.trust.source == ProfileSourceKind::BuiltIn {
        input.protected_account_defaults.as_ref()
    } else {
        None
    }
}

pub(super) struct ConfigurationPath {
    source_index: usize,
    spelling: String,
    resolved: String,
    observations: Vec<FilesystemObservation>,
}

impl ConfigurationPath {
    pub(super) fn evidence(
        self,
        node_id: String,
        command: &str,
        input_id: &str,
        detail: &str,
    ) -> ToolConfigInputEvidence {
        ToolConfigInputEvidence {
            node_id,
            command: command.into(),
            input_id: input_id.into(),
            source_index: self.source_index,
            source: "static_environment_model".into(),
            path: Some(self.spelling),
            resolved_path: Some(self.resolved),
            status: ToolConfigInputStatus::AssumedProtected,
            observations: self.observations,
            detail: detail.into(),
        }
    }
}

/// Derive the account-home candidates from a declared implicit search. An
/// alternate search location reported by the request stays with native parsing.
pub(super) fn search_account_defaults<'a>(
    ctx: &RunnerContext,
    environment: &ExecutionEnvironment,
    sources: &'a [ImplicitConfigSource],
) -> Option<Vec<(usize, &'a str)>> {
    let mut suffixes = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        match source {
            ImplicitConfigSource::AccountHome { suffix } => {
                suffixes.push((index, suffix.as_str()));
            }
            ImplicitConfigSource::EnvironmentDirectory {
                name,
                suffix,
                unless_environment_set,
                ..
            } => {
                if let Some(selector) = unless_environment_set {
                    if !unobserved_selector(ctx, environment, selector) {
                        return None;
                    }
                }
                if name == "HOME" {
                    suffixes.push((index, suffix.as_str()));
                } else if !unobserved_selector(ctx, environment, name) {
                    return None;
                }
            }
        }
    }
    Some(suffixes)
}

pub(super) fn protected_account_defaults<'a>(
    ctx: &RunnerContext,
    environment: &ExecutionEnvironment,
    namespace: &mut NamespaceResolver,
    suffixes: impl IntoIterator<Item = (usize, &'a str)>,
) -> Option<Vec<ConfigurationPath>> {
    let request = ctx.request();
    if !ctx.assumes_protected_defaults() || request.shell_kind != ShellKind::Bash {
        return None;
    }
    let home = request.home.as_deref()?;
    let workspace = request.workspace_root.as_deref()?;
    if !clean_absolute(home) || !clean_absolute(workspace) {
        return None;
    }
    match environment.scalar("HOME") {
        Ok(Some(value)) if value == home => (),
        Err(_) if unobserved_selector(ctx, environment, "HOME") => (),
        _ => return None,
    }

    let boundary = ConfigurationBoundary::new(ctx, namespace)?;
    let mut paths = Vec::new();
    for (source_index, suffix) in suffixes {
        let spelling = Path::new(home).join(suffix);
        let spelling = spelling.to_str()?;
        let location = boundary.resolve(namespace, spelling, source_index)?;
        if location.writable {
            return None;
        }
        paths.push(location.path);
    }
    (!paths.is_empty()).then_some(paths)
}

struct ConfigurationBoundary {
    roots: Vec<String>,
    observations: Vec<FilesystemObservation>,
}

struct ConfigurationLocation {
    path: ConfigurationPath,
    writable: bool,
}

impl ConfigurationBoundary {
    fn new(ctx: &RunnerContext, namespace: &mut NamespaceResolver) -> Option<Self> {
        let workspace = ctx.request().workspace_root.as_deref()?;
        if !clean_absolute(workspace) {
            return None;
        }
        let writable = std::iter::once(workspace)
            .chain(DEFAULT_TEMPORARY_PATH_ROOTS.iter().copied())
            .chain(
                ctx.policy()
                    .mutation_path_exemptions
                    .iter()
                    .map(|entry| entry.root.as_str()),
            );
        let mut roots = Vec::new();
        let mut observations = Vec::new();
        for root in writable {
            let (SemanticResolution::Resolved { value }, observed) =
                namespace.resolve(root, PathTargetAccess::Follow)
            else {
                return None;
            };
            roots.extend([root.to_owned(), value.concrete_path()?.to_owned()]);
            observations.extend(observed);
        }
        Some(Self {
            roots,
            observations,
        })
    }

    fn resolve(
        &self,
        namespace: &mut NamespaceResolver,
        spelling: &str,
        source_index: usize,
    ) -> Option<ConfigurationLocation> {
        let (SemanticResolution::Resolved { value }, mut observations) =
            namespace.resolve(spelling, PathTargetAccess::Follow)
        else {
            return None;
        };
        let resolved = value.concrete_path()?;
        let writable = self.roots.iter().any(|root| {
            Path::new(spelling).starts_with(root)
                || Path::new(resolved).starts_with(root)
                || observations
                    .iter()
                    .any(|entry| Path::new(&entry.path).starts_with(root))
        });
        observations.extend(self.observations.iter().cloned());
        observations.sort_by(|a, b| a.path.cmp(&b.path));
        observations.dedup();
        Some(ConfigurationLocation {
            path: ConfigurationPath {
                source_index,
                spelling: spelling.into(),
                resolved: resolved.into(),
                observations,
            },
            writable,
        })
    }
}

/// Record the boundary for every reached native configuration file. A
/// protected location does not settle unresolved selection or include chains.
pub(super) fn record_native_config_locations(
    ctx: &mut RunnerContext,
    node_id: &str,
    command: &str,
    sources: Vec<(String, PathResolution)>,
) {
    if sources.is_empty() {
        return;
    }
    let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
    let boundary = ConfigurationBoundary::new(ctx, &mut namespace);
    for (source_index, (source, path)) in sources.into_iter().enumerate() {
        let location = path.concrete_path().and_then(|spelling| {
            boundary
                .as_ref()?
                .resolve(&mut namespace, spelling, source_index)
        });
        let (status, resolved_path, observations, detail) = match location {
            Some(location) => (
                if location.writable {
                    ToolConfigInputStatus::WritableLocation
                } else {
                    ToolConfigInputStatus::ProtectedLocation
                },
                Some(location.path.resolved),
                location.path.observations,
                "native configuration file location classified",
            ),
            None => (
                ToolConfigInputStatus::UnresolvedLocation,
                None,
                Vec::new(),
                "native configuration file location unresolved",
            ),
        };
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: detail.into(),
            kind: EvidenceKind::ToolConfigInput(ToolConfigInputEvidence {
                node_id: node_id.into(),
                command: command.into(),
                input_id: "native_configuration".into(),
                source_index,
                source,
                path: path.concrete_path().map(str::to_owned),
                resolved_path,
                status,
                observations,
                detail: detail.into(),
            }),
        });
    }
}

fn clean_absolute(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && !Path::new(path)
            .components()
            .any(|part| part == Component::ParentDir)
}

fn unobserved_selector(
    ctx: &RunnerContext,
    environment: &ExecutionEnvironment,
    name: &str,
) -> bool {
    let state = &ctx.request().shell_state_before;
    matches!(environment.value(name), EnvironmentValueRef::Unknown)
        && !state.environment.iter().any(|entry| entry.name == name)
        && !state.variables.iter().any(|entry| entry.name == name)
}
