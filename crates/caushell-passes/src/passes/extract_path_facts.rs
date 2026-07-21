use std::fs;

use caushell_graph::EdgeKind;
use caushell_profile::{
    EffectKind, EffectTarget, PathPurpose, PathRole, ResolveInvocationArtifactResult,
};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    DerivedPathBasis, DerivedPathRule, PathResolution, ResolvedPathPurpose, ResolvedPathRole,
    ShellValueSnapshot,
};

use crate::path::{
    collect_mutation_scope_facts, collect_path_facts, collect_redirection_path_facts,
    edge_kind_for_mutation_scope_operation, edge_kind_for_path_role, mutation_scope_fact_node_id,
    path_fact_node_id, provenance_artifact_for_path, provenance_edge_for_path_fact,
    provenance_path_artifact_node_id, resolved_path_purpose_for_profile_purpose,
    resolved_path_role_for_profile_role,
};
use crate::path::{join_shell_path, normalize_shell_path};
use crate::support::{
    ExecutionResolveRecordRef, graph_backed_execution_resolve_records,
    redirection_parent_command_index, source_node_id_for_redirection,
};

pub struct ExtractPathFactsPass;

impl SessionTransformPass for ExtractPathFactsPass {
    fn name(&self) -> &'static str {
        "extract_path_facts"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let cwd = ctx.request().shell_state_before.cwd.clone();
        let home = ctx.request().home.clone();
        let records = graph_backed_execution_resolve_records(ctx);
        let mut mutations = collect_resolved_path_mutations(&records, &cwd, home.as_deref());
        mutations.extend(collect_mutation_scope_mutations(
            &records,
            &cwd,
            home.as_deref(),
        ));

        mutations.extend(collect_redirection_path_mutations(
            ctx,
            &records,
            &cwd,
            home.as_deref(),
        ));

        mutations.extend(collect_git_hook_path_mutations(
            ctx.request(),
            &records,
            &cwd,
        ));

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_mutation_scope_mutations(
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<PendingMutation> {
    collect_mutation_scope_facts(records, cwd, home)
        .into_iter()
        .map(|scope| {
            let node_id = mutation_scope_fact_node_id(
                &scope.source_node_id,
                scope.command_index,
                scope.effect_index,
                &scope.slot_name,
                &scope.resolution,
                scope.operation,
            );
            let relation = edge_kind_for_mutation_scope_operation(scope.operation);

            PendingMutation::AddMutationScopeFact {
                source_node_id: scope.source_node_id,
                node_id,
                resolution: scope.resolution,
                operation: scope.operation,
                slot_name: scope.slot_name,
                normalized_command_name: Some(scope.normalized_command_name),
                relation,
            }
        })
        .collect()
}

fn collect_resolved_path_mutations(
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<PendingMutation> {
    collect_path_facts(records, cwd, home)
        .into_iter()
        .flat_map(|path| {
            let source_node_id = path.source_node_id;
            let resolution = path.resolution;
            let slot_name = path.slot_name;
            let normalized_command_name = path.normalized_command_name;
            let purpose = path.purpose.map(resolved_path_purpose_for_profile_purpose);
            let node_id =
                path_fact_node_id(&source_node_id, path.command_index, &slot_name, &resolution);
            let relation = edge_kind_for_path_role(path.role);
            let mut mutations = vec![match path.metadata_mutation {
                Some(metadata_mutation) => PendingMutation::AddPathMetadataMutationFact {
                    node_id,
                    source_node_id: source_node_id.clone(),
                    resolution: resolution.clone(),
                    purpose,
                    slot_name: slot_name.clone(),
                    normalized_command_name: Some(normalized_command_name.clone()),
                    metadata_mutation,
                    relation,
                },
                None => PendingMutation::AddPathFact {
                    node_id,
                    source_node_id: source_node_id.clone(),
                    resolution: resolution.clone(),
                    role: resolved_path_role_for_profile_role(path.role),
                    purpose,
                    slot_name: slot_name.clone(),
                    normalized_command_name: Some(normalized_command_name.clone()),
                    relation,
                },
            }];

            if let Some(path_string) = resolution.concrete_path() {
                if let Some((relation, semantics)) = provenance_edge_for_path_fact(
                    path.role,
                    path.purpose,
                    &slot_name,
                    Some(normalized_command_name.as_str()),
                ) {
                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id,
                        node_id: provenance_path_artifact_node_id(path_string),
                        artifact: provenance_artifact_for_path(path_string),
                        relation,
                        semantics,
                    });
                }
            }

            mutations
        })
        .collect()
}

fn collect_redirection_path_mutations(
    ctx: &RunnerContext,
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for record in records {
        let parsed_scope = record.parsed_scope();

        for path in collect_redirection_path_facts(parsed_scope, cwd, home) {
            if redirection_parent_command_index(parsed_scope, &path.fact)
                != Some(record.command_index())
            {
                continue;
            }

            mutations.extend(project_redirection_path_mutations(
                record.source_node_id().clone(),
                path.redirection_index,
                path.slot_name,
                path.resolution,
                path.role,
            ));
        }
    }

    // Bare top-level redirections do not have a resolved execution record, so they remain a
    // direct top-level parse projection.
    if let Some(parsed_command) = ctx.parsed_command() {
        for path in collect_redirection_path_facts(parsed_command, cwd, home) {
            if redirection_parent_command_index(parsed_command, &path.fact).is_some() {
                continue;
            }

            let source_node_id =
                source_node_id_for_redirection(ctx.request(), parsed_command, &path.fact);
            mutations.extend(project_redirection_path_mutations(
                source_node_id,
                path.redirection_index,
                path.slot_name,
                path.resolution,
                path.role,
            ));
        }
    }

    mutations
}

fn project_redirection_path_mutations(
    source_node_id: caushell_graph::NodeId,
    redirection_index: usize,
    slot_name: String,
    resolution: PathResolution,
    role: PathRole,
) -> Vec<PendingMutation> {
    let mut mutations = vec![PendingMutation::AddPathFact {
        source_node_id: source_node_id.clone(),
        node_id: path_fact_node_id(&source_node_id, redirection_index, &slot_name, &resolution),
        resolution: resolution.clone(),
        role: resolved_path_role_for_profile_role(role),
        purpose: None,
        slot_name: slot_name.clone(),
        normalized_command_name: None,
        relation: edge_kind_for_path_role(role),
    }];

    if let Some(path_string) = resolution.concrete_path() {
        if let Some((relation, semantics)) =
            provenance_edge_for_path_fact(role, None, &slot_name, None)
        {
            mutations.push(PendingMutation::AddProvenanceArtifact {
                source_node_id,
                node_id: provenance_path_artifact_node_id(path_string),
                artifact: provenance_artifact_for_path(path_string),
                relation,
                semantics,
            });
        }
    }

    mutations
}

fn collect_git_hook_path_mutations(
    request: &caushell_types::CheckRequest,
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        if resolved.normalized_command_name != "git" {
            continue;
        }

        let hook_kind = match resolved.bound.subcommand_path.as_slice() {
            [subcommand] if subcommand == "commit" => GitHookKind::Commit,
            [subcommand] if subcommand == "am" => GitHookKind::Am,
            _ => continue,
        };

        let effective_cwd = git_effective_cwd(cwd, &resolved.bound);

        let Some(config_path) =
            resolved
                .bound
                .effects
                .iter()
                .find_map(|effect| match &effect.target {
                    EffectTarget::ToolConventionPath(target)
                        if effect.kind == EffectKind::LoadConfig
                            && target.convention == "git.local_config" =>
                    {
                        Some(if target.path.starts_with('/') {
                            normalize_shell_path(&target.path)
                        } else {
                            join_shell_path(&effective_cwd, &target.path)
                        })
                    }
                    _ => None,
                })
        else {
            continue;
        };

        for config_fact in git_nonlocal_config_path_facts(request) {
            mutations.push(
                config_fact
                    .path_mutation(record.source_node_id(), &resolved.normalized_command_name),
            );
            mutations.push(
                config_fact.provenance_mutation(
                    record.source_node_id(),
                    &resolved.normalized_command_name,
                ),
            );
        }

        let hook_paths = resolve_git_hook_paths(
            request,
            &config_path,
            &effective_cwd,
            &resolved.bound,
            hook_kind,
        );

        for hook_path in hook_paths {
            let slot_name = git_hook_slot_name(hook_path.stage);
            let node_id = path_fact_node_id(
                record.source_node_id(),
                record.command_index(),
                &slot_name,
                &hook_path.resolution,
            );

            mutations.push(PendingMutation::AddPathFact {
                source_node_id: record.source_node_id().clone(),
                node_id,
                resolution: hook_path.resolution.clone(),
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::ScriptSource),
                slot_name: slot_name.clone(),
                normalized_command_name: Some(resolved.normalized_command_name.clone()),
                relation: EdgeKind::Reads,
            });

            if let Some(path_string) = hook_path.resolution.concrete_path() {
                if let Some((relation, semantics)) = provenance_edge_for_path_fact(
                    PathRole::Read,
                    Some(PathPurpose::ScriptSource),
                    &slot_name,
                    Some(resolved.normalized_command_name.as_str()),
                ) {
                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id: record.source_node_id().clone(),
                        node_id: provenance_path_artifact_node_id(path_string),
                        artifact: provenance_artifact_for_path(path_string),
                        relation,
                        semantics,
                    });
                }
            }
        }
    }

    mutations
}

#[derive(Debug, Clone)]
struct GitHookPath {
    stage: &'static str,
    resolution: PathResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitHookKind {
    Commit,
    Am,
}

#[derive(Debug, Clone)]
struct GitHooksRoot {
    path: String,
    config_path: String,
    convention: String,
}

fn resolve_git_hook_paths(
    request: &caushell_types::CheckRequest,
    local_config_path: &str,
    cwd: &str,
    invocation: &caushell_profile::BoundInvocation,
    kind: GitHookKind,
) -> Vec<GitHookPath> {
    let hook_root =
        effective_git_hooks_root(request, local_config_path, cwd).unwrap_or_else(|| {
            let config_dir = parent_dir_or_cwd(local_config_path, cwd);
            GitHooksRoot {
                path: join_shell_path(&config_dir, "hooks"),
                config_path: normalize_shell_path(local_config_path),
                convention: "git.default_hooks".to_string(),
            }
        });

    git_hook_stages(invocation, kind)
        .into_iter()
        .map(|stage| GitHookPath {
            stage,
            resolution: git_hook_stage_resolution(&hook_root, stage),
        })
        .collect()
}

fn git_hook_stages(
    invocation: &caushell_profile::BoundInvocation,
    kind: GitHookKind,
) -> Vec<&'static str> {
    match kind {
        GitHookKind::Commit => {
            let mut stages = vec!["prepare-commit-msg", "post-commit"];

            if !invocation_has_modifier(invocation, "no_verify") {
                stages.insert(0, "pre-commit");
                stages.insert(2, "commit-msg");
            }

            if invocation_has_modifier(invocation, "amend")
                && !invocation_has_modifier(invocation, "no_post_rewrite")
            {
                stages.push("post-rewrite");
            }

            stages
        }
        GitHookKind::Am => {
            let mut stages = vec!["post-applypatch"];

            if !invocation_has_modifier(invocation, "no_verify") {
                stages.insert(0, "pre-applypatch");
                stages.insert(0, "applypatch-msg");
            }

            stages
        }
    }
}

fn effective_git_hooks_root(
    request: &caushell_types::CheckRequest,
    local_config_path: &str,
    cwd: &str,
) -> Option<GitHooksRoot> {
    let repo_root = git_repo_root_from_local_config(local_config_path, cwd);
    let mut root = None;

    for source in git_config_sources(request, local_config_path) {
        if let Some(hooks_path) = load_git_hooks_path(&source.path) {
            root = Some(GitHooksRoot {
                path: resolve_git_hooks_root_path(&hooks_path, &repo_root),
                config_path: source.path,
                convention: source.convention.to_string(),
            });
        }
    }

    root
}

#[derive(Debug, Clone)]
struct GitConfigSource {
    path: String,
    convention: &'static str,
    slot_name: &'static str,
}

fn git_config_sources(
    request: &caushell_types::CheckRequest,
    local_config_path: &str,
) -> Vec<GitConfigSource> {
    let mut sources = git_nonlocal_config_sources(request);

    sources.push(GitConfigSource {
        path: normalize_shell_path(local_config_path),
        convention: "git.local_config",
        slot_name: "git_local_config",
    });

    sources
}

fn git_nonlocal_config_sources(request: &caushell_types::CheckRequest) -> Vec<GitConfigSource> {
    let mut sources = Vec::new();

    if let Some(path) = git_system_config_path(request) {
        sources.push(GitConfigSource {
            path,
            convention: "git.system_config",
            slot_name: "git_system_config",
        });
    }

    sources.extend(git_global_config_sources(request));
    sources
}

fn git_system_config_path(request: &caushell_types::CheckRequest) -> Option<String> {
    exported_exact_scalar(request, "GIT_CONFIG_SYSTEM")
        .filter(|value| !value.is_empty())
        .map(|value| normalize_shell_path(&value))
        .or_else(|| {
            Some("/etc/gitconfig".to_string()).filter(|path| std::path::Path::new(path).exists())
        })
}

fn git_global_config_sources(request: &caushell_types::CheckRequest) -> Vec<GitConfigSource> {
    if let Some(path) = exported_exact_scalar(request, "GIT_CONFIG_GLOBAL") {
        return vec![GitConfigSource {
            path: normalize_shell_path(&path),
            convention: "git.global_config",
            slot_name: "git_global_config_env",
        }];
    }

    let mut paths = Vec::new();

    if let Some(xdg_config_home) = exported_exact_scalar(request, "XDG_CONFIG_HOME") {
        paths.push(GitConfigSource {
            path: join_shell_path(&xdg_config_home, "git/config"),
            convention: "git.global_config",
            slot_name: "git_global_config_xdg",
        });
    } else if let Some(home) = request.home.as_deref() {
        paths.push(GitConfigSource {
            path: join_shell_path(home, ".config/git/config"),
            convention: "git.global_config",
            slot_name: "git_global_config_xdg",
        });
    }

    if let Some(home) = request.home.as_deref() {
        paths.push(GitConfigSource {
            path: join_shell_path(home, ".gitconfig"),
            convention: "git.global_config",
            slot_name: "git_global_config_home",
        });
    }

    paths
}

fn exported_exact_scalar(request: &caushell_types::CheckRequest, name: &str) -> Option<String> {
    let binding = request.shell_state_before.exported_variable(name)?;
    match &binding.value {
        ShellValueSnapshot::ExactScalar { value }
        | ShellValueSnapshot::RuntimeProduced { value, .. } => Some(value.clone()),
        ShellValueSnapshot::OpaqueDynamic { .. } | ShellValueSnapshot::RuntimeInput { .. } => None,
    }
}

fn load_git_hooks_path(config_path: &str) -> Option<String> {
    let content = fs::read_to_string(config_path).ok()?;
    parse_git_config_hooks_path(&content)
}

fn resolve_git_hooks_root_path(hooks_path: &str, repo_root: &str) -> String {
    if hooks_path.starts_with('/') {
        normalize_shell_path(hooks_path)
    } else {
        join_shell_path(repo_root, hooks_path)
    }
}

fn git_repo_root_from_local_config(local_config_path: &str, cwd: &str) -> String {
    let git_dir = parent_dir_or_cwd(local_config_path, cwd);
    parent_dir_or_cwd(&git_dir, cwd)
}

fn parse_git_config_hooks_path(content: &str) -> Option<String> {
    let mut in_core = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            let normalized = section.split_whitespace().collect::<Vec<_>>().join(" ");
            in_core = normalized.eq_ignore_ascii_case("core");
            continue;
        }

        if !in_core {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if !key.trim().eq_ignore_ascii_case("hooksPath") {
            continue;
        }

        let value = value.trim();
        if value.is_empty() {
            return None;
        }

        return Some(strip_wrapping_quotes(value).to_string());
    }

    None
}

fn strip_wrapping_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }

    value
}

fn git_hook_stage_resolution(root: &GitHooksRoot, stage: &str) -> PathResolution {
    PathResolution::DerivedConcrete {
        path: join_shell_path(&root.path, stage),
        basis: git_hook_path_basis(root),
        rule: DerivedPathRule::ChildUnder {
            relative_path: stage.to_string(),
        },
    }
}

fn git_hook_path_basis(root: &GitHooksRoot) -> DerivedPathBasis {
    DerivedPathBasis::ConfigDerivedRoot {
        config_path: normalize_shell_path(&root.config_path),
        convention: root.convention.clone(),
        key: "core.hooksPath".to_string(),
        value: normalize_shell_path(&root.path),
    }
}

fn git_hook_slot_name(stage: &str) -> String {
    format!("git_hook_{}", stage.replace('-', "_"))
}

fn invocation_has_modifier(
    invocation: &caushell_profile::BoundInvocation,
    modifier_id: &str,
) -> bool {
    invocation
        .applied_modifiers
        .iter()
        .any(|modifier| modifier.as_str() == modifier_id)
}

#[derive(Debug, Clone)]
struct GitConfigPathFact {
    slot_name: String,
    resolution: PathResolution,
}

impl GitConfigPathFact {
    fn path_mutation(
        &self,
        source_node_id: &caushell_graph::NodeId,
        normalized_command_name: &str,
    ) -> PendingMutation {
        PendingMutation::AddPathFact {
            source_node_id: source_node_id.clone(),
            node_id: path_fact_node_id(source_node_id, 0, &self.slot_name, &self.resolution),
            resolution: self.resolution.clone(),
            role: ResolvedPathRole::Config,
            purpose: Some(ResolvedPathPurpose::ToolConfig),
            slot_name: self.slot_name.clone(),
            normalized_command_name: Some(normalized_command_name.to_string()),
            relation: EdgeKind::Reads,
        }
    }

    fn provenance_mutation(
        &self,
        source_node_id: &caushell_graph::NodeId,
        normalized_command_name: &str,
    ) -> PendingMutation {
        let path = self
            .resolution
            .concrete_path()
            .expect("git config path fact should always be concrete");
        let (relation, semantics) = provenance_edge_for_path_fact(
            PathRole::Config,
            Some(PathPurpose::ToolConfig),
            &self.slot_name,
            Some(normalized_command_name),
        )
        .expect("tool config provenance should exist");

        PendingMutation::AddProvenanceArtifact {
            source_node_id: source_node_id.clone(),
            node_id: provenance_path_artifact_node_id(path),
            artifact: provenance_artifact_for_path(path),
            relation,
            semantics,
        }
    }
}

fn git_nonlocal_config_path_facts(
    request: &caushell_types::CheckRequest,
) -> Vec<GitConfigPathFact> {
    let mut facts = Vec::new();

    for source in git_nonlocal_config_sources(request) {
        if std::path::Path::new(&source.path).exists() {
            facts.push(GitConfigPathFact {
                slot_name: source.slot_name.to_string(),
                resolution: PathResolution::Concrete { path: source.path },
            });
        }
    }

    facts
}

fn git_effective_cwd(cwd: &str, invocation: &caushell_profile::BoundInvocation) -> String {
    if !invocation_has_modifier(invocation, "work_tree") {
        return normalize_shell_path(cwd);
    }

    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == "working_directory")
        .and_then(|parameter| {
            parameter.values.iter().find_map(|value| match value {
                caushell_profile::BoundValue::Argument { text, .. } => {
                    Some(if text.starts_with('/') {
                        normalize_shell_path(text)
                    } else {
                        join_shell_path(cwd, text)
                    })
                }
                caushell_profile::BoundValue::ImplicitInput { .. } => None,
            })
        })
        .unwrap_or_else(|| normalize_shell_path(cwd))
}

fn parent_dir_or_cwd(path: &str, fallback: &str) -> String {
    let normalized = normalize_shell_path(path);
    let Some(index) = normalized.rfind('/') else {
        return normalize_shell_path(fallback);
    };

    if index == 0 {
        "/".to_string()
    } else {
        normalized[..index].to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::ExtractPathFactsPass;
    use crate::{
        ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, DerivedPathBasis, DerivedPathRule,
        DerivedPathUnresolvedReason, MutationScopeResolution, PathMetadataMutation,
        PathMetadataMutationKind, PathResolution, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind,
        RepositoryWorktreePathSet, RepositoryWorktreeScopeResolution,
        ResolvedMutationScopeOperation, ResolvedPathPurpose, ResolvedPathRole, RuntimeMetadata,
        RuntimeProducedValueKind, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str, home: Option<&str>) -> CheckRequest {
        sample_request_with_shell_state(
            command,
            home,
            caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
        )
    }

    fn sample_request_with_shell_state(
        command: &str,
        home: Option<&str>,
        shell_state_before: caushell_types::ShellStateSnapshot,
    ) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
            command: command.to_string(),
            shell_state_before,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: home.map(str::to_string),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profiles_dir = manifest_dir.join("../caushell-profile/profiles");

        ProfileRegistry::load_dir(&profiles_dir)
            .expect("expected built-in profiles directory to load")
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("expected system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }

    fn registry_from_yaml(yaml: &str) -> ProfileRegistry {
        let profile = load_command_profile_from_str(yaml).expect("expected profile to load");
        ProfileRegistry::from_profiles(vec![profile]).expect("expected registry to build")
    }

    fn run_pass(command: &str, home: Option<&str>) -> RunnerContext {
        run_pass_with_registry(command, home, built_in_registry())
    }

    fn run_pass_with_request(request: CheckRequest, registry: ProfileRegistry) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractPipelineFlowPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn run_pass_with_registry(
        command: &str,
        home: Option<&str>,
        registry: ProfileRegistry,
    ) -> RunnerContext {
        run_pass_with_request(sample_request(command, home), registry)
    }

    fn path_artifact(path: &str) -> ProvenanceArtifact {
        ProvenanceArtifact::PathContent {
            path: path.to_string(),
            version: None,
        }
    }

    fn path_domain_label(
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
    ) -> Option<ProvenanceDomainLabel> {
        Some(ProvenanceDomainLabel::Path { role, purpose })
    }

    fn relevant_pending_mutations(ctx: &RunnerContext) -> Vec<PendingMutation> {
        ctx.pending_mutations()
            .iter()
            .filter(|mutation| {
                !matches!(
                    mutation,
                    PendingMutation::AddRequestAnchor { .. }
                        | PendingMutation::AddTopLevelCommandInvocation { .. }
                        | PendingMutation::AddDerivedInvocation { .. }
                        | PendingMutation::AddExecutionUnitFlow { .. }
                )
            })
            .cloned()
            .collect()
    }

    fn has_mutation_scope_fact(
        ctx: &RunnerContext,
        source_node_id: &str,
        resolution: &MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: &str,
        normalized_command_name: &str,
        relation: EdgeKind,
    ) -> bool {
        ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddMutationScopeFact {
                    source_node_id: actual_source_node_id,
                    resolution: actual_resolution,
                    operation: actual_operation,
                    slot_name: actual_slot_name,
                    normalized_command_name: Some(actual_command_name),
                    relation: actual_relation,
                    ..
                } if actual_source_node_id.0 == source_node_id
                    && actual_resolution == resolution
                    && *actual_operation == operation
                    && actual_slot_name == slot_name
                    && actual_command_name == normalized_command_name
                    && *actual_relation == relation
            )
        })
    }

    #[test]
    fn extract_path_facts_projects_git_commit_hook_from_core_hookspath() {
        let temp_dir = unique_temp_dir("caushell-git-hookspath");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(
            git_dir.join("config"),
            "[core]\n    hooksPath = .githooks\n",
        )
        .expect("expected git config to be written");

        let mut request = sample_request("git commit -m 'ship it'", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::ScriptSource),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && slot_name == "git_hook_pre_commit"
                && command_name == "git"
                && path == &temp_dir.join(".githooks/pre-commit").to_string_lossy()
                && *basis == DerivedPathBasis::ConfigDerivedRoot {
                    config_path: temp_dir.join(".git/config").to_string_lossy().into_owned(),
                    convention: "git.local_config".to_string(),
                    key: "core.hooksPath".to_string(),
                    value: temp_dir.join(".githooks").to_string_lossy().into_owned(),
                }
                && *rule == DerivedPathRule::ChildUnder {
                    relative_path: "pre-commit".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_projects_default_git_commit_hook_without_core_hookspath() {
        let temp_dir = unique_temp_dir("caushell-git-default-hook");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected git config to be written");

        let mut request = sample_request("git commit -m 'ship it'", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                slot_name,
                ..
            } if slot_name == "git_hook_pre_commit"
                && path == &temp_dir.join(".git/hooks/pre-commit").to_string_lossy()
                && *basis == DerivedPathBasis::ConfigDerivedRoot {
                    config_path: temp_dir.join(".git/config").to_string_lossy().into_owned(),
                    convention: "git.default_hooks".to_string(),
                    key: "core.hooksPath".to_string(),
                    value: temp_dir.join(".git/hooks").to_string_lossy().into_owned(),
                }
                && *rule == DerivedPathRule::ChildUnder {
                    relative_path: "pre-commit".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_git_commit_local_hookspath_overrides_global() {
        let temp_dir = unique_temp_dir("caushell-git-local-over-global-hook");
        let git_dir = temp_dir.join(".git");
        let home_dir = temp_dir.join("home");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::create_dir_all(&home_dir).expect("expected home dir to exist");
        fs::write(
            git_dir.join("config"),
            "[core]\n    hooksPath = .repo-hooks\n",
        )
        .expect("expected local git config to be written");
        fs::write(
            home_dir.join(".gitconfig"),
            "[core]\n    hooksPath = /opt/global-hooks\n",
        )
        .expect("expected global git config to be written");

        let mut request =
            sample_request("git commit -m 'ship it'", Some(&home_dir.to_string_lossy()));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, .. },
                slot_name,
                ..
            } if slot_name == "git_hook_pre_commit"
                && path == &temp_dir.join(".repo-hooks/pre-commit").to_string_lossy()
                && *basis == DerivedPathBasis::ConfigDerivedRoot {
                    config_path: temp_dir.join(".git/config").to_string_lossy().into_owned(),
                    convention: "git.local_config".to_string(),
                    key: "core.hooksPath".to_string(),
                    value: temp_dir.join(".repo-hooks").to_string_lossy().into_owned(),
                }
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::Concrete { path },
                slot_name,
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::ToolConfig),
                ..
            } if slot_name == "git_global_config_home"
                && path == &home_dir.join(".gitconfig").to_string_lossy()
        )));
    }

    #[test]
    fn extract_path_facts_git_commit_global_hookspath_applies_when_local_missing() {
        let temp_dir = unique_temp_dir("caushell-git-global-fallback-hook");
        let git_dir = temp_dir.join(".git");
        let home_dir = temp_dir.join("home");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::create_dir_all(&home_dir).expect("expected home dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected local git config to be written");
        fs::write(
            home_dir.join(".gitconfig"),
            "[core]\n    hooksPath = /opt/global-hooks\n",
        )
        .expect("expected global git config to be written");

        let mut request =
            sample_request("git commit -m 'ship it'", Some(&home_dir.to_string_lossy()));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, .. },
                slot_name,
                ..
            } if slot_name == "git_hook_pre_commit"
                && path == "/opt/global-hooks/pre-commit"
                && *basis == DerivedPathBasis::ConfigDerivedRoot {
                    config_path: home_dir.join(".gitconfig").to_string_lossy().into_owned(),
                    convention: "git.global_config".to_string(),
                    key: "core.hooksPath".to_string(),
                    value: "/opt/global-hooks".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_git_commit_system_hookspath_applies_when_local_and_global_missing() {
        let temp_dir = unique_temp_dir("caushell-git-system-fallback-hook");
        let git_dir = temp_dir.join(".git");
        let system_config = temp_dir.join("gitconfig-system");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected local git config to be written");
        fs::write(
            &system_config,
            "[core]\n    hooksPath = /opt/system-hooks\n",
        )
        .expect("expected system git config to be written");

        let mut request = sample_request("git commit -m 'ship it'", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned())
                .with_exact_scalar_variable(
                    "GIT_CONFIG_SYSTEM",
                    system_config.to_string_lossy(),
                    true,
                )
                .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly);
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, .. },
                slot_name,
                ..
            } if slot_name == "git_hook_pre_commit"
                && path == "/opt/system-hooks/pre-commit"
                && *basis == DerivedPathBasis::ConfigDerivedRoot {
                    config_path: system_config.to_string_lossy().into_owned(),
                    convention: "git.system_config".to_string(),
                    key: "core.hooksPath".to_string(),
                    value: "/opt/system-hooks".to_string(),
                }
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::Concrete { path },
                slot_name,
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::ToolConfig),
                ..
            } if slot_name == "git_system_config"
                && path == &system_config.to_string_lossy()
        )));
    }

    #[test]
    fn extract_path_facts_git_commit_projects_prepare_and_post_commit_even_with_no_verify() {
        let temp_dir = unique_temp_dir("caushell-git-no-verify-hook");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected git config to be written");

        let mut request =
            sample_request("git commit --no-verify -m 'ship it'", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());
        let slot_names = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddPathFact { slot_name, .. }
                    if slot_name.starts_with("git_hook_") =>
                {
                    Some(slot_name.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(slot_names.contains(&"git_hook_prepare_commit_msg"));
        assert!(slot_names.contains(&"git_hook_post_commit"));
        assert!(!slot_names.contains(&"git_hook_pre_commit"));
        assert!(!slot_names.contains(&"git_hook_commit_msg"));
    }

    #[test]
    fn extract_path_facts_git_commit_amend_projects_post_rewrite_hook() {
        let temp_dir = unique_temp_dir("caushell-git-amend-hook");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected git config to be written");

        let mut request = sample_request("git commit --amend --no-edit", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, .. },
                slot_name,
                ..
            } if slot_name == "git_hook_post_rewrite"
                && path == &temp_dir.join(".git/hooks/post-rewrite").to_string_lossy()
        )));
    }

    #[test]
    fn extract_path_facts_git_am_projects_applypatch_hooks() {
        let temp_dir = unique_temp_dir("caushell-git-am-hook");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected git config to be written");

        let mut request = sample_request("git am patch.mbox", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());
        let slot_names = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddPathFact { slot_name, .. }
                    if slot_name.starts_with("git_hook_") =>
                {
                    Some(slot_name.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(slot_names.contains(&"git_hook_applypatch_msg"));
        assert!(slot_names.contains(&"git_hook_pre_applypatch"));
        assert!(slot_names.contains(&"git_hook_post_applypatch"));
    }

    #[test]
    fn extract_path_facts_git_am_no_verify_skips_bypassable_hooks() {
        let temp_dir = unique_temp_dir("caushell-git-am-no-verify-hook");
        let git_dir = temp_dir.join(".git");
        fs::create_dir_all(&git_dir).expect("expected git dir to exist");
        fs::write(git_dir.join("config"), "[core]\n    bare = false\n")
            .expect("expected git config to be written");

        let mut request = sample_request("git am --no-verify patch.mbox", Some("/home/alice"));
        request.shell_state_before =
            caushell_types::ShellStateSnapshot::new(temp_dir.to_string_lossy().into_owned());
        request.workspace_root = Some(temp_dir.to_string_lossy().into_owned());

        let ctx = run_pass_with_request(request, built_in_registry());
        let slot_names = ctx
            .pending_mutations()
            .iter()
            .filter_map(|mutation| match mutation {
                PendingMutation::AddPathFact { slot_name, .. }
                    if slot_name.starts_with("git_hook_") =>
                {
                    Some(slot_name.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(!slot_names.contains(&"git_hook_applypatch_msg"));
        assert!(!slot_names.contains(&"git_hook_pre_applypatch"));
        assert!(slot_names.contains(&"git_hook_post_applypatch"));
    }

    #[test]
    fn extract_path_facts_stages_read_path_mutation_for_concrete_operand() {
        let ctx = run_pass("bash ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:script_path:/tmp/project/scripts/build.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/scripts/build.sh".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
                    artifact: path_artifact("/tmp/project/scripts/build.sh"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::ScriptSource),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_stages_mv_source_as_path_content_consume() {
        let ctx = run_pass("mv ./r3-move-source.sh ./r3-moved.sh", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Read,
                slot_name,
                normalized_command_name: Some(command_name),
                relation,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/r3-move-source.sh"
                && slot_name == "source_paths"
                && command_name == "mv"
                && *relation == EdgeKind::Reads
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact: ProvenanceArtifact::PathContent { path, version: None },
                relation,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::PathRead,
                    slot_name,
                    normalized_command_name,
                    ..
                },
            } if source_node_id.0 == "command:sess-1:2:0"
                && node_id.0 == "artifact:path-content:/tmp/project/r3-move-source.sh"
                && path == "/tmp/project/r3-move-source.sh"
                && *relation == EdgeKind::Consumes
                && slot_name.as_deref() == Some("source_paths")
                && normalized_command_name.as_deref() == Some("mv")
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_rm_delete_paths() {
        let ctx = run_pass("git rm Cargo.lock target/debug.log", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Target,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Targets,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && (path == "/tmp/project/Cargo.lock" || path == "/tmp/project/target/debug.log")
                && slot_name == "pathspecs"
                && command_name == "git"
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_restore_write_paths() {
        let ctx = run_pass("git restore -- src/main.rs Cargo.toml", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Write,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && (path == "/tmp/project/src/main.rs" || path == "/tmp/project/Cargo.toml")
                && slot_name == "pathspecs"
                && command_name == "git"
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_checkout_write_paths() {
        let ctx = run_pass("git checkout -- src/main.rs", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Write,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/src/main.rs"
                && slot_name == "pathspecs"
                && command_name == "git"
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_checkout_treeish_write_paths() {
        let ctx = run_pass("git checkout HEAD -- .", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Write,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project"
                && slot_name == "pathspecs"
                && command_name == "git"
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_clean_explicit_targets() {
        let ctx = run_pass("git clean -fdx build/ tmp/", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Target,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Targets,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && (path == "/tmp/project/build" || path == "/tmp/project/tmp")
                && slot_name == "pathspecs"
                && command_name == "git"
        )));
    }

    #[test]
    fn extract_path_facts_stages_git_clean_repo_scoped_delete() {
        let ctx = run_pass("git clean -fdx", Some("/home/alice"));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::UntrackedAndIgnored,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Delete,
            "repository_worktree",
            "git",
            EdgeKind::Targets,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_reset_hard_repo_scoped_write() {
        let ctx = run_pass("git reset --hard", Some("/home/alice"));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::Tracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "working_directory",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_reset_hard_revision_under_git_c() {
        let ctx = run_pass("git -C repo reset --hard HEAD~1", Some("/home/alice"));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project/repo".to_string(),
                },
                path_set: RepositoryWorktreePathSet::Tracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "working_directory",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_apply_patch_read_and_mutation_scope() {
        let ctx = run_pass("git apply patch.diff", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/patch.diff"
                && slot_name == "patch_paths"
                && command_name == "git"
        )));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::PatchSelectedTracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "repository_worktree",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_clone_recursive_submodules_scope() {
        let ctx = run_pass(
            "git clone --recurse-submodules https://example.test/repo.git ./repo",
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::DerivedConcrete { path, .. },
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::ToolConfig),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/repo/.gitmodules"
                && slot_name == "derived_path_2"
                && command_name == "git"
        )));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project/repo".to_string(),
                },
                path_set: RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "destination",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_am_mailbox_read_and_patch_scope() {
        let ctx = run_pass("git am patch.mbox", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/patch.mbox"
                && slot_name == "mailbox_paths"
                && command_name == "git"
        )));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::PatchSelectedTracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "repository_worktree",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_restore_worktree_subtree() {
        let ctx = run_pass(
            "git restore --source=HEAD~1 --worktree .",
            Some("/home/alice"),
        );

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::Tracked,
                scope: RepositoryWorktreeScopeResolution::Subtree {
                    path: PathResolution::Concrete {
                        path: "/tmp/project".to_string(),
                    },
                },
            },
            ResolvedMutationScopeOperation::Write,
            "subtree",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_checkout_branch_worktree() {
        let ctx = run_pass("git checkout main", Some("/home/alice"));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::Tracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "repository_worktree",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_git_submodule_update_recursive_scope() {
        let ctx = run_pass(
            "git submodule update --init --recursive",
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::ToolConvention { path, convention },
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::ToolConfig),
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && (path == "/tmp/project/.gitmodules" || path == "/tmp/project/.git/config")
                && (slot_name == "tool_convention_path_0_git_modules_config"
                    || slot_name == "tool_convention_path_1_git_local_config")
                && (convention == "git.modules_config" || convention == "git.local_config")
                && command_name == "git"
        )));

        assert!(has_mutation_scope_fact(
            &ctx,
            "command:sess-1:2:0",
            &MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            ResolvedMutationScopeOperation::Write,
            "repository_worktree",
            "git",
            EdgeKind::Writes,
        ));
    }

    #[test]
    fn extract_path_facts_stages_tool_convention_config_path() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: projtool
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: load_convention
    selector:
      kind: all
      items: []
    effects:
      - kind: load_config
        target:
          kind: tool_convention_path
          path: package.json
          convention: npm.package_json
          purpose: project_config

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("projtool", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::ToolConvention { path, convention },
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::ProjectConfig),
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Reads,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/package.json"
                && convention == "npm.package_json"
                && command_name == "projtool"
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact: ProvenanceArtifact::PathContent { path, version: None },
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::ProjectConfigSource,
                    normalized_command_name: Some(command_name),
                    ..
                },
            } if source_node_id.0 == "command:sess-1:2:0"
                && node_id.0 == "artifact:path-content:/tmp/project/package.json"
                && path == "/tmp/project/package.json"
                && command_name == "projtool"
        )));
    }

    #[test]
    fn extract_path_facts_stages_derived_append_suffix_write_path() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: gzipish
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: default
    selector:
      kind: all
      items: []
    parameters:
      - name: input_paths
        semantic:
          kind: path
          role: read
          purpose: generic_operand
        binding:
          kind: remaining_positionals
        cardinality: required_many
    effects:
      - kind: write_path
        target:
          kind: derived_path
          source:
            kind: slot
            name: input_paths
          rule:
            kind: append_suffix
            suffix: ".gz"
          purpose: generic_operand

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("gzipish foo.txt", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if source_node_id.0 == "command:sess-1:2:0"
                && path == "/tmp/project/foo.txt.gz"
                && command_name == "gzipish"
                && *basis == DerivedPathBasis::PathOperand {
                    raw: "foo.txt".to_string(),
                    resolved_input_path: Some("/tmp/project/foo.txt".to_string()),
                    slot_name: "input_paths".to_string(),
                }
                && *rule == DerivedPathRule::AppendSuffix {
                    suffix: ".gz".to_string(),
                }
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                artifact: ProvenanceArtifact::PathContent { path, version: None },
                relation: EdgeKind::Produces,
                semantics: ProvenanceEdgeSemantics::Produce {
                    produce_kind: ProvenanceProduceKind::PathWrite,
                    normalized_command_name: Some(command_name),
                    ..
                },
                ..
            } if path == "/tmp/project/foo.txt.gz" && command_name == "gzipish"
        )));
    }

    #[test]
    fn extract_path_facts_stages_derived_strip_suffix_write_path() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: gunzipish
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: default
    selector:
      kind: all
      items: []
    parameters:
      - name: input_paths
        semantic:
          kind: path
          role: read
          purpose: generic_operand
        binding:
          kind: remaining_positionals
        cardinality: required_many
    effects:
      - kind: write_path
        target:
          kind: derived_path
          source:
            kind: slot
            name: input_paths
          rule:
            kind: strip_suffix
            suffix: ".gz"
          purpose: generic_operand

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("gunzipish foo.txt.gz", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                relation: EdgeKind::Writes,
                ..
            } if path == "/tmp/project/foo.txt"
                && *basis == DerivedPathBasis::PathOperand {
                    raw: "foo.txt.gz".to_string(),
                    resolved_input_path: Some("/tmp/project/foo.txt.gz".to_string()),
                    slot_name: "input_paths".to_string(),
                }
                && *rule == DerivedPathRule::StripSuffix {
                    suffix: ".gz".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_stages_derived_replace_suffix_write_path() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: replaceish
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: default
    selector:
      kind: all
      items: []
    parameters:
      - name: input_paths
        semantic:
          kind: path
          role: read
          purpose: generic_operand
        binding:
          kind: remaining_positionals
        cardinality: required_many
    effects:
      - kind: write_path
        target:
          kind: derived_path
          source:
            kind: slot
            name: input_paths
          rule:
            kind: replace_suffix
            from: ".in"
            to: ".out"
          purpose: generic_operand

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("replaceish foo.in", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                relation: EdgeKind::Writes,
                ..
            } if path == "/tmp/project/foo.out"
                && *basis == DerivedPathBasis::PathOperand {
                    raw: "foo.in".to_string(),
                    resolved_input_path: Some("/tmp/project/foo.in".to_string()),
                    slot_name: "input_paths".to_string(),
                }
                && *rule == DerivedPathRule::ReplaceSuffix {
                    from: ".in".to_string(),
                    to: ".out".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_stages_tool_convention_root_child_write_path() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: cachetool
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: default
    selector:
      kind: all
      items: []
    effects:
      - kind: target_path
        target:
          kind: tool_convention_path
          path: .cache/cachetool
          convention: cachetool.cache_root
          purpose: generic_operand
      - kind: write_path
        target:
          kind: derived_path
          source:
            kind: tool_convention_root
            convention: cachetool.cache_root
          rule:
            kind: child_under
            relative_path: index.json
          purpose: generic_operand

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("cachetool", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                relation: EdgeKind::Writes,
                normalized_command_name: Some(command_name),
                ..
            } if command_name == "cachetool"
                && path == "/tmp/project/.cache/cachetool/index.json"
                && *basis == DerivedPathBasis::ToolConventionRoot {
                    path: "/tmp/project/.cache/cachetool".to_string(),
                    convention: "cachetool.cache_root".to_string(),
                }
                && *rule == DerivedPathRule::ChildUnder {
                    relative_path: "index.json".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_stages_derived_archive_members_as_unresolved() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: untarish
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: default
    selector:
      kind: all
      items: []
    parameters:
      - name: archive_path
        semantic:
          kind: path
          role: read
          purpose: generic_operand
        binding:
          kind: next_positional
        cardinality: required_one
    effects:
      - kind: write_path
        target:
          kind: derived_path
          source:
            kind: slot
            name: archive_path
          rule:
            kind: archive_members
          purpose: generic_operand

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry("untarish archive.tar", Some("/home/alice"), registry);

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedUnresolved { basis, rule, reason },
                role: ResolvedPathRole::Write,
                relation: EdgeKind::Writes,
                ..
            } if *basis == DerivedPathBasis::PathOperand {
                    raw: "archive.tar".to_string(),
                    resolved_input_path: Some("/tmp/project/archive.tar".to_string()),
                    slot_name: "archive_path".to_string(),
                }
                && *rule == DerivedPathRule::ArchiveMembers
                && *reason == DerivedPathUnresolvedReason::UnknownArchiveMembers
        )));

        assert!(!ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                artifact: ProvenanceArtifact::PathContent { path, .. },
                relation: EdgeKind::Produces,
                ..
            } if path != "/tmp/project/archive.tar"
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_gzip_multi_value_derived_writes() {
        let ctx = run_pass("gzip foo.txt bar.txt", Some("/home/alice"));

        let derived_writes: Vec<&PendingMutation> = ctx
            .pending_mutations()
            .iter()
            .filter(|mutation| {
                matches!(
                    mutation,
                    PendingMutation::AddPathFact {
                        resolution: PathResolution::DerivedConcrete { .. },
                        role: ResolvedPathRole::Write,
                        normalized_command_name: Some(command_name),
                        relation: EdgeKind::Writes,
                        ..
                    } if command_name == "gzip"
                )
            })
            .collect();

        assert_eq!(derived_writes.len(), 2);
        assert!(derived_writes.iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, .. },
                ..
            } if path == "/tmp/project/foo.txt.gz"
        )));
        assert!(derived_writes.iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, .. },
                ..
            } if path == "/tmp/project/bar.txt.gz"
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_gunzip_derived_write() {
        let ctx = run_pass("gunzip foo.txt.gz", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "gunzip"
                && path == "/tmp/project/foo.txt"
                && *basis == DerivedPathBasis::PathOperand {
                    raw: "foo.txt.gz".to_string(),
                    resolved_input_path: Some("/tmp/project/foo.txt.gz".to_string()),
                    slot_name: "input_paths".to_string(),
                }
                && *rule == DerivedPathRule::StripSuffix {
                    suffix: ".gz".to_string(),
                }
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_iconv_output_path_write() {
        let ctx = run_pass(
            "iconv -f utf-8 -t ascii -o output.txt input.txt",
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::Concrete { path },
                role: ResolvedPathRole::Write,
                slot_name,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "iconv"
                && slot_name == "output_path"
                && path == "/tmp/project/output.txt"
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_tar_extract_as_unresolved_derived_write() {
        let ctx = run_pass(
            "tar -x -f archive.tar -C ./out member.sh",
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedUnresolved { basis, rule, reason },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "tar"
                && *basis == DerivedPathBasis::PathOperand {
                    raw: "archive.tar".to_string(),
                    resolved_input_path: Some("/tmp/project/archive.tar".to_string()),
                    slot_name: "archive_file".to_string(),
                }
                && *rule == DerivedPathRule::ArchiveMembers
                && *reason == DerivedPathUnresolvedReason::UnknownArchiveMembers
        )));

        assert!(!ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::Concrete { path },
                slot_name,
                normalized_command_name: Some(command_name),
                ..
            } if command_name == "tar"
                && slot_name == "member_filters"
                && path == "/tmp/project/member.sh"
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_wget_default_output_as_endpoint_derived_path() {
        let ctx = run_pass("wget https://example.test/payload.sh", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "wget"
                && path == "/tmp/project/payload.sh"
                && *basis == DerivedPathBasis::EndpointOperand {
                    raw: "https://example.test/payload.sh".to_string(),
                    slot_name: "endpoints".to_string(),
                }
                && *rule == DerivedPathRule::UrlBasename
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_wget_directory_prefixed_output_as_derived_path() {
        let ctx = run_pass(
            "wget -P ./downloads https://example.test/payload.sh",
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "wget"
                && path == "/tmp/project/downloads/payload.sh"
                && *basis == DerivedPathBasis::EndpointOperand {
                    raw: "https://example.test/payload.sh".to_string(),
                    slot_name: "endpoints".to_string(),
                }
                && *rule == DerivedPathRule::UrlBasename
        )));
    }

    #[test]
    fn extract_path_facts_records_missing_endpoint_basename_as_unresolved_derived_path() {
        let ctx = run_pass("wget https://example.test/", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedUnresolved { basis, rule, reason },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "wget"
                && *basis == DerivedPathBasis::EndpointOperand {
                    raw: "https://example.test/".to_string(),
                    slot_name: "endpoints".to_string(),
                }
                && *rule == DerivedPathRule::UrlBasename
                && *reason == DerivedPathUnresolvedReason::MissingUrlBasename
        )));
    }

    #[test]
    fn extract_path_facts_stages_builtin_curl_remote_name_as_endpoint_derived_path() {
        let ctx = run_pass("curl -O https://example.test/tool.tgz", Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                resolution: PathResolution::DerivedConcrete { path, basis, rule },
                role: ResolvedPathRole::Write,
                normalized_command_name: Some(command_name),
                relation: EdgeKind::Writes,
                ..
            } if command_name == "curl"
                && path == "/tmp/project/tool.tgz"
                && *basis == DerivedPathBasis::EndpointOperand {
                    raw: "https://example.test/tool.tgz".to_string(),
                    slot_name: "endpoint".to_string(),
                }
                && *rule == DerivedPathRule::UrlBasename
        )));
    }

    #[test]
    fn extract_path_facts_stages_read_path_mutation_for_home_expansion() {
        let ctx = run_pass("bash --rcfile ~/team.rc", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:startup_config:/home/alice/team.rc"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/home/alice/team.rc".to_string()
                    },
                    role: ResolvedPathRole::Config,
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                    slot_name: "startup_config".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/home/alice/team.rc"),
                    artifact: path_artifact("/home/alice/team.rc"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StartupConfigSource,
                        slot_name: Some("startup_config".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Config,
                            Some(ResolvedPathPurpose::StartupConfig),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_stages_metadata_mutation_without_content_write() {
        let ctx = run_pass("chmod -R +x ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chmod".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![PathMetadataMutationKind::ChangeMode],
                    raw_operand: Some("+x".to_string()),
                    owner_group: None,
                    recursive: true,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_stages_chown_owner_and_group_metadata_mutation() {
        let ctx = run_pass("chown root:staff ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chown".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![
                        PathMetadataMutationKind::ChangeOwner,
                        PathMetadataMutationKind::ChangeGroup
                    ],
                    raw_operand: Some("root:staff".to_string()),
                    owner_group: Some(caushell_types::OwnerGroupSpec {
                        owner: Some("root".to_string()),
                        group: Some("staff".to_string()),
                        trailing_colon: false,
                    }),
                    recursive: false,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_stages_chown_owner_only_metadata_mutation() {
        let ctx = run_pass("chown root ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chown".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![PathMetadataMutationKind::ChangeOwner],
                    raw_operand: Some("root".to_string()),
                    owner_group: Some(caushell_types::OwnerGroupSpec {
                        owner: Some("root".to_string()),
                        group: None,
                        trailing_colon: false,
                    }),
                    recursive: false,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_stages_chown_group_only_metadata_mutation() {
        let ctx = run_pass("chown :staff ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chown".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![PathMetadataMutationKind::ChangeGroup],
                    raw_operand: Some(":staff".to_string()),
                    owner_group: Some(caushell_types::OwnerGroupSpec {
                        owner: None,
                        group: Some("staff".to_string()),
                        trailing_colon: false,
                    }),
                    recursive: false,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_stages_chown_trailing_colon_metadata_mutation() {
        let ctx = run_pass("chown root: ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chown".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![PathMetadataMutationKind::ChangeOwner],
                    raw_operand: Some("root:".to_string()),
                    owner_group: Some(caushell_types::OwnerGroupSpec {
                        owner: Some("root".to_string()),
                        group: None,
                        trailing_colon: true,
                    }),
                    recursive: false,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_stages_chgrp_group_metadata_mutation() {
        let ctx = run_pass("chgrp staff ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathMetadataMutationFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:path_targets:/tmp/project/scripts/build.sh"
                ),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/scripts/build.sh".to_string()
                },
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path_targets".to_string(),
                normalized_command_name: Some("chgrp".to_string()),
                metadata_mutation: PathMetadataMutation {
                    mutation_kinds: vec![PathMetadataMutationKind::ChangeGroup],
                    raw_operand: Some("staff".to_string()),
                    owner_group: None,
                    recursive: false,
                },
                relation: EdgeKind::MutatesMetadata,
            }]
        );
    }

    #[test]
    fn extract_path_facts_records_dynamic_path_operands_as_unresolved_path_facts() {
        let ctx = run_pass(r#"bash --rcfile "$RCFILE""#, Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:startup_config:dynamic-text:$RCFILE"
                ),
                resolution: PathResolution::UnsupportedDynamicText {
                    text: "$RCFILE".to_string(),
                },
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::StartupConfig),
                slot_name: "startup_config".to_string(),
                normalized_command_name: Some("bash".to_string()),
                relation: EdgeKind::Reads,
            }]
        );
    }

    #[test]
    fn extract_path_facts_materializes_runtime_produced_path_bindings_into_concrete_paths() {
        let request = sample_request_with_shell_state(
            r#"bash "$TMP_SCRIPT""#,
            Some("/home/alice"),
            caushell_types::ShellStateSnapshot::new("/tmp/project".to_string())
                .with_runtime_produced_variable(
                    "TMP_SCRIPT",
                    "/tmp/runtime/tmp.abcd.sh",
                    RuntimeProducedValueKind::Path,
                    false,
                )
                .with_variable_knowledge(caushell_types::ShellStateKnowledge::Complete),
        );

        let ctx = run_pass_with_request(request, built_in_registry());

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:script_path:/tmp/runtime/tmp.abcd.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/runtime/tmp.abcd.sh".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/runtime/tmp.abcd.sh"),
                    artifact: path_artifact("/tmp/runtime/tmp.abcd.sh"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::ScriptSource),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_materializes_runtime_produced_scalar_binding_as_concrete_path_in_path_slot()
     {
        let request = sample_request_with_shell_state(
            r#"bash "$TMP_SCRIPT""#,
            Some("/home/alice"),
            caushell_types::ShellStateSnapshot::new("/tmp/project".to_string())
                .with_runtime_produced_variable(
                    "TMP_SCRIPT",
                    "payload.sh",
                    RuntimeProducedValueKind::Scalar,
                    false,
                )
                .with_variable_knowledge(caushell_types::ShellStateKnowledge::Complete),
        );

        let ctx = run_pass_with_request(request, built_in_registry());

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:script_path:/tmp/project/payload.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/payload.sh".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
                    artifact: path_artifact("/tmp/project/payload.sh"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::ScriptSource),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_records_missing_home_for_home_relative_operand() {
        let ctx = run_pass("bash --rcfile ~/team.rc", None);

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:startup_config:home-unavailable:~/team.rc"
                ),
                resolution: PathResolution::HomeUnavailable {
                    text: "~/team.rc".to_string(),
                },
                role: ResolvedPathRole::Config,
                purpose: Some(ResolvedPathPurpose::StartupConfig),
                slot_name: "startup_config".to_string(),
                normalized_command_name: Some("bash".to_string()),
                relation: EdgeKind::Reads,
            }]
        );
    }

    #[test]
    fn extract_path_facts_projects_node_preload_path_as_in_process_code_source() {
        let ctx = run_pass("node -r ./hook.js app.js", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:script_path:/tmp/project/app.js"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/app.js".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("node".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/app.js"),
                    artifact: path_artifact("/tmp/project/app.js"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("node".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::ScriptSource),
                        ),
                    },
                },
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:preload_targets:/tmp/project/hook.js"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/hook.js".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::InProcessCode),
                    slot_name: "preload_targets".to_string(),
                    normalized_command_name: Some("node".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/hook.js"),
                    artifact: path_artifact("/tmp/project/hook.js"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::InProcessCodeSource,
                        slot_name: Some("preload_targets".to_string()),
                        normalized_command_name: Some("node".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::InProcessCode),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_stages_write_path_mutation_for_output_redirection() {
        let ctx = run_pass("echo hi > ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:redirect_target_0:/tmp/project/scripts/build.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/scripts/build.sh".to_string()
                    },
                    role: ResolvedPathRole::Write,
                    purpose: None,
                    slot_name: "redirect_target_0".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Writes,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
                    artifact: path_artifact("/tmp/project/scripts/build.sh"),
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::PathWrite,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: None,
                        domain_label: path_domain_label(ResolvedPathRole::Write, None),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_stages_read_path_mutation_for_input_redirection() {
        let ctx = run_pass("cat < ./scripts/build.sh", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:redirect_target_0:/tmp/project/scripts/build.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/scripts/build.sh".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: None,
                    slot_name: "redirect_target_0".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
                    artifact: path_artifact("/tmp/project/scripts/build.sh"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: None,
                        domain_label: path_domain_label(ResolvedPathRole::Read, None),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_ignores_descriptor_duplication_redirection() {
        let ctx = run_pass("echo hi 2>&1", Some("/home/alice"));

        assert!(relevant_pending_mutations(&ctx).is_empty());
    }

    #[test]
    fn extract_path_facts_uses_pipeline_segment_owner_for_redirection() {
        let ctx = run_pass("cat < ./scripts/build.sh | bash", Some("/home/alice"));

        assert!(ctx.pending_mutations().contains(&PendingMutation::AddPathFact {
            source_node_id: NodeId::new("pipeline-segment:sess-1:2:0"),
            node_id: NodeId::new(
                "resolved-path:pipeline-segment:sess-1:2:0:0:redirect_target_0:/tmp/project/scripts/build.sh"
            ),
            resolution: PathResolution::Concrete {
                path: "/tmp/project/scripts/build.sh".to_string()
            },
            role: ResolvedPathRole::Read,
            purpose: None,
            slot_name: "redirect_target_0".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        }));
    }

    #[test]
    fn extract_path_facts_projects_shell_payload_child_redirection() {
        let ctx = run_pass(
            r#"bash -lc 'cat < ./scripts/build.sh'"#,
            Some("/home/alice"),
        );

        assert!(ctx.pending_mutations().contains(&PendingMutation::AddPathFact {
            source_node_id: NodeId::new("expanded-shell-payload:command:sess-1:2:0:0"),
            node_id: NodeId::new(
                "resolved-path:expanded-shell-payload:command:sess-1:2:0:0:0:redirect_target_0:/tmp/project/scripts/build.sh"
            ),
            resolution: PathResolution::Concrete {
                path: "/tmp/project/scripts/build.sh".to_string()
            },
            role: ResolvedPathRole::Read,
            purpose: None,
            slot_name: "redirect_target_0".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        }));
    }

    #[test]
    fn extract_path_facts_stages_grep_pattern_file_and_input_paths() {
        let ctx = run_pass(
            "grep --file ./patterns.txt ./src/lib.rs",
            Some("/home/alice"),
        );

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:input_paths:/tmp/project/src/lib.rs"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/src/lib.rs".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "input_paths".to_string(),
                    normalized_command_name: Some("grep".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/src/lib.rs"),
                    artifact: path_artifact("/tmp/project/src/lib.rs"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some("input_paths".to_string()),
                        normalized_command_name: Some("grep".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::GenericOperand),
                        ),
                    },
                },
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:pattern_files:/tmp/project/patterns.txt"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/patterns.txt".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "pattern_files".to_string(),
                    normalized_command_name: Some("grep".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/patterns.txt"),
                    artifact: path_artifact("/tmp/project/patterns.txt"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some("pattern_files".to_string()),
                        normalized_command_name: Some("grep".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::GenericOperand),
                        ),
                    },
                },
            ]
        );
    }

    #[test]
    fn extract_path_facts_skips_grep_stdin_sentinels() {
        let ctx = run_pass("grep -e TODO -f - - ./src/lib.rs", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:input_paths:/tmp/project/src/lib.rs"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/src/lib.rs".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "input_paths".to_string(),
                    normalized_command_name: Some("grep".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/src/lib.rs"),
                    artifact: path_artifact("/tmp/project/src/lib.rs"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some("input_paths".to_string()),
                        normalized_command_name: Some("grep".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::GenericOperand),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_stages_head_input_paths_but_skips_stdin_sentinel() {
        let ctx = run_pass("head - ./src/lib.rs", Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:input_paths:/tmp/project/src/lib.rs"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/src/lib.rs".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                    slot_name: "input_paths".to_string(),
                    normalized_command_name: Some("head".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/src/lib.rs"),
                    artifact: path_artifact("/tmp/project/src/lib.rs"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name: Some("input_paths".to_string()),
                        normalized_command_name: Some("head".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::GenericOperand),
                        ),
                    },
                }
            ]
        );
    }

    #[test]
    fn extract_path_facts_merges_profile_paths_and_redirection_paths() {
        let ctx = run_pass(
            "bash ./scripts/build.sh > ./logs/build.log",
            Some("/home/alice"),
        );

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:script_path:/tmp/project/scripts/build.sh"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/scripts/build.sh".to_string()
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
                    artifact: path_artifact("/tmp/project/scripts/build.sh"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ScriptSource,
                        slot_name: Some("script_path".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: path_domain_label(
                            ResolvedPathRole::Read,
                            Some(ResolvedPathPurpose::ScriptSource),
                        ),
                    },
                },
                PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:0:redirect_target_0:/tmp/project/logs/build.log"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/logs/build.log".to_string()
                    },
                    role: ResolvedPathRole::Write,
                    purpose: None,
                    slot_name: "redirect_target_0".to_string(),
                    normalized_command_name: None,
                    relation: EdgeKind::Writes,
                },
                PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/logs/build.log"),
                    artifact: path_artifact("/tmp/project/logs/build.log"),
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::PathWrite,
                        slot_name: Some("redirect_target_0".to_string()),
                        normalized_command_name: None,
                        domain_label: path_domain_label(ResolvedPathRole::Write, None),
                    },
                },
            ]
        );
    }

    #[test]
    fn extract_path_facts_records_dynamic_redirection_targets_as_unresolved_path_facts() {
        let ctx = run_pass(r#"echo hi > "$OUT""#, Some("/home/alice"));

        assert_eq!(
            relevant_pending_mutations(&ctx),
            &[PendingMutation::AddPathFact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "resolved-path:command:sess-1:2:0:0:redirect_target_0:dynamic-text:$OUT"
                ),
                resolution: PathResolution::UnsupportedDynamicText {
                    text: "$OUT".to_string(),
                },
                role: ResolvedPathRole::Write,
                purpose: None,
                slot_name: "redirect_target_0".to_string(),
                normalized_command_name: None,
                relation: EdgeKind::Writes,
            }]
        );
    }

    #[test]
    fn extract_path_facts_skips_process_substitution_redirection_targets() {
        let ctx = run_pass("cat < <(echo hi)", Some("/home/alice"));

        assert!(
            !ctx.pending_mutations()
                .iter()
                .any(|mutation| matches!(mutation, PendingMutation::AddPathFact { .. }))
        );
    }

    #[test]
    fn extract_path_facts_stages_path_mutation_for_derived_invocation_operand() {
        let ctx = run_pass(r#"bash -c 'bash ../shared/build.sh'"#, Some("/home/alice"));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddPathFact {
                source_node_id,
                node_id,
                resolution: PathResolution::Concrete { path },
                relation,
                ..
            } if source_node_id.0 == "derived:sess-1:2:0:0"
                && node_id.0 == "resolved-path:derived:sess-1:2:0:0:0:script_path:/tmp/shared/build.sh"
                && path == "/tmp/shared/build.sh"
                && *relation == EdgeKind::Reads
        )));

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact: ProvenanceArtifact::PathContent { path, version: None },
                relation,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::ScriptSource,
                    slot_name,
                    normalized_command_name,
                    ..
                },
            } if source_node_id.0 == "derived:sess-1:2:0:0"
                && node_id.0 == "artifact:path-content:/tmp/shared/build.sh"
                && path == "/tmp/shared/build.sh"
                && *relation == EdgeKind::Consumes
                && slot_name.as_deref() == Some("script_path")
                && normalized_command_name.as_deref() == Some("bash")
        )));
    }
}
