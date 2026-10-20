//! Shared Git hook locations and event selection. No hook program is read here.
use super::config_tasks::decoded_task_arguments;
use crate::path::{join_shell_path, normalize_shell_path};
use caushell_types::{DerivedPathBasis, DerivedPathRule, PathResolution, ShellValueSnapshot};
use std::fs;

pub(crate) fn hook_language(body: &str) -> caushell_profile::PayloadLanguage {
    use caushell_profile::PayloadLanguage;
    if body.contains('\0') || body.starts_with("\u{7f}ELF") {
        return PayloadLanguage::Opaque;
    }
    let Some(line) = body.strip_prefix("#!") else {
        return PayloadLanguage::Sh;
    };
    let words = line
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    let words = if words.first() == Some(&"/usr/bin/env") {
        &words[1..]
    } else {
        &words[..]
    };
    let Some(program) = words.first() else {
        return PayloadLanguage::Opaque;
    };
    if words
        .iter()
        .skip(1)
        .any(|word| !matches!(*word, "-e" | "-u" | "-eu" | "-ue" | "-x" | "--"))
    {
        return PayloadLanguage::Opaque;
    }
    match *program {
        "/bin/sh" | "/usr/bin/sh" | "sh" | "/bin/dash" | "/usr/bin/dash" | "dash" => {
            PayloadLanguage::Sh
        }
        "/bin/bash" | "/usr/bin/bash" | "bash" => PayloadLanguage::Bash,
        _ => PayloadLanguage::Opaque,
    }
}

pub(crate) fn hook_kind(bound: &caushell_profile::BoundInvocation) -> Option<GitHookKind> {
    if !bound.effects.iter().any(|e| matches!(&e.target, caushell_profile::EffectTarget::ToolConventionPath(t) if e.kind == caushell_profile::EffectKind::LoadConfig && t.convention == "git.local_config")) { return None }
    match bound.subcommand_path.as_slice() {
        [sub] if sub == "commit" => Some(GitHookKind::Commit),
        [sub] if sub == "am" => Some(GitHookKind::Am),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GitHookPath {
    pub stage: &'static str,
    pub resolution: PathResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHookKind {
    Commit,
    Am,
}

#[derive(Debug, Clone)]
struct GitHooksRoot {
    path: String,
    config_path: String,
    convention: String,
}

pub(crate) fn resolve_git_hook_paths(
    request: &caushell_types::CheckRequest,
    local_config_path: &str,
    cwd: &str,
    invocation: &caushell_profile::BoundInvocation,
    kind: GitHookKind,
) -> Vec<GitHookPath> {
    resolve_git_hook_paths_with(request, local_config_path, cwd, invocation, kind, |_| None)
}

pub(crate) fn resolve_git_hook_paths_with(
    request: &caushell_types::CheckRequest,
    local_config_path: &str,
    cwd: &str,
    invocation: &caushell_profile::BoundInvocation,
    kind: GitHookKind,
    mut observed_config: impl FnMut(&str) -> Option<String>,
) -> Vec<GitHookPath> {
    let mut hook_root =
        effective_git_hooks_root(request, local_config_path, cwd, &mut observed_config)
            .unwrap_or_else(|| {
                let config_dir = parent_dir_or_cwd(local_config_path, cwd);
                GitHooksRoot {
                    path: join_shell_path(&config_dir, "hooks"),
                    config_path: normalize_shell_path(local_config_path),
                    convention: "git.default_hooks".to_string(),
                }
            });

    let Some(overrides) = decoded_task_arguments(invocation, "configuration_overrides") else {
        return git_hook_stages(invocation, kind)
            .into_iter()
            .map(|stage| GitHookPath {
                stage,
                resolution: PathResolution::UnsupportedDynamicText {
                    text: "Git configuration override is unresolved".into(),
                },
            })
            .collect();
    };
    for item in overrides {
        let (key, value) = item.split_once('=').unwrap_or((&item, ""));
        if key.eq_ignore_ascii_case("core.hooksPath") {
            hook_root = GitHooksRoot {
                path: resolve_git_hooks_root_path(value, cwd),
                config_path: local_config_path.to_owned(),
                convention: "git.command_config".into(),
            };
        }
    }
    if hook_root.path == "/dev/null" {
        return Vec::new();
    }

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
    observed_config: &mut impl FnMut(&str) -> Option<String>,
) -> Option<GitHooksRoot> {
    let repo_root = git_repo_root_from_local_config(local_config_path, cwd);
    let mut root = None;

    for source in git_config_sources(request, local_config_path) {
        let hooks_path = match observed_config(&source.path) {
            Some(content) => parse_git_config_hooks_path(&content),
            None => load_git_hooks_path(&source.path),
        };
        if let Some(hooks_path) = hooks_path {
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
pub(crate) struct GitConfigSource {
    pub path: String,
    pub convention: &'static str,
    pub slot_name: &'static str,
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

pub(crate) fn git_nonlocal_config_sources(
    request: &caushell_types::CheckRequest,
) -> Vec<GitConfigSource> {
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

pub(crate) fn git_hook_slot_name(stage: &str) -> String {
    format!("git_hook_{}", stage.replace('-', "_"))
}

pub(crate) fn hook_task_name(stage: &str) -> String {
    format!("git-hook:{stage}")
}

pub(crate) fn project_resolved_hook_inputs(
    paths: &mut Vec<GitHookPath>,
    ctx: &caushell_runner::RunnerContext,
    source: &caushell_graph::NodeId,
    command_index: usize,
) {
    let mut roots = Vec::new();
    for record in ctx.nested_payload_records() {
        let matches_parent = match &record.parent_ref {
            caushell_runner::NestedPayloadParentRef::RootCommand { command_index: i } => {
                *i == command_index
                    && ctx.execution_unit_resolve_records().iter().any(|r| {
                        r.source_node_id == *source
                            && r.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    })
            }
            caushell_runner::NestedPayloadParentRef::DerivedInvocation { node_id } => {
                node_id == source
            }
        };
        if !matches_parent
            || !matches!(
                record.candidate.candidate.input,
                caushell_profile::RecursivePayloadInput::LiteralText { .. }
            )
        {
            continue;
        }
        let caushell_profile::RecursivePayloadOrigin::ConfigDefinedTask {
            config_path,
            task_name,
        } = &record.candidate.candidate.origin
        else {
            continue;
        };
        for path in paths.iter() {
            if *task_name != hook_task_name(path.stage) {
                continue;
            }
            if let Some(root) = config_path.strip_suffix(&format!("/{}", path.stage)) {
                if !roots.contains(&root.to_owned()) {
                    roots.push(root.to_owned())
                }
            }
        }
    }
    if roots.is_empty() {
        return;
    }
    let mut projected = Vec::new();
    for root in roots {
        for path in paths.iter() {
            projected.push(GitHookPath {
                stage: path.stage,
                resolution: PathResolution::Concrete {
                    path: join_shell_path(&root, path.stage),
                },
            });
        }
    }
    *paths = projected;
}

pub(crate) fn observed_repository_root(
    cwd: &str,
    observations: &[(
        caushell_profile::ResolveInvocationArtifactResult,
        caushell_profile::SessionBindings,
    )],
    cwds: &[caushell_runner::EffectiveCwd],
) -> Option<String> {
    let mut roots = Vec::new();
    for (i, (result, _)) in observations.iter().enumerate() {
        let caushell_profile::ResolveInvocationArtifactResult::Resolved(resolved) = result else {
            continue;
        };
        if resolved.normalized_command_name != "git"
            || resolved.bound.form_id.as_str() != "initialize_repository"
        {
            continue;
        }
        let Some(caushell_runner::EffectiveCwd::Known(base)) = cwds.get(i) else {
            continue;
        };
        let Some(paths) = decoded_task_arguments(&resolved.bound, "init_directory") else {
            continue;
        };
        let root = paths.first().map_or_else(
            || normalize_shell_path(base),
            |path| {
                if path.starts_with('/') {
                    normalize_shell_path(path)
                } else {
                    join_shell_path(base, path)
                }
            },
        );
        if cwd == root
            || cwd
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            roots.push(root)
        }
    }
    roots.into_iter().max_by_key(String::len)
}

pub(crate) fn hook_explicitly_nonexecutable(
    path: &str,
    parsed: &caushell_parse::ParsedCommandArtifact,
    before_command_index: usize,
    observations: &[(
        caushell_profile::ResolveInvocationArtifactResult,
        caushell_profile::SessionBindings,
    )],
    cwds: &[caushell_runner::EffectiveCwd],
    home: Option<&str>,
    initial: bool,
) -> bool {
    let mut disabled = initial;
    for (i, (result, _)) in observations.iter().take(before_command_index).enumerate() {
        let caushell_profile::ResolveInvocationArtifactResult::Resolved(resolved) = result else {
            disabled = false;
            continue;
        };
        let command = &parsed.commands[i];
        if resolved.bound.effects.iter().any(|e| {
            matches!(
                e.kind,
                caushell_profile::EffectKind::ExecutePayload
                    | caushell_profile::EffectKind::ExecuteHook
                    | caushell_profile::EffectKind::DispatchCommand
                    | caushell_profile::EffectKind::ExecuteConfigDefinedTask
                    | caushell_profile::EffectKind::SourceScriptIntoCurrentShell
            )
        }) {
            disabled = false;
        }
        let Some(caushell_runner::EffectiveCwd::Known(cwd)) = cwds.get(i) else {
            disabled = false;
            continue;
        };
        if crate::path::collect_invocation_mutation_targets(result, None, cwd, home)
            .iter()
            .any(|t| {
                matches!(
                    t.operation,
                    caushell_profile::EffectKind::WritePath
                        | caushell_profile::EffectKind::MovePath
                        | caushell_profile::EffectKind::DeletePath
                ) && t.resolution.concrete_path().is_none_or(|p| {
                    p == path
                        || path
                            .strip_prefix(p)
                            .is_some_and(|tail| tail.starts_with('/'))
                })
            })
        {
            disabled = false;
        }
        for effect in &resolved.bound.effects {
            if effect.kind != caushell_profile::EffectKind::ChangeMode {
                continue;
            }
            let caushell_profile::EffectTarget::Slot(slot) = &effect.target else {
                continue;
            };
            let Some(targets) = decoded_task_arguments(&resolved.bound, slot.as_str()) else {
                disabled = false;
                continue;
            };
            if !targets.iter().any(|p| {
                (if p.starts_with('/') {
                    normalize_shell_path(p)
                } else {
                    join_shell_path(cwd, p)
                }) == path
            }) {
                continue;
            }
            if command.in_pipeline
                || command.guarded
                || command.conditional_execution
                || command.control_flow_span.is_some()
                || command.terminator == Some(caushell_parse::StatementTerminator::Background)
            {
                disabled = false;
                continue;
            }
            let mode = effect
                .extensions
                .get("metadata_mutation.raw_operand_slot")
                .and_then(|s| s.as_str())
                .and_then(|slot| decoded_task_arguments(&resolved.bound, slot))
                .and_then(|v| v.first().cloned());
            disabled = mode.as_deref().is_some_and(|mode| {
                if !mode.is_empty() && mode.chars().all(|c| matches!(c, '0'..='7')) {
                    u32::from_str_radix(mode, 8).is_ok_and(|n| n & 0o111 == 0)
                } else {
                    matches!(mode, "a-x" | "ugo-x" | "a=" | "a=r" | "a=rw")
                }
            });
        }
    }
    disabled
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

pub(crate) fn git_effective_cwd(
    cwd: &str,
    invocation: &caushell_profile::BoundInvocation,
) -> String {
    if !invocation_has_modifier(invocation, "work_tree") {
        return normalize_shell_path(cwd);
    }

    decoded_task_arguments(invocation, "working_directory")
        .and_then(|paths| {
            paths.last().map(|text| {
                if text.starts_with('/') {
                    normalize_shell_path(text)
                } else {
                    join_shell_path(cwd, text)
                }
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
