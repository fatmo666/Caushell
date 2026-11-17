//! Shared Git hook locations and event selection. No hook program is read here.
use super::ExecutionEnvironment;
use super::config_tasks::decoded_task_arguments;
use crate::path::{join_shell_path, normalize_shell_path};
use caushell_types::PathResolution;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHookKind {
    Commit,
    Am,
}

pub(crate) fn git_hook_stages(
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

#[derive(Debug, Clone)]
pub(crate) struct GitConfigSource {
    pub resolution: PathResolution,
    pub convention: &'static str,
    pub slot_name: &'static str,
}

/// The ordered native config search uses only this process's effective exports.
/// Unknown selection stays unresolved instead of selecting an entry-time file.
pub(crate) fn git_nonlocal_config_sources(
    environment: &ExecutionEnvironment,
    cwd: &str,
    system_config: Option<&str>,
) -> Vec<GitConfigSource> {
    fn source(
        value: Result<Option<&str>, String>,
        fallback: Option<&str>,
        cwd: &str,
        convention: &'static str,
        slot_name: &'static str,
    ) -> Option<GitConfigSource> {
        let resolution = match value {
            Ok(value) => {
                let path = value.or(fallback)?;
                if path.is_empty() {
                    return None;
                }
                PathResolution::Concrete {
                    path: if path.starts_with('/') {
                        normalize_shell_path(path)
                    } else {
                        join_shell_path(cwd, path)
                    },
                }
            }
            Err(text) => PathResolution::UnsupportedDynamicText { text },
        };
        Some(GitConfigSource {
            resolution,
            convention,
            slot_name,
        })
    }
    let mut sources = Vec::new();
    let selected_system = || {
        environment.scalar("GIT_CONFIG_SYSTEM").and_then(|path| {
        path.or(system_config).map(Some).ok_or_else(||
            "Git default system configuration depends on an unattested native build/runtime prefix".to_owned())
    })
    };
    let system = match environment.scalar("GIT_CONFIG_NOSYSTEM") {
        Ok(None | Some("" | "0" | "false" | "no" | "off")) => Some(selected_system()),
        Ok(Some(value))
            if ["1", "true", "yes", "on"]
                .iter()
                .any(|v| value.eq_ignore_ascii_case(v)) =>
        {
            None
        }
        Ok(Some(value))
            if ["false", "no", "off"]
                .iter()
                .any(|v| value.eq_ignore_ascii_case(v)) =>
        {
            Some(selected_system())
        }
        _ => Some(Err("Git system config selection is unresolved".into())),
    };
    if let Some(value) = system
        && let Some(item) = source(value, None, cwd, "git.system_config", "git_system_config")
    {
        sources.push(item);
    }
    match environment.scalar("GIT_CONFIG_GLOBAL") {
        Ok(None) => {
            let home = environment.scalar("HOME");
            let xdg = match environment.scalar("XDG_CONFIG_HOME") {
                Ok(None | Some("")) => home.clone().map(|v| {
                    v.filter(|v| !v.is_empty())
                        .map(|v| join_shell_path(v, ".config"))
                }),
                other => other.map(|v| v.map(str::to_owned)),
            };
            let xdg_path = xdg.map(|v| v.map(|v| join_shell_path(&v, "git/config")));
            if let Some(item) = source(
                xdg_path
                    .as_ref()
                    .map(|v| v.as_deref())
                    .map_err(Clone::clone),
                None,
                cwd,
                "git.global_config",
                "git_global_config_xdg",
            ) {
                sources.push(item);
            }
            let home_path = home.map(|v| {
                v.filter(|v| !v.is_empty())
                    .map(|v| join_shell_path(v, ".gitconfig"))
            });
            if let Some(item) = source(
                home_path
                    .as_ref()
                    .map(|v| v.as_deref())
                    .map_err(Clone::clone),
                None,
                cwd,
                "git.global_config",
                "git_global_config_home",
            ) {
                sources.push(item);
            }
        }
        value => {
            if let Some(item) = source(
                value,
                None,
                cwd,
                "git.global_config",
                "git_global_config_env",
            ) {
                sources.push(item);
            }
        }
    }
    sources
}

pub(crate) fn git_hook_slot_name(stage: &str) -> String {
    format!("git_hook_{}", stage.replace('-', "_"))
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
