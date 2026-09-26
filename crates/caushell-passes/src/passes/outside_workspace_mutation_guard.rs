use std::collections::BTreeSet;

use caushell_parse::ParsedCommandArtifact;
use caushell_profile::EffectKind;
use caushell_runner::{EffectiveCwd, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{PathResolution, RuleId};

use crate::path::{
    MutationTargetCandidate, collect_effect_mutation_targets, collect_redirection_path_facts,
    normalize_shell_path, path_is_within_root, path_operand_depends_on_cwd,
};
use crate::support::{
    decision_for_rule_action, graph_backed_execution_resolve_records,
    is_file_write_redirection_operator, redirection_parent_command_index,
};

pub struct OutsideWorkspaceMutationGuardPass;

impl SessionAnalysisPass for OutsideWorkspaceMutationGuardPass {
    fn name(&self) -> &'static str {
        "outside_workspace_mutation_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let workspace_root = ctx
            .request()
            .workspace_root
            .as_deref()
            .filter(|root| root.starts_with('/'))
            .map(normalize_shell_path);
        let fallback_cwd = ctx.request().shell_state_before.cwd().to_string();
        let home = ctx.request().home.clone();
        let mut reasons = BTreeSet::new();

        for record in graph_backed_execution_resolve_records(ctx) {
            let cwd_options = effective_cwd_options(
                ctx.effective_cwd_for_node(record.source_node_id()),
                &fallback_cwd,
            );
            for cwd in cwd_options {
                let resolution_cwd = cwd.as_deref().unwrap_or(&fallback_cwd);
                let mut targets =
                    collect_effect_mutation_targets(record, resolution_cwd, home.as_deref());
                targets.extend(collect_redirection_mutation_targets(
                    record.parsed_scope(),
                    Some(record.command_index()),
                    resolution_cwd,
                    home.as_deref(),
                ));
                for target in targets {
                    add_reason_for_target(
                        &mut reasons,
                        target.operation,
                        &target.slot_name,
                        &target.resolution,
                        target.cwd_dependent,
                        cwd.is_none(),
                        workspace_root.as_deref(),
                    );
                }
            }
        }

        // A standalone redirection has no command invocation record.
        if let Some(parsed) = ctx.parsed_command() {
            for target in
                collect_redirection_mutation_targets(parsed, None, &fallback_cwd, home.as_deref())
            {
                add_reason_for_target(
                    &mut reasons,
                    target.operation,
                    &target.slot_name,
                    &target.resolution,
                    target.cwd_dependent,
                    false,
                    workspace_root.as_deref(),
                );
            }
        }

        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::OutsideWorkspaceMutation);
        for reason in reasons {
            ctx.add_finding(RuleId::OutsideWorkspaceMutation, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::OutsideWorkspaceMutation,
                    decision,
                    reason,
                );
            }
        }
    }
}

fn effective_cwd_options(effective: Option<&EffectiveCwd>, fallback: &str) -> Vec<Option<String>> {
    match effective {
        Some(cwd) if cwd.is_unreachable() => Vec::new(),
        Some(cwd) => {
            let mut options: Vec<Option<String>> = cwd
                .known_cwds()
                .iter()
                .map(|path| Some(path.to_string()))
                .collect();
            if cwd.has_unknown() || options.is_empty() {
                options.push(None);
            }
            options
        }
        None => vec![Some(fallback.to_string())],
    }
}

fn collect_redirection_mutation_targets(
    parsed: &ParsedCommandArtifact,
    command_index: Option<usize>,
    cwd: &str,
    home: Option<&str>,
) -> Vec<MutationTargetCandidate> {
    collect_redirection_path_facts(parsed, cwd, home)
        .into_iter()
        .filter(|path| redirection_parent_command_index(parsed, &path.fact) == command_index)
        .filter(|path| {
            path.fact.operator.as_deref().is_some_and(|operator| {
                is_file_write_redirection_operator(operator) || operator == "<>"
            })
        })
        .map(|path| MutationTargetCandidate {
            operation: EffectKind::WritePath,
            slot_name: path.slot_name,
            resolution: path.resolution,
            cwd_dependent: path.fact.target.as_ref().is_some_and(|target| {
                path_operand_depends_on_cwd(&target.text, target.quoted, &target.node_kind, None)
            }),
        })
        .collect()
}

fn add_reason_for_target(
    reasons: &mut BTreeSet<String>,
    operation: EffectKind,
    slot_name: &str,
    resolution: &PathResolution,
    cwd_dependent: bool,
    cwd_unknown: bool,
    workspace_root: Option<&str>,
) {
    // Both command effects (e.g. `tee /dev/null`) and shell redirections
    // discard writes to this sink. Do not exempt deletion or metadata changes.
    if operation == EffectKind::WritePath && resolution.concrete_path() == Some("/dev/null") {
        return;
    }
    let operation = operation_name(operation);
    if cwd_unknown && cwd_dependent {
        reasons.insert(format!(
            "{operation} target for slot {slot_name} has an unknown effective working directory"
        ));
        return;
    }

    let Some(root) = workspace_root else {
        reasons.insert(format!(
            "{operation} target for slot {slot_name} cannot be checked because workspace root is unavailable"
        ));
        return;
    };

    match resolution.concrete_path() {
        Some(path) if path.starts_with('/') && path_is_within_root(path, root) => {}
        Some(path) if path.starts_with('/') => {
            reasons.insert(format!(
                "{operation} target {path} for slot {slot_name} is outside workspace root {root}"
            ));
        }
        Some(path) => {
            reasons.insert(format!(
                "{operation} target {path} for slot {slot_name} is not an absolute resolved path"
            ));
        }
        None => {
            if let PathResolution::BoundedPathSet { roots, may_escape } = resolution {
                if *may_escape {
                    reasons.insert(format!(
                        "{operation} target for slot {slot_name} may escape its bounded path set"
                    ));
                    return;
                }
                if roots.is_empty() {
                    reasons.insert(format!(
                        "{operation} target for slot {slot_name} has an empty or unknown path bound"
                    ));
                    return;
                }
                for path in roots {
                    let normalized = normalize_shell_path(path);
                    if !path_is_within_root(&normalized, root) {
                        reasons.insert(format!(
                            "{operation} target may be outside workspace root {root} through bounded path {path}"
                        ));
                    }
                }
                return;
            }
            reasons.insert(format!(
                "{operation} target for slot {slot_name} cannot be resolved: {resolution:?}"
            ));
        }
    }
}

fn operation_name(kind: EffectKind) -> &'static str {
    match kind {
        EffectKind::WritePath => "write",
        EffectKind::DeletePath => "delete",
        EffectKind::MovePath => "move source",
        EffectKind::ChangeMode
        | EffectKind::ChangeOwner
        | EffectKind::ChangeGroup
        | EffectKind::MetadataMutation => "metadata mutation",
        _ => unreachable!("only mutation effects are collected"),
    }
}
