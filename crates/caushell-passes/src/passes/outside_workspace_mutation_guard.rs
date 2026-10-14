use std::collections::BTreeSet;

use caushell_parse::ParsedCommandArtifact;
use caushell_profile::EffectKind;
use caushell_query::IoTarget;
use caushell_runner::{CwdPathContext, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    MutationExemptionOperation, MutationPathExemption, PathMetadataMutationKind, PathResolution,
    RuleId,
};

use crate::path::{
    MutationTargetCandidate, collect_effect_mutation_targets, collect_redirection_path_facts,
    effective_cwd_cases, normalize_shell_path, path_is_within_root, project_path_at_cwd,
};
use crate::support::{
    bound_invocation, content_io_target, decision_for_rule_action,
    graph_backed_execution_resolve_records, is_file_write_redirection_operator,
    redirection_parent_command_index, slot_uses_content_open,
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
        let exemptions = &ctx.policy().mutation_path_exemptions;

        for record in graph_backed_execution_resolve_records(ctx) {
            let home = record.bindings().tilde_home_with_default(home.as_deref());
            for (effective_cwd, redirections) in [
                (ctx.execution_cwd_for_node(record.source_node_id()), false),
                (ctx.effective_cwd_for_node(record.source_node_id()), true),
            ] {
                for case in effective_cwd_cases(effective_cwd, &fallback_cwd) {
                    let resolution_cwd = case.resolution_base(&fallback_cwd);
                    let targets = if redirections {
                        collect_redirection_mutation_targets(
                            record.parsed_scope(),
                            Some(record.command_index()),
                            resolution_cwd,
                            home,
                        )
                    } else {
                        collect_effect_mutation_targets(record, resolution_cwd, home)
                    };
                    for target in targets {
                        let exemption_operation = exemption_operation_for_target(&target);
                        if !redirections
                            && target.operation == EffectKind::WritePath
                            && target.resolution.concrete_path().is_some_and(|path| {
                                path == "/dev/null"
                                    || caushell_query::IoTargetQuery::descriptor_alias(path)
                                        .is_some()
                            })
                            && bound_invocation(record.result()).is_some_and(|bound| {
                                slot_uses_content_open(bound, &target.slot_name, target.operation)
                            })
                        {
                            let shell_cwd = ctx.effective_cwd_for_node(record.source_node_id());
                            // A tool-local chdir must not change the interpretation
                            // of a relative file opened earlier by the caller shell.
                            let entries = effective_cwd_cases(shell_cwd, &fallback_cwd);
                            for entry in entries {
                                let io = content_io_target(
                                    record.parsed_scope(),
                                    Some(record.command_index()),
                                    None,
                                    &target.resolution,
                                    target.cwd_dependent,
                                    entry.resolution_base(&fallback_cwd),
                                    home,
                                );
                                if let Some((resolution, dependent)) = mutation_path_for_io(io) {
                                    let resolution =
                                        project_path_at_cwd(resolution, dependent, entry);
                                    add_reason_for_target(
                                        &mut reasons,
                                        target.operation,
                                        &target.slot_name,
                                        &resolution,
                                        dependent,
                                        matches!(entry, CwdPathContext::Unknown),
                                        workspace_root.as_deref(),
                                        exemptions,
                                        exemption_operation,
                                    );
                                }
                            }
                            continue;
                        }
                        // Only a declaratively identified implicit cache fallback
                        // is exempt. Explicit, unknown argv paths and redirections
                        // cannot acquire this exemption from their purpose alone.
                        if target.operation == EffectKind::WritePath
                            && target.implicit_incidental_cache
                            && target.resolution.concrete_path().is_none()
                        {
                            continue;
                        }
                        let resolution =
                            project_path_at_cwd(target.resolution, target.cwd_dependent, case);
                        add_reason_for_target(
                            &mut reasons,
                            target.operation,
                            &target.slot_name,
                            &resolution,
                            target.cwd_dependent,
                            matches!(case, CwdPathContext::Unknown),
                            workspace_root.as_deref(),
                            exemptions,
                            exemption_operation,
                        );
                    }
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
                    exemptions,
                    exemption_operation_for_target(&target),
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
        .filter_map(|path| {
            let io = content_io_target(
                parsed,
                command_index,
                Some(path.redirection_index),
                &path.resolution,
                path.cwd_dependent,
                cwd,
                home,
            );
            let (resolution, cwd_dependent) = mutation_path_for_io(io)?;
            Some(MutationTargetCandidate {
                metadata_mutation: None,
                implicit_incidental_cache: false,
                operation: EffectKind::WritePath,
                slot_name: path.slot_name,
                resolution,
                cwd_dependent,
            })
        })
        .collect()
}

fn mutation_path_for_io(target: IoTarget) -> Option<(PathResolution, bool)> {
    match target {
        IoTarget::Path {
            resolution,
            cwd_dependent,
        } => Some((resolution, cwd_dependent)),
        IoTarget::UnknownDescriptor { descriptor } => Some((
            PathResolution::UnsupportedDynamicText {
                text: format!("unknown file descriptor {descriptor} target"),
            },
            false,
        )),
        IoTarget::InlineContent { .. } => Some((
            PathResolution::UnsupportedDynamicText {
                text: "write through an inline-content descriptor has no known filesystem target"
                    .into(),
            },
            false,
        )),
        IoTarget::InheritedDescriptor { .. }
        | IoTarget::ProcessSubstitution { .. }
        | IoTarget::Closed
        | IoTarget::Discard => None,
    }
}

fn add_reason_for_target(
    reasons: &mut BTreeSet<String>,
    operation: EffectKind,
    slot_name: &str,
    resolution: &PathResolution,
    cwd_dependent: bool,
    cwd_unknown: bool,
    workspace_root: Option<&str>,
    exemptions: &[MutationPathExemption],
    exemption_operation: Option<MutationExemptionOperation>,
) {
    // Content-open sinks have already been classified by the shared I/O query.
    // Namespace operations must never inherit a device-path exemption.
    let operation = operation_name(operation);
    if cwd_unknown && cwd_dependent {
        reasons.insert(format!(
            "{operation} target for slot {slot_name} has an unknown effective working directory"
        ));
        return;
    }

    if exemption_operation
        .is_some_and(|operation| resolution_is_exempt(resolution, operation, exemptions))
    {
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
            if let PathResolution::FileNamePrefix { directory, .. } = resolution {
                if !directory.starts_with('/')
                    || !path_is_within_root(&normalize_shell_path(directory), root)
                {
                    reasons.insert(format!("{operation} filename family for slot {slot_name} is outside workspace root {root} through directory {directory}"));
                }
                return;
            }
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
                    if !path_is_within_root(&normalized, root)
                        && !exemption_operation.is_some_and(|operation| {
                            resolution_is_exempt(
                                &PathResolution::Concrete {
                                    path: normalized.clone(),
                                },
                                operation,
                                exemptions,
                            )
                        })
                    {
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

fn exemption_operation_for_target(
    target: &MutationTargetCandidate,
) -> Option<MutationExemptionOperation> {
    if target.operation == EffectKind::WritePath {
        return Some(MutationExemptionOperation::Write);
    }
    let mutation = target.metadata_mutation.as_ref()?;
    if mutation.mutation_kinds.is_empty()
        || !mutation.mutation_kinds.iter().all(|kind| match kind {
            PathMetadataMutationKind::ChangeMode => mutation
                .raw_operand
                .as_deref()
                .is_some_and(ordinary_permission_mode),
            PathMetadataMutationKind::ChangeOwner | PathMetadataMutationKind::ChangeGroup => true,
            PathMetadataMutationKind::Generic => false,
        })
    {
        return None;
    }
    Some(MutationExemptionOperation::OrdinaryMetadata)
}

fn resolution_is_exempt(
    resolution: &PathResolution,
    operation: MutationExemptionOperation,
    exemptions: &[MutationPathExemption],
) -> bool {
    let path_is_exempt = |path: &str| {
        path.starts_with('/')
            && exemptions.iter().any(|entry| {
                entry.root.starts_with('/')
                    && !entry.root.contains('\0')
                    && entry.operations.contains(&operation)
                    && path_is_within_root(path, &entry.root)
            })
    };
    if let Some(path) = resolution.concrete_path() {
        return path_is_exempt(path);
    }
    match resolution {
        PathResolution::FileNamePrefix { directory, .. } => path_is_exempt(directory),
        PathResolution::BoundedPathSet {
            roots,
            may_escape: false,
        } => !roots.is_empty() && roots.iter().all(|root| path_is_exempt(root)),
        _ => false,
    }
}

// The existing metadata fact supplies the operand. This is a permission-mode
// check, not a command-name switch or a new interpretation of Profile syntax.
fn ordinary_permission_mode(mode: &str) -> bool {
    let numeric = mode.strip_prefix(['+', '-']).unwrap_or(mode);
    if !numeric.is_empty() && numeric.bytes().all(|b| matches!(b, b'0'..=b'7')) {
        return u32::from_str_radix(numeric, 8)
            .is_ok_and(|bits| bits <= 0o7777 && bits & 0o6000 == 0);
    }
    mode.split(',').all(|clause| {
        let bytes = clause.as_bytes();
        let mut index = 0;
        while index < bytes.len() && matches!(bytes[index], b'u' | b'g' | b'o' | b'a') {
            index += 1;
        }
        let mut saw_operation = false;
        while index < bytes.len() {
            let action = bytes[index];
            if !matches!(action, b'+' | b'-' | b'=') {
                return false;
            }
            saw_operation = true;
            index += 1;
            while index < bytes.len() && !matches!(bytes[index], b'+' | b'-' | b'=') {
                if !matches!(
                    bytes[index],
                    b'r' | b'w' | b'x' | b'X' | b's' | b't' | b'u' | b'g' | b'o'
                ) || (bytes[index] == b's' && action != b'-')
                {
                    return false;
                }
                index += 1;
            }
        }
        saw_operation
    })
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

#[cfg(test)]
mod exemption_tests {
    use super::*;
    use caushell_types::default_mutation_path_exemptions;

    #[test]
    fn permission_modes_preserve_special_and_unknown_boundaries() {
        for mode in [
            "600", "0755", "1755", "u+rw,g-w", "+x", "u-s", "a=rw", "u=g",
        ] {
            assert!(ordinary_permission_mode(mode), "{mode}");
        }
        for mode in [
            "4755", "2755", "6755", "u+s", "a=rwxs", "u+s,g-s", "$MODE", "garbage", "999", "",
            "600,",
        ] {
            assert!(!ordinary_permission_mode(mode), "{mode}");
        }
    }

    #[test]
    fn exemption_requires_every_known_bound_and_no_escape() {
        let exemptions = default_mutation_path_exemptions();
        let scope = |roots: &[&str], may_escape| PathResolution::BoundedPathSet {
            roots: roots.iter().map(|s| (*s).into()).collect(),
            may_escape,
        };
        assert!(resolution_is_exempt(
            &scope(&["/tmp/a", "/private/tmp/b"], false),
            MutationExemptionOperation::Write,
            &exemptions
        ));
        for resolution in [
            scope(&[], false),
            scope(&["/tmp/a"], true),
            scope(&["/tmp/a", "/etc/b"], false),
            PathResolution::UnsupportedDynamicText {
                text: "/tmp/$UNKNOWN".into(),
            },
        ] {
            assert!(!resolution_is_exempt(
                &resolution,
                MutationExemptionOperation::Write,
                &exemptions
            ));
        }
        let mut reasons = BTreeSet::new();
        add_reason_for_target(
            &mut reasons,
            EffectKind::WritePath,
            "test",
            &scope(&["/tmp/a", "/workspace/b"], false),
            false,
            false,
            Some("/workspace"),
            &exemptions,
            Some(MutationExemptionOperation::Write),
        );
        assert!(reasons.is_empty(), "{reasons:?}");
    }
}
