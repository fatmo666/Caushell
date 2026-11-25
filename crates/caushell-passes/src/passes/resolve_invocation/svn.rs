use std::path::{Component, Path};

use caushell_profile::{
    EffectKind, EffectTarget, EnvironmentValueRef, ResidualKind, ResolveInvocationArtifactResult,
    SessionValue,
};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext};
use caushell_types::{
    DEFAULT_TEMPORARY_PATH_ROOTS, Evidence, EvidenceKind, RuleId, ShellKind,
    ToolConfigInputEvidence, ToolConfigInputStatus,
};

use super::ExpandedFrontierEntry;
use crate::support::ExecutionEnvironment;

// Plain local status reads the working copy. On POSIX its startup may create
// missing stock files under the account's default configuration directory.
// That initialization belongs to the protected static environment model.
pub(super) fn close_default_status_initialization(
    ctx: &mut RunnerContext,
    entry: &mut ExpandedFrontierEntry,
) {
    if !ctx.assumes_protected_defaults()
        || entry.shell_kind != ShellKind::Bash
        || entry.origin_kind != ExecutionUnitOriginKind::TopLevel
        || !matches!(&entry.result, ResolveInvocationArtifactResult::Resolved(resolved)
            if resolved.normalized_command_name == "svn"
                && resolved.bound.form_id.as_str() == "local_status"
                && resolved.bound.applied_modifiers.is_empty()
                && matches!(resolved.bound.residuals.as_slice(), [residual]
                    if residual.kind == ResidualKind::UnboundControlSurface
                        && residual.reason == "form local_status declares unresolved tool-owned operation semantics"))
    {
        return;
    }
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return;
    };
    if command.command_name.as_deref() != Some("svn")
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || !matches!(command.tokens.as_slice(), [token]
            if !token.runtime_data && !token.quoted
                && matches!(token.text.as_str(), "status" | "stat" | "st"))
    {
        return;
    }

    let request = ctx.request();
    let (Some(home), Some(workspace)) =
        (request.home.as_deref(), request.workspace_root.as_deref())
    else {
        return;
    };
    let clean_absolute = |path: &str| {
        path.starts_with('/')
            && !path.contains('\0')
            && !Path::new(path)
                .components()
                .any(|part| part == Component::ParentDir)
    };
    let config = Path::new(home).join(".subversion");
    let env =
        ExecutionEnvironment::for_command(&entry.bindings, &entry.parsed_scope, &entry.command_ref);
    let default_home = match env.value("HOME") {
        EnvironmentValueRef::Unknown => true,
        EnvironmentValueRef::Present(SessionValue::ExactScalar(value)) => value == home,
        _ => false,
    };
    if !default_home
        || request
            .shell_state_before
            .environment
            .iter()
            .any(|entry| entry.name == "HOME")
        || !clean_absolute(home)
        || !clean_absolute(workspace)
        || std::iter::once(workspace)
            .chain(DEFAULT_TEMPORARY_PATH_ROOTS.iter().copied())
            .chain(
                ctx.policy()
                    .mutation_path_exemptions
                    .iter()
                    .map(|entry| entry.root.as_str()),
            )
            .any(|root| config.starts_with(root))
    {
        return;
    }

    let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result else {
        return;
    };
    let bound = &mut resolved.bound;
    bound.residuals.clear();
    bound.operation_semantics_unresolved = false;
    bound.effects.retain(|effect| {
        !matches!(effect.kind, EffectKind::LoadConfig | EffectKind::WritePath)
            || !matches!(&effect.target, EffectTarget::ConfiguredPath(path)
                if matches!(path.sources.as_slice(), [source] if source.slot.as_str() == "config_dir"))
    });
    ctx.add_evidence(Evidence {
        rule_id: RuleId::SelectionError,
        summary: "protected default Subversion configuration initialization".into(),
        kind: EvidenceKind::ToolConfigInput(ToolConfigInputEvidence {
            node_id: entry.source_node_id.0.clone(),
            command: "svn".into(),
            input_id: "default_config".into(),
            source_index: 0,
            source: "static_environment_model".into(),
            path: config.to_str().map(str::to_owned),
            resolved_path: None,
            status: ToolConfigInputStatus::AssumedProtected,
            observations: Vec::new(),
            detail: "plain local status may initialize missing stock configuration in the default account directory".into(),
        }),
    });
}
