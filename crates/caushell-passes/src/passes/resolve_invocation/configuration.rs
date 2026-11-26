use caushell_profile::{
    Effect, EffectKind, EffectTarget, ImplicitConfigSource, NativeConfigurationSyntax,
    ProfileRegistry, ProtectedAccountDefaults, ResidualKind, ResolveInvocationArtifactResult,
};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext, SessionView};
use caushell_types::{CheckRequest, Evidence, EvidenceKind, RuleId, ShellKind};

use super::{ExpandedFrontierEntry, ProgramSourceContext};
use crate::passes::configuration_policy::{protected_account_defaults, registered_defaults};
use crate::path::namespace::NamespaceResolver;
use crate::support::ExecutionEnvironment;

/// Dispatch the native loader declared by the selected Profile.
pub(super) fn resolve_native_configuration(
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
    let native = registry
        .lookup(&resolved.normalized_command_name)
        .profile
        .and_then(|profile| profile.native_configuration);
    if native == Some(NativeConfigurationSyntax::Git) {
        super::git::refresh(registry, session, request, entry, context, ctx);
    }
}

/// Interpret only Profile registrations for known stock initialization.
/// Other configurations retain their normal bound load and write effects.
pub(super) fn resolve_stock_initialization(
    registry: &ProfileRegistry,
    ctx: &mut RunnerContext,
    entry: &mut ExpandedFrontierEntry,
) {
    if !ctx.assumes_protected_defaults()
        || entry.shell_kind != ShellKind::Bash
        || entry.origin_kind != ExecutionUnitOriginKind::TopLevel
    {
        return;
    }
    let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result else {
        return;
    };
    let Some(profile) = registry.lookup(&resolved.normalized_command_name).profile else {
        return;
    };
    let Some(command) = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)
    else {
        return;
    };
    let [token] = command.tokens.as_slice() else {
        return;
    };
    let bound = &mut resolved.bound;
    if command.command_name.as_deref() != Some(resolved.normalized_command_name.as_str())
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || token.runtime_data
        || token.quoted
        || !bound.applied_modifiers.is_empty()
    {
        return;
    }

    for input in &profile.implicit_config_files {
        let Some(ProtectedAccountDefaults::StockInitialization {
            form,
            sole_argument,
            config_slot,
        }) = registered_defaults(profile, input)
        else {
            continue;
        };
        if bound.form_id.as_str() != form || !sole_argument.contains(&token.text) {
            continue;
        }
        let declared_gap =
            format!("form {form} declares unresolved tool-owned operation semantics");
        if !matches!(bound.residuals.as_slice(), [residual]
            if residual.kind == ResidualKind::UnboundControlSurface && residual.reason == declared_gap)
        {
            continue;
        }
        let [ImplicitConfigSource::AccountHome { suffix }] = input.sources.as_slice() else {
            continue;
        };
        let matches_effect = |effect: &Effect| {
            matches!(&effect.target, EffectTarget::ConfiguredPath(path)
                if matches!(path.sources.as_slice(), [source] if source.slot.as_str() == config_slot))
        };
        if ![EffectKind::LoadConfig, EffectKind::WritePath]
            .iter()
            .all(|kind| {
                bound
                    .effects
                    .iter()
                    .any(|effect| &effect.kind == kind && matches_effect(effect))
            })
        {
            continue;
        }

        let environment = ExecutionEnvironment::for_command(
            &entry.bindings,
            &entry.parsed_scope,
            &entry.command_ref,
        );
        let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
        let Some(paths) =
            protected_account_defaults(ctx, &environment, &mut namespace, [(0, suffix.as_str())])
        else {
            continue;
        };
        let Some(config) = paths.into_iter().next() else {
            continue;
        };

        bound.residuals.clear();
        bound.operation_semantics_unresolved = false;
        bound.effects.retain(|effect| {
            !matches!(effect.kind, EffectKind::LoadConfig | EffectKind::WritePath)
                || !matches_effect(effect)
        });
        let detail = "registered stock initialization belongs to the protected static baseline";
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: detail.into(),
            kind: EvidenceKind::ToolConfigInput(config.evidence(
                entry.source_node_id.0.clone(),
                profile.primary_name(),
                &input.id,
                detail,
            )),
        });
        break;
    }
}
