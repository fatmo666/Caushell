//! Optional byte recovery must not replace a closed symbolic effect proof.
use caushell_profile::{
    CommandProfile, Effect, EffectKind, ProfileRegistry, ResolveInvocationArtifactResult,
    ResolvedInvocationArtifact, bind_invocation, select_invocation,
};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext};
use caushell_types::NativeInputEffectEvidence;

pub(super) fn read_effect(effect: &Effect) -> bool {
    matches!(
        effect.kind,
        EffectKind::ReadPath | EffectKind::ConsumeStdin | EffectKind::TransformData
    ) && effect.catastrophic.semantic_class.is_none()
        && effect.host_risk.semantic_class.is_none()
        && effect.namespace_effect.is_none()
        && effect.state_operation.is_none()
        && effect.repository_operation.is_none()
        && effect.database_operation.is_none()
        && effect.terminal_session_operation.is_none()
        && effect.shell_job_operation.is_none()
        && effect.interactive_escape_surface.is_none()
}

/// A flat native data reader, not a command-name allowlist. Every declared mode
/// must remain read/data-only; config, argument files and code projections need
/// their own proofs. Strict rebinding accounts for ALL argv even for a legacy
/// profile that does not escalate every residual in ordinary resolution.
pub(super) fn reader_profile(profile: &CommandProfile) -> bool {
    if profile.subcommands.is_some()
        || !profile.dispatch_overrides.is_empty()
        || !profile.argument_regions.is_empty()
        || !profile.argument_files.is_empty()
        || !profile.environment_inputs.is_empty()
        || profile.option_environment.is_some()
        || profile.archive_extraction.is_some()
        || !profile.implicit_config_files.is_empty()
        || profile.configuration_files.is_some()
        || profile.native_configuration.is_some()
        || profile.forms.iter().any(|f| {
            f.operation_semantics_unresolved
                || !f.payload_projections.is_empty()
                || f.effects.iter().any(|e| !read_effect(e))
        })
        || profile
            .modifiers
            .iter()
            .any(|m| m.effects.iter().any(|e| !read_effect(e)))
        || !profile.selection_failure_effects.is_empty()
    {
        return false;
    }
    true
}
fn closed_reader(profile: &CommandProfile, resolved: &ResolvedInvocationArtifact) -> bool {
    if !reader_profile(profile)
        || resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
        || resolved.bound.effects.iter().any(|e| !read_effect(e))
    {
        return false;
    }
    if resolved.bound.native_read_envelope {
        return true;
    }
    let mut audited = profile.clone();
    audited.opaque_on_unresolved = true;
    audited.read_only_control_surface = false;
    let argv = &resolved.materialized_projection.invocation;
    let Ok(selection) = select_invocation(&audited, argv) else {
        return false;
    };
    // A legacy remaining-positionals binder may consume a runtime tail even
    // when its bytes could be options. Require a per-field non-option bound,
    // or an owned native terminator. A textual -- may instead be an option's
    // operand (e.g. grep -e --); it cannot manufacture an ownership proof.
    // Legacy grammars without a terminator certificate keep the stronger bound.
    let mut after_options = false;
    for (index, arg) in argv.args.iter().enumerate() {
        let shape = caushell_profile::argument_structure(arg);
        if shape.exact_value() == Some("--") && selection.option_terminators.contains(&index) {
            after_options = true;
        } else if !after_options
            && shape.exact_value().is_none()
            && (shape.fields == caushell_profile::ArgumentFieldCount::Unknown
                || shape.may_start_with("-")
                || shape.may_start_with("+"))
        {
            return false;
        }
    }
    let bound = bind_invocation(&audited, argv, &selection);
    bound.form_id == resolved.bound.form_id
        && !bound.operation_semantics_unresolved
        && bound.residuals.is_empty()
        && bound.effects.iter().all(read_effect)
}

pub(super) fn prove(
    ctx: &RunnerContext,
    registry: &ProfileRegistry,
    node: &str,
    producer: &str,
    gap: &str,
) -> Option<NativeInputEffectEvidence> {
    let records = ctx.execution_unit_resolve_records();
    let parent = records.iter().find(|r| r.source_node_id.0 == node)?;
    let ResolveInvocationArtifactResult::Resolved(resolved) = &parent.result else {
        return None;
    };
    if resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
        || resolved
            .bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "arg_file")
    {
        return None;
    }
    let children = records
        .iter()
        .filter(|r| r.source_node_id.0 != node && r.parent_execution_node_id.0 == node)
        .collect::<Vec<_>>();
    if children.is_empty() {
        return None;
    }
    for child in &children {
        if child.origin_kind != ExecutionUnitOriginKind::StaticXargs
            || records
                .iter()
                .any(|r| r.parent_execution_node_id == child.source_node_id)
        {
            return None;
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) = &child.result else {
            return None;
        };
        let profile = registry.lookup(&resolved.normalized_command_name).profile?;
        if !closed_reader(profile, resolved) {
            return None;
        }
    }
    Some(NativeInputEffectEvidence {
        control_envelope: children.iter().any(|c|matches!(&c.result,ResolveInvocationArtifactResult::Resolved(r) if r.bound.native_read_envelope)),
        node_id: node.into(),
        producer_node_id: producer.into(),
        child_node_ids: children
            .iter()
            .map(|r| r.source_node_id.0.clone())
            .collect(),
        observation_gap: gap.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_runner::{PassRunner, SessionView};
    use caushell_types::*;

    fn context(registry: &ProfileRegistry, command: &str) -> RunnerContext {
        let mut ctx = RunnerContext::new(CheckRequest {
            session_id: SessionId::new("symbolic-audit"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/work"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/work".into()),
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        });
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(registry.clone()));
        let graph = caushell_graph::SessionGraph::new();
        let summary = SessionSummary::default();
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }
    fn proof_count(ctx: &RunnerContext) -> usize {
        ctx.evidence
            .iter()
            .filter(|e| matches!(e.kind, EvidenceKind::NativeInputEffect(_)))
            .count()
    }
    fn reader_registry(mut edit: impl FnMut(&mut CommandProfile)) -> ProfileRegistry {
        let registry = ProfileRegistry::built_in().unwrap();
        let mut profiles = registry.profiles().to_vec();
        let mut reader = registry.lookup("cat").profile.unwrap().clone();
        reader.identity.canonical_name = caushell_profile::CommandName::new("fixture_reader");
        reader.identity.aliases.clear();
        edit(&mut reader);
        profiles.push(reader);
        ProfileRegistry::from_profiles(profiles).unwrap()
    }
    #[test]
    fn strict_audit_is_based_on_contracts_not_reader_names() {
        let registry = reader_registry(|_| {});
        let ctx = context(
            &registry,
            "find /unobserved-input -print0 | xargs -0 fixture_reader --",
        );
        assert_eq!(proof_count(&ctx), 1);
    }
    #[test]
    fn total_control_contract_is_generic_and_carries_no_output_shape_claim() {
        let registry = reader_registry(|_| {});
        let ctx = context(
            &registry,
            "find /unobserved-input -print | xargs fixture_reader",
        );
        let child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find_map(|r| match &r.result {
                ResolveInvocationArtifactResult::Resolved(r) if r.bound.native_read_envelope => {
                    Some(r)
                }
                _ => None,
            })
            .unwrap();
        assert!(child.bound.stdout_scalar.is_none());
        assert!(child.bound.stdout_records.is_none());
        assert!(child.proven_stdout_growth().is_none());
        let stream = child.proven_stream_contract().unwrap();
        assert_eq!(stream.stdout_dependency, StreamDataDependency::Inputs);
        assert_eq!(stream.stderr_dependency, StreamDataDependency::Inputs);
        assert!(
            ctx.evidence.iter().any(
                |e| matches!(&e.kind, EvidenceKind::NativeInputEffect(p) if p.control_envelope)
            )
        );
    }
    #[test]
    fn an_unselected_mutating_mode_prevents_a_universal_reader_claim() {
        let registry = reader_registry(|reader| {
            let mut mode = reader.forms[1].clone();
            mode.id = caushell_profile::FormId::new("unsafe_mode");
            mode.selector = caushell_profile::SelectorExpr::Predicate(
                caushell_profile::SelectorPredicate::HasFlag(caushell_profile::FlagName::new(
                    "--unsafe-mode",
                )),
            );
            mode.effects[0].kind = EffectKind::WritePath;
            reader.forms.push(mode);
        });
        let ctx = context(
            &registry,
            "find /unobserved-input -print0 | xargs -0 fixture_reader --",
        );
        assert_eq!(proof_count(&ctx), 0);
        assert_eq!(
            proof_count(&context(
                &registry,
                "find /unobserved-input -print | xargs fixture_reader"
            )),
            0
        );
    }
    #[test]
    fn incomplete_option_ownership_does_not_get_an_effect_proof() {
        let registry = ProfileRegistry::built_in().unwrap();
        for command in [
            "find /unobserved-input -print0 | xargs -0 cat --unreviewed-control",
            // wc's indirect --files0-from control has no total argv envelope.
            "find /unobserved-input -print | xargs wc -l",
            "find /unobserved-input -print0 | xargs -0 wc --files0-from",
            "find /unobserved-input -print | xargs grep -e --",
        ] {
            assert_eq!(proof_count(&context(&registry, command)), 0, "{command}");
        }
    }
}
