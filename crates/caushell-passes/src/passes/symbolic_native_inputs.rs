//! Optional byte recovery must not replace a closed symbolic effect proof.
use caushell_profile::{
    CommandProfile, Effect, ProfileRegistry, ResolveInvocationArtifactResult,
    ResolvedInvocationArtifact, bind_invocation, select_invocation,
};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext};
use caushell_types::NativeInputEffectEvidence;
#[cfg(test)]
use caushell_profile::EffectKind;

pub(super) fn read_effect(effect: &Effect) -> bool {
    caushell_profile::native_effect_contract_allows_effect(
        caushell_types::NativeArgvEffectEnvelope::ContentRead,
        effect,
    )
}

/// A flat native data reader, not a command-name allowlist. Every declared mode
/// must remain read/data-only; filename-list reads retain their declared effects.
/// Configuration, native argv-reparsing files and code projections need
/// their own proofs. Strict rebinding accounts for ALL argv even for a legacy
/// profile that does not escalate every residual in ordinary resolution.
pub(super) fn reader_profile(profile: &CommandProfile) -> bool {
    effect_profile(
        profile,
        caushell_types::NativeArgvEffectEnvelope::ContentRead,
    )
}

pub(super) fn effect_profile(profile: &CommandProfile, contract: caushell_types::NativeArgvEffectEnvelope) -> bool {
    caushell_profile::native_effect_contract_is_closed(profile, contract)
}

fn closed_effects(profile: &CommandProfile, resolved: &ResolvedInvocationArtifact) -> bool {
    let contract = resolved
        .bound
        .native_argv_effect_envelope
        .or(profile.native_argv_effect_envelope)
        .unwrap_or(caushell_types::NativeArgvEffectEnvelope::ContentRead);
    if !effect_profile(profile, contract)
        || resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
        || resolved
            .bound
            .effects
            .iter()
            .any(|e| !caushell_profile::native_effect_contract_allows_effect(contract, e))
    {
        return false;
    }
    if resolved.bound.native_argv_effect_envelope.is_some() {
        return contract == caushell_types::NativeArgvEffectEnvelope::ContentRead
            || profile.native_argv_effect_envelope == Some(contract);
    }
    strictly_bound_invocation(profile, resolved).is_some_and(|bound| bound.effects.iter().all(|e| caushell_profile::native_effect_contract_allows_effect(contract, e)))
}

/// Reuse the same native ownership audit for every selected effect class.
/// This proves binding, not output bytes, path authority, or execution success.
pub(super) fn strictly_bound_invocation(profile: &CommandProfile, resolved: &ResolvedInvocationArtifact) -> Option<caushell_profile::BoundInvocation> {
    if resolved.bound.operation_semantics_unresolved || !resolved.bound.residuals.is_empty() { return None; }
    let mut audited = profile.clone();
    audited.opaque_on_unresolved = true;
    audited.read_only_control_surface = false;
    let argv = &resolved.materialized_projection.invocation;
    let Ok(selection) = select_invocation(&audited, argv) else {
        return None;
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
            return None;
        }
    }
    let bound = bind_invocation(&audited, argv, &selection);
    (bound.form_id == resolved.bound.form_id
        && !bound.operation_semantics_unresolved
        && bound.residuals.is_empty()
    ).then_some(bound)
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
        if !closed_effects(profile, resolved) {
            return None;
        }
    }
    let kinds = children
        .iter()
        .map(|c| match &c.result {
            ResolveInvocationArtifactResult::Resolved(r) => r.bound.native_argv_effect_envelope.or_else(|| registry.lookup(&r.normalized_command_name).profile.and_then(|p| p.native_argv_effect_envelope)).unwrap_or(caushell_types::NativeArgvEffectEnvelope::ContentRead),
            _ => unreachable!("every child passed the resolved closed-effect audit"),
        })
        .collect::<Vec<_>>();
    let envelope = Some(kinds.iter().copied().fold(caushell_types::NativeArgvEffectEnvelope::DataOnly, |a,b| a.union(b)));
    Some(NativeInputEffectEvidence {
        bound_effects: None,
        effect_envelope: envelope,
        control_envelope: children.iter().any(|c|matches!(&c.result,ResolveInvocationArtifactResult::Resolved(r) if r.bound.native_argv_effect_envelope.is_some())),
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
                ResolveInvocationArtifactResult::Resolved(r)
                    if r.bound.native_argv_effect_envelope.is_some() =>
                {
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
    fn a_metadata_contract_is_name_independent_and_never_becomes_a_reader_or_decoder() {
        let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
        let mut query = ProfileRegistry::built_in()
            .unwrap()
            .lookup("stat")
            .profile
            .unwrap()
            .clone();
        query.identity.canonical_name = caushell_profile::CommandName::new("fixture_metadata");
        query.identity.aliases.clear();
        assert!(!reader_profile(&query));
        assert!(effect_profile(&query, NativeArgvEffectEnvelope::MetadataQuery), "{query:#?}");
        profiles.push(query.clone());
        let registry = ProfileRegistry::from_profiles(profiles).unwrap();
        let ctx = context(
            &registry,
            "find /unobserved -print | xargs fixture_metadata -c %s",
        );
        let child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find_map(|r| match &r.result {
                ResolveInvocationArtifactResult::Resolved(r)
                    if r.bound.native_argv_effect_envelope
                        == Some(NativeArgvEffectEnvelope::MetadataQuery) =>
                {
                    Some(r)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("{:#?}", ctx.execution_unit_resolve_records()));
        assert!(
            !child
                .bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ReadPath)
        );
        assert!(child.bound.stdout_records.is_none() && child.bound.stdout_scalar.is_none());
        assert_eq!(
            child.proven_stream_contract().unwrap().stderr_dependency,
            StreamDataDependency::Inputs
        );
        assert!(ctx.evidence.iter().any(|e|matches!(&e.kind,EvidenceKind::NativeInputEffect(p) if p.effect_envelope==Some(NativeArgvEffectEnvelope::MetadataQuery))));
        // An unselected writable mode invalidates a universal contract too.
        query.forms[0]
            .effects
            .push(Effect::new(EffectKind::WritePath));
        let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
        profiles.push(query);
        let registry = ProfileRegistry::from_profiles(profiles).unwrap();
        let ctx = context(
            &registry,
            "find /unobserved -print | xargs fixture_metadata -c %s",
        );
        assert_eq!(proof_count(&ctx), 0);
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
            "find /unobserved-input -print0 | xargs -0 wc --files0-from",
        ] {
            assert_eq!(proof_count(&context(&registry, command)), 0, "{command}");
        }
    }

    #[test]
    fn regex_parameter_ownership_and_total_reader_effects_are_separate_proofs() {
        let registry = ProfileRegistry::built_in().unwrap();
        let command = "find /unobserved-input -print | xargs grep -e --";
        assert!(proof_count(&context(&registry, command)) > 0);
        // -- belongs to -e as pattern data, so it cannot certify a native
        // terminator. Without the total contract the legacy strict audit
        // must still reject that argument-ownership claim.
        let mut profiles = registry.profiles().to_vec();
        let grep = profiles.iter_mut().find(|p| p.identity.canonical_name.as_str() == "grep").unwrap();
        grep.native_argv_effect_envelope = None;
        let registry = ProfileRegistry::from_profiles(profiles).unwrap();
        assert_eq!(proof_count(&context(&registry, command)), 0);
    }

    #[test]
    fn declared_capabilities_generate_only_their_distinct_access_roles() {
        let registry=ProfileRegistry::built_in().unwrap();
        for (command,contract,read,metadata) in [
            ("find /unobserved -print | xargs echo",NativeArgvEffectEnvelope::DataOnly,false,false),
            ("find /unobserved -print | xargs du -s",NativeArgvEffectEnvelope::ContentRead.union(NativeArgvEffectEnvelope::MetadataQuery),true,true),
        ] {
            let ctx=context(&registry,command);
            let bound=ctx.execution_unit_resolve_records().iter().find_map(|r|match &r.result {ResolveInvocationArtifactResult::Resolved(r) if r.bound.native_argv_effect_envelope==Some(contract)=>Some(&r.bound),_=>None}).unwrap();
            assert_eq!(bound.effects.iter().any(|e|e.kind==EffectKind::ReadPath),read);
            assert_eq!(bound.effects.iter().any(|e|e.kind==EffectKind::TargetPath),metadata);
            assert!(bound.stdout_records.is_none() && bound.stdout_scalar.is_none());
            assert_eq!(bound.stream_contract.unwrap().stdout_dependency,StreamDataDependency::Inputs);
        }
    }
}

#[cfg(test)]
#[test]
fn namespace_neutrality_is_not_a_read_envelope_grant() {
    let target = Effect::new(EffectKind::TargetPath).for_slot("paths");
    assert_eq!(
        target.filesystem_namespace_impact(),
        caushell_profile::FilesystemNamespaceImpact::Neutral
    );
    assert!(!read_effect(&target));
    let mut read = Effect::new(EffectKind::ReadPath).for_slot("paths");
    assert!(read_effect(&read));
    read.extensions
        .insert("unreviewed_native_action".into(), serde_json::json!(true));
    assert!(!read_effect(&read));
}
