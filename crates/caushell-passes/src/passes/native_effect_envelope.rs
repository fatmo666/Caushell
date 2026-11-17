//! Effect envelopes for typed native argv tails. Never decode them as shell.
use caushell_profile::*;
use caushell_types::{
    ImplicitInputSource as RuntimeInputSource, RuntimeArgumentDomain, ShellKind,
};

pub(super) fn refine(
    registry: &ProfileRegistry,
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
    shell: ShellKind,
    result: &mut ResolveInvocationArtifactResult,
) {
    let name = match result {
        ResolveInvocationArtifactResult::Resolved(r) => r.normalized_command_name.clone(),
        ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            error,
            ..
        } if matches!(
            error,
            BindError::NoFormMatched { .. }
                | BindError::MultipleFormsMatched { .. }
                | BindError::UnsupportedProfileFeature { .. }
        ) =>
        {
            normalized_command_name.clone()
        }
        _ => return,
    };
    let Some(profile) = registry.lookup(&name).profile else {
        return;
    };
    let contract = profile
        .native_argv_effect_envelope
        .unwrap_or(NativeArgvEffectEnvelope::ContentRead);
    if !super::symbolic_native_inputs::effect_profile(profile, contract) {
        return;
    }
    let projection = project_invocation(
        command,
        InvocationRuntimeContext::new().with_shell_kind(shell),
    );
    let materialized = materialize_projected_invocation(&projection, bindings);
    let argv = &materialized.invocation;
    let native = |a: &ProjectedArg| {
        a.implicit_input_source == Some(RuntimeInputSource::StdinData)
            && matches!(
                a.node_kind.as_str(),
                "runtime_scalar" | "runtime_argument_list"
            )
    };
    let start = argv.args.iter().position(native);
    if let Some(start) = start {
        if !argv.args[start..].iter().all(native) {
            return;
        }
        // Existing precise non-option/path proofs keep their original model.
        if (contract == NativeArgvEffectEnvelope::ContentRead
            || contract == NativeArgvEffectEnvelope::DataOnly)
            && argv.args[start..].iter().all(|a| {
                let s = argument_structure(a);
                s.fields != ArgumentFieldCount::Unknown
                    && !s.may_start_with("-")
                    && !s.may_start_with("+")
            })
        {
            return;
        }
    } else if !matches!(result, ResolveInvocationArtifactResult::Resolved(r)
        if r.bound.stream_contract.is_some_and(|s| matches!(s.stdin_mode,StreamInputMode::DataOptional|StreamInputMode::DataRequired)))
    {
        return;
    }
    let mut prefix = argv.clone();
    prefix.args.truncate(start.unwrap_or(argv.args.len()));
    if prefix
        .args
        .iter()
        .any(|a| argument_structure(a).exact_value().is_none())
    {
        return;
    }
    let mut audited = profile.clone();
    audited.opaque_on_unresolved = true;
    audited.read_only_control_surface = false;
    let selection = select_invocation(&audited, &prefix);
    // A reviewed total metadata contract covers all native argv modes. A
    // prefix alone may lack a required file or be a different possible mode;
    // certifying that prefix as one valid invocation is a separate question.
    // Preserve all prefix words as possible metadata inputs, without asserting
    // option ownership or using metadata as file-content read authority.
    let mut bound = if !contract.reads_content()
        && profile.native_argv_effect_envelope == Some(contract)
        && start.is_some()
    {
        let mut bound = BoundInvocation::new(
            CommandName::new(name.as_str()),
            FormId::new("__native_metadata_effect_envelope__"),
        );
        let slot = SlotName::new("__native_effect_prefix__");
        let mut parameter = BoundParameter::new(
            slot.clone(),
            if contract.queries_metadata() {
                SemanticType::Path(PathSemantic {
                    role: PathRole::Target,
                    purpose: Some(PathPurpose::GenericOperand),
                })
            } else {
                SemanticType::PlainValue
            },
        );
        for arg in &prefix.args {
            let value = argument_structure(arg).exact_value().unwrap().to_owned();
            parameter.values.push(BoundValue::Argument {
                text: value,
                quoted: arg.quoted,
                node_kind: arg.node_kind.clone(),
                span: arg.span.clone(),
                binding_source: ArgumentBindingSource::RemainingArg,
                materialization: BoundArgumentMaterialization::RuntimeData,
                ownership: ArgumentOwnership::Unproven,
            });
        }
        bound.bound_parameters.push(parameter);
        if !contract.queries_metadata() {
            bound.effects.push(Effect::new(EffectKind::TransformData));
        }
        bound
    } else {
        let Ok(selection) = &selection else {
            return;
        };
        bind_invocation(&audited, &prefix, selection)
    };
    if bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || bound
            .effects
            .iter()
            .any(|e| !native_effect_contract_allows_effect(contract, e))
    {
        return;
    }
    if start.is_some()
        && profile.native_argv_effect_envelope != Some(contract)
        && !selection
            .as_ref()
            .is_ok_and(|selection| !selection.option_terminators.is_empty())
    {
        return;
    }
    retain_symbolic_argv_stream_contract(&mut bound, contract);
    bound.form_id = FormId::new("__native_argv_effect_envelope__");
    if let Some(index) = start {
        // Each admitted access gets its own role. Metadata never acquires
        // content authority, and pure data arguments never invent file reads.
        let mut roles = Vec::new();
        if contract.reads_content() {
            roles.push((
                "__native_symbolic_paths__",
                Some(PathRole::Read),
                Some(EffectKind::ReadPath),
            ));
        }
        if contract.queries_metadata() {
            roles.push((
                "__native_symbolic_metadata__",
                Some(PathRole::Target),
                Some(EffectKind::TargetPath),
            ));
        }
        if contract.queries_network() {
            roles.push((
                "__native_symbolic_network__",
                None,
                Some(EffectKind::NetworkEndpoint),
            ));
        }
        if roles.is_empty() {
            roles.push(("__native_symbolic_data__", None, None));
        }
        for (name, role, effect) in roles {
            let slot = SlotName::new(name);
            let mut parameter = BoundParameter::new(
                slot.clone(),
                if let Some(role) = role {
                    SemanticType::Path(PathSemantic {
                        role,
                        purpose: Some(PathPurpose::GenericOperand),
                    })
                } else if effect == Some(EffectKind::NetworkEndpoint) {
                    SemanticType::Endpoint(EndpointSemantic {
                        kind: EndpointKind::HostPort,
                        usage: EndpointUsage::GenericEndpoint,
                    })
                } else {
                    SemanticType::PlainValue
                },
            );
            parameter.values.push(BoundValue::ImplicitInput {
                source: ImplicitInputSource::StdinData,
                domain: Some(RuntimeArgumentDomain::Unbounded),
                origin: Some(BoundImplicitArgumentOrigin {
                    span: argv.args[index].span.clone(),
                    single_field: argv.args[index].node_kind == "runtime_scalar",
                }),
            });
            if effect == Some(EffectKind::NetworkEndpoint) {
                parameter.value_projection = Some(ValueProjection::Unknown);
                refresh_parameter_semantic_values(&mut parameter);
            }
            bound.bound_parameters.push(parameter);
            if let Some(effect) = effect {
                let mut access = Effect::new(effect).for_slot(slot.as_str());
                if effect == EffectKind::NetworkEndpoint {
                    // Native argv bytes came from this input, not FD 0 of the
                    // launched program. Preserve both the tool-owned source
                    // and every exact prefix value as possible query data.
                    access.input_scope = Some(EndpointInputScope {
                        slots: bound.bound_parameters.iter().map(|p| p.name.as_str().to_owned()).collect(),
                        stdin: true,
                    });
                }
                bound.effects.push(access);
            }
        }
        // Keep the native origin on this read slot. The provenance pass treats
        // its argument bytes as runtime input, which may reach diagnostics.
    }
    if !bound
        .bound_implicit_inputs
        .iter()
        .any(|i| i.source == ImplicitInputSource::StdinData)
    {
        bound.bound_implicit_inputs.push(BoundImplicitInput::new(
            ImplicitInputSource::StdinData,
            SemanticType::PlainValue,
        ));
    }
    let mut stdin = Effect::new(EffectKind::ConsumeStdin);
    stdin.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
    bound.effects.push(stdin);
    *result = ResolveInvocationArtifactResult::Resolved(ResolvedInvocationArtifact {
        normalized_command_name: name,
        projection,
        materialized_projection: materialized,
        bound,
    });
}
