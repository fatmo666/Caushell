//! A metadata query is not a grant to read arbitrary file contents.
use crate::{
    CommandLookupDomain, CommandProfile, Effect, EffectKind, FilesystemNamespaceImpact, Parameter, PathRole,
    PathSemantic, SemanticType, StructuredValueContext,
};
use caushell_types::NativeArgvEffectEnvelope;

pub fn native_effect_contract_allows_effect(
    kind: NativeArgvEffectEnvelope,
    effect: &Effect,
) -> bool {
    let allowed = match effect.kind {
        EffectKind::ReadPath => kind.reads_content(),
        EffectKind::TargetPath => kind.queries_metadata(),
        EffectKind::NetworkEndpoint => kind.queries_network(),
        EffectKind::ConsumeStdin | EffectKind::TransformData => true,
        _ => false,
    };
    allowed && effect.filesystem_namespace_impact() == FilesystemNamespaceImpact::Neutral
}

pub fn native_effect_contract_allows_parameter(
    kind: NativeArgvEffectEnvelope,
    parameter: &Parameter,
) -> bool {
    match &parameter.semantic {
        SemanticType::PlainValue => true,
        SemanticType::Endpoint(_) => kind.queries_network(),
        SemanticType::Path(PathSemantic { role, .. }) => {
            (*role == PathRole::Read && kind.reads_content())
                || (*role == PathRole::Target && kind.queries_metadata())
        }
        SemanticType::StructuredValue(value) => match value.context {
            // In an explicitly reviewed data-only native surface, numeric
            // operands and format strings are data, not shell evaluation.
            // State writes, dispatch, config and code effects still fail the
            // total closure below (including printf's native variable writes).
            StructuredValueContext::FormatString => {
                kind.queries_metadata() || kind == NativeArgvEffectEnvelope::DataOnly
            }
            StructuredValueContext::NumericQuantity => kind == NativeArgvEffectEnvelope::DataOnly,
            StructuredValueContext::Regex => kind.reads_content(),
            StructuredValueContext::PathExpression => kind == NativeArgvEffectEnvelope::DataOnly,
            _ => false,
        },
        _ => false,
    }
}

fn native_surface_is_direct(profile: &CommandProfile) -> bool {
    profile.subcommands.is_none()
        && profile.dispatch_overrides.is_empty()
        && profile.argument_regions.is_empty()
        && profile.argument_files.is_empty()
        && profile.environment_inputs.is_empty()
        && profile.option_environment.is_none()
        && profile.archive_extraction.is_none()
        && profile.implicit_config_files.is_empty()
        && profile.configuration_files.is_none()
        && profile.native_configuration.is_none()
        && profile.selection_failure_effects.is_empty()
}

pub fn native_effect_contract_is_closed(
    profile: &CommandProfile,
    contract: NativeArgvEffectEnvelope,
) -> bool {
    native_effect_contract_is_closed_in_domain(profile, contract, &CommandLookupDomain::Unknown)
}

/// An externally dispatched utility cannot use an owning-shell variable
/// write grammar. All other closure requirements are independent of lookup.
pub fn native_effect_contract_is_closed_in_domain(
    profile: &CommandProfile,
    contract: NativeArgvEffectEnvelope,
    lookup_domain: &CommandLookupDomain,
) -> bool {
    if profile.native_argv_effect_envelope == Some(contract) && !profile.read_only_control_surface {
        return false;
    }

    if profile.native_argv_effect_envelope == Some(contract)
        && (profile
            .forms
            .iter()
            .flat_map(|f| &f.parameters)
            .any(|p| !native_effect_contract_allows_parameter(contract, p))
            || profile
                .modifiers
                .iter()
                .flat_map(|m| &m.parameters)
                .any(|p| !native_effect_contract_allows_parameter(contract, p)))
    {
        return false;
    }
    if !native_surface_is_direct(profile)
        || (profile.native_variable_writes.is_some()
            && !matches!(lookup_domain, CommandLookupDomain::External))
        || profile.forms.iter().any(|f| {
            f.operation_semantics_unresolved
                || !f.payload_projections.is_empty()
                || f.effects
                    .iter()
                    .any(|e| !native_effect_contract_allows_effect(contract, e))
        })
        || profile.modifiers.iter().any(|m| {
            m.effects
                .iter()
                .any(|e| !native_effect_contract_allows_effect(contract, e))
        })
    {
        return false;
    }
    true
}

/// An exact-argv budget gap can be irrelevant to native effects, but only
/// after a fixed prefix has selected a plain-data remainder. Do not infer
/// controls, paths, destinations, exact values, counts or output shapes.
pub(crate) fn budget_gaps_are_data_operands(
    profile: &CommandProfile,
    selection: &crate::InvocationSelection<'_>,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &crate::BoundInvocation,
) -> bool {
    use crate::*;
    if !native_surface_is_direct(profile)
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || selection.form.operation_semantics_unresolved
        || !selection.form.payload_projections.is_empty()
        || !bound.payload_projections.is_empty()
        || !bound.argument_regions.is_empty()
        || materialized.shell_expansion_gaps.is_empty()
        || materialized.shell_expansion_gaps.iter().any(|gap| {
            gap.kind != ShellExpansionGapKind::BraceBudgetExhausted
                || gap.bounded_literal_bytes.is_none()
        })
        || bound.effects.is_empty()
        || bound.effects.iter().any(|effect| {
            !native_effect_contract_allows_effect(NativeArgvEffectEnvelope::DataOnly, effect)
        })
    {
        return false;
    }
    let Some(first) = materialized.invocation.args.iter().position(|arg| {
        materialized
            .shell_expansion_gaps
            .iter()
            .any(|gap| gap.span == arg.span)
    }) else {
        return false;
    };
    if first == 0
        || materialized.invocation.args[..first]
            .iter()
            .any(|arg| argument_structure(arg).exact_value().is_none())
    {
        return false;
    }
    materialized.shell_expansion_gaps.iter().all(|gap| {
        bound.bound_parameters.iter().any(|parameter| {
            parameter.semantic == SemanticType::PlainValue
                && parameter.structured_projection.is_none()
                && parameter.value_projection.is_none()
                && selection.form.parameters.iter().any(|declared| declared.name == parameter.name && declared.binding == BindingSpec::RemainingArgs)
                && parameter.values.iter().any(|value| matches!(value,
                    BoundValue::Argument { span, binding_source: ArgumentBindingSource::RemainingArg, .. } if span == &gap.span))
        })
    })
}
/// Shared uncertainty contract for native argument interpretation, irrespective
/// of the producer of argv. Never certify records, scalars or output bounds.
pub fn retain_symbolic_argv_stream_contract(
    bound: &mut crate::BoundInvocation,
    contract: NativeArgvEffectEnvelope,
) {
    use crate::*;
    bound.native_argv_effect_envelope = Some(contract);
    bound.stdout_records = None;
    bound.stdout_growth = None;
    bound.stdout_scalar = None;
    bound.stdout_scalar_inputs.clear();
    bound.stdout_scalar_native_variant = None;
    bound.stdout_scalar_complete = false;
    bound.stdout_growth_complete = false;
    bound.stream_contract = Some(StreamContract {
        stdin_mode: StreamInputMode::DataOptional,
        stdout_mode: StreamOutputMode::Data,
        stderr_mode: StreamOutputMode::Data,
        stdout_dependency: caushell_types::StreamDataDependency::Inputs,
        stderr_dependency: caushell_types::StreamDataDependency::Inputs,
        stdout_from_payload: false,
    });
}

/// Certify the exact prefix before symbolic argv. Both selection recovery and
/// binding closure use this same proof: no unknown option ownership is guessed.
/// Literal data after the symbolic word stays a possible input; known controls
/// after it require a separate ownership proof and cannot use this certificate.
pub(crate) fn symbolic_shell_argv_prefix(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
) -> Option<crate::ProjectedInvocation> {
    use crate::*;
    let contract = profile.native_argv_effect_envelope?;
    if materialized.shell_expansion_unresolved
        || !native_effect_contract_is_closed(profile, contract)
    {
        return None;
    }
    let argv = &materialized.invocation;
    if argv.args.len() > 4096 || argv.args.iter().map(|a| a.text.len()).sum::<usize>() > 262_144 {
        return None;
    }

    // Typed tool inputs have their own origin adapter. Do not relabel them as
    // shell words or lose their existing precise field/path certificates.
    if argv.args.iter().any(|a| a.implicit_input_source.is_some()) {
        return None;
    }
    let start = argv
        .args
        .iter()
        .position(|a| argument_structure(a).exact_value().is_none())?;
    // Keep known controls after an uncertain-width word conservative. A future
    // ownership proof must preserve their possible option-operand relations.
    if argv.args[start..].iter().any(|a| {
        argument_structure(a)
            .exact_value()
            .is_some_and(|value| value.starts_with('-') || value.starts_with('+'))
    }) {
        return None;
    }
    let mut prefix = argv.clone();
    prefix.args.truncate(start);
    let mut audited = profile.clone();
    audited.opaque_on_unresolved = true;
    audited.read_only_control_surface = false;
    let Ok(selection) = select_invocation(&audited, &prefix) else {
        return None;
    };
    let prefix_bound = bind_invocation(&audited, &prefix, &selection);
    if prefix_bound.operation_semantics_unresolved
        || !prefix_bound.residuals.is_empty()
        || prefix_bound
            .effects
            .iter()
            .any(|e| !native_effect_contract_allows_effect(contract, e))
    {
        return None;
    }
    Some(prefix)
}

/// A reviewed total native control surface does not depend on knowing the
/// fields produced by a shell word. The shell and all its child effects are
/// analyzed separately. Keep original argv, origins and access effects.
pub(crate) fn close_symbolic_shell_argv(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let Some(prefix) = symbolic_shell_argv_prefix(profile, materialized) else {
        return;
    };
    let contract = profile.native_argv_effect_envelope.unwrap();
    if bound
        .effects
        .iter()
        .any(|e| !native_effect_contract_allows_effect(contract, e))
    {
        return;
    }
    let start = prefix.args.len();
    let argv = &materialized.invocation;
    for (slot, role, effect) in [
        (
            "__symbolic_argv_reads__",
            PathRole::Read,
            EffectKind::ReadPath,
        ),
        (
            "__symbolic_argv_metadata__",
            PathRole::Target,
            EffectKind::TargetPath,
        ),
    ] {
        if role == PathRole::Read && !contract.reads_content()
            || role == PathRole::Target && !contract.queries_metadata()
        {
            continue;
        }
        let mut parameter = BoundParameter::new(
            SlotName::new(slot),
            SemanticType::Path(PathSemantic {
                role,
                purpose: Some(PathPurpose::GenericOperand),
            }),
        );
        for (arg, resolution) in argv
            .args
            .iter()
            .zip(&materialized.arg_resolutions)
            .skip(start)
        {
            let origin = match resolution {
                ValueMaterialization::ResolvedExactScalar { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedExactScalar {
                        variable_name: variable_name.clone(),
                    }
                }
                ValueMaterialization::ResolvedRuntimeProduced { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedRuntimeProduced {
                        variable_name: variable_name.clone(),
                    }
                }
                _ if arg.runtime_data => BoundArgumentMaterialization::RuntimeData,
                _ => BoundArgumentMaterialization::Literal,
            };
            parameter.values.push(
                BoundValue::argument_with_node_kind(
                    arg.text.clone(),
                    arg.quoted,
                    arg.node_kind.clone(),
                    arg.span.clone(),
                    ArgumentBindingSource::RemainingArg,
                )
                .with_materialization(origin),
            );
        }
        let mut access = Effect::new(effect).for_slot(slot);
        if effect == EffectKind::ReadPath {
            // Content-open semantics also preserve /dev/fd and /proc fd aliases.
            access.path_access = Some(PathAccessKind::ContentOpen);
        }
        bound.effects.push(access);
        bound.bound_parameters.push(parameter);
    }

    if contract == NativeArgvEffectEnvelope::DataOnly || contract.queries_network() {
        let slot = SlotName::new(if contract.queries_network() {
            "__symbolic_argv_network__"
        } else {
            "__symbolic_argv_data__"
        });
        let mut parameter = BoundParameter::new(slot.clone(), if contract.queries_network() {
            SemanticType::Endpoint(EndpointSemantic {
                kind: EndpointKind::HostPort,
                usage: EndpointUsage::GenericEndpoint,
            })
        } else { SemanticType::PlainValue });
        // Any symbolic field can become query data or a resolver option.
        // Its spelling is never proof of the recursive resolver's route.
        if contract.queries_network() {
            parameter.value_projection = Some(ValueProjection::Unknown);
        }
        for arg in argv.args.iter().skip(start) {
            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::RemainingArg,
            );
            parameter.values.push(if arg.runtime_data {
                value.with_materialization(BoundArgumentMaterialization::RuntimeData)
            } else {
                value
            });
        }
        if contract.queries_network() {
            crate::refresh_parameter_semantic_values(&mut parameter);
        }
        bound.bound_parameters.push(parameter);
        let mut effect = Effect::new(if contract.queries_network() {
            EffectKind::NetworkEndpoint
        } else { EffectKind::TransformData }).for_slot(slot.as_str());
        if contract.queries_network() {
            effect.input_scope = Some(EndpointInputScope {
                slots: bound.bound_parameters.iter().map(|p| p.name.as_str().to_owned()).collect(),
                stdin: false,
            });
        }
        bound.effects.push(effect);
    }
    // Existing bound parameters retain data/variable and substitution origins,
    // including for data-only commands. No input is manufactured from stdin.
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    bound.form_id = FormId::new("__symbolic_argv_effect_envelope__");
    retain_symbolic_argv_stream_contract(bound, contract);
    let mut stdin = Effect::new(EffectKind::ConsumeStdin);
    stdin.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
    bound.effects.push(stdin);
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
}
