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

/// The lone decimal word following pv's rate option can be absent, be the
/// rate, or also yield input filenames. Close that transfer's effect union
/// without assigning the actual argv or dropping any possible content read.
pub(crate) fn retain_pv_read_effects_for_split_rate(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    projection: &crate::ProjectedInvocation,
    selection: &crate::InvocationSelection<'_>,
    bindings: &crate::SessionBindings,
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let contract = NativeArgvEffectEnvelope::ContentRead;
    if profile.primary_name() != "pv"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || profile.native_variable_writes.is_some()
        || projection.shell_kind != caushell_types::ShellKind::Bash
        || !command.prefix_assignments.is_empty()
        || observed_ifs_value(bindings).is_some()
        || bound.form_id.as_str() != "transfer_stream"
        || !bound.operation_semantics_unresolved
        || bound.residuals.len() != 1
        || bound.residuals != selection.residuals
        || !selection.option_scope.as_ref().is_some_and(|scope| {
            scope.ownership_unresolved && scope.error.is_none()
        })
        || !bound.effects.iter().all(|effect| native_effect_contract_allows_effect(contract, effect))
        || !profile.forms.iter().any(|form| {
            form.id.as_str() == "transfer_files"
                && !form.operation_semantics_unresolved
                && form.payload_projections.is_empty()
                && form.effects.iter().all(|effect| native_effect_contract_allows_effect(contract, effect))
        })
    {
        return;
    }
    let [flag, argument] = projection.args.as_slice() else {
        return;
    };
    if !matches!(argument_structure(flag).exact_value(), Some("-L" | "--rate-limit"))
        || argument.node_kind != "arithmetic_expansion"
        || argument.quoted
        || argument.runtime_data
        || argument.implicit_input_source.is_some()
        || argument.runtime_argument_domain.is_some()
    {
        return;
    }
    let Some(value) = caushell_parse::constant_arithmetic_word(&argument.text)
        .and_then(|number| u32::try_from(number).ok())
    else {
        return;
    };
    let Some(layouts) = crate::field_splitting::decimal_field_layouts(value) else {
        return;
    };

    // The option's first field is its rate, never a filename. Missing/empty
    // rates and empty pathnames add no successful content open. Including the
    // later nonempty fields of every layout is a conservative read union.
    let paths: std::collections::BTreeSet<_> = layouts.into_iter()
        .flat_map(|fields| fields.into_iter().skip(1).filter(|field| !field.is_empty()))
        .collect();
    if !paths.is_empty() {
        let slot = SlotName::new("possible_input_files");
        let mut parameter = BoundParameter::new(
            slot.clone(),
            SemanticType::Path(PathSemantic {
                role: PathRole::Read,
                purpose: Some(PathPurpose::GenericOperand),
            }),
        );
        parameter.values.extend(paths.into_iter().map(|path| {
            BoundValue::argument(path, false, argument.span.clone(), ArgumentBindingSource::RemainingArg)
                .with_materialization(BoundArgumentMaterialization::RuntimeData)
        }));
        let mut read = Effect::new(EffectKind::ReadPath).for_slot(slot.as_str());
        read.path_access = Some(PathAccessKind::ContentOpen);
        bound.bound_parameters.push(parameter);
        bound.effects.push(read);
    }
    bound.form_id = FormId::new("__symbolic_argv_effect_envelope__");
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    retain_symbolic_argv_stream_contract(bound, contract);
}

/// Close the known effects of a single sed operand with a proved expansion.
pub(crate) fn retain_sed_substitution(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    projection: &crate::ProjectedInvocation,
    proofs: &[(caushell_parse::SourceSpan, crate::SubstitutionOutputProof)],
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let [argument] = projection.args.as_slice() else {
        return;
    };
    let [(source, proof)] = proofs else {
        return;
    };
    if profile.primary_name() != "sed"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || profile.native_variable_writes.is_some()
        || projection.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || argument.runtime_data
        || argument.implicit_input_source.is_some()
        || argument.span != *source
        || bound.form_id.as_str() != "positional_script_transform_stdin"
    {
        return;
    }
    if let SubstitutionOutputProof::SedDayTemplate { literal_parts } = proof {
        if sed_day_template_only_transforms(literal_parts) {
            let mut transform = BoundInvocation::new(
                bound.command_name.clone(),
                FormId::new("__symbolic_argv_effect_envelope__"),
            );
            let mut stdin = Effect::new(EffectKind::ConsumeStdin);
            stdin.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
            transform.effects.push(stdin);
            transform.bound_implicit_inputs.push(BoundImplicitInput::new(
                ImplicitInputSource::StdinData,
                SemanticType::PlainValue,
            ));
            transform.effects.push(Effect::new(EffectKind::TransformData));
            retain_symbolic_argv_stream_contract(&mut transform, NativeArgvEffectEnvelope::DataOnly);
            *bound = transform;
        }
        return;
    }
    if argument.quoted || !matches!(proof, SubstitutionOutputProof::LineCountQuit) {
        return;
    }
    // Splitting a decimal count plus q can add filenames or leave an
    // invalid script. It cannot introduce options or sed instructions.
    let mut reads = BoundInvocation::new(
        bound.command_name.clone(),
        FormId::new("__symbolic_argv_effect_envelope__"),
    );
    let slot = "possible_input_files";
    let mut parameter = BoundParameter::new(
        SlotName::new(slot),
        SemanticType::Path(PathSemantic {
            role: PathRole::Read,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    parameter.values.push(BoundValue::argument_with_node_kind(
        argument.text.clone(), false, argument.node_kind.clone(), argument.span.clone(),
        ArgumentBindingSource::RemainingArg,
    ));
    reads.bound_parameters.push(parameter);
    let mut file_read = Effect::new(EffectKind::ReadPath).for_slot(slot);
    file_read.path_access = Some(PathAccessKind::ContentOpen);
    reads.effects.push(file_read);
    retain_symbolic_argv_stream_contract(&mut reads, NativeArgvEffectEnvelope::ContentRead);
    *bound = reads;
}

fn sed_day_template_only_transforms(literal_parts: &[String]) -> bool {
    let [first, suffixes @ ..] = literal_parts else {
        return false;
    };
    if !first.starts_with("s/")
        || !(1..=2).contains(&suffixes.len())
        || literal_parts.iter().map(String::len).sum::<usize>() > 256
    {
        return false;
    }
    // Each capture can fail independently. An empty pattern or a changed
    // parse in any expansion must also pass the same lexical effect decoder.
    let days: Vec<_> = std::iter::once(String::new())
        .chain((1..=31).map(|day| format!("{day:02}")))
        .collect();
    let mut scripts = vec![first.clone()];
    for suffix in suffixes {
        scripts = scripts.iter()
            .flat_map(|prefix| days.iter().map(move |day| format!("{prefix}{day}{suffix}")))
            .collect();
    }
    scripts.iter().all(|script| {
        crate::sed_payload::decode(script, 260, 16).is_ok_and(|targets| {
            targets.reads.is_empty() && targets.writes.is_empty() && targets.executions.is_empty()
        })
    })
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
