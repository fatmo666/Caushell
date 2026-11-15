//! Effect envelopes for typed native argv tails. Never decode them as shell.
use caushell_profile::*;
use caushell_types::{
    ImplicitInputSource as RuntimeInputSource, RuntimeArgumentDomain, ShellKind,
    StreamDataDependency,
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
    if !super::symbolic_native_inputs::reader_profile(profile) {
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
        if argv.args[start..].iter().all(|a| {
            let s = argument_structure(a);
            s.fields != ArgumentFieldCount::Unknown
                && !s.may_start_with("-")
                && !s.may_start_with("+")
        }) {
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
    let Ok(selection) = select_invocation(&audited, &prefix) else {
        return;
    };
    let mut bound = bind_invocation(&audited, &prefix, &selection);
    if bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || bound
            .effects
            .iter()
            .any(|e| !super::symbolic_native_inputs::read_effect(e))
    {
        return;
    }
    // A possibly control-shaped tail needs either a reviewed total native
    // control contract, or an actual parsed end-of-options marker. A data
    // operand spelled -- is not such a marker. Indirect-input tools do not
    // acquire the total contract merely because their current forms read.
    if start.is_some()
        && !profile.native_argv_read_envelope
        && selection.option_terminators.is_empty()
    {
        return;
    }
    bound.native_read_envelope = true;
    bound.form_id = FormId::new("__native_read_effect_envelope__");
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
        stdout_dependency: StreamDataDependency::Inputs,
        stderr_dependency: StreamDataDependency::Inputs,
        stdout_from_payload: false,
    });
    if let Some(index) = start {
        let slot = SlotName::new("__native_read_paths__");
        let mut parameter = BoundParameter::new(
            slot.clone(),
            SemanticType::Path(PathSemantic {
                role: PathRole::Read,
                purpose: Some(PathPurpose::GenericOperand),
            }),
        );
        parameter.values.push(BoundValue::ImplicitInput {
            source: ImplicitInputSource::StdinData,
            domain: Some(RuntimeArgumentDomain::Unbounded),
            origin: Some(BoundImplicitArgumentOrigin {
                span: argv.args[index].span.clone(),
                single_field: argv.args[index].node_kind == "runtime_scalar",
            }),
        });
        bound.bound_parameters.push(parameter);
        bound
            .effects
            .push(Effect::new(EffectKind::ReadPath).for_slot(slot.as_str()));
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
