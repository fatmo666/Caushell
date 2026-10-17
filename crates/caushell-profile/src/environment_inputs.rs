//! Native environment operands declared by Profiles. No tool names, host
//! environment reads, filesystem discovery or second shell expansion.
use crate::{
    ArgumentBindingSource, BoundArgumentMaterialization, BoundInvocation, BoundParameter,
    BoundValue, CommandProfile, Effect, EffectKind, EffectTarget, EnvironmentValueRef,
    ImplicitInputSource, SemanticType, SessionBindings, SessionValue,
};

pub(crate) fn attach(
    profile: &CommandProfile,
    mut bound: BoundInvocation,
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
) -> BoundInvocation {
    if profile.environment_inputs.is_empty() {
        return bound;
    }
    let prefix_values = crate::materialize_prefix_environment(command, bindings);
    let mut added = false;
    for input in &profile.environment_inputs {
        if input
            .unless_modifiers
            .iter()
            .any(|id| bound.applied_modifiers.contains(id))
        {
            continue;
        }
        let prefix = command
            .prefix_assignments
            .iter()
            .rev()
            .find(|a| a.name == input.environment.name);
        let value = if let Some((_, value)) = prefix_values
            .iter()
            .rev()
            .find(|(name, _)| name == &input.environment.name)
        {
            value
        } else {
            // Absence of supplied evidence does not introduce a new ambient
            // loader policy. Explicit unknown values are Present(Opaque/Runtime).
            match bindings.environment_value(&input.environment.name) {
                EnvironmentValueRef::Present(value) => value,
                EnvironmentValueRef::Absent | EnvironmentValueRef::Unknown => continue,
            }
        };
        let value = match value {
            SessionValue::ExactScalar(text) | SessionValue::RuntimeProduced { value: text, .. } => {
                if input.environment.empty_is_unset && text.is_empty() {
                    continue;
                }
                BoundValue::argument_with_node_kind(
                    text,
                    true,
                    "environment_value",
                    prefix.map_or_else(|| command.span.clone(), |a| a.value.span.clone()),
                    ArgumentBindingSource::RemainingArg,
                )
                .with_materialization(BoundArgumentMaterialization::RuntimeData)
            }
            _ => BoundValue::implicit_input(ImplicitInputSource::InheritedEnvironment),
        };
        let mut parameter =
            BoundParameter::new(input.name.clone(), input.semantic.clone()).with_value(value);
        parameter.structured_projection = input.structured_projection.clone();
        parameter.payload_generated = true;
        bound.bound_parameters.push(parameter);
        added = true;
    }
    if added {
        crate::structured_projection::refresh_structured_parameters(&mut bound);
        // Preserve execution semantics as well as recursive candidates. Only
        // populated payload slots originate an effect; disabled branches don't.
        for parameter in &bound.bound_parameters {
            if profile.environment_inputs.iter().any(|input| {
                input.name == parameter.name
                    || parameter.structured_source.as_ref() == Some(&input.name)
            }) && matches!(parameter.semantic, SemanticType::Payload(_))
                && !parameter.values.is_empty()
                && !bound.effects.iter().any(|e| {
                    e.kind == EffectKind::ExecutePayload
                        && e.target == EffectTarget::Slot(parameter.name.clone())
                })
            {
                bound.effects.push(
                    Effect::new(EffectKind::ExecutePayload).for_slot(parameter.name.as_str()),
                );
            }
        }
    }
    bound
}
