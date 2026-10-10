//! Function state operations shared by ordered analysis and persistence.
use caushell_profile::{
    ArgumentFieldCount, MaterializedProjectedInvocation, SessionBindings, SessionValue,
    ValueMaterialization, VariablePresence, argument_structure,
};
use caushell_runner::PendingMutation;
use caushell_types::{CommandSequenceNo, SessionFunctionBinding};

/// A function shares its caller namespace, but replaces positional parameters.
/// Both execution expansion and variable-effect replay consume this query.
pub(crate) fn function_call_bindings(
    base: &SessionBindings,
    projection: &MaterializedProjectedInvocation,
) -> SessionBindings {
    let mut bindings = base.clone();
    bindings.enter_function_scope();
    if projection
        .invocation
        .args
        .iter()
        .any(|arg| argument_structure(arg).fields != ArgumentFieldCount::ExactlyOne)
    {
        bindings.forget_positional_parameters();
        return bindings;
    }
    bindings.replace_positional_parameters(projection.invocation.args.iter().enumerate().map(
        |(i, a)| {
            match projection.arg_resolutions.get(i) {
                Some(ValueMaterialization::ResolvedExactScalar { .. })
                    if a.implicit_input_source.is_none() =>
                {
                    SessionValue::exact_scalar(&a.text)
                }
                Some(ValueMaterialization::ResolvedRuntimeProduced { kind, .. })
                    if a.implicit_input_source.is_none() =>
                {
                    SessionValue::runtime_produced(&a.text, *kind)
                }
                _ if a.runtime_data && a.implicit_input_source.is_none() => {
                    SessionValue::exact_scalar(&a.text)
                }
                Some(ValueMaterialization::Static) if a.implicit_input_source.is_none() => {
                    caushell_parse::decode_static_shell_argument(&a.text, a.quoted, &a.node_kind)
                        .map(SessionValue::exact_scalar)
                        .unwrap_or_else(|| {
                            SessionValue::opaque_dynamic("unresolved function argument")
                        })
                }
                _ => SessionValue::opaque_dynamic("unresolved function argument"),
            }
        },
    ));
    bindings
}

pub(crate) fn visible_function_bindings_before_span(
    summary: &caushell_types::SessionSummary,
    request: &caushell_types::CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    span: &caushell_parse::SourceSpan,
    observed_at: CommandSequenceNo,
) -> std::collections::BTreeMap<String, SessionFunctionBinding> {
    let bindings = super::apply_visible_variable_bindings_before_span(
        super::request_variable_bindings(summary, request),
        parsed,
        span.start_byte,
        observed_at,
    );
    bindings
        .function_names()
        .filter_map(|name| {
            bindings
                .function_binding(name)
                .filter(|binding| binding.uncertainty.is_none())
                .map(|binding| (name.to_string(), binding.clone()))
        })
        .collect()
}

pub(super) fn define_function(
    bindings: &mut SessionBindings,
    definition: &caushell_parse::FunctionDefinitionFact,
    observed_at: CommandSequenceNo,
) -> PendingMutation {
    let binding = if definition.conditional_execution {
        SessionFunctionBinding::uncertain(
            &definition.name,
            "conditional function definition",
            observed_at,
        )
    } else {
        SessionFunctionBinding::new(&definition.name, &definition.body_text, observed_at)
    };
    bindings.upsert_function_binding(binding.clone());
    PendingMutation::UpsertFunctionBinding { binding }
}

pub(super) fn unset_function_target(
    bindings: &mut SessionBindings,
    name: &str,
    mode: super::UnsetMode,
    conditional: bool,
    observed_at: CommandSequenceNo,
) -> Option<PendingMutation> {
    if bindings.function_binding(name).is_none() {
        // Retain explicit -f removals in the audit even without a known body.
        return (mode == super::UnsetMode::Functions && !conditional).then(|| {
            PendingMutation::UnsetFunction {
                name: name.into(),
                observed_at,
            }
        });
    }
    let uncertain = match mode {
        super::UnsetMode::Functions => conditional,
        super::UnsetMode::Default => match if super::scalar_identifier(name) {
            bindings.variable_presence(name)
        } else {
            // Bash function names need not be scalar variable identifiers.
            VariablePresence::Absent
        } {
            VariablePresence::Present => return None,
            VariablePresence::Absent => conditional,
            VariablePresence::Unknown => true,
        },
        _ => return None,
    };
    if uncertain {
        let binding = SessionFunctionBinding::uncertain(
            name,
            "unset may remove function binding",
            observed_at,
        );
        bindings.upsert_function_binding(binding.clone());
        Some(PendingMutation::UpsertFunctionBinding { binding })
    } else {
        bindings.unset_function(name);
        Some(PendingMutation::UnsetFunction {
            name: name.into(),
            observed_at,
        })
    }
}

pub(super) fn invalidate_function_targets(
    bindings: &mut SessionBindings,
    observed_at: CommandSequenceNo,
) -> Vec<PendingMutation> {
    let names = bindings
        .function_names()
        .map(str::to_string)
        .collect::<Vec<_>>();
    names
        .into_iter()
        .map(|name| {
            let binding = SessionFunctionBinding::uncertain(
                name,
                "unresolved function unset target/options",
                observed_at,
            );
            bindings.upsert_function_binding(binding.clone());
            PendingMutation::UpsertFunctionBinding { binding }
        })
        .collect()
}
