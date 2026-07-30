use caushell_parse::{
    CommandFact, CommandToken, CommandTokenKind, ParsedCommandArtifact, StatementTerminator,
};
use caushell_profile::{
    MaterializedShellField, SessionBindings, SessionValue, ValueMaterialization,
    exact_scalar_shell_parameter_reference_value, exact_shell_parameter_reference,
    materialize_exact_shell_parameter_reference_fields,
};
use caushell_types::{
    CheckRequest, CommandSequenceNo, SessionSummary, SessionVariableBinding, SessionVariableValue,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PositionalParameterMutation {
    Replace(Vec<SessionValue>),
    Shift(usize),
    Forget,
}

pub(crate) fn visible_variable_bindings_before_span(
    summary: &SessionSummary,
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> SessionBindings {
    let bindings =
        SessionBindings::from_summary_and_shell_state(summary, &request.shell_state_before);
    apply_visible_variable_bindings_before_span(bindings, parsed, span_start_byte, observed_at)
}

pub(crate) fn apply_visible_variable_bindings_before_span(
    mut bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> SessionBindings {
    let mut events = Vec::new();

    for declaration in &parsed.declaration_commands {
        if declaration.span.end_byte <= span_start_byte {
            events.push(VariableOverlayEvent::Declaration(declaration));
        }
    }

    for assignment_command in &parsed.assignment_commands {
        if assignment_command.span.end_byte <= span_start_byte {
            events.push(VariableOverlayEvent::AssignmentCommand(assignment_command));
        }
    }

    for unset in &parsed.unset_commands {
        if unset.span.end_byte <= span_start_byte && unset.options.is_empty() {
            events.push(VariableOverlayEvent::Unset(unset));
        }
    }

    for command in &parsed.commands {
        if command.span.end_byte <= span_start_byte
            && matches!(command.command_name.as_deref(), Some("set" | "shift"))
        {
            events.push(VariableOverlayEvent::SetPositionalParameters(command));
        }
    }

    events.sort_by_key(|event| event.start_byte());

    for event in events {
        match event {
            VariableOverlayEvent::Declaration(declaration) => {
                if declaration.kind != caushell_parse::DeclarationCommandKind::Export
                    || !declaration.options.is_empty()
                {
                    continue;
                }

                for assignment in &declaration.assignments {
                    apply_binding(
                        &mut bindings,
                        SessionVariableBinding::new(
                            assignment.name.clone(),
                            classify_assignment_value(&assignment.value),
                            true,
                            observed_at,
                        ),
                    );
                }
            }
            VariableOverlayEvent::AssignmentCommand(assignment_command) => {
                for assignment in &assignment_command.assignments {
                    if assignment.operator != caushell_parse::AssignmentOperator::Assign {
                        continue;
                    }

                    apply_binding(
                        &mut bindings,
                        SessionVariableBinding::new(
                            assignment.name.clone(),
                            classify_assignment_value(&assignment.value),
                            false,
                            observed_at,
                        ),
                    );
                }
            }
            VariableOverlayEvent::Unset(unset) => {
                for name in &unset.names {
                    bindings.remove(name);
                }
            }
            VariableOverlayEvent::SetPositionalParameters(command) => {
                if let Some(mutation) =
                    positional_parameter_mutation_for_command(command, &bindings)
                {
                    apply_positional_parameter_mutation(&mut bindings, mutation);
                }
            }
        }
    }

    bindings
}

enum VariableOverlayEvent<'a> {
    Declaration(&'a caushell_parse::DeclarationCommandFact),
    AssignmentCommand(&'a caushell_parse::AssignmentCommandFact),
    Unset(&'a caushell_parse::UnsetCommandFact),
    SetPositionalParameters(&'a CommandFact),
}

impl VariableOverlayEvent<'_> {
    fn start_byte(&self) -> usize {
        match self {
            Self::Declaration(declaration) => declaration.span.start_byte,
            Self::AssignmentCommand(assignment_command) => assignment_command.span.start_byte,
            Self::Unset(unset) => unset.span.start_byte,
            Self::SetPositionalParameters(command) => command.span.start_byte,
        }
    }
}

fn set_dashdash_positional_values(
    command: &CommandFact,
    bindings: &SessionBindings,
) -> Option<PositionalParameterMutation> {
    if command.tokens.first()?.kind != CommandTokenKind::DashDash {
        return None;
    }

    let mut values = Vec::new();
    for token in command.tokens.iter().skip(1) {
        if token.kind == CommandTokenKind::DashDash {
            return None;
        }
        match set_positional_token_values(token, bindings) {
            SetPositionalTokenValues::Values(token_values) => values.extend(token_values),
            SetPositionalTokenValues::UnknownArity => {
                return Some(PositionalParameterMutation::Forget);
            }
        }
    }

    Some(PositionalParameterMutation::Replace(values))
}

enum SetPositionalTokenValues {
    Values(Vec<SessionValue>),
    UnknownArity,
}

fn set_positional_token_values(
    token: &CommandToken,
    bindings: &SessionBindings,
) -> SetPositionalTokenValues {
    if let Some(fields) =
        materialize_exact_shell_parameter_reference_fields(&token.text, token.quoted, bindings)
    {
        let Some(values) = fields
            .into_iter()
            .map(materialized_shell_field_to_session_value)
            .collect::<Option<Vec<_>>>()
        else {
            return SetPositionalTokenValues::UnknownArity;
        };
        return SetPositionalTokenValues::Values(values);
    }

    if let Some(value) = exact_set_positional_token_value(token, bindings) {
        return SetPositionalTokenValues::Values(vec![SessionValue::exact_scalar(value)]);
    }

    if token.quoted && contains_unescaped_dynamic_syntax(&token.text) {
        return SetPositionalTokenValues::Values(vec![SessionValue::opaque_dynamic(
            token.text.clone(),
        )]);
    }

    SetPositionalTokenValues::UnknownArity
}

fn materialized_shell_field_to_session_value(
    field: MaterializedShellField,
) -> Option<SessionValue> {
    match field.resolution {
        ValueMaterialization::ResolvedExactScalar { .. } => {
            Some(SessionValue::exact_scalar(field.text))
        }
        ValueMaterialization::ResolvedRuntimeProduced { kind, .. } => {
            Some(SessionValue::runtime_produced(field.text, kind))
        }
        _ => None,
    }
}

pub(crate) fn positional_parameter_mutation_for_command(
    command: &CommandFact,
    bindings: &SessionBindings,
) -> Option<PositionalParameterMutation> {
    if !command_can_update_current_shell(command) {
        return None;
    }

    match command.command_name.as_deref()? {
        "set" => set_dashdash_positional_values(command, bindings),
        "shift" => shift_positional_parameters(command, bindings),
        _ => None,
    }
}

fn command_can_update_current_shell(command: &CommandFact) -> bool {
    !command.in_pipeline
        && command.terminator != Some(StatementTerminator::Background)
        && command.subshell_span.is_none()
        && command.control_flow_span.is_none()
}

pub(crate) fn apply_positional_parameter_mutation(
    bindings: &mut SessionBindings,
    mutation: PositionalParameterMutation,
) {
    match mutation {
        PositionalParameterMutation::Replace(values) => {
            bindings.replace_positional_parameters(values);
        }
        PositionalParameterMutation::Shift(count) => {
            let values = bindings
                .positional_parameters()
                .iter()
                .skip(count)
                .cloned()
                .collect::<Vec<_>>();
            bindings.replace_positional_parameters(values);
        }
        PositionalParameterMutation::Forget => {
            bindings.replace_positional_parameters(Vec::<SessionValue>::new());
        }
    }
}

fn shift_positional_parameters(
    command: &CommandFact,
    bindings: &SessionBindings,
) -> Option<PositionalParameterMutation> {
    let count = match command.tokens.as_slice() {
        [] => 1,
        [token] if token.kind == CommandTokenKind::Arg => {
            let value = exact_set_positional_token_value(token, bindings)?;
            value.parse::<usize>().ok()?
        }
        _ => return None,
    };

    if count > bindings.positional_parameters().len() {
        return None;
    }

    Some(PositionalParameterMutation::Shift(count))
}

fn exact_set_positional_token_value(
    token: &CommandToken,
    bindings: &SessionBindings,
) -> Option<String> {
    if exact_shell_parameter_reference(&token.text).is_some() {
        let value = exact_scalar_shell_parameter_reference_value(&token.text, bindings)?;
        return (token.quoted || is_plain_unquoted_set_arg_literal(&value)).then_some(value);
    }

    match token.node_kind.as_str() {
        "raw_string" | "ansi_c_string" | "number" => Some(token.text.clone()),
        "string" if is_plain_quoted_literal(&token.text) => Some(token.text.clone()),
        "word" if is_plain_unquoted_set_arg_literal(&token.text) => Some(token.text.clone()),
        _ => None,
    }
}

fn classify_assignment_value(value: &caushell_parse::AssignmentValueFact) -> SessionVariableValue {
    match value.node_kind.as_str() {
        "empty" => SessionVariableValue::exact_scalar(String::new()),
        "raw_string" | "ansi_c_string" | "number" => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        "string" if is_plain_quoted_literal(&value.text) => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        "word" if is_plain_unquoted_literal(&value.text) => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        _ => SessionVariableValue::opaque_dynamic(value.text.clone()),
    }
}

fn apply_binding(bindings: &mut SessionBindings, binding: SessionVariableBinding) {
    match binding.value {
        SessionVariableValue::ExactScalar(value) => {
            bindings.insert_exact_scalar(&binding.name, value);
        }
        SessionVariableValue::RuntimeProduced { value, kind } => {
            bindings.insert_runtime_produced(&binding.name, value, kind);
        }
        SessionVariableValue::OpaqueDynamic { repr } => {
            bindings.insert_opaque_dynamic(&binding.name, repr);
        }
        SessionVariableValue::RuntimeInput { source, capture } => {
            bindings.insert_runtime_input(&binding.name, source, capture);
        }
    }
}

fn is_plain_quoted_literal(text: &str) -> bool {
    !text.contains('\\') && !contains_unescaped_dynamic_syntax(text)
}

fn is_plain_unquoted_literal(text: &str) -> bool {
    !text.contains('\\') && !text.contains('~') && !contains_unescaped_dynamic_syntax(text)
}

fn is_plain_unquoted_set_arg_literal(text: &str) -> bool {
    is_plain_unquoted_literal(text)
        && !text
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn contains_unescaped_dynamic_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }

        if bytes[index] == b'$' || bytes[index] == b'`' {
            return true;
        }

        index += 1;
    }

    false
}
