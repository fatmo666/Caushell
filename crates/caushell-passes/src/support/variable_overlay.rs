use super::{ExportMode, UnsetMode, export_mode, scalar_identifier, state_visible, unset_mode};
use caushell_parse::{
    CommandFact, CommandToken, CommandTokenKind, ParsedCommandArtifact, StatementTerminator,
};
use caushell_profile::{
    MaterializedShellField, SessionBindings, SessionValue, ValueMaterialization,
    exact_scalar_shell_parameter_reference_value, exact_shell_parameter_reference,
    materialize_exact_shell_parameter_reference_fields, materialize_shell_assignment_value,
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

pub(crate) fn request_variable_bindings(
    summary: &SessionSummary,
    request: &CheckRequest,
) -> SessionBindings {
    let mut bindings =
        SessionBindings::from_summary_and_shell_state(summary, &request.shell_state_before);
    if bindings.get("HOME").is_none()
        && let Some(home) = request.home.as_deref()
    {
        bindings.insert_inherited_exact_scalar("HOME", home);
    }
    bindings
}

pub(crate) fn apply_visible_variable_bindings_before_span(
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> SessionBindings {
    apply_variable_overlay(bindings, parsed, span_start_byte, observed_at, None).bindings
}

pub(crate) fn static_variable_overlay(
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    observed_at: CommandSequenceNo,
) -> super::runtime_variable_overlay::RuntimeVariableOverlay {
    apply_variable_overlay(bindings, parsed, usize::MAX, observed_at, None)
}

pub(super) fn apply_variable_overlay(
    mut bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
    mut runtime: Option<&mut super::runtime_variable_overlay::RuntimeVariableContext<'_>>,
) -> super::runtime_variable_overlay::RuntimeVariableOverlay {
    let mut events = Vec::new();
    let mut touched = std::collections::BTreeSet::new();
    let mut positional_state = None;
    let mut assigned = std::collections::BTreeSet::new();
    let mut state_fences = Vec::new();
    let mut function_mutations = Vec::new();

    for definition in &parsed.function_definitions {
        if definition.span.end_byte <= span_start_byte {
            events.push(VariableOverlayEvent::FunctionDefinition(definition));
        }
    }

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
        if unset.span.end_byte <= span_start_byte {
            events.push(VariableOverlayEvent::Unset(unset));
        }
    }

    for command in &parsed.commands {
        if command.span.end_byte <= span_start_byte
            && matches!(command.command_name.as_deref(), Some("set" | "shift"))
        {
            events.push(VariableOverlayEvent::SetPositionalParameters(command));
        }
        if runtime.is_some() && command.span.end_byte <= span_start_byte {
            events.push(VariableOverlayEvent::RuntimeCommand(command));
        }
    }

    events.sort_by_key(|event| event.start_byte());

    for event in events {
        if state_fences
            .iter()
            .any(|(start, end)| event.start_byte() >= *start && event.start_byte() < *end)
        {
            continue;
        }
        match event {
            VariableOverlayEvent::FunctionDefinition(definition) => {
                if state_visible(&definition.shell_scope_span, span_start_byte) {
                    function_mutations.push((
                        super::function_overlay::define_function(
                            &mut bindings,
                            definition,
                            observed_at,
                        ),
                        definition.span.start_byte,
                    ));
                }
            }
            VariableOverlayEvent::Declaration(declaration) => {
                if !state_visible(&declaration.shell_scope_span, span_start_byte) {
                    continue;
                }
                if declaration.kind == caushell_parse::DeclarationCommandKind::Local
                    && bindings.in_function_scope()
                    && declaration.options.is_empty()
                    && !declaration.assignments.is_empty()
                    && declaration.assignments.iter().all(|a| {
                        scalar_identifier(&a.name)
                            && !bindings.runtime_variable_target_is_unresolved(&a.name)
                            && a.operator == caushell_parse::AssignmentOperator::Assign
                    })
                {
                    // Operands expand before the declaration takes effect.
                    // Keep scalar bytes only in a proved function frame; local
                    // export attributes remain unknown rather than guessed.
                    let values = declaration
                        .assignments
                        .iter()
                        .map(|a| classify_assignment_value(&a.value, &bindings))
                        .collect::<Vec<_>>();
                    for (assignment, value) in declaration.assignments.iter().zip(values) {
                        assigned.insert(assignment.name.clone());
                        apply_binding(
                            &mut bindings,
                            SessionVariableBinding::new(
                                assignment.name.clone(),
                                value,
                                false,
                                observed_at,
                            ),
                        );
                        if declaration.conditional_execution {
                            bindings.insert_opaque_dynamic(
                                &assignment.name,
                                "conditional local assignment",
                            );
                        }
                        bindings.set_environment_value(
                            &assignment.name,
                            SessionValue::opaque_dynamic("unresolved local export attribute"),
                        );
                    }
                    for name in &declaration.names {
                        bindings.insert_opaque_dynamic(name, "uninitialised local declaration");
                        bindings.set_environment_value(
                            name,
                            SessionValue::opaque_dynamic("unresolved local export attribute"),
                        );
                    }
                    continue;
                }
                if declaration.kind == caushell_parse::DeclarationCommandKind::Readonly
                    || (declaration.kind != caushell_parse::DeclarationCommandKind::Export
                        && declaration.options.iter().any(|option| {
                            option.starts_with('-')
                                && option[1..]
                                    .chars()
                                    .any(|c| matches!(c, 'n' | 'a' | 'A' | 'r'))
                        }))
                {
                    for name in declaration
                        .names
                        .iter()
                        .map(String::as_str)
                        .chain(declaration.assignments.iter().map(|a| a.name.as_str()))
                    {
                        bindings.mark_unresolved_runtime_variable_target(name);
                    }
                }
                if declaration.kind != caushell_parse::DeclarationCommandKind::Export {
                    for name in declaration
                        .names
                        .iter()
                        .map(String::as_str)
                        .chain(declaration.assignments.iter().map(|a| a.name.as_str()))
                    {
                        bindings.mark_variable_presence_unknown(name);
                    }
                    // Export-affecting declarations beyond plain `export` are
                    // not proved absent merely because the scalar overlay does
                    // not model their option semantics (declare -x, typeset,
                    // etc.). Preserve this uncertainty for tools.
                    for name in declaration
                        .names
                        .iter()
                        .map(String::as_str)
                        .chain(declaration.assignments.iter().map(|a| a.name.as_str()))
                    {
                        bindings.set_environment_value(
                            name,
                            SessionValue::opaque_dynamic("unresolved export declaration"),
                        );
                    }
                    continue;
                }
                let mode = export_mode(&declaration.options);
                if matches!(mode, ExportMode::Invalid | ExportMode::Functions) {
                    // Invalid leading options fail before touching operands.
                    // Function export is a separate, not-yet-modeled namespace.
                    continue;
                }
                if mode == ExportMode::Unresolved {
                    invalidate_unknown_scalar_targets(&mut bindings, &mut assigned);
                    continue;
                }
                if declaration
                    .names
                    .iter()
                    .any(|name| name.contains('$') || name.contains('`'))
                {
                    bindings.forget_variable_presence();
                }
                // Declaration-builtin operands expand before the builtin
                // applies any assignment. Unlike a pure assignment command,
                // a later `B=$A` does not see an earlier `A=new` here.
                let values = declaration
                    .assignments
                    .iter()
                    .map(|assignment| classify_assignment_value(&assignment.value, &bindings))
                    .collect::<Vec<_>>();
                for (assignment, value) in declaration.assignments.iter().zip(values) {
                    assigned.insert(assignment.name.clone());
                    if assignment.operator != caushell_parse::AssignmentOperator::Assign {
                        bindings.insert_opaque_dynamic(
                            &assignment.name,
                            "unresolved export assignment operator",
                        );
                    } else {
                        apply_binding(
                            &mut bindings,
                            SessionVariableBinding::new(
                                assignment.name.clone(),
                                value,
                                mode == ExportMode::Export,
                                observed_at,
                            ),
                        );
                    }
                    if declaration.conditional_execution {
                        bindings.insert_opaque_dynamic(
                            &assignment.name,
                            "conditional export assignment",
                        );
                    }
                }
                for name in declaration
                    .names
                    .iter()
                    .map(String::as_str)
                    .chain(declaration.assignments.iter().map(|a| a.name.as_str()))
                    .filter(|name| scalar_identifier(name))
                {
                    // Exporting an unset name marks an attribute but does not
                    // create a scalar value. Do not persist a fictitious value.
                    if bindings.get(name).is_some() {
                        assigned.insert(name.to_string());
                    }
                    if declaration.conditional_execution {
                        bindings.insert_opaque_dynamic(name, "conditional export attribute");
                        bindings.set_environment_value(
                            name,
                            SessionValue::opaque_dynamic("conditional export attribute"),
                        );
                    } else if mode == ExportMode::Unexport {
                        bindings.unexport(name);
                    } else {
                        // `export NAME` creates a variable symbol even without
                        // a scalar value. `export -n NAME` alone does not.
                        bindings.mark_variable_present(name);
                        bindings.export(name);
                    }
                }
            }
            VariableOverlayEvent::AssignmentCommand(assignment_command) => {
                if !state_visible(&assignment_command.shell_scope_span, span_start_byte) {
                    continue;
                }
                for assignment in &assignment_command.assignments {
                    if assignment.operator != caushell_parse::AssignmentOperator::Assign {
                        if !matches!(
                            bindings.environment_value(&assignment.name),
                            caushell_profile::EnvironmentValueRef::Absent
                        ) {
                            bindings.set_environment_value(
                                &assignment.name,
                                SessionValue::opaque_dynamic("unresolved assignment operator"),
                            );
                        }
                        continue;
                    }
                    assigned.insert(assignment.name.clone());
                    let value = classify_assignment_value(&assignment.value, &bindings);
                    apply_binding(
                        &mut bindings,
                        SessionVariableBinding::new(
                            assignment.name.clone(),
                            value,
                            false,
                            observed_at,
                        ),
                    );
                    if assignment_command.conditional_execution {
                        // A conditional/isolated assignment is not proof that
                        // an invalidated runtime value became exact again.
                        bindings.insert_opaque_dynamic(
                            &assignment.name,
                            "conditional assignment after runtime write",
                        );
                    }
                    if assignment_command.conditional_execution
                        && !matches!(
                            bindings.environment_value(&assignment.name),
                            caushell_profile::EnvironmentValueRef::Absent
                        )
                    {
                        bindings.set_environment_value(
                            &assignment.name,
                            SessionValue::opaque_dynamic("conditional or isolated assignment"),
                        );
                    }
                }
            }
            VariableOverlayEvent::Unset(unset) => {
                if !state_visible(&unset.shell_scope_span, span_start_byte) {
                    continue;
                }
                let mode = unset_mode(&unset.options);
                if mode == UnsetMode::Unresolved
                    || (matches!(mode, UnsetMode::Default | UnsetMode::Functions)
                        && unset
                            .names
                            .iter()
                            .any(|name| name.contains('$') || name.contains('`')))
                {
                    function_mutations.extend(
                        super::function_overlay::invalidate_function_targets(
                            &mut bindings,
                            observed_at,
                        )
                        .into_iter()
                        .map(|m| (m, unset.span.start_byte)),
                    );
                }
                match mode {
                    UnsetMode::Invalid => continue,
                    UnsetMode::Nameref | UnsetMode::Unresolved => {
                        // Do not assert exact values for possible indirect or
                        // dynamic targets. Nameref resolution is deferred.
                        invalidate_unknown_scalar_targets(&mut bindings, &mut assigned);
                        continue;
                    }
                    UnsetMode::Default | UnsetMode::Variables | UnsetMode::Functions => {}
                }
                for name in &unset.names {
                    if name.contains('$')
                        || name.contains('`')
                        || (!scalar_identifier(name)
                            && mode != UnsetMode::Functions
                            && bindings.function_binding(name).is_none())
                    {
                        continue;
                    }
                    if let Some(mutation) = super::function_overlay::unset_function_target(
                        &mut bindings,
                        name,
                        mode,
                        unset.conditional_execution,
                        observed_at,
                    ) {
                        function_mutations.push((mutation, unset.span.start_byte));
                    }
                    if mode == UnsetMode::Functions || !scalar_identifier(name) {
                        continue;
                    }
                    assigned.insert(name.clone());
                    if !unset.conditional_execution {
                        bindings.remove(name);
                    } else {
                        bindings.insert_opaque_dynamic(name, "conditional unset");
                        bindings.set_environment_value(
                            name,
                            SessionValue::opaque_dynamic("unresolved unset scope/options"),
                        );
                    }
                }
            }
            VariableOverlayEvent::SetPositionalParameters(command) => {
                if command.command_name.as_deref() == Some("set")
                    && command
                        .tokens
                        .iter()
                        .take_while(|token| token.text != "--")
                        .any(|token| {
                            token.text == "-o"
                                || token.text == "+o"
                                || ((token.text.starts_with('-') || token.text.starts_with('+'))
                                    && token.text[1..].contains('a'))
                                || token.text.contains('$')
                        })
                {
                    // The request protocol carries variable/export facts, not
                    // shell option state. After an allexport mode change, do
                    // not keep asserting that new assignments are unexported.
                    bindings.forget_environment();
                }
                if let Some(mutation) =
                    positional_parameter_mutation_for_command(command, &bindings)
                {
                    let forget = matches!(mutation, PositionalParameterMutation::Forget)
                        || (matches!(positional_state, Some(PositionalParameterMutation::Forget))
                            && matches!(mutation, PositionalParameterMutation::Shift(_)));
                    apply_positional_parameter_mutation(&mut bindings, mutation);
                    positional_state = Some(if forget {
                        PositionalParameterMutation::Forget
                    } else {
                        PositionalParameterMutation::Replace(
                            bindings.positional_parameters().to_vec(),
                        )
                    });
                }
            }
            VariableOverlayEvent::RuntimeCommand(command) => {
                if let Some(runtime) = runtime.as_deref_mut() {
                    if let Some(fence) = runtime.apply_command(
                        command,
                        parsed,
                        span_start_byte,
                        &mut bindings,
                        &mut touched,
                        &mut function_mutations,
                    ) {
                        state_fences.push(fence);
                    }
                }
            }
        }
    }

    super::runtime_variable_overlay::RuntimeVariableOverlay {
        bindings,
        touched,
        positional_state,
        assigned,
        state_fences,
        function_mutations,
    }
}

fn invalidate_unknown_scalar_targets(
    bindings: &mut SessionBindings,
    assigned: &mut std::collections::BTreeSet<String>,
) {
    bindings.forget_variable_presence();
    let names = bindings
        .variable_names()
        .map(str::to_string)
        .collect::<Vec<_>>();
    bindings.forget_environment();
    for name in names {
        assigned.insert(name.clone());
        bindings.insert_opaque_dynamic(&name, "unresolved scalar state target");
        bindings.set_environment_value(
            &name,
            SessionValue::opaque_dynamic("unresolved scalar state target"),
        );
    }
}

enum VariableOverlayEvent<'a> {
    FunctionDefinition(&'a caushell_parse::FunctionDefinitionFact),
    Declaration(&'a caushell_parse::DeclarationCommandFact),
    AssignmentCommand(&'a caushell_parse::AssignmentCommandFact),
    Unset(&'a caushell_parse::UnsetCommandFact),
    SetPositionalParameters(&'a CommandFact),
    RuntimeCommand(&'a CommandFact),
}

impl VariableOverlayEvent<'_> {
    fn start_byte(&self) -> usize {
        match self {
            Self::FunctionDefinition(definition) => definition.span.start_byte,
            Self::Declaration(declaration) => declaration.span.start_byte,
            Self::AssignmentCommand(assignment_command) => assignment_command.span.start_byte,
            Self::Unset(unset) => unset.span.start_byte,
            Self::SetPositionalParameters(command) => command.span.start_byte,
            Self::RuntimeCommand(command) => command.span.start_byte,
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
            if !bindings.positional_parameters_are_complete() {
                bindings.forget_positional_parameters();
                return;
            }
            let values = bindings
                .positional_parameters()
                .iter()
                .skip(count)
                .cloned()
                .collect::<Vec<_>>();
            bindings.replace_positional_parameters(values);
        }
        PositionalParameterMutation::Forget => {
            bindings.forget_positional_parameters();
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
            let Some(value) = exact_set_positional_token_value(token, bindings) else {
                // An unknown count can change any positional index. It is
                // not evidence that shift was invalid or did nothing.
                return Some(PositionalParameterMutation::Forget);
            };
            value.parse::<usize>().ok()?
        }
        _ => return None,
    };

    if !bindings.positional_parameters_are_complete() {
        return Some(PositionalParameterMutation::Forget);
    }
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

pub(crate) fn command_environment_bindings(
    base: &SessionBindings,
    parsed: &ParsedCommandArtifact,
    command_ref: &caushell_runner::ParsedCommandRef,
) -> SessionBindings {
    let mut bindings = base.clone();
    let command = parsed
        .commands
        .get(command_ref.command_index)
        .filter(|command| command.span == command_ref.span)
        .or_else(|| {
            parsed
                .commands
                .iter()
                .find(|command| command.span == command_ref.span)
        });
    let Some(command) = command else {
        bindings.forget_environment();
        return bindings;
    };
    for assignment in &command.prefix_assignments {
        let value = if assignment.operator == caushell_parse::AssignmentOperator::Assign {
            classify_assignment_value(&assignment.value, base)
        } else {
            SessionVariableValue::opaque_dynamic("unresolved prefix assignment")
        };
        bindings.set_child_environment_value(
            &assignment.name,
            caushell_profile::SessionValue::from_session_variable_value(&value),
        );
    }
    bindings
}

pub(crate) fn classify_assignment_value(
    value: &caushell_parse::AssignmentValueFact,
    bindings: &SessionBindings,
) -> SessionVariableValue {
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
        _ => materialize_shell_assignment_value(
            &value.text,
            value.quoted,
            &value.node_kind,
            bindings,
        )
        .map(SessionVariableValue::exact_scalar)
        .unwrap_or_else(|| SessionVariableValue::opaque_dynamic(value.text.clone())),
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
    if binding.exported {
        bindings.export(&binding.name);
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
