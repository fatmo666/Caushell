use std::collections::BTreeMap;

use caushell_types::{
    RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind, SessionSummary,
    SessionVariableValue, ShellStateKnowledge, ShellStateSnapshot, ShellValueSnapshot,
};

use crate::{
    ImplicitInputSource, ProjectedArg, ProjectedArgKind, ProjectedInvocation,
    RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
    RecursivePayloadFragmentMaterialization, RecursivePayloadInput,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionValue {
    ExactScalar(String),
    RuntimeProduced {
        value: String,
        kind: RuntimeProducedValueKind,
    },
    OpaqueDynamic {
        repr: String,
    },
    RuntimeInput {
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    },
}

impl SessionValue {
    pub fn exact_scalar(value: impl Into<String>) -> Self {
        Self::ExactScalar(value.into())
    }

    pub fn runtime_produced(value: impl Into<String>, kind: RuntimeProducedValueKind) -> Self {
        Self::RuntimeProduced {
            value: value.into(),
            kind,
        }
    }

    pub fn opaque_dynamic(repr: impl Into<String>) -> Self {
        Self::OpaqueDynamic { repr: repr.into() }
    }

    pub fn runtime_input(source: RuntimeInputSource, capture: RuntimeInputCapture) -> Self {
        Self::RuntimeInput { source, capture }
    }

    pub fn from_session_variable_value(value: &SessionVariableValue) -> Self {
        match value {
            SessionVariableValue::ExactScalar(value) => Self::exact_scalar(value.clone()),
            SessionVariableValue::RuntimeProduced { value, kind } => {
                Self::runtime_produced(value.clone(), *kind)
            }
            SessionVariableValue::OpaqueDynamic { repr } => Self::opaque_dynamic(repr.clone()),
            SessionVariableValue::RuntimeInput { source, capture } => {
                Self::runtime_input(*source, capture.clone())
            }
        }
    }

    pub fn to_session_variable_value(&self) -> SessionVariableValue {
        match self {
            Self::ExactScalar(value) => SessionVariableValue::exact_scalar(value.clone()),
            Self::RuntimeProduced { value, kind } => {
                SessionVariableValue::runtime_produced(value.clone(), *kind)
            }
            Self::OpaqueDynamic { repr } => SessionVariableValue::opaque_dynamic(repr.clone()),
            Self::RuntimeInput { source, capture } => {
                SessionVariableValue::runtime_input(*source, capture.clone())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingOrigin {
    SessionBinding,
    InheritedEnvironment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingValueRef<'a> {
    pub origin: BindingOrigin,
    pub value: &'a SessionValue,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionBindings {
    session_variables: BTreeMap<String, SessionValue>,
    inherited_environment: BTreeMap<String, SessionValue>,
    positional_parameters: Vec<SessionValue>,
}

impl SessionBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_session_summary(summary: &SessionSummary) -> Self {
        let mut bindings = Self::new();

        for binding in summary.variable_bindings() {
            bindings.session_variables.insert(
                binding.name.clone(),
                SessionValue::from_session_variable_value(&binding.value),
            );
        }

        if let Some(positional_parameters) = summary.positional_parameters() {
            bindings.replace_positional_parameters(
                positional_parameters
                    .values
                    .iter()
                    .map(SessionValue::from_session_variable_value),
            );
        }

        bindings
    }

    pub fn from_summary_and_shell_state(
        summary: &SessionSummary,
        shell_state: &ShellStateSnapshot,
    ) -> Self {
        let mut bindings = match shell_state.observability.variables {
            ShellStateKnowledge::Complete => Self::new(),
            ShellStateKnowledge::ExportedOnly | ShellStateKnowledge::Unknown => {
                Self::from_session_summary(summary)
            }
        };

        for variable in &shell_state.variables {
            if let Some(value) = shell_value_to_session_value(&variable.value) {
                match shell_state.observability.variables {
                    ShellStateKnowledge::Complete => {
                        bindings
                            .session_variables
                            .insert(variable.name.clone(), value);
                    }
                    ShellStateKnowledge::ExportedOnly | ShellStateKnowledge::Unknown => {
                        if variable.exported {
                            bindings
                                .inherited_environment
                                .insert(variable.name.clone(), value);
                        }
                    }
                }
            }
        }

        if shell_state.observability.positional_parameters == ShellStateKnowledge::Complete {
            let values = shell_state
                .positional_parameters
                .iter()
                .map(shell_value_to_session_value)
                .collect::<Option<Vec<_>>>();
            if let Some(values) = values {
                bindings.replace_positional_parameters(values);
            }
        }

        bindings
    }

    pub fn with_exact_scalar(mut self, name: &str, value: impl Into<String>) -> Self {
        self.insert_exact_scalar(name, value);
        self
    }

    pub fn with_opaque_dynamic(mut self, name: &str, repr: impl Into<String>) -> Self {
        self.insert_opaque_dynamic(name, repr);
        self
    }

    pub fn with_runtime_produced(
        mut self,
        name: &str,
        value: impl Into<String>,
        kind: RuntimeProducedValueKind,
    ) -> Self {
        self.insert_runtime_produced(name, value, kind);
        self
    }

    pub fn insert_exact_scalar(&mut self, name: &str, value: impl Into<String>) {
        self.session_variables
            .insert(name.to_string(), SessionValue::exact_scalar(value));
    }

    pub fn insert_runtime_produced(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: RuntimeProducedValueKind,
    ) {
        self.session_variables.insert(
            name.to_string(),
            SessionValue::runtime_produced(value, kind),
        );
    }

    pub fn insert_opaque_dynamic(&mut self, name: &str, repr: impl Into<String>) {
        self.session_variables
            .insert(name.to_string(), SessionValue::opaque_dynamic(repr));
    }

    pub fn with_runtime_input(
        mut self,
        name: &str,
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    ) -> Self {
        self.insert_runtime_input(name, source, capture);
        self
    }

    pub fn insert_runtime_input(
        &mut self,
        name: &str,
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    ) {
        self.session_variables.insert(
            name.to_string(),
            SessionValue::runtime_input(source, capture),
        );
    }

    pub fn with_inherited_exact_scalar(mut self, name: &str, value: impl Into<String>) -> Self {
        self.insert_inherited_exact_scalar(name, value);
        self
    }

    pub fn insert_inherited_exact_scalar(&mut self, name: &str, value: impl Into<String>) {
        self.inherited_environment
            .insert(name.to_string(), SessionValue::exact_scalar(value));
    }

    pub fn replace_positional_parameters<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = SessionValue>,
    {
        self.positional_parameters = values.into_iter().collect();
    }

    pub fn replace_positional_parameters_with_exact_scalars<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.replace_positional_parameters(values.into_iter().map(SessionValue::exact_scalar));
    }

    pub fn positional_parameter(&self, position: usize) -> Option<&SessionValue> {
        if position == 0 {
            return None;
        }

        self.positional_parameters.get(position - 1)
    }

    pub fn positional_parameters(&self) -> &[SessionValue] {
        &self.positional_parameters
    }

    pub fn remove(&mut self, name: &str) {
        self.session_variables.remove(name);
        self.inherited_environment.remove(name);
    }

    pub fn get(&self, name: &str) -> Option<BindingValueRef<'_>> {
        if let Some(value) = self.session_variables.get(name) {
            return Some(BindingValueRef {
                origin: BindingOrigin::SessionBinding,
                value,
            });
        }

        self.inherited_environment
            .get(name)
            .map(|value| BindingValueRef {
                origin: BindingOrigin::InheritedEnvironment,
                value,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellParameterReference {
    Variable(String),
    Positional(usize),
    AllPositionals(ShellAllPositionalsKind),
    Expansion {
        parameter: ShellParameterName,
        operator: ShellParameterExpansionOperator,
        word: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellAllPositionalsKind {
    At,
    Star,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellParameterName {
    Variable(String),
    Positional(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellParameterExpansionOperator {
    UseDefaultIfUnsetOrNull,
    UseDefaultIfUnset,
    UseAlternateIfSetAndNotNull,
    UseAlternateIfSet,
}

pub fn parse_shell_parameter_reference_after_dollar<I>(
    chars: &mut std::iter::Peekable<I>,
) -> Option<ShellParameterReference>
where
    I: Iterator<Item = char>,
{
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut body = String::new();
        while let Some(ch) = chars.next() {
            if ch == '}' {
                if body == "@" {
                    return Some(ShellParameterReference::AllPositionals(
                        ShellAllPositionalsKind::At,
                    ));
                }
                if body == "*" {
                    return Some(ShellParameterReference::AllPositionals(
                        ShellAllPositionalsKind::Star,
                    ));
                }
                if let Some(position) = parse_positional_parameter_index(&body) {
                    return Some(ShellParameterReference::Positional(position));
                }
                if is_valid_variable_name(&body) {
                    return Some(ShellParameterReference::Variable(body));
                }
                return parse_braced_shell_parameter_expansion(&body);
            }
            body.push(ch);
        }
        return None;
    }

    if chars.peek().is_some_and(|ch| ch.is_ascii_digit()) {
        let position = chars.next()?.to_digit(10)? as usize;
        return Some(ShellParameterReference::Positional(position));
    }

    if chars.peek().is_some_and(|ch| matches!(ch, '@' | '*')) {
        let kind = match chars.next()? {
            '@' => ShellAllPositionalsKind::At,
            '*' => ShellAllPositionalsKind::Star,
            _ => unreachable!(),
        };
        return Some(ShellParameterReference::AllPositionals(kind));
    }

    let mut name = String::new();
    while let Some(ch) = chars.peek().copied() {
        if !is_variable_name_char(ch, name.is_empty()) {
            break;
        }
        name.push(ch);
        chars.next();
    }

    is_valid_variable_name(&name).then_some(ShellParameterReference::Variable(name))
}

pub fn exact_shell_parameter_reference(text: &str) -> Option<ShellParameterReference> {
    let mut chars = text.chars().peekable();
    if chars.next()? != '$' {
        return None;
    }

    let reference = parse_shell_parameter_reference_after_dollar(&mut chars)?;
    chars.next().is_none().then_some(reference)
}

pub fn exact_scalar_shell_parameter_reference_value(
    text: &str,
    bindings: &SessionBindings,
) -> Option<String> {
    let reference = exact_shell_parameter_reference(text)?;
    exact_scalar_shell_parameter_value(bindings, &reference)
}

pub fn exact_scalar_shell_parameter_value(
    bindings: &SessionBindings,
    reference: &ShellParameterReference,
) -> Option<String> {
    match reference {
        ShellParameterReference::Variable(name) => {
            exact_scalar_session_value(bindings.get(name)?.value)
        }
        ShellParameterReference::Positional(position) => {
            exact_scalar_session_value(bindings.positional_parameter(*position)?)
        }
        ShellParameterReference::AllPositionals(kind) => {
            exact_scalar_all_positional_parameters(bindings, *kind)
        }
        ShellParameterReference::Expansion {
            parameter,
            operator,
            word,
        } => exact_scalar_shell_parameter_expansion_value(bindings, parameter, *operator, word),
    }
}

fn exact_scalar_all_positional_parameters(
    bindings: &SessionBindings,
    kind: ShellAllPositionalsKind,
) -> Option<String> {
    let values = bindings
        .positional_parameters()
        .iter()
        .map(exact_scalar_session_value)
        .collect::<Option<Vec<_>>>()?;

    match kind {
        ShellAllPositionalsKind::At if values.len() <= 1 => {
            Some(values.into_iter().next().unwrap_or_default())
        }
        ShellAllPositionalsKind::At => None,
        ShellAllPositionalsKind::Star => Some(values.join(" ")),
    }
}

fn exact_scalar_session_value(value: &SessionValue) -> Option<String> {
    match value {
        SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. } => {
            Some(value.clone())
        }
        SessionValue::OpaqueDynamic { .. } | SessionValue::RuntimeInput { .. } => None,
    }
}

fn parse_braced_shell_parameter_expansion(body: &str) -> Option<ShellParameterReference> {
    let (parameter, rest) = parse_shell_parameter_name_prefix(body)?;
    let (operator, word) = if let Some(word) = rest.strip_prefix(":-") {
        (
            ShellParameterExpansionOperator::UseDefaultIfUnsetOrNull,
            word,
        )
    } else if let Some(word) = rest.strip_prefix('-') {
        (ShellParameterExpansionOperator::UseDefaultIfUnset, word)
    } else if let Some(word) = rest.strip_prefix(":+") {
        (
            ShellParameterExpansionOperator::UseAlternateIfSetAndNotNull,
            word,
        )
    } else if let Some(word) = rest.strip_prefix('+') {
        (ShellParameterExpansionOperator::UseAlternateIfSet, word)
    } else {
        return None;
    };

    Some(ShellParameterReference::Expansion {
        parameter,
        operator,
        word: word.to_string(),
    })
}

fn parse_shell_parameter_name_prefix(body: &str) -> Option<(ShellParameterName, &str)> {
    let mut chars = body.char_indices();
    let (_, first) = chars.next()?;

    if first.is_ascii_digit() {
        let end = body
            .char_indices()
            .find_map(|(index, ch)| (!ch.is_ascii_digit()).then_some(index))
            .unwrap_or(body.len());
        let position = parse_positional_parameter_index(&body[..end])?;
        return Some((ShellParameterName::Positional(position), &body[end..]));
    }

    if !is_variable_name_char(first, true) {
        return None;
    }

    let end = body
        .char_indices()
        .skip(1)
        .find_map(|(index, ch)| (!is_variable_name_char(ch, false)).then_some(index))
        .unwrap_or(body.len());
    let name = &body[..end];
    Some((ShellParameterName::Variable(name.to_string()), &body[end..]))
}

enum ShellParameterBindingRef<'a> {
    Bound { value: &'a SessionValue },
    Unset,
}

fn shell_parameter_binding<'a>(
    bindings: &'a SessionBindings,
    parameter: &ShellParameterName,
) -> ShellParameterBindingRef<'a> {
    match parameter {
        ShellParameterName::Variable(name) => bindings
            .get(name)
            .map(|binding| ShellParameterBindingRef::Bound {
                value: binding.value,
            })
            .unwrap_or(ShellParameterBindingRef::Unset),
        ShellParameterName::Positional(position) => bindings
            .positional_parameter(*position)
            .map(|value| ShellParameterBindingRef::Bound { value })
            .unwrap_or(ShellParameterBindingRef::Unset),
    }
}

fn exact_scalar_shell_parameter_expansion_value(
    bindings: &SessionBindings,
    parameter: &ShellParameterName,
    operator: ShellParameterExpansionOperator,
    word: &str,
) -> Option<String> {
    let binding = shell_parameter_binding(bindings, parameter);
    match operator {
        ShellParameterExpansionOperator::UseDefaultIfUnset => match binding {
            ShellParameterBindingRef::Unset => literal_parameter_expansion_word(word),
            ShellParameterBindingRef::Bound { value } => exact_scalar_session_value(value),
        },
        ShellParameterExpansionOperator::UseDefaultIfUnsetOrNull => match binding {
            ShellParameterBindingRef::Unset => literal_parameter_expansion_word(word),
            ShellParameterBindingRef::Bound { value } => {
                let value = exact_scalar_session_value(value)?;
                if value.is_empty() {
                    literal_parameter_expansion_word(word)
                } else {
                    Some(value)
                }
            }
        },
        ShellParameterExpansionOperator::UseAlternateIfSet => match binding {
            ShellParameterBindingRef::Unset => Some(String::new()),
            ShellParameterBindingRef::Bound { .. } => literal_parameter_expansion_word(word),
        },
        ShellParameterExpansionOperator::UseAlternateIfSetAndNotNull => match binding {
            ShellParameterBindingRef::Unset => Some(String::new()),
            ShellParameterBindingRef::Bound { value } => {
                let value = exact_scalar_session_value(value)?;
                if value.is_empty() {
                    Some(String::new())
                } else {
                    literal_parameter_expansion_word(word)
                }
            }
        },
    }
}

fn literal_parameter_expansion_word(word: &str) -> Option<String> {
    if contains_unescaped_dynamic_syntax(word)
        || word.chars().any(|ch| matches!(ch, '\'' | '"' | '\\'))
    {
        return None;
    }

    Some(word.to_string())
}

fn shell_value_to_session_value(value: &ShellValueSnapshot) -> Option<SessionValue> {
    match value {
        ShellValueSnapshot::ExactScalar { value } => {
            Some(SessionValue::exact_scalar(value.clone()))
        }
        ShellValueSnapshot::RuntimeProduced { value, value_kind } => {
            Some(SessionValue::runtime_produced(value.clone(), *value_kind))
        }
        ShellValueSnapshot::OpaqueDynamic { repr } => {
            Some(SessionValue::opaque_dynamic(repr.clone()))
        }
        ShellValueSnapshot::RuntimeInput { source, capture } => {
            Some(SessionValue::runtime_input(*source, capture.clone()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueMaterialization {
    Static,
    ResolvedExactScalar {
        variable_name: String,
        value: String,
        origin: BindingOrigin,
    },
    ResolvedRuntimeProduced {
        variable_name: String,
        value: String,
        kind: RuntimeProducedValueKind,
        origin: BindingOrigin,
    },
    MissingBinding {
        variable_name: String,
    },
    UnsupportedDynamicBinding {
        variable_name: String,
        repr: String,
        origin: BindingOrigin,
    },
    UnsupportedDynamicText {
        text: String,
    },
    UnsafeUnquotedScalar {
        variable_name: String,
        value: String,
        origin: BindingOrigin,
    },
    RequiresRuntimeInput {
        source: ImplicitInputSource,
        capture: Option<RuntimeInputCapture>,
        variable_name: Option<String>,
        origin: Option<BindingOrigin>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedProjectedInvocation {
    pub invocation: ProjectedInvocation,
    pub arg_resolutions: Vec<ValueMaterialization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedShellField {
    pub text: String,
    pub resolution: ValueMaterialization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedRecursivePayloadCandidate {
    pub candidate: RecursivePayloadCandidate,
    pub resolution: ValueMaterialization,
    pub fragment_resolutions: Vec<ValueMaterialization>,
}

pub fn materialize_projected_invocation(
    projection: &ProjectedInvocation,
    bindings: &SessionBindings,
) -> MaterializedProjectedInvocation {
    let mut args = Vec::with_capacity(projection.args.len());
    let mut arg_resolutions = Vec::with_capacity(projection.args.len());

    for arg in &projection.args {
        for materialized in materialize_argument_fields(arg, bindings) {
            args.push(ProjectedArg {
                text: materialized.text,
                kind: arg.kind,
                quoted: arg.quoted,
                node_kind: arg.node_kind.clone(),
                span: arg.span.clone(),
            });
            arg_resolutions.push(materialized.resolution);
        }
    }

    reclassify_projected_args(&mut args);

    MaterializedProjectedInvocation {
        invocation: ProjectedInvocation {
            command_name: projection.command_name.clone(),
            args,
            stdin_payload_available: projection.stdin_payload_available,
            interactive_session: projection.interactive_session,
        },
        arg_resolutions,
    }
}

pub fn materialize_recursive_payload_candidate(
    candidate: &RecursivePayloadCandidate,
    bindings: &SessionBindings,
) -> MaterializedRecursivePayloadCandidate {
    match &candidate.input {
        RecursivePayloadInput::ArgumentFragments { fragments } => {
            let mut materialized_fragments = Vec::with_capacity(fragments.len());
            let mut fragment_resolutions = Vec::with_capacity(fragments.len());

            for fragment in fragments {
                let materialized = materialize_recursive_fragment_text(fragment, bindings);

                materialized_fragments.push(RecursivePayloadArgumentFragment {
                    text: materialized.text,
                    quoted: fragment.quoted,
                    node_kind: fragment.node_kind.clone(),
                    span: fragment.span.clone(),
                    materialization: fragment.materialization.clone(),
                });
                fragment_resolutions.push(materialized.resolution);
            }

            let resolution = aggregate_recursive_payload_resolution(&fragment_resolutions);
            MaterializedRecursivePayloadCandidate {
                candidate: RecursivePayloadCandidate {
                    language: candidate.language,
                    source: candidate.source,
                    origin: candidate.origin.clone(),
                    input: RecursivePayloadInput::ArgumentFragments {
                        fragments: materialized_fragments,
                    },
                },
                resolution,
                fragment_resolutions,
            }
        }
        RecursivePayloadInput::ImplicitInput { source } => MaterializedRecursivePayloadCandidate {
            candidate: candidate.clone(),
            resolution: ValueMaterialization::RequiresRuntimeInput {
                source: *source,
                capture: None,
                variable_name: None,
                origin: None,
            },
            fragment_resolutions: Vec::new(),
        },
        RecursivePayloadInput::LiteralText { .. } => MaterializedRecursivePayloadCandidate {
            candidate: candidate.clone(),
            resolution: ValueMaterialization::Static,
            fragment_resolutions: Vec::new(),
        },
    }
}

fn materialize_recursive_fragment_text(
    fragment: &RecursivePayloadArgumentFragment,
    bindings: &SessionBindings,
) -> MaterializedText {
    match &fragment.materialization {
        RecursivePayloadFragmentMaterialization::ResolvedExactScalar { variable_name } => {
            return MaterializedText {
                text: fragment.text.clone(),
                resolution: ValueMaterialization::ResolvedExactScalar {
                    variable_name: variable_name.clone(),
                    value: fragment.text.clone(),
                    origin: BindingOrigin::SessionBinding,
                },
            };
        }
        RecursivePayloadFragmentMaterialization::ResolvedRuntimeProduced { variable_name } => {
            if let Some(binding) = bindings.get(variable_name) {
                if let SessionValue::RuntimeProduced { kind, .. } = binding.value {
                    return MaterializedText {
                        text: fragment.text.clone(),
                        resolution: ValueMaterialization::ResolvedRuntimeProduced {
                            variable_name: variable_name.clone(),
                            value: fragment.text.clone(),
                            kind: *kind,
                            origin: binding.origin,
                        },
                    };
                }
            }
        }
        RecursivePayloadFragmentMaterialization::Literal => {}
    }

    materialize_argument_text(
        &fragment.text,
        fragment.quoted,
        &fragment.node_kind,
        bindings,
    )
}

fn aggregate_recursive_payload_resolution(
    fragment_resolutions: &[ValueMaterialization],
) -> ValueMaterialization {
    if let Some(resolution) = fragment_resolutions.iter().find(|resolution| {
        matches!(
            resolution,
            ValueMaterialization::RequiresRuntimeInput { .. }
        )
    }) {
        return resolution.clone();
    }

    if let Some(resolution) = fragment_resolutions.iter().find(|resolution| {
        !matches!(
            resolution,
            ValueMaterialization::Static
                | ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedRuntimeProduced { .. }
        )
    }) {
        return resolution.clone();
    }

    fragment_resolutions
        .iter()
        .find(|resolution| !matches!(resolution, ValueMaterialization::Static))
        .cloned()
        .unwrap_or(ValueMaterialization::Static)
}

pub(crate) struct MaterializedText {
    pub(crate) text: String,
    pub(crate) resolution: ValueMaterialization,
}

fn materialize_argument_fields(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
) -> Vec<MaterializedText> {
    if !matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string")
        && matches!(
            exact_shell_parameter_reference(&arg.text),
            Some(ShellParameterReference::AllPositionals(_))
        )
    {
        if let Some(fields) =
            materialize_exact_shell_parameter_reference_fields(&arg.text, arg.quoted, bindings)
        {
            return fields
                .into_iter()
                .map(|field| MaterializedText {
                    text: field.text,
                    resolution: field.resolution,
                })
                .collect();
        }
    }

    vec![materialize_argument_text(
        &arg.text,
        arg.quoted,
        &arg.node_kind,
        bindings,
    )]
}

pub fn materialize_exact_shell_parameter_reference_fields(
    text: &str,
    quoted: bool,
    bindings: &SessionBindings,
) -> Option<Vec<MaterializedShellField>> {
    let reference = exact_shell_parameter_reference(text)?;
    materialize_shell_parameter_reference_fields(&reference, quoted, bindings)
}

fn materialize_shell_parameter_reference_fields(
    reference: &ShellParameterReference,
    quoted: bool,
    bindings: &SessionBindings,
) -> Option<Vec<MaterializedShellField>> {
    match reference {
        ShellParameterReference::AllPositionals(kind) => {
            materialize_all_positional_parameter_fields(*kind, quoted, bindings)
        }
        ShellParameterReference::Variable(name) => {
            let binding = bindings.get(name)?;
            materialize_session_value_field(name.clone(), binding.value, binding.origin, quoted)
                .map(|field| vec![field])
        }
        ShellParameterReference::Positional(position) => {
            let value = bindings.positional_parameter(*position)?;
            materialize_session_value_field(
                position.to_string(),
                value,
                BindingOrigin::SessionBinding,
                quoted,
            )
            .map(|field| vec![field])
        }
        ShellParameterReference::Expansion { .. } => {
            let value = exact_scalar_shell_parameter_value(bindings, reference)?;
            if !quoted && !is_safe_unquoted_scalar(&value) {
                return None;
            }

            Some(vec![MaterializedShellField {
                text: value.clone(),
                resolution: ValueMaterialization::ResolvedExactScalar {
                    variable_name: shell_parameter_reference_name(reference),
                    value,
                    origin: BindingOrigin::SessionBinding,
                },
            }])
        }
    }
}

fn materialize_all_positional_parameter_fields(
    kind: ShellAllPositionalsKind,
    quoted: bool,
    bindings: &SessionBindings,
) -> Option<Vec<MaterializedShellField>> {
    let mut fields = Vec::with_capacity(bindings.positional_parameters().len());

    for (index, value) in bindings.positional_parameters().iter().enumerate() {
        let variable_name = (index + 1).to_string();
        fields.push(materialize_session_value_field(
            variable_name,
            value,
            BindingOrigin::SessionBinding,
            quoted,
        )?);
    }

    match kind {
        ShellAllPositionalsKind::At => Some(fields),
        ShellAllPositionalsKind::Star if quoted => {
            let text = fields
                .iter()
                .map(|field| field.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            Some(vec![MaterializedShellField {
                text: text.clone(),
                resolution: ValueMaterialization::ResolvedExactScalar {
                    variable_name: "*".to_string(),
                    value: text,
                    origin: BindingOrigin::SessionBinding,
                },
            }])
        }
        ShellAllPositionalsKind::Star => Some(fields),
    }
}

fn materialize_session_value_field(
    variable_name: String,
    value: &SessionValue,
    origin: BindingOrigin,
    quoted: bool,
) -> Option<MaterializedShellField> {
    match value {
        SessionValue::ExactScalar(value) => {
            let value = value.clone();
            if !quoted && !is_safe_unquoted_scalar(&value) {
                return None;
            }

            Some(MaterializedShellField {
                text: value.clone(),
                resolution: ValueMaterialization::ResolvedExactScalar {
                    variable_name,
                    value,
                    origin,
                },
            })
        }
        SessionValue::RuntimeProduced { value, kind } => {
            let value = value.clone();
            if !quoted && !is_safe_unquoted_scalar(&value) {
                return None;
            }

            Some(MaterializedShellField {
                text: value.clone(),
                resolution: ValueMaterialization::ResolvedRuntimeProduced {
                    variable_name,
                    value,
                    kind: *kind,
                    origin,
                },
            })
        }
        SessionValue::OpaqueDynamic { .. } | SessionValue::RuntimeInput { .. } => None,
    }
}

pub(crate) fn materialize_argument_text(
    text: &str,
    quoted: bool,
    node_kind: &str,
    bindings: &SessionBindings,
) -> MaterializedText {
    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return MaterializedText {
            text: text.to_string(),
            resolution: ValueMaterialization::Static,
        };
    }

    if let Some(variable_name) = exact_variable_reference(text) {
        let Some(binding) = bindings.get(variable_name) else {
            return MaterializedText {
                text: text.to_string(),
                resolution: ValueMaterialization::MissingBinding {
                    variable_name: variable_name.to_string(),
                },
            };
        };

        match binding.value {
            SessionValue::ExactScalar(value) => {
                let value = value.clone();

                if !quoted && !is_safe_unquoted_scalar(&value) {
                    return MaterializedText {
                        text: text.to_string(),
                        resolution: ValueMaterialization::UnsafeUnquotedScalar {
                            variable_name: variable_name.to_string(),
                            value,
                            origin: binding.origin,
                        },
                    };
                }

                return MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedExactScalar {
                        variable_name: variable_name.to_string(),
                        value,
                        origin: binding.origin,
                    },
                };
            }
            SessionValue::RuntimeProduced { value, kind } => {
                let value = value.clone();

                if !quoted && !is_safe_unquoted_scalar(&value) {
                    return MaterializedText {
                        text: text.to_string(),
                        resolution: ValueMaterialization::UnsafeUnquotedScalar {
                            variable_name: variable_name.to_string(),
                            value,
                            origin: binding.origin,
                        },
                    };
                }

                return MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedRuntimeProduced {
                        variable_name: variable_name.to_string(),
                        value,
                        kind: *kind,
                        origin: binding.origin,
                    },
                };
            }
            SessionValue::OpaqueDynamic { repr } => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: variable_name.to_string(),
                        repr: repr.clone(),
                        origin: binding.origin,
                    },
                };
            }
            SessionValue::RuntimeInput { source, capture } => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::RequiresRuntimeInput {
                        source: runtime_input_source_to_implicit_input_source(*source),
                        capture: Some(capture.clone()),
                        variable_name: Some(variable_name.to_string()),
                        origin: Some(binding.origin),
                    },
                };
            }
        }
    }

    if let Some(ShellParameterReference::Positional(position)) =
        exact_shell_parameter_reference(text)
    {
        let Some(value) = bindings.positional_parameter(position) else {
            return MaterializedText {
                text: text.to_string(),
                resolution: ValueMaterialization::MissingBinding {
                    variable_name: position.to_string(),
                },
            };
        };

        match value {
            SessionValue::ExactScalar(value) => {
                let value = value.clone();

                if !quoted && !is_safe_unquoted_scalar(&value) {
                    return MaterializedText {
                        text: text.to_string(),
                        resolution: ValueMaterialization::UnsafeUnquotedScalar {
                            variable_name: position.to_string(),
                            value,
                            origin: BindingOrigin::SessionBinding,
                        },
                    };
                }

                return MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedExactScalar {
                        variable_name: position.to_string(),
                        value,
                        origin: BindingOrigin::SessionBinding,
                    },
                };
            }
            SessionValue::RuntimeProduced { value, kind } => {
                let value = value.clone();

                if !quoted && !is_safe_unquoted_scalar(&value) {
                    return MaterializedText {
                        text: text.to_string(),
                        resolution: ValueMaterialization::UnsafeUnquotedScalar {
                            variable_name: position.to_string(),
                            value,
                            origin: BindingOrigin::SessionBinding,
                        },
                    };
                }

                return MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedRuntimeProduced {
                        variable_name: position.to_string(),
                        value,
                        kind: *kind,
                        origin: BindingOrigin::SessionBinding,
                    },
                };
            }
            SessionValue::OpaqueDynamic { repr } => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: position.to_string(),
                        repr: repr.clone(),
                        origin: BindingOrigin::SessionBinding,
                    },
                };
            }
            SessionValue::RuntimeInput { source, capture } => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::RequiresRuntimeInput {
                        source: runtime_input_source_to_implicit_input_source(*source),
                        capture: Some(capture.clone()),
                        variable_name: Some(position.to_string()),
                        origin: Some(BindingOrigin::SessionBinding),
                    },
                };
            }
        }
    }

    if let Some(reference @ ShellParameterReference::Expansion { .. }) =
        exact_shell_parameter_reference(text)
    {
        if let Some(value) = exact_scalar_shell_parameter_value(bindings, &reference) {
            if !quoted && !is_safe_unquoted_scalar(&value) {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::UnsafeUnquotedScalar {
                        variable_name: shell_parameter_reference_name(&reference),
                        value,
                        origin: BindingOrigin::SessionBinding,
                    },
                };
            }

            return MaterializedText {
                text: value.clone(),
                resolution: ValueMaterialization::ResolvedExactScalar {
                    variable_name: shell_parameter_reference_name(&reference),
                    value,
                    origin: BindingOrigin::SessionBinding,
                },
            };
        }
    }

    if contains_unescaped_dynamic_syntax(text) {
        return MaterializedText {
            text: text.to_string(),
            resolution: ValueMaterialization::UnsupportedDynamicText {
                text: text.to_string(),
            },
        };
    }

    MaterializedText {
        text: text.to_string(),
        resolution: ValueMaterialization::Static,
    }
}

fn shell_parameter_reference_name(reference: &ShellParameterReference) -> String {
    match reference {
        ShellParameterReference::Variable(name) => name.clone(),
        ShellParameterReference::Positional(position) => position.to_string(),
        ShellParameterReference::AllPositionals(ShellAllPositionalsKind::At) => "@".to_string(),
        ShellParameterReference::AllPositionals(ShellAllPositionalsKind::Star) => "*".to_string(),
        ShellParameterReference::Expansion { parameter, .. } => shell_parameter_name(parameter),
    }
}

fn shell_parameter_name(parameter: &ShellParameterName) -> String {
    match parameter {
        ShellParameterName::Variable(name) => name.clone(),
        ShellParameterName::Positional(position) => position.to_string(),
    }
}

fn exact_variable_reference(text: &str) -> Option<&str> {
    if let Some(name) = text
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return is_valid_variable_name(name).then_some(name);
    }

    let name = text.strip_prefix('$')?;
    is_valid_variable_name(name).then_some(name)
}

fn is_valid_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if first != '_' && !first.is_ascii_alphabetic() {
        return false;
    }

    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_variable_name_char(ch: char, first: bool) -> bool {
    if first {
        ch == '_' || ch.is_ascii_alphabetic()
    } else {
        ch == '_' || ch.is_ascii_alphanumeric()
    }
}

fn parse_positional_parameter_index(text: &str) -> Option<usize> {
    if text.is_empty() || !text.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    text.parse::<usize>().ok()
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

fn runtime_input_source_to_implicit_input_source(
    source: RuntimeInputSource,
) -> ImplicitInputSource {
    match source {
        RuntimeInputSource::StdinPayload => ImplicitInputSource::StdinPayload,
        RuntimeInputSource::StdinData => ImplicitInputSource::StdinData,
        RuntimeInputSource::InteractiveSession => ImplicitInputSource::InteractiveSession,
    }
}

fn is_safe_unquoted_scalar(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| !ch.is_whitespace() && !matches!(ch, '*' | '?' | '[' | ']'))
}

fn reclassify_projected_args(args: &mut [ProjectedArg]) {
    let mut dashdash_seen = false;

    for arg in args {
        arg.kind = if arg.text == "--" {
            dashdash_seen = true;
            ProjectedArgKind::DashDash
        } else if !dashdash_seen && arg.text.len() > 1 && arg.text.starts_with('-') {
            ProjectedArgKind::Flag
        } else {
            ProjectedArgKind::Positional
        };
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use caushell_parse::{SourceSpan, parse_command};
    use caushell_types::{
        CommandSequenceNo, RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind,
        SessionSummary, SessionVariableValue, ShellKind,
    };

    use super::{
        BindingOrigin, SessionBindings, ValueMaterialization, materialize_projected_invocation,
        materialize_recursive_payload_candidate,
    };
    use crate::{
        CommandProfile, ImplicitInputSource, PayloadLanguage, PayloadSource,
        RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
        RecursivePayloadFragmentMaterialization, RecursivePayloadInput, RecursivePayloadOrigin,
        load_command_profile_from_path, project_invocation, select_invocation,
    };

    fn built_in_profile(name: &str) -> CommandProfile {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join(format!("{name}.yaml"));

        load_command_profile_from_path(&profile_path).expect("expected built-in profile to load")
    }

    fn empty_span() -> SourceSpan {
        SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            start_column: 0,
            end_row: 0,
            end_column: 0,
        }
    }

    #[test]
    fn materializes_quoted_exact_scalar_payload() {
        let bindings = SessionBindings::new().with_exact_scalar("cmd", "echo ok");
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "$cmd".to_string(),
                    quoted: true,
                    node_kind: "string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "cmd".to_string(),
                value: "echo ok".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );

        match materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments[0].text, "echo ok");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn raw_string_stays_literal() {
        let bindings = SessionBindings::new().with_exact_scalar("cmd", "echo ok");
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "$cmd".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(materialized.resolution, ValueMaterialization::Static);

        match materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments[0].text, "$cmd");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn ansi_c_string_stays_literal_after_parser_decoding() {
        let bindings = SessionBindings::new().with_exact_scalar("cmd", "echo ok");
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "line1\n$cmd".to_string(),
                    quoted: true,
                    node_kind: "ansi_c_string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(materialized.resolution, ValueMaterialization::Static);

        match materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments[0].text, "line1\n$cmd");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn partial_dynamic_text_remains_unmaterialized() {
        let bindings = SessionBindings::new().with_exact_scalar("cmd", "echo ok");
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "prefix$cmd".to_string(),
                    quoted: true,
                    node_kind: "string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::UnsupportedDynamicText {
                text: "prefix$cmd".to_string(),
            }
        );
    }

    #[test]
    fn missing_binding_is_reported() {
        let materialized = materialize_recursive_payload_candidate(
            &RecursivePayloadCandidate {
                language: PayloadLanguage::Bash,
                source: PayloadSource::InlineString,
                origin: RecursivePayloadOrigin::FormImplicitInput,
                input: RecursivePayloadInput::ArgumentFragments {
                    fragments: vec![RecursivePayloadArgumentFragment {
                        text: "${cmd}".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        span: empty_span(),
                        materialization: RecursivePayloadFragmentMaterialization::Literal,
                    }],
                },
            },
            &SessionBindings::new(),
        );

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::MissingBinding {
                variable_name: "cmd".to_string(),
            }
        );
    }

    #[test]
    fn session_bindings_import_exact_scalar_from_summary() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", true, CommandSequenceNo::new(1));

        let bindings = SessionBindings::from_session_summary(&summary);
        let binding = bindings
            .get("SCRIPT")
            .expect("expected binding imported from summary");

        assert_eq!(binding.origin, BindingOrigin::SessionBinding);
        assert_eq!(
            binding.value,
            &crate::SessionValue::ExactScalar("build.sh".to_string())
        );
    }

    #[test]
    fn session_bindings_import_opaque_dynamic_from_summary() {
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable(
            "USER_CMD",
            "$payload",
            true,
            CommandSequenceNo::new(2),
        );

        let bindings = SessionBindings::from_session_summary(&summary);
        let binding = bindings
            .get("USER_CMD")
            .expect("expected opaque binding imported from summary");

        assert_eq!(binding.origin, BindingOrigin::SessionBinding);
        assert_eq!(
            binding.value,
            &crate::SessionValue::OpaqueDynamic {
                repr: "$payload".to_string(),
            }
        );
    }

    #[test]
    fn session_bindings_import_runtime_input_from_summary() {
        let mut summary = SessionSummary::new();
        summary.set_runtime_input_variable(
            "USER_CMD",
            RuntimeInputSource::StdinData,
            RuntimeInputCapture::Descriptor {
                descriptor: "read USER_CMD".to_string(),
            },
            true,
            CommandSequenceNo::new(2),
        );

        let bindings = SessionBindings::from_session_summary(&summary);
        let binding = bindings
            .get("USER_CMD")
            .expect("expected runtime input binding imported from summary");

        assert_eq!(binding.origin, BindingOrigin::SessionBinding);
        assert_eq!(
            binding.value,
            &crate::SessionValue::RuntimeInput {
                source: RuntimeInputSource::StdinData,
                capture: RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
            }
        );
    }

    #[test]
    fn session_bindings_import_runtime_produced_path_from_summary() {
        let mut summary = SessionSummary::new();
        summary.set_runtime_produced_variable(
            "TMP_SCRIPT",
            "/tmp/tmp.abcd.sh",
            RuntimeProducedValueKind::Path,
            false,
            CommandSequenceNo::new(3),
        );

        let bindings = SessionBindings::from_session_summary(&summary);
        let binding = bindings
            .get("TMP_SCRIPT")
            .expect("expected runtime-produced binding imported from summary");

        assert_eq!(binding.origin, BindingOrigin::SessionBinding);
        assert_eq!(
            binding.value,
            &crate::SessionValue::RuntimeProduced {
                value: "/tmp/tmp.abcd.sh".to_string(),
                kind: RuntimeProducedValueKind::Path,
            }
        );
    }

    #[test]
    fn runtime_produced_path_materializes_as_runtime_produced_resolution() {
        let bindings = SessionBindings::new().with_runtime_produced(
            "TMP_SCRIPT",
            "/tmp/tmp.abcd.sh",
            RuntimeProducedValueKind::Path,
        );
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "$TMP_SCRIPT".to_string(),
                    quoted: true,
                    node_kind: "string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::ResolvedRuntimeProduced {
                variable_name: "TMP_SCRIPT".to_string(),
                value: "/tmp/tmp.abcd.sh".to_string(),
                kind: RuntimeProducedValueKind::Path,
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn session_bindings_merge_inherited_environment_without_overriding_session_bindings() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("MODE", "-s", false, CommandSequenceNo::new(4));

        let bindings = SessionBindings::from_summary_and_shell_state(
            &summary,
            &caushell_types::ShellStateSnapshot::new("/tmp/project")
                .with_exact_scalar_variable("MODE", "--rcfile", true)
                .with_exact_scalar_variable("USER_CMD", "echo ok", true)
                .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly),
        );

        let mode = bindings.get("MODE").expect("expected MODE binding");
        assert_eq!(mode.origin, BindingOrigin::SessionBinding);
        assert_eq!(
            mode.value,
            &crate::SessionValue::ExactScalar("-s".to_string())
        );

        let user_cmd = bindings
            .get("USER_CMD")
            .expect("expected inherited USER_CMD binding");
        assert_eq!(user_cmd.origin, BindingOrigin::InheritedEnvironment);
        assert_eq!(
            user_cmd.value,
            &crate::SessionValue::ExactScalar("echo ok".to_string())
        );
    }

    #[test]
    fn projected_invocation_materializes_from_summary_bindings() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash $script", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("script", "build.sh", false, CommandSequenceNo::new(4));

        let bindings = SessionBindings::from_session_summary(&summary);
        let materialized = materialize_projected_invocation(&projection, &bindings);
        let selection = select_invocation(&profile, &materialized.invocation)
            .expect("expected materialized invocation to select");

        assert_eq!(materialized.invocation.args[0].text, "build.sh");
        assert_eq!(selection.form.id.as_str(), "script_file");
        assert_eq!(
            materialized.arg_resolutions[0],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "script".to_string(),
                value: "build.sh".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn projected_invocation_materializes_positional_parameters() {
        let artifact =
            parse_command(r#"rm -rf "$1""#, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let mut bindings = SessionBindings::new().with_exact_scalar("IGNORED", "value");
        bindings.replace_positional_parameters_with_exact_scalars(["/"]);
        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "/");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "1".to_string(),
                value: "/".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn projected_invocation_materializes_quoted_all_positional_parameters() {
        let artifact =
            parse_command(r#"rm -rf "$@""#, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let mut bindings = SessionBindings::new();
        bindings.replace_positional_parameters_with_exact_scalars(["/", "/etc"]);
        let materialized = materialize_projected_invocation(&projection, &bindings);
        let texts: Vec<&str> = materialized
            .invocation
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect();

        assert_eq!(texts, vec!["-rf", "/", "/etc"]);
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "1".to_string(),
                value: "/".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
        assert_eq!(
            materialized.arg_resolutions[2],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "2".to_string(),
                value: "/etc".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn projected_invocation_materializes_unquoted_all_positional_parameters_when_safe() {
        let artifact =
            parse_command(r#"rm -rf $@"#, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let mut bindings = SessionBindings::new();
        bindings.replace_positional_parameters_with_exact_scalars(["/", "/etc"]);
        let materialized = materialize_projected_invocation(&projection, &bindings);
        let texts: Vec<&str> = materialized
            .invocation
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect();

        assert_eq!(texts, vec!["-rf", "/", "/etc"]);
    }

    #[test]
    fn projected_invocation_materializes_quoted_star_positional_parameters_as_one_field() {
        let artifact =
            parse_command(r#"rm -rf "$*""#, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let mut bindings = SessionBindings::new();
        bindings.replace_positional_parameters_with_exact_scalars(["/", "/etc"]);
        let materialized = materialize_projected_invocation(&projection, &bindings);
        let texts: Vec<&str> = materialized
            .invocation
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect();

        assert_eq!(texts, vec!["-rf", "/ /etc"]);
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "*".to_string(),
                value: "/ /etc".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn session_bindings_import_positional_parameters_from_summary() {
        let mut summary = SessionSummary::new();
        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/")],
            CommandSequenceNo::new(4),
        );

        let bindings = SessionBindings::from_session_summary(&summary);

        assert_eq!(
            bindings.positional_parameter(1),
            Some(&crate::SessionValue::ExactScalar("/".to_string()))
        );
    }

    #[test]
    fn projected_invocation_materializes_default_parameter_expansion() {
        let artifact = parse_command(r#"rm -rf "${TARGET_ROOT:-/}""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let bindings = SessionBindings::new().with_exact_scalar("TARGET_ROOT", "");
        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "/");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "TARGET_ROOT".to_string(),
                value: "/".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn materialization_preserves_known_dynamic_binding() {
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable("cmd", "$payload", true, CommandSequenceNo::new(3));

        let bindings = SessionBindings::from_session_summary(&summary);
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "$cmd".to_string(),
                    quoted: true,
                    node_kind: "string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::UnsupportedDynamicBinding {
                variable_name: "cmd".to_string(),
                repr: "$payload".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );

        match materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments[0].text, "$cmd");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn unquoted_safe_scalar_can_select_script_form() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash $script", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());
        let bindings = SessionBindings::new().with_exact_scalar("script", "build.sh");

        let materialized = materialize_projected_invocation(&projection, &bindings);
        let selection = select_invocation(&profile, &materialized.invocation)
            .expect("expected materialized invocation to select");

        assert_eq!(materialized.invocation.args[0].text, "build.sh");
        assert_eq!(selection.form.id.as_str(), "script_file");
        assert_eq!(
            materialized.arg_resolutions[0],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "script".to_string(),
                value: "build.sh".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn materialization_reclassifies_flags() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash $mode", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());
        let bindings = SessionBindings::new().with_exact_scalar("mode", "-s");

        let materialized = materialize_projected_invocation(&projection, &bindings);
        let selection = select_invocation(&profile, &materialized.invocation)
            .expect("expected materialized invocation to select");

        assert_eq!(materialized.invocation.args[0].text, "-s");
        assert_eq!(
            materialized.invocation.args[0].kind,
            crate::ProjectedArgKind::Flag
        );
        assert_eq!(selection.form.id.as_str(), "stdin_script_explicit");
    }

    #[test]
    fn materialization_reclassifies_dashdash_and_following_args() {
        let artifact =
            parse_command("echo $marker -n", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());
        let bindings = SessionBindings::new().with_exact_scalar("marker", "--");

        let materialized = materialize_projected_invocation(&projection, &bindings);
        let kinds: Vec<_> = materialized
            .invocation
            .args
            .iter()
            .map(|arg| arg.kind)
            .collect();

        assert_eq!(
            kinds,
            vec![
                crate::ProjectedArgKind::DashDash,
                crate::ProjectedArgKind::Positional,
            ]
        );
    }

    #[test]
    fn unsafe_unquoted_scalar_stays_unmaterialized() {
        let artifact =
            parse_command("bash -c $cmd", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());
        let bindings = SessionBindings::new().with_exact_scalar("cmd", "echo ok");

        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "$cmd");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::UnsafeUnquotedScalar {
                variable_name: "cmd".to_string(),
                value: "echo ok".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn inherited_environment_is_used_when_session_binding_is_missing() {
        let bindings = SessionBindings::new().with_inherited_exact_scalar("USER_CMD", "echo ok");

        let materialized = materialize_recursive_payload_candidate(
            &RecursivePayloadCandidate {
                language: PayloadLanguage::Bash,
                source: PayloadSource::InlineString,
                origin: RecursivePayloadOrigin::FormImplicitInput,
                input: RecursivePayloadInput::ArgumentFragments {
                    fragments: vec![RecursivePayloadArgumentFragment {
                        text: "$USER_CMD".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        span: empty_span(),
                        materialization: RecursivePayloadFragmentMaterialization::Literal,
                    }],
                },
            },
            &bindings,
        );

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "USER_CMD".to_string(),
                value: "echo ok".to_string(),
                origin: BindingOrigin::InheritedEnvironment,
            }
        );
    }

    #[test]
    fn implicit_recursive_input_requires_runtime_input() {
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::Stdin,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ImplicitInput {
                source: ImplicitInputSource::StdinPayload,
            },
        };

        let materialized =
            materialize_recursive_payload_candidate(&candidate, &SessionBindings::new());

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::RequiresRuntimeInput {
                source: ImplicitInputSource::StdinPayload,
                capture: None,
                variable_name: None,
                origin: None,
            }
        );
        assert_eq!(materialized.candidate, candidate);
    }

    #[test]
    fn runtime_input_binding_materializes_to_requires_runtime_input() {
        let mut summary = SessionSummary::new();
        summary.set_runtime_input_variable(
            "USER_CMD",
            RuntimeInputSource::StdinData,
            RuntimeInputCapture::Descriptor {
                descriptor: "read USER_CMD".to_string(),
            },
            true,
            CommandSequenceNo::new(3),
        );

        let bindings = SessionBindings::from_session_summary(&summary);
        let materialized = materialize_recursive_payload_candidate(
            &RecursivePayloadCandidate {
                language: PayloadLanguage::Bash,
                source: PayloadSource::InlineString,
                origin: RecursivePayloadOrigin::FormImplicitInput,
                input: RecursivePayloadInput::ArgumentFragments {
                    fragments: vec![RecursivePayloadArgumentFragment {
                        text: "$USER_CMD".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        span: empty_span(),
                        materialization: RecursivePayloadFragmentMaterialization::Literal,
                    }],
                },
            },
            &bindings,
        );

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::RequiresRuntimeInput {
                source: ImplicitInputSource::StdinData,
                capture: Some(RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                }),
                variable_name: Some("USER_CMD".to_string()),
                origin: Some(BindingOrigin::SessionBinding),
            }
        );

        match materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments[0].text, "$USER_CMD");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn joined_recursive_payload_materializes_each_fragment_and_joins_text() {
        let bindings = SessionBindings::new()
            .with_exact_scalar("LEFT", "echo ok")
            .with_exact_scalar("RIGHT", "&& pwd");
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![
                    RecursivePayloadArgumentFragment {
                        text: "$LEFT".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        span: empty_span(),
                        materialization: RecursivePayloadFragmentMaterialization::Literal,
                    },
                    RecursivePayloadArgumentFragment {
                        text: "$RIGHT".to_string(),
                        quoted: true,
                        node_kind: "string".to_string(),
                        span: empty_span(),
                        materialization: RecursivePayloadFragmentMaterialization::Literal,
                    },
                ],
            },
        };

        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);

        match &materialized.candidate.input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments.len(), 2);
                assert_eq!(fragments[0].text, "echo ok");
                assert_eq!(fragments[1].text, "&& pwd");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }

        assert_eq!(materialized.fragment_resolutions.len(), 2);
        assert!(materialized.fragment_resolutions.iter().all(|resolution| {
            matches!(resolution, ValueMaterialization::ResolvedExactScalar { .. })
        }));
        assert!(matches!(
            materialized.resolution,
            ValueMaterialization::ResolvedExactScalar { .. }
        ));
    }
}
