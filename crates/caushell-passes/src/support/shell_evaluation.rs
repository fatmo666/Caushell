use std::collections::BTreeSet;
mod numeric;

use caushell_parse::{
    ArithmeticReference as Ref, ParsedCommandArtifact, ShellEvaluationKind, ShellEvaluationSite,
};
use caushell_profile::{
    SessionBindings, SessionValue, VariablePresence, materialize_shell_assignment_value,
};

#[derive(Default)]
pub(crate) struct Evaluation {
    pub programs: Vec<String>,
    pub unresolved: bool,
}

/// A bounded interpreter of executable *positions*, not of Bash values. Only
/// an indexed subscript reopens shell expansion while following scalar values.
pub(crate) fn evaluate(
    registry: &caushell_profile::ProfileRegistry,
    request: &caushell_types::CheckRequest,
    parsed: &ParsedCommandArtifact,
    site: &ShellEvaluationSite,
    bindings: &SessionBindings,
    base_bindings: &SessionBindings,
    max_depth: u8,
) -> Evaluation {
    let facts = numeric::NumericFacts::new(registry, request, parsed, base_bindings);
    let mut checked_site = site.clone();
    checked_site
        .numeric_locals
        .retain(|name| facts.loop_local(name, site));
    let mut evaluator = Evaluator {
        parsed,
        site: &checked_site,
        bindings,
        facts: &facts,
        result: Evaluation::default(),
        active: BTreeSet::new(),
        numeric: BTreeSet::new(),
        budget: 256,
        max_depth: usize::from(max_depth),
    };
    match &site.kind {
        ShellEvaluationKind::ParameterAssignment { .. } => {}
        ShellEvaluationKind::ArrayElementAssignment { .. } => {}
        ShellEvaluationKind::Arithmetic => evaluator.expression(&site.input.text, true, 0),
        ShellEvaluationKind::UnresolvedArithmetic => evaluator.result.unresolved = true,
        ShellEvaluationKind::ArrayIndex { name } => {
            evaluator.index(name, &site.input.text, false, 0);
        }
        ShellEvaluationKind::UnsetOperand { functions_only } => {
            // The first expansion takes place even for `unset -f/-n`.
            for subst in &site.input.command_substitutions {
                evaluator.result.programs.push(subst.body_text.clone());
            }
            if !functions_only {
                match materialize_shell_assignment_value(
                    &site.input.text,
                    site.input.quoted,
                    &site.input.node_kind,
                    bindings,
                ) {
                    Some(value) => {
                        if let Some((name, index)) = array_operand(&value) {
                            evaluator.index(name, index, false, 0);
                        } else if value.contains('[') || value.contains(']') {
                            evaluator.result.unresolved = true;
                        }
                    }
                    None => {
                        if let Some((name, index)) = array_operand(&site.input.text) {
                            evaluator.index(name, index, false, 0);
                        } else {
                            evaluator.result.unresolved = true;
                        }
                    }
                }
            }
        }
        ShellEvaluationKind::ArithmeticBuiltin => {
            if bindings.function_binding("let").is_some()
                && parsed.commands.iter().any(|c| {
                    c.top_level_span == site.top_level_span
                        && c.command_name.as_deref() == Some("let")
                })
            {
                return evaluator.result;
            }
            for subst in &site.input.command_substitutions {
                evaluator.result.programs.push(subst.body_text.clone());
            }
            match materialize_shell_assignment_value(
                &site.input.text,
                site.input.quoted,
                &site.input.node_kind,
                bindings,
            ) {
                Some(value) => evaluator.expression(&value, false, 0),
                None => evaluator.result.unresolved = true,
            }
        }
    }
    evaluator.result
}

struct Evaluator<'a> {
    parsed: &'a ParsedCommandArtifact,
    site: &'a ShellEvaluationSite,
    bindings: &'a SessionBindings,
    facts: &'a numeric::NumericFacts<'a>,
    result: Evaluation,
    active: BTreeSet<String>,
    numeric: BTreeSet<String>,
    budget: usize,
    max_depth: usize,
}

impl Evaluator<'_> {
    fn expression(&mut self, text: &str, expands: bool, depth: usize) {
        if text.trim().is_empty() {
            return;
        }
        if depth > self.max_depth || self.budget == 0 {
            self.result.unresolved = true;
            return;
        }
        self.budget -= 1;
        let Some(refs) = caushell_parse::parse_arithmetic_references(text) else {
            self.result.unresolved = true;
            return;
        };
        self.references(&refs, expands, depth);
    }

    fn references(&mut self, refs: &[Ref], expands: bool, depth: usize) {
        for reference in refs {
            if self.budget == 0 {
                self.result.unresolved = true;
                return;
            }
            self.budget -= 1;
            match reference {
                Ref::ArithmeticExpansion(text) => {
                    if expands {
                        self.expression(text, true, depth + 1);
                    }
                }
                Ref::Optional(refs) => {
                    let before = self.numeric.clone();
                    self.references(refs, expands, depth + 1);
                    self.numeric = before;
                }
                Ref::Variable(name) => self.variable(name, depth + 1),
                Ref::Array {
                    name,
                    index,
                    read_value,
                } => self.index(name, index, *read_value, depth + 1),
                Ref::CommandSubstitution(subst) => {
                    if expands {
                        self.result.programs.push(subst.body_text.clone());
                        self.result.unresolved |=
                            !self.facts.stdout(&subst.body_text, self.bindings);
                    }
                    // Literal substitution syntax in a scalar arithmetic value
                    // is invalid arithmetic, not an instruction to execute it.
                }
                Ref::ExpandedWord {
                    text,
                    quoted,
                    node_kind,
                } => {
                    if !expands {
                        continue;
                    }
                    for subst in caushell_parse::parse_command_substitutions(
                        text,
                        caushell_types::ShellKind::Bash,
                    )
                    .unwrap_or_default()
                    {
                        self.result.programs.push(subst.body_text);
                    }
                    let value = caushell_parse::AssignmentValueFact {
                        text: text.clone(),
                        quoted: *quoted,
                        node_kind: node_kind.clone(),
                        span: self.site.input.span.clone(),
                        command_substitutions: caushell_parse::parse_command_substitutions(
                            text,
                            self.parsed.shell_kind,
                        )
                        .unwrap_or_default(),
                    };
                    if self
                        .facts
                        .word(&value, self.site.top_level_span.start_byte, depth)
                    {
                        continue;
                    }
                    if matches!(node_kind.as_str(), "simple_expansion" | "expansion")
                        && let Some(name) = text
                            .strip_prefix("${")
                            .and_then(|s| s.strip_suffix('}'))
                            .or_else(|| text.strip_prefix('$'))
                        && super::scalar_identifier(name)
                    {
                        self.variable(name, depth + 1);
                        continue;
                    }
                    match materialize_shell_assignment_value(
                        text,
                        *quoted,
                        node_kind,
                        self.bindings,
                    ) {
                        Some(value) if value != *text => self.expression(&value, false, depth + 1),
                        Some(value) if !value.contains('$') && !value.contains('`') => {
                            self.expression(&value, false, depth + 1)
                        }
                        _ => self.result.unresolved = true,
                    }
                }
                Ref::Assignment {
                    name,
                    reads_previous,
                    value,
                } => {
                    if *reads_previous {
                        self.variable(name, depth + 1);
                    }
                    self.references(value, expands, depth + 1);
                    // Arithmetic assignment results are numeric, unlike a
                    // shell assignment containing an unevaluated expression.
                    self.numeric.insert(name.clone());
                }
                Ref::Unsupported(_) => self.result.unresolved = true,
            }
        }
    }

    fn variable(&mut self, name: &str, depth: usize) {
        if self.numeric.contains(name) || self.site.numeric_locals.iter().any(|n| n == name) {
            return;
        }
        let frame_facts = self.bindings.variable_facts(name);
        if frame_facts.scalar_shape == Some(caushell_profile::StdoutScalarShape::ArithmeticText)
            || frame_facts.element_shape
                == Some(caushell_profile::StdoutScalarShape::ArithmeticText)
        {
            return;
        }
        if self
            .facts
            .variable(name, self.site.top_level_span.start_byte, depth)
        {
            return;
        }
        if !self.active.insert(name.into()) {
            self.result.unresolved = true;
            return;
        }
        let indexed = self.parsed.shell_evaluations.iter().any(|s| {
            matches!(&s.kind, ShellEvaluationKind::ArrayElementAssignment { name: n, .. } if n == name)
                && s.input.span.start_byte < self.site.input.span.start_byte
                && super::state_visible(&s.shell_scope_span, self.site.input.span.start_byte)
        }) || self.bindings.get(name).is_some_and(|b| match b.value {
            SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. } => self.literal_array(name, value).is_some(),
            _ => false,
        });
        if indexed {
            self.index(name, "0", true, depth);
            self.active.remove(name);
            return;
        }
        match self.bindings.get(name).map(|b| b.value) {
            Some(
                SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. },
            ) => {
                self.expression(value, false, depth);
            }
            Some(SessionValue::OpaqueDynamic { repr }) => {
                if let Some(values) = caushell_parse::static_array_values(repr) {
                    if let Some(value) = values.first() {
                        self.expression(value, false, depth);
                    }
                } else {
                    self.result.unresolved = true;
                }
            }
            Some(_) => self.result.unresolved = true,
            None if self.bindings.variable_presence(name) == VariablePresence::Absent => {}
            None => self.result.unresolved = true,
        }
        self.active.remove(name);
    }

    fn associative(&self, name: &str) -> bool {
        if self.bindings.variable_facts(name).array_kind
            == Some(caushell_profile::ShellArrayKind::Associative)
        {
            return true;
        }
        self.parsed
            .declaration_commands
            .iter()
            .rev()
            .find(|d| {
                d.span.start_byte < self.site.input.span.start_byte
                    && !super::variable_facts::declaration_has_shadow(d, self.bindings)
                    && super::state_visible(&d.shell_scope_span, self.site.input.span.start_byte)
                    && (d.names.iter().any(|n| n == name)
                        || d.assignments.iter().any(|a| a.name == name))
                    && d.options.iter().any(|o| {
                        o.starts_with('-') && (o[1..].contains('A') || o[1..].contains('a'))
                    })
            })
            .is_some_and(|d| {
                !d.conditional_execution
                    && d.options
                        .iter()
                        .any(|o| o.starts_with('-') && o[1..].contains('A'))
                    && !self.parsed.unset_commands.iter().any(|u| {
                        u.span.start_byte > d.span.start_byte
                            && u.span.start_byte < self.site.input.span.start_byte
                    })
                    && !self.parsed.commands.iter().any(|c| {
                        c.span.start_byte > d.span.start_byte
                            && c.span.start_byte < self.site.input.span.start_byte
                    })
            })
    }

    fn literal_array(&self, name: &str, value: &str) -> Option<Vec<String>> {
        let declared_array = self
            .parsed
            .assignment_commands
            .iter()
            .filter(|c| {
                c.span.start_byte < self.site.input.span.start_byte
                    && super::state_visible(&c.shell_scope_span, self.site.input.span.start_byte)
            })
            .flat_map(|c| &c.assignments)
            .chain(
                self.parsed
                    .declaration_commands
                    .iter()
                    .filter(|c| {
                        c.span.start_byte < self.site.input.span.start_byte
                            && super::state_visible(
                                &c.shell_scope_span,
                                self.site.input.span.start_byte,
                            )
                    })
                    .flat_map(|c| &c.assignments),
            )
            .any(|a| a.name == name && a.value.node_kind == "array" && a.value.text == value);
        declared_array
            .then(|| caushell_parse::static_array_values(value))
            .flatten()
    }

    fn index(&mut self, name: &str, index: &str, read_value: bool, depth: usize) {
        if matches!(index.trim(), "@" | "*") {
            return;
        }
        if self.associative(name) {
            // Associative keys are strings, but explicit substitutions still run.
            for subst in
                caushell_parse::parse_command_substitutions(index, caushell_types::ShellKind::Bash)
                    .unwrap_or_default()
            {
                self.result.programs.push(subst.body_text);
            }
            if read_value {
                self.result.unresolved = true;
            }
            return;
        }
        self.expression(index, true, depth);
        if !read_value {
            return;
        }
        // Element assignments have separate syntax facts. They must not be hidden by an earlier whole-array
        // literal. Recover possible expressions, and retain the unresolved
        // array-state gap rather than claim a complete array snapshot.
        let reset = self
            .parsed
            .assignment_commands
            .iter()
            .flat_map(|c| &c.assignments)
            .chain(
                self.parsed
                    .declaration_commands
                    .iter()
                    .flat_map(|c| &c.assignments),
            )
            .filter(|a| a.name == name && a.span.start_byte < self.site.input.span.start_byte)
            .map(|a| a.span.start_byte)
            .max()
            .unwrap_or(0);
        let wanted = index.trim().parse::<usize>().ok();
        let mut elements = Vec::new();
        let mut overrides_element = false;
        for source in &self.parsed.shell_evaluations {
            let ShellEvaluationKind::ArrayElementAssignment {
                name: array,
                index: element_index,
            } = &source.kind
            else {
                continue;
            };
            if array != name
                || source.input.span.start_byte < reset
                || source.input.span.start_byte >= self.site.input.span.start_byte
                || !super::state_visible(&source.shell_scope_span, self.site.input.span.start_byte)
            {
                continue;
            }
            let element_index = element_index.trim().parse::<usize>().ok();
            if let (Some(wanted), Some(actual)) = (wanted, element_index) {
                if wanted != actual {
                    continue;
                }
                if !source.conditional_execution {
                    elements.clear();
                    overrides_element = true;
                }
            }
            elements.push(source);
        }
        if !elements.is_empty() {
            self.result.unresolved = true;
            for source in elements {
                if let Some(value) = caushell_parse::decode_static_shell_argument(
                    &source.input.text,
                    source.input.quoted,
                    &source.input.node_kind,
                ) {
                    self.expression(&value, false, depth + 1);
                }
            }
            if overrides_element {
                return;
            }
        }
        match self.bindings.get(name).map(|b| b.value) {
            Some(SessionValue::OpaqueDynamic { repr }) => {
                if let Some(values) = caushell_parse::static_array_values(repr) {
                    if let Ok(index) = index.trim().parse::<usize>() {
                        if let Some(value) = values.get(index) {
                            self.expression(value, false, depth + 1);
                        }
                    } else {
                        // All possible elements matter when the exact index is
                        // unknown. The expression budget bounds this traversal.
                        for value in values {
                            self.expression(&value, false, depth + 1);
                        }
                    }
                } else {
                    self.result.unresolved = true;
                }
            }
            Some(
                SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. },
            ) => {
                if let Some(values) = self.literal_array(name, value) {
                    if let Ok(index) = index.trim().parse::<usize>() {
                        if let Some(value) = values.get(index) {
                            self.expression(value, false, depth + 1);
                        }
                    } else {
                        for value in values {
                            self.expression(&value, false, depth + 1);
                        }
                    }
                } else {
                    self.expression(value, false, depth + 1);
                }
            }
            None if self.bindings.variable_presence(name) == VariablePresence::Absent => {}
            _ => self.result.unresolved = true,
        }
    }
}

fn array_operand(value: &str) -> Option<(&str, &str)> {
    let (name, index) = value.split_once('[')?;
    if !super::scalar_identifier(name) {
        return None;
    }
    Some((name, index.strip_suffix(']')?))
}
