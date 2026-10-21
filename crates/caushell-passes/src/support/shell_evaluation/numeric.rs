use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{
    AssignmentValueFact, CommandFact, ParsedCommandArtifact, ShellEvaluationKind,
    ShellEvaluationSite,
};
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    SessionValue, VariablePresence,
};
use caushell_types::CheckRequest;

/// Shape proofs are local analysis facts, never fictitious concrete values.
pub(super) struct NumericFacts<'a> {
    registry: &'a ProfileRegistry,
    request: &'a CheckRequest,
    parsed: &'a ParsedCommandArtifact,
    base: &'a SessionBindings,
    bindings: RefCell<BTreeMap<usize, SessionBindings>>,
    active: RefCell<BTreeSet<(String, usize)>>,
    budget: Cell<usize>,
}

pub(super) fn arithmetic_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, '+' | '-'))
}

impl<'a> NumericFacts<'a> {
    pub fn new(
        registry: &'a ProfileRegistry,
        request: &'a CheckRequest,
        parsed: &'a ParsedCommandArtifact,
        base: &'a SessionBindings,
    ) -> Self {
        Self {
            registry,
            request,
            parsed,
            base,
            bindings: RefCell::new(BTreeMap::new()),
            active: RefCell::new(BTreeSet::new()),
            budget: Cell::new(256),
        }
    }

    fn step(&self, depth: usize) -> bool {
        let remaining = self.budget.get();
        if remaining == 0 || depth > 16 {
            return false;
        }
        self.budget.set(remaining - 1);
        true
    }

    fn at(&self, before: usize) -> SessionBindings {
        if let Some(bindings) = self.bindings.borrow().get(&before) {
            return bindings.clone();
        }
        let bindings = super::super::apply_runtime_variable_bindings_before_span(
            self.registry,
            self.request,
            self.base.clone(),
            self.parsed,
            before,
            self.request.sequence_no,
        );
        if self.bindings.borrow().len() < 64 {
            self.bindings.borrow_mut().insert(before, bindings.clone());
        }
        bindings
    }

    pub fn variable(&self, name: &str, before: usize, depth: usize) -> bool {
        if !self.step(depth) {
            return false;
        }
        let key = (name.to_owned(), before);
        if !self.active.borrow_mut().insert(key.clone()) {
            return false;
        }
        let result = self.variable_inner(name, before, depth);
        self.active.borrow_mut().remove(&key);
        result
    }

    fn variable_inner(&self, name: &str, before: usize, depth: usize) -> bool {
        let bindings = self.at(before);
        // The scalar overlay does not claim a complete array-element snapshot.
        if self.parsed.shell_evaluations.iter().any(|s| {
            matches!(&s.kind,
            ShellEvaluationKind::ArrayElementAssignment { name: n, .. } if n == name)
                && s.input.span.start_byte < before
                && super::super::state_visible(&s.shell_scope_span, before)
        }) {
            return false;
        }
        match bindings.get(name).map(|b| b.value) {
            Some(SessionValue::ExactScalar(v) | SessionValue::RuntimeProduced { value: v, .. })
                if arithmetic_text(v) =>
            {
                return true;
            }
            None if bindings.variable_presence(name) == VariablePresence::Absent => return true,
            None if name == "RANDOM"
                && !self
                    .parsed
                    .unset_commands
                    .iter()
                    .any(|u| u.span.start_byte < before) =>
            {
                return true;
            }
            _ => {}
        }

        let mut definitions: Vec<_> = self
            .parsed
            .assignment_commands
            .iter()
            .filter(|c| {
                c.span.start_byte < before
                    && super::super::state_visible(&c.shell_scope_span, before)
            })
            .flat_map(|c| {
                c.assignments
                    .iter()
                    .filter(move |a| a.name == name)
                    .map(move |a| {
                        (
                            c.span.start_byte,
                            c.conditional_execution,
                            a.operator.clone(),
                            &a.value,
                        )
                    })
            })
            .chain(
                self.parsed
                    .declaration_commands
                    .iter()
                    .filter(|c| {
                        c.span.start_byte < before
                            && super::super::state_visible(&c.shell_scope_span, before)
                    })
                    .flat_map(|c| {
                        c.assignments
                            .iter()
                            .filter(move |a| a.name == name)
                            .map(move |a| {
                                (
                                    c.span.start_byte,
                                    c.conditional_execution,
                                    a.operator.clone(),
                                    &a.value,
                                )
                            })
                    }),
            )
            .collect();
        definitions.sort_by_key(|d| d.0);
        let mut start = definitions
            .iter()
            .rfind(|d| {
                (!d.1
                    || caushell_parse::assignment_dominates_use(
                        &self.parsed.raw_command,
                        d.0,
                        before,
                    ))
                    && d.2 == caushell_parse::AssignmentOperator::Assign
            })
            .map(|d| d.0);
        if let Some((span, values)) = caushell_parse::exhaustive_case_assignment_values(
            &self.parsed.raw_command,
            name,
            before,
        ) && start.is_none_or(|s| span.end_byte > s)
            && self.preserves(name, span.start_byte, span.end_byte, depth + 1)
            && values
                .iter()
                .all(|v| self.word(v, span.start_byte, depth + 1))
        {
            start = Some(span.end_byte);
        }
        let Some(start) = start else {
            return false;
        };
        if !self.preserves(name, start, before, depth + 1) {
            return false;
        }
        if self.parsed.declaration_commands.iter().any(|d| {
            d.span.start_byte > start
                && d.span.start_byte < before
                && super::super::state_visible(&d.shell_scope_span, before)
                && d.names.iter().any(|n| n == name)
        }) {
            return false;
        }
        definitions
            .iter()
            .filter(|d| d.0 >= start)
            .all(|d| self.word(d.3, d.0, depth + 1))
    }

    pub fn parameter(&self, text: &str, before: usize, depth: usize) -> bool {
        if matches!(
            text,
            "$#" | "${#}" | "$?" | "${?}" | "$$" | "${$}" | "$!" | "${!}"
        ) {
            return true;
        }
        if let Some(name) = text.strip_prefix("${#").and_then(|s| s.strip_suffix('}')) {
            return super::super::scalar_identifier(name)
                || name
                    .strip_suffix("[@]")
                    .or_else(|| name.strip_suffix("[*]"))
                    .is_some_and(super::super::scalar_identifier);
        }
        let name = text
            .strip_prefix("${")
            .and_then(|s| s.strip_suffix('}'))
            .or_else(|| text.strip_prefix('$'));
        name.is_some_and(|name| {
            super::super::scalar_identifier(name) && self.variable(name, before, depth + 1)
        })
    }

    pub fn word(&self, value: &AssignmentValueFact, before: usize, depth: usize) -> bool {
        if !self.step(depth) {
            return false;
        }
        let bindings = self.at(before);
        if caushell_profile::materialize_shell_assignment_value(
            &value.text,
            value.quoted,
            &value.node_kind,
            &bindings,
        )
        .is_some_and(|v| arithmetic_text(&v))
        {
            return true;
        }
        if value.node_kind == "arithmetic_expansion" {
            return true;
        }
        if value.node_kind != "raw_string" && value.node_kind != "ansi_c_string" {
            if value.text.starts_with("$((")
                && caushell_parse::parse_arithmetic_references(&value.text).is_some_and(|r| {
                    matches!(
                        r.as_slice(),
                        [caushell_parse::ArithmeticReference::ArithmeticExpansion(_)]
                    )
                })
            {
                return true;
            }
            if self.parameter(&value.text, before, depth + 1) {
                return true;
            }
            if let Some(inner) = value
                .text
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                && let Some((name, tail)) = inner.split_once('[')
                && let Some((_, fallback)) = tail.rsplit_once(']')
                && (fallback.is_empty() || fallback.strip_prefix(":-").is_some_and(arithmetic_text))
                && self.array_numeric(name, before, depth + 1)
            {
                return true;
            }
            if !value.command_substitutions.is_empty() {
                let mut rendered = value.text.clone();
                for substitution in &value.command_substitutions {
                    if !self.stdout(&substitution.body_text, &bindings) {
                        return false;
                    }
                    rendered = rendered.replacen(&substitution.text, "0", 1);
                }
                return caushell_profile::materialize_shell_assignment_value(
                    &rendered,
                    value.quoted,
                    &value.node_kind,
                    &bindings,
                )
                .is_some_and(|s| arithmetic_text(&s));
            }
        }
        false
    }

    pub fn stdout(&self, body: &str, bindings: &SessionBindings) -> bool {
        if !self.step(0) || body.len() > 8192 {
            return false;
        }
        let Ok(parsed) = caushell_parse::parse_command(body, self.parsed.shell_kind) else {
            return false;
        };
        if parsed.status != caushell_parse::ParseStatus::Complete
            || parsed.commands.len() != 1
            || !parsed.assignment_commands.is_empty()
            || !parsed.declaration_commands.is_empty()
            || !parsed.unset_commands.is_empty()
            || !parsed.function_definitions.is_empty()
        {
            return false;
        }
        let command = &parsed.commands[0];
        if command.in_pipeline
            || command.guarded
            || command.conditional_execution
            || command.terminator.is_some()
            || !command.prefix_assignments.is_empty()
        {
            return false;
        }
        // Input redirects do not change the declared output alphabet. Output
        // duplication could mix stderr or another producer into captured stdout.
        if parsed
            .redirections
            .iter()
            .any(|r| !matches!(r.operator.as_deref(), Some("<" | "<<" | "<<-" | "<<<")))
        {
            return false;
        }
        if command.command_name.as_deref().is_some_and(|n| {
            bindings.function_binding(n).is_some() || bindings.profile_has_alias_shadow(n)
        }) {
            return false;
        }
        matches!(caushell_profile::resolve_invocation_artifact_with_bindings(self.registry, command,
            InvocationRuntimeContext::default().with_shell_kind(self.parsed.shell_kind), bindings),
            ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout())
    }

    fn array_numeric(&self, name: &str, before: usize, depth: usize) -> bool {
        if !self.step(depth) {
            return false;
        }
        let definition = self
            .parsed
            .declaration_commands
            .iter()
            .filter(|c| {
                c.span.start_byte < before
                    && super::super::state_visible(&c.shell_scope_span, before)
                    && !c.conditional_execution
            })
            .flat_map(|c| {
                c.assignments
                    .iter()
                    .filter(move |a| a.name == name)
                    .map(move |a| (c.span.start_byte, a))
            })
            .chain(
                self.parsed
                    .assignment_commands
                    .iter()
                    .filter(|c| {
                        c.span.start_byte < before
                            && super::super::state_visible(&c.shell_scope_span, before)
                            && !c.conditional_execution
                    })
                    .flat_map(|c| {
                        c.assignments
                            .iter()
                            .filter(move |a| a.name == name)
                            .map(move |a| (c.span.start_byte, a))
                    }),
            )
            .max_by_key(|d| d.0);
        let Some((start, assignment)) = definition else {
            return false;
        };
        let value = &assignment.value;
        if assignment.operator != caushell_parse::AssignmentOperator::Assign
            || value.node_kind != "array" || !self.preserves(name, start, before, depth + 1)
            || self.parsed.assignment_commands.iter().filter(|c| c.span.start_byte > start && c.span.start_byte < before)
                .flat_map(|c| &c.assignments).any(|a| a.name == name)
            || self.parsed.declaration_commands.iter().filter(|c| c.span.start_byte > start && c.span.start_byte < before)
                .any(|d| d.names.iter().any(|n| n == name) || d.assignments.iter().any(|a| a.name == name))
            || self.parsed.shell_evaluations.iter().any(|s| matches!(&s.kind, ShellEvaluationKind::ArrayElementAssignment { name: n, .. } if n == name)
                && s.input.span.start_byte > start && s.input.span.start_byte < before) { return false; }
        caushell_parse::static_array_entry_values(&value.text)
            .is_some_and(|values| values.iter().all(|v| arithmetic_text(v)))
    }

    pub fn loop_local(&self, name: &str, site: &ShellEvaluationSite) -> bool {
        let Some(span) = &site.numeric_scope_span else {
            return false;
        };
        let within = |start: usize| start >= span.start_byte && start < span.end_byte;
        if self.parsed.declaration_commands.iter().any(|d| d.span.start_byte < span.end_byte
            && super::super::state_visible(&d.shell_scope_span, site.input.span.start_byte)
            && super::super::declaration_uses_nameref(d))
            || self.parsed.shell_evaluations.iter().any(|s| within(s.input.span.start_byte)
                && matches!(&s.kind, ShellEvaluationKind::ArrayElementAssignment { name: n, .. } if n == name)
                && !self.word(&s.input, s.input.span.start_byte, 0)) {
            return false;
        }
        !self
            .parsed
            .assignment_commands
            .iter()
            .filter(|c| within(c.span.start_byte))
            .flat_map(|c| c.assignments.iter().map(move |a| (c.span.start_byte, a)))
            .chain(
                self.parsed
                    .declaration_commands
                    .iter()
                    .filter(|c| within(c.span.start_byte))
                    .flat_map(|c| c.assignments.iter().map(move |a| (c.span.start_byte, a))),
            )
            .any(|(start, a)| {
                a.name == name
                    && !self.parsed.shell_evaluations.iter().any(|s| {
                        matches!(s.kind, ShellEvaluationKind::Arithmetic)
                            && s.input.span.start_byte <= a.span.start_byte
                            && s.input.span.end_byte >= a.span.end_byte
                    })
                    && !self.word(&a.value, start, 0)
            })
            && !self
                .parsed
                .declaration_commands
                .iter()
                .any(|d| within(d.span.start_byte) && d.names.iter().any(|n| n == name))
            && self.preserves(name, span.start_byte, span.end_byte, 0)
    }

    fn preserves(&self, name: &str, start: usize, end: usize, depth: usize) -> bool {
        if !self.step(depth) {
            return false;
        }
        !self.parsed.unset_commands.iter().any(|u| {
            u.span.start_byte >= start
                && u.span.start_byte < end
                && super::super::state_visible(&u.shell_scope_span, end.saturating_sub(1))
                && (u
                    .names
                    .iter()
                    .any(|n| n == name || !super::super::scalar_identifier(n))
                    || !u.options.is_empty())
        }) && self
            .parsed
            .commands
            .iter()
            .filter(|c| c.span.start_byte >= start && c.span.start_byte < end)
            .all(|c| !self.command_writes(c, &self.at(c.span.start_byte), name, depth + 1))
    }

    fn command_writes(
        &self,
        command: &CommandFact,
        bindings: &SessionBindings,
        name: &str,
        depth: usize,
    ) -> bool {
        if !self.step(depth) {
            return true;
        }
        if command
            .command_name
            .as_deref()
            .is_some_and(|n| bindings.profile_has_alias_shadow(n))
        {
            return true;
        }
        if let Some(binding) = command
            .command_name
            .as_deref()
            .and_then(|n| bindings.function_binding(n))
        {
            if binding.uncertainty.is_some() {
                return true;
            }
            let Ok(body) = caushell_parse::parse_command(&binding.body, self.parsed.shell_kind)
            else {
                return true;
            };
            if !super::super::function_variable_escapes(&body, name) {
                return false;
            }
            return body.assignment_commands.iter().flat_map(|c| &c.assignments).any(|a| a.name == name)
                || body.declaration_commands.iter().any(|d| d.names.iter().any(|n| n == name) || d.assignments.iter().any(|a| a.name == name))
                || super::super::has_nameref_declaration(&body)
                || body.shell_evaluations.iter().any(|s| matches!(&s.kind, ShellEvaluationKind::ArrayElementAssignment {name:n,..} if n == name))
                || !body.unset_commands.is_empty()
                || body.commands.iter().any(|c| self.command_writes(c,bindings,name,depth+1));
        }
        match caushell_profile::resolve_invocation_artifact_with_bindings(
            self.registry,
            command,
            InvocationRuntimeContext::default().with_shell_kind(self.parsed.shell_kind),
            bindings,
        ) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                let writes = caushell_profile::runtime_variable_writes(&r.bound);
                writes.unresolved
                    || writes.names.iter().any(|n| n == name)
                    || r.bound.operation_semantics_unresolved
                    || r.bound.effects.iter().any(|e| {
                        matches!(
                            e.kind,
                            caushell_profile::EffectKind::SourceScriptIntoCurrentShell
                                | caushell_profile::EffectKind::ExecutePayload
                        )
                    })
            }
            _ => true,
        }
    }
}
