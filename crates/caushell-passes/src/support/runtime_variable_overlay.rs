//! Ordered shell-state effects, shared with the static assignment overlay.
//! The registry supplies semantics; this module does not know wait/read names.
use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{CommandFact, ParsedCommandArtifact, StatementTerminator};
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    SessionValue, materialize_command_name, materialize_projected_invocation, project_invocation,
    resolve_invocation_artifact_with_bindings, runtime_variable_writes,
};
use caushell_types::{
    CheckRequest, CommandSequenceNo, SessionAliasBinding, SessionFunctionBinding, SessionSummary,
};

use super::variable_overlay::{
    apply_variable_overlay, apply_visible_variable_bindings_before_span,
};
use super::{apply_alias_command, expand_alias_chain, request_variable_bindings};

pub(crate) struct RuntimeVariableOverlay {
    pub bindings: SessionBindings,
    pub touched: BTreeSet<String>,
    pub positional_state: Option<super::PositionalParameterMutation>,
    pub assigned: BTreeSet<String>,
    /// State-only fences. Commands remain present for conservative risk auditing.
    pub state_fences: Vec<(usize, usize)>,
    pub function_mutations: Vec<(caushell_runner::PendingMutation, usize)>,
    pub state_capture: Option<super::state_capture::StateCapture>,
}

/// Explicit replay interface for static consumers that otherwise reconstruct
/// stale variables independently of invocation resolution.
pub(crate) trait VariableBindingReplay {
    fn base(&self) -> &SessionBindings;
    fn apply_before(
        &self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> SessionBindings;
}

impl VariableBindingReplay for SessionBindings {
    fn base(&self) -> &SessionBindings {
        self
    }
    fn apply_before(
        &self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> SessionBindings {
        apply_visible_variable_bindings_before_span(bindings, parsed, end, observed_at)
    }
}

impl std::ops::Deref for dyn VariableBindingReplay + '_ {
    type Target = SessionBindings;
    fn deref(&self) -> &SessionBindings {
        self.base()
    }
}

pub(crate) struct RuntimeBindingReplay<'a> {
    pub registry: &'a ProfileRegistry,
    pub request: &'a CheckRequest,
    pub bindings: &'a SessionBindings,
}
impl VariableBindingReplay for RuntimeBindingReplay<'_> {
    fn base(&self) -> &SessionBindings {
        self.bindings
    }
    fn apply_before(
        &self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> SessionBindings {
        apply_runtime_variable_bindings_before_span(
            self.registry,
            self.request,
            bindings,
            parsed,
            end,
            observed_at,
        )
    }
}
impl std::ops::Deref for RuntimeBindingReplay<'_> {
    type Target = SessionBindings;
    fn deref(&self) -> &SessionBindings {
        self.bindings
    }
}

pub(crate) struct RebasedBindingReplay<'a> {
    pub parent: &'a dyn VariableBindingReplay,
    pub bindings: SessionBindings,
}
impl VariableBindingReplay for RebasedBindingReplay<'_> {
    fn base(&self) -> &SessionBindings {
        &self.bindings
    }
    fn apply_before(
        &self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> SessionBindings {
        self.parent.apply_before(bindings, parsed, end, observed_at)
    }
}

pub(crate) fn runtime_visible_variable_bindings_before_span(
    registry: &ProfileRegistry,
    summary: &SessionSummary,
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> SessionBindings {
    apply_runtime_variable_bindings_before_span(
        registry,
        request,
        request_variable_bindings(summary, request),
        parsed,
        span_start_byte,
        observed_at,
    )
}

pub(crate) fn apply_runtime_variable_bindings_before_span(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> SessionBindings {
    runtime_variable_overlay(
        registry,
        request,
        bindings,
        parsed,
        span_start_byte,
        observed_at,
    )
    .bindings
}

pub(crate) fn runtime_variable_overlay(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
) -> RuntimeVariableOverlay {
    runtime_variable_overlay_impl(
        registry,
        request,
        bindings,
        parsed,
        span_start_byte,
        observed_at,
        None,
        None,
    )
}

pub(crate) fn runtime_variable_overlay_with_history(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    observed_at: CommandSequenceNo,
    limits: caushell_types::AnalysisBudgetPolicy,
    session: caushell_query::QuerySession<'_>,
) -> RuntimeVariableOverlay {
    runtime_variable_overlay_impl(
        registry,
        request,
        bindings,
        parsed,
        usize::MAX,
        observed_at,
        Some(limits),
        Some(session),
    )
}

pub(crate) fn runtime_source_bindings_before_span(
    registry: &ProfileRegistry,
    session: caushell_query::QuerySession<'_>,
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    end: usize,
) -> SessionBindings {
    runtime_variable_overlay_impl(
        registry,
        request,
        request_variable_bindings(session.summary(), request),
        parsed,
        end,
        request.sequence_no,
        None,
        Some(session),
    )
    .bindings
}

fn runtime_variable_overlay_impl(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    bindings: SessionBindings,
    parsed: &ParsedCommandArtifact,
    span_start_byte: usize,
    observed_at: CommandSequenceNo,
    capture_limits: Option<caushell_types::AnalysisBudgetPolicy>,
    session: Option<caushell_query::QuerySession<'_>>,
) -> RuntimeVariableOverlay {
    let mut context = RuntimeVariableContext {
        registry,
        request,
        depth: 0,
        aliases: bindings
            .alias_bindings()
            .map(|binding| (binding.name.clone(), binding.clone()))
            .collect(),
        can_prove_termination: true,
        capture_limits,
        session,
        observations: Vec::new(),
        entry_cwd: caushell_runner::EffectiveCwd::known(request.shell_state_before.cwd()),
        source_scopes: Vec::new(),
        sourced: false,
        work: std::rc::Rc::new(std::cell::Cell::new(1024usize)),
    };
    context.replay(bindings, parsed, span_start_byte, observed_at)
}

pub(super) struct RuntimeVariableContext<'a> {
    registry: &'a ProfileRegistry,
    request: &'a CheckRequest,
    depth: u8,
    aliases: BTreeMap<String, SessionAliasBinding>,
    can_prove_termination: bool,
    capture_limits: Option<caushell_types::AnalysisBudgetPolicy>,
    session: Option<caushell_query::QuerySession<'a>>,
    observations: Vec<(ResolveInvocationArtifactResult, SessionBindings)>,
    entry_cwd: caushell_runner::EffectiveCwd,
    source_scopes: Vec<super::source_state::SourceStateScope>,
    sourced: bool,
    work: std::rc::Rc<std::cell::Cell<usize>>,
}

impl RuntimeVariableContext<'_> {
    fn apply_source(
        &mut self,
        command: &CommandFact,
        expanded: &CommandFact,
        parsed: &ParsedCommandArtifact,
        bindings: &mut SessionBindings,
        touched: &mut BTreeSet<String>,
        function_mutations: &mut Vec<(caushell_runner::PendingMutation, usize)>,
        capture: &mut Option<super::state_capture::StateCapture>,
        positional_state: &mut Option<super::PositionalParameterMutation>,
        visible: bool,
        resolved: &caushell_profile::ResolvedInvocationArtifact,
    ) {
        if !visible {
            return;
        }
        let scope = super::source_state::SourceStateScope::new(
            parsed,
            command,
            self.request,
            &self.entry_cwd,
            &self.observations,
        );
        let empty_graph = caushell_graph::SessionGraph::new();
        let empty_summary = SessionSummary::new();
        // Without a history view, only bytes proved within the current source
        // scope can be recovered. Missing history is never a file-content fact.
        let session = self
            .session
            .unwrap_or_else(|| caushell_query::QuerySession::new(&empty_graph, &empty_summary));
        let body = (self.depth < 8)
            .then(|| {
                super::source_state::body(
                    session,
                    self.registry,
                    self.request,
                    resolved,
                    bindings,
                    scope.as_ref()?,
                    &self.source_scopes,
                )
            })
            .flatten()
            .filter(|text| text.len() <= 65536)
            .and_then(|text| caushell_parse::parse_command(&text, parsed.shell_kind).ok())
            .filter(|p| p.status == caushell_parse::ParseStatus::Complete);
        let Some(body) = body else {
            touched.extend(bindings.variable_names().map(str::to_owned));
            bindings.mark_shell_state_uncertain("sourced shell state is incomplete");
            *positional_state = Some(super::PositionalParameterMutation::Forget);
            return;
        };
        let projection = materialize_projected_invocation(
            &project_invocation(
                expanded,
                InvocationRuntimeContext::default().with_shell_kind(parsed.shell_kind),
            ),
            bindings,
        );
        if projection.shell_expansion_unresolved {
            touched.extend(bindings.variable_names().map(str::to_owned));
            bindings.mark_shell_state_uncertain("sourced argument expansion is incomplete");
            *positional_state = Some(super::PositionalParameterMutation::Forget);
            return;
        }
        let mut local = super::command_environment_bindings(
            bindings,
            parsed,
            &caushell_runner::ParsedCommandRef::new(usize::MAX, command.span.clone()),
        );
        let prefixed_environment = local != *bindings;
        let args = projection
            .invocation
            .args
            .iter()
            .skip(1)
            .map(|arg| SessionValue::exact_scalar(&arg.text))
            .collect::<Vec<_>>();
        let temporary_args = !args.is_empty();
        if temporary_args {
            local.replace_positional_parameters(args);
        }
        let scope = scope.unwrap();
        let mut source_scopes = self.source_scopes.clone();
        source_scopes.push(scope.clone());
        let mut child = RuntimeVariableContext {
            registry: self.registry,
            request: self.request,
            depth: self.depth + 1,
            aliases: self.aliases.clone(),
            can_prove_termination: true,
            capture_limits: self.capture_limits.clone(),
            session: self.session,
            observations: Vec::new(),
            entry_cwd: scope.cwd(),
            source_scopes,
            sourced: true,
            work: self.work.clone(),
        };
        let mut result = child.replay(local, &body, usize::MAX, self.request.sequence_no);
        if prefixed_environment {
            result.bindings.mark_shell_state_uncertain(
                "sourced prefix assignment has unresolved caller-frame lifetime",
            );
        }
        if bindings.in_function_scope()
            && body.declaration_commands.iter().any(|declaration| {
                matches!(
                    declaration.kind,
                    caushell_parse::DeclarationCommandKind::Local
                        | caushell_parse::DeclarationCommandKind::Declare
                        | caushell_parse::DeclarationCommandKind::Typeset
                )
            })
        {
            result.bindings.mark_shell_state_uncertain(
                "sourced local declaration has unresolved caller-frame lifetime",
            );
        }
        // An unproved branch may execute or retain the entry state. Do not
        // install its definitions as unconditional caller facts.
        if command.conditional_execution {
            touched.extend(bindings.variable_names().map(str::to_owned));
            touched.extend(result.assigned);
            touched.extend(result.touched);
            bindings.mark_shell_state_uncertain("conditional sourced shell state");
            *positional_state = Some(super::PositionalParameterMutation::Forget);
            return;
        }
        touched.extend(result.assigned);
        touched.extend(result.touched);
        if temporary_args {
            if bindings.positional_parameters_are_complete() {
                result.bindings.replace_positional_parameters(
                    bindings.positional_parameters().iter().cloned(),
                );
            } else {
                result.bindings.forget_positional_parameters();
            }
        } else if result.positional_state.is_some() {
            *positional_state = result.positional_state;
        }
        if let (Some(parent), Some(child)) = (capture.as_mut(), result.state_capture.take()) {
            parent.incomplete.extend(child.incomplete);
            parent.merge(
                child
                    .observations
                    .into_iter()
                    .filter_map(|mut observation| {
                        if temporary_args
                            && observation.kind == caushell_types::SafetyStateKind::Positionals
                        {
                            return None;
                        }
                        observation.source_end = command.span.end_byte;
                        Some(observation)
                    }),
            );
        }
        function_mutations.extend(
            result
                .function_mutations
                .into_iter()
                .map(|(mutation, _)| (mutation, command.span.start_byte)),
        );
        self.aliases = result
            .bindings
            .alias_bindings()
            .map(|binding| (binding.name.clone(), binding.clone()))
            .collect();
        *bindings = result.bindings;
    }

    fn replay(
        &mut self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> RuntimeVariableOverlay {
        let mut bindings = bindings;
        if self.sourced {
            let cost = parsed
                .commands
                .len()
                .saturating_add(parsed.function_definitions.len())
                .max(1);
            if cost > self.work.get() {
                bindings.mark_shell_state_uncertain("sourced state replay budget exceeded");
                return apply_variable_overlay(
                    bindings,
                    parsed,
                    0,
                    observed_at,
                    None,
                    None,
                    self.capture_limits.clone(),
                );
            }
            self.work.set(self.work.get() - cost);
        }
        // Fast path: no candidate, alias or function can introduce a writer.
        let candidate = self.sourced
            || parsed.commands.iter().any(|command| {
                command.span.end_byte <= end
                    && command.command_name.as_deref().is_none_or(|name| {
                        name.contains('$')
                            || name.contains('`')
                            || self.registry.may_write_runtime_variable(name)
                            || self.registry.may_terminate_shell(name)
                            || self.registry.lookup(name).profile.is_some_and(|profile| {
                                profile.forms.iter().flat_map(|f| &f.effects).any(|e| {
                                e.kind == caushell_profile::EffectKind::SourceScriptIntoCurrentShell
                            })
                            })
                            || self.aliases.contains_key(name)
                            || bindings.function_binding(name).is_some()
                            || !super::alias_assignments(command).is_empty()
                            || (self.capture_limits.is_some()
                                && !super::unalias_names(command).is_empty())
                            || parsed.function_definitions.iter().any(|f| f.name == name)
                    })
            });
        if !candidate {
            // Static state effects still need the same ordered result for
            // persistence and for propagation through a called function.
            return apply_variable_overlay(
                bindings,
                parsed,
                end,
                observed_at,
                Some(self.registry),
                None,
                self.capture_limits.clone(),
            );
        }
        let capture_limits = self.capture_limits.clone();
        apply_variable_overlay(
            bindings,
            parsed,
            end,
            observed_at,
            Some(self.registry),
            Some(self),
            capture_limits,
        )
    }

    pub(super) fn apply_command(
        &mut self,
        command: &CommandFact,
        parsed: &ParsedCommandArtifact,
        target_start: usize,
        bindings: &mut SessionBindings,
        touched: &mut BTreeSet<String>,
        function_mutations: &mut Vec<(caushell_runner::PendingMutation, usize)>,
        capture: &mut Option<super::state_capture::StateCapture>,
        positional_state: &mut Option<super::PositionalParameterMutation>,
    ) -> Option<(usize, usize)> {
        // A pipeline/background shell cannot write the caller's variables.
        // A (...) write is visible only to later commands inside that scope.
        let visible = runtime_write_visible(command, parsed, target_start);
        let (expanded, _) = expand_alias_chain(command, self.request.shell_kind, &self.aliases, 8);
        let old_aliases = capture.as_ref().map(|_| self.aliases.clone());
        apply_alias_command(&mut self.aliases, command, self.request.sequence_no);
        if visible && let (Some(capture), Some(old)) = (capture.as_mut(), old_aliases) {
            let names: BTreeSet<_> = old.keys().chain(self.aliases.keys()).collect();
            for name in names {
                if old.get(name) == self.aliases.get(name) {
                    continue;
                }
                if let Some(binding) = old.get(name) {
                    capture.observe(
                        caushell_types::SafetyStateKind::Alias,
                        name,
                        caushell_types::SafetyStateValue::Definition {
                            body: binding.body.clone(),
                            uncertainty: None,
                        },
                        command.span.start_byte,
                    );
                }
                let value = self.aliases.get(name).map_or(
                    caushell_types::SafetyStateValue::Absent,
                    |binding| caushell_types::SafetyStateValue::Definition {
                        body: binding.body.clone(),
                        uncertainty: None,
                    },
                );
                capture.observe(
                    caushell_types::SafetyStateKind::Alias,
                    name,
                    value,
                    command.span.end_byte,
                );
            }
        }
        if visible {
            let removed = bindings
                .alias_bindings()
                .filter(|b| !self.aliases.contains_key(&b.name))
                .map(|b| b.name.clone())
                .collect::<Vec<_>>();
            for name in removed {
                bindings.unset_alias(&name);
            }
            for binding in self.aliases.values() {
                bindings.upsert_alias_binding(binding.clone());
            }
        }
        let name = expanded
            .command_name
            .as_deref()
            .and_then(|name| materialize_command_name(name, bindings))
            .or_else(|| expanded.command_name.clone());
        let result = resolve_invocation_artifact_with_bindings(
            self.registry,
            &expanded,
            InvocationRuntimeContext::default().with_shell_kind(parsed.shell_kind),
            bindings,
        );
        self.observations.push((result.clone(), bindings.clone()));
        if let ResolveInvocationArtifactResult::Resolved(resolved) = &result
            && resolved
                .bound
                .effects
                .iter()
                .any(|e| e.kind == caushell_profile::EffectKind::SourceScriptIntoCurrentShell)
        {
            self.apply_source(
                command,
                &expanded,
                parsed,
                bindings,
                touched,
                function_mutations,
                capture,
                positional_state,
                visible,
                resolved,
            );
            self.can_prove_termination = false;
            return None;
        }
        if let Some(function) = name
            .as_ref()
            .and_then(|n| bindings.function_binding(n))
            .cloned()
        {
            if function.uncertainty.is_some() {
                self.can_prove_termination = false;
                if visible {
                    for variable in bindings
                        .variable_names()
                        .map(str::to_string)
                        .collect::<BTreeSet<_>>()
                    {
                        touched.insert(variable.clone());
                        bindings
                            .insert_opaque_dynamic(&variable, "uncertain function runtime effects");
                    }
                }
                return None;
            }
            // The normal execution frontier enforces expansion limits and
            // contributes approval evidence. The overlay must also be bounded.
            if self.depth >= 8 {
                // Never retain exact values past this bounded replay. The
                // execution frontier separately enforces its policy budget.
                let names = bindings
                    .variable_names()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                for name in names {
                    touched.insert(name.clone());
                    bindings.insert_opaque_dynamic(&name, "variable effect replay depth exceeded");
                }
                return None;
            }
            let Ok(body) = caushell_parse::parse_command(&function.body, self.request.shell_kind)
            else {
                return None;
            };
            let projection = materialize_projected_invocation(
                &project_invocation(
                    &expanded,
                    InvocationRuntimeContext::default().with_shell_kind(parsed.shell_kind),
                ),
                bindings,
            );
            let environment = super::command_environment_bindings(
                bindings,
                parsed,
                &caushell_runner::ParsedCommandRef::new(usize::MAX, command.span.clone()),
            );
            let local = super::function_call_bindings(&environment, &projection);
            let call_scope = super::source_state::SourceStateScope::new(
                parsed,
                command,
                self.request,
                &self.entry_cwd,
                &self.observations,
            );
            let mut source_scopes = self.source_scopes.clone();
            if let Some(scope) = &call_scope {
                source_scopes.push(scope.clone());
            }
            let mut child = RuntimeVariableContext {
                registry: self.registry,
                request: self.request,
                depth: self.depth + 1,
                aliases: self.aliases.clone(),
                can_prove_termination: true,
                capture_limits: self.capture_limits.clone(),
                session: self.session,
                observations: Vec::new(),
                entry_cwd: call_scope
                    .map_or(caushell_runner::EffectiveCwd::Unknown, |scope| scope.cwd()),
                source_scopes,
                sourced: self.sourced,
                work: self.work.clone(),
            };
            let mut result = child.replay(local, &body, usize::MAX, self.request.sequence_no);
            if visible && let Some(reason) = result.bindings.shell_state_uncertainty() {
                bindings.mark_shell_state_uncertain(reason);
            }
            if visible {
                let before: BTreeMap<_, _> = bindings
                    .retained_alias_bindings()
                    .map(|binding| (binding.name.clone(), binding.clone()))
                    .collect();
                let after: BTreeMap<_, _> = result
                    .bindings
                    .retained_alias_bindings()
                    .map(|binding| (binding.name.clone(), binding.clone()))
                    .collect();
                if before != after && command.conditional_execution {
                    bindings.mark_shell_state_uncertain("conditional alias state effect");
                } else {
                    for name in before.keys().filter(|name| !after.contains_key(*name)) {
                        bindings.unset_alias(name);
                    }
                    for binding in after.values() {
                        bindings.upsert_alias_binding(binding.clone());
                    }
                    self.aliases = after;
                }
            }
            if visible
                && let (Some(capture), Some(child_capture)) =
                    (capture.as_mut(), result.state_capture.take())
            {
                capture.incomplete.extend(child_capture.incomplete);
                capture.merge(child_capture.observations.into_iter().filter_map(
                    |mut observation| {
                        use caushell_types::SafetyStateKind as K;
                        let escapes = match observation.kind {
                            K::Variable => function_variable_escapes_in_frame(
                                &body,
                                &observation.name,
                                Some(bindings),
                            ),
                            K::Function | K::Alias => true,
                            _ => false,
                        };
                        if !escapes {
                            return None;
                        }
                        // Child source offsets are not caller offsets. Global
                        // effects become possible after this call, never before it.
                        observation.source_end = command.span.end_byte;
                        Some(observation)
                    },
                ));
            }
            let terminates = result
                .state_fences
                .iter()
                .any(|(_, end)| *end == usize::MAX);
            if visible {
                let names = result
                    .function_mutations
                    .iter()
                    .filter_map(|(mutation, _)| match mutation {
                        caushell_runner::PendingMutation::UpsertFunctionBinding { binding } => {
                            Some(binding.name.clone())
                        }
                        caushell_runner::PendingMutation::UnsetFunction { name, .. } => {
                            Some(name.clone())
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                for name in names {
                    let mutation = if command.conditional_execution {
                        let binding = SessionFunctionBinding::uncertain(
                            &name,
                            "conditional function state effect",
                            self.request.sequence_no,
                        );
                        bindings.upsert_function_binding(binding.clone());
                        caushell_runner::PendingMutation::UpsertFunctionBinding { binding }
                    } else if let Some(binding) = result.bindings.retained_function_binding(&name) {
                        bindings.upsert_function_binding(binding.clone());
                        caushell_runner::PendingMutation::UpsertFunctionBinding {
                            binding: binding.clone(),
                        }
                    } else {
                        bindings.unset_function(&name);
                        caushell_runner::PendingMutation::UnsetFunction {
                            name,
                            observed_at: self.request.sequence_no,
                        }
                    };
                    function_mutations.push((mutation, command.span.start_byte));
                }
            }
            result.touched.extend(result.assigned);
            for variable in result.touched.into_iter().filter(|_| visible) {
                // Plain function locals do not escape to the calling shell.
                if !function_variable_escapes_in_frame(&body, &variable, Some(bindings)) {
                    continue;
                }
                touched.insert(variable.clone());
                if command.guarded || command.control_flow_span.is_some() {
                    bindings.insert_opaque_dynamic(&variable, "conditional function runtime write");
                } else if result
                    .bindings
                    .runtime_variable_target_is_unresolved(&variable)
                {
                    bindings.insert_opaque_dynamic(&variable, "function structured variable write");
                } else if let Some(value) = result.bindings.get(&variable) {
                    match value.value {
                        SessionValue::ExactScalar(value) => {
                            bindings.insert_exact_scalar(&variable, value)
                        }
                        _ => bindings.insert_opaque_dynamic(&variable, "function runtime write"),
                    }
                } else if result.bindings.variable_presence(&variable)
                    == caushell_profile::VariablePresence::Absent
                {
                    bindings.remove(&variable);
                } else {
                    bindings.insert_opaque_dynamic(&variable, "function variable state unknown");
                }
                if !command.guarded && command.control_flow_span.is_none() {
                    if result
                        .bindings
                        .runtime_variable_target_is_unresolved(&variable)
                    {
                        bindings.mark_unresolved_runtime_variable_target(&variable);
                    }
                    bindings
                        .set_variable_facts(&variable, result.bindings.variable_facts(&variable));
                }
                match result.bindings.environment_value(&variable) {
                    caushell_profile::EnvironmentValueRef::Present(_) => bindings.export(&variable),
                    caushell_profile::EnvironmentValueRef::Absent => bindings.unexport(&variable),
                    caushell_profile::EnvironmentValueRef::Unknown => {}
                }
            }
            // Nameref targets are not necessarily present in assignment facts.
            if visible && has_nameref_declaration(&body) {
                let names: Vec<_> = bindings.variable_names().map(str::to_owned).collect();
                for name in names {
                    if function_variable_escapes_in_frame(&body, &name, Some(bindings)) {
                        bindings.insert_opaque_dynamic(&name, "function nameref write target");
                        touched.insert(name);
                    }
                }
                bindings.forget_variable_presence();
            }
            return (self.can_prove_termination && terminates && !command.conditional_execution)
                .then(|| termination_fence(command, parsed))
                .flatten();
        }
        let Some(name) = name else {
            self.can_prove_termination = false;
            return None;
        };
        if self.sourced
            && match &result {
                ResolveInvocationArtifactResult::Resolved(resolved) => {
                    resolved.bound.effects.iter().any(|effect| {
                        matches!(
                            effect.kind,
                            caushell_profile::EffectKind::ExecutePayload
                                | caushell_profile::EffectKind::LoadInProcessCode
                        )
                    })
                }
                _ => true,
            }
        {
            touched.extend(bindings.variable_names().map(str::to_owned));
            bindings
                .mark_shell_state_uncertain("sourced command has unresolved shell-state effects");
        }
        if self.depth > 0 {
            // An unmodeled invocation can return from the function before a
            // later terminator. Opaque payload execution can change control
            // flow too. Do not infer caller termination through this gap.
            let profile = self.registry.lookup(&name).profile;
            if profile.is_none_or(|p| {
                p.forms
                    .iter()
                    .flat_map(|f| &f.effects)
                    .chain(p.modifiers.iter().flat_map(|m| &m.effects))
                    .any(|e| {
                        matches!(
                            e.kind,
                            caushell_profile::EffectKind::ExecutePayload
                                | caushell_profile::EffectKind::SourceScriptIntoCurrentShell
                        )
                    })
            }) {
                self.can_prove_termination = false;
            }
        }
        if !self.registry.may_write_runtime_variable(&name)
            && !self.registry.may_terminate_shell(&name)
        {
            return None;
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) = result else {
            return None;
        };
        let terminates = self.can_prove_termination
            && !resolved.bound.operation_semantics_unresolved
            && resolved
                .bound
                .effects
                .iter()
                .any(|e| e.kind == caushell_profile::EffectKind::TerminateCurrentShell);
        let writes = runtime_variable_writes(&resolved.bound);
        if visible && writes.unresolved {
            super::variable_facts::invalidate_all(bindings, touched);
        }
        for variable in writes.names.into_iter().filter(|_| visible) {
            touched.insert(variable.clone());
            bindings.insert_opaque_dynamic(&variable, "runtime variable write (possibly unset)");
        }
        (terminates && !command.conditional_execution)
            .then(|| termination_fence(command, parsed))
            .flatten()
    }
}

fn termination_fence(
    command: &CommandFact,
    parsed: &ParsedCommandArtifact,
) -> Option<(usize, usize)> {
    // Redirection setup can fail before the terminating builtin/function runs.
    // Keep the continuing path; do not use a hypothetical exit to hide later writes.
    if parsed.redirections.iter().any(|r| {
        r.top_level_span.start_byte <= command.span.start_byte
            && r.top_level_span.end_byte >= command.span.end_byte
    }) {
        return None;
    }
    Some((
        command.span.end_byte,
        command
            .shell_scope_span
            .as_ref()
            .map_or(usize::MAX, |s| s.end_byte),
    ))
}

pub(crate) fn runtime_write_visible(
    command: &CommandFact,
    parsed: &ParsedCommandArtifact,
    target_start: usize,
) -> bool {
    let same_pipeline_shell = parsed
        .commands
        .iter()
        .find(|c| c.span.start_byte == target_start)
        .is_some_and(|target| {
            target.in_pipeline
                && target.pipeline_span == command.pipeline_span
                && target.pipeline_position == command.pipeline_position
        });
    !((command.in_pipeline && !same_pipeline_shell)
        || command.terminator == Some(StatementTerminator::Background)
        || command
            .shell_scope_span
            .as_ref()
            .is_some_and(|s| target_start < s.start_byte || target_start >= s.end_byte)
        || command
            .subshell_span
            .as_ref()
            .is_some_and(|s| target_start < s.start_byte || target_start >= s.end_byte))
}

pub(crate) fn has_nameref_declaration(body: &ParsedCommandArtifact) -> bool {
    body.declaration_commands
        .iter()
        .any(declaration_uses_nameref)
}

pub(crate) fn declaration_uses_nameref(d: &caushell_parse::DeclarationCommandFact) -> bool {
    matches!(
        d.kind,
        caushell_parse::DeclarationCommandKind::Declare
            | caushell_parse::DeclarationCommandKind::Typeset
            | caushell_parse::DeclarationCommandKind::Local
    ) && d
        .options
        .iter()
        .any(|o| o.starts_with('-') && !o.starts_with("--") && o[1..].contains('n'))
}

pub(crate) fn function_variable_escapes(body: &ParsedCommandArtifact, variable: &str) -> bool {
    function_variable_escapes_in_frame(body, variable, None)
}

pub(crate) fn function_variable_escapes_in_frame(
    body: &ParsedCommandArtifact,
    variable: &str,
    bindings: Option<&SessionBindings>,
) -> bool {
    !body.declaration_commands.iter().any(|d| {
        matches!(
            d.kind,
            caushell_parse::DeclarationCommandKind::Local
                | caushell_parse::DeclarationCommandKind::Declare
                | caushell_parse::DeclarationCommandKind::Typeset
        ) && d.unconditional_current_shell
            && !super::variable_facts::declaration_prints_only(d)
            && bindings.is_none_or(|b| !super::variable_facts::declaration_has_shadow(d, b))
            && !body.function_definitions.iter().any(|f| {
                f.name == super::variable_facts::declaration_name(d)
                    && f.span.start_byte < d.span.start_byte
            })
            && !d
                .options
                .iter()
                .any(|o| o.starts_with('-') && o[1..].contains('g'))
            && (d.names.iter().any(|name| name == variable)
                || d.assignments.iter().any(|a| a.name == variable))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::*;

    #[test]
    fn generic_termination_effect_fences_state_without_command_name_cases() {
        let registry = ProfileRegistry::built_in().unwrap();
        let mut profile = registry.lookup("exit").profile.unwrap().clone();
        profile.identity.canonical_name = caushell_profile::CommandName::new("finish_shell");
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        assert!(registry.may_terminate_shell("finish_shell"));
        assert!(!registry.may_terminate_shell("exit"));
        let request = CheckRequest {
            session_id: SessionId::new("generic-termination"),
            sequence_no: CommandSequenceNo::new(1),
            command: "target=/opt/shared/file; finish_shell; target=cache/file".into(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some("/tmp/project".into()),
        };
        let parsed = caushell_parse::parse_command(&request.command, request.shell_kind).unwrap();
        let overlay = runtime_variable_overlay(
            &registry,
            &request,
            SessionBindings::new(),
            &parsed,
            usize::MAX,
            request.sequence_no,
        );
        assert!(
            overlay
                .state_fences
                .iter()
                .any(|(_, end)| *end == usize::MAX)
        );
        assert_eq!(
            overlay.bindings.get("target").unwrap().value,
            &SessionValue::exact_scalar("/opt/shared/file")
        );
    }

    #[test]
    fn effect_replay_works_for_an_arbitrary_registered_writer() {
        let built_in = ProfileRegistry::built_in().unwrap();
        let mut writer = built_in.lookup("read").profile.unwrap().clone();
        writer.identity.canonical_name = caushell_profile::CommandName::new("capture_value");
        writer.identity.aliases.clear();
        let registry = ProfileRegistry::from_profiles(vec![writer]).unwrap();
        assert!(registry.may_write_runtime_variable("capture_value"));
        assert!(!registry.may_write_runtime_variable("wait"));
        let request = CheckRequest {
            session_id: SessionId::new("effect-replay"),
            sequence_no: CommandSequenceNo::new(1),
            command: "x=cache/old; y=cache/keep; capture_value x".into(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some("/tmp/project".into()),
        };
        let parsed = caushell_parse::parse_command(&request.command, request.shell_kind).unwrap();
        let overlay = runtime_variable_overlay(
            &registry,
            &request,
            SessionBindings::new(),
            &parsed,
            usize::MAX,
            request.sequence_no,
        );
        assert_eq!(overlay.touched.into_iter().collect::<Vec<_>>(), ["x"]);
        assert!(matches!(
            overlay.bindings.get("x").unwrap().value,
            SessionValue::OpaqueDynamic { .. }
        ));
        assert_eq!(
            overlay.bindings.get("y").unwrap().value,
            &SessionValue::exact_scalar("cache/keep")
        );
    }
}
