//! Ordered variable effects, shared with the ordinary static assignment overlay.
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
    let mut context = RuntimeVariableContext {
        registry,
        request,
        depth: 0,
        aliases: request
            .shell_state_before
            .aliases
            .iter()
            .map(|a| {
                (
                    a.name.clone(),
                    SessionAliasBinding::new(&a.name, &a.body, observed_at),
                )
            })
            .collect(),
        can_prove_termination: true,
    };
    context.replay(bindings, parsed, span_start_byte, observed_at)
}

pub(super) struct RuntimeVariableContext<'a> {
    registry: &'a ProfileRegistry,
    request: &'a CheckRequest,
    depth: u8,
    aliases: BTreeMap<String, SessionAliasBinding>,
    can_prove_termination: bool,
}

impl RuntimeVariableContext<'_> {
    fn replay(
        &mut self,
        bindings: SessionBindings,
        parsed: &ParsedCommandArtifact,
        end: usize,
        observed_at: CommandSequenceNo,
    ) -> RuntimeVariableOverlay {
        // Fast path: no candidate, alias or function can introduce a writer.
        let candidate = parsed.commands.iter().any(|command| {
            command.span.end_byte <= end
                && command.command_name.as_deref().is_none_or(|name| {
                    name.contains('$')
                        || name.contains('`')
                        || self.registry.may_write_runtime_variable(name)
                        || self.registry.may_terminate_shell(name)
                        || self.aliases.contains_key(name)
                        || bindings.function_binding(name).is_some()
                        || !super::alias_assignments(command).is_empty()
                        || parsed.function_definitions.iter().any(|f| f.name == name)
                })
        });
        if !candidate {
            // Static state effects still need the same ordered result for
            // persistence and for propagation through a called function.
            return apply_variable_overlay(bindings, parsed, end, observed_at, None);
        }
        apply_variable_overlay(bindings, parsed, end, observed_at, Some(self))
    }

    pub(super) fn apply_command(
        &mut self,
        command: &CommandFact,
        parsed: &ParsedCommandArtifact,
        target_start: usize,
        bindings: &mut SessionBindings,
        touched: &mut BTreeSet<String>,
        function_mutations: &mut Vec<(caushell_runner::PendingMutation, usize)>,
    ) -> Option<(usize, usize)> {
        // A pipeline/background shell cannot write the caller's variables.
        // A (...) write is visible only to later commands inside that scope.
        let same_pipeline_shell = parsed
            .commands
            .iter()
            .find(|c| c.span.start_byte == target_start)
            .is_some_and(|target| {
                target.in_pipeline
                    && target.pipeline_span == command.pipeline_span
                    && target.pipeline_position == command.pipeline_position
            });
        let visible = !((command.in_pipeline && !same_pipeline_shell)
            || command.terminator == Some(StatementTerminator::Background)
            || command.shell_scope_span.as_ref().is_some_and(|scope| {
                target_start < scope.start_byte || target_start >= scope.end_byte
            })
            || command.subshell_span.as_ref().is_some_and(|scope| {
                target_start < scope.start_byte || target_start >= scope.end_byte
            }));
        let (expanded, _) = expand_alias_chain(command, self.request.shell_kind, &self.aliases, 8);
        apply_alias_command(&mut self.aliases, command, self.request.sequence_no);
        let name = expanded
            .command_name
            .as_deref()
            .and_then(|name| materialize_command_name(name, bindings))
            .or_else(|| expanded.command_name.clone());
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
                &project_invocation(&expanded, InvocationRuntimeContext::default()),
                bindings,
            );
            let environment = super::command_environment_bindings(
                bindings,
                parsed,
                &caushell_runner::ParsedCommandRef::new(usize::MAX, command.span.clone()),
            );
            let local = super::function_call_bindings(&environment, &projection);
            let mut child = RuntimeVariableContext {
                registry: self.registry,
                request: self.request,
                depth: self.depth + 1,
                aliases: self.aliases.clone(),
                can_prove_termination: true,
            };
            let mut result = child.replay(local, &body, usize::MAX, self.request.sequence_no);
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
                    } else if let Some(binding) = result.bindings.function_binding(&name) {
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
                if body.declaration_commands.iter().any(|d| {
                    d.kind == caushell_parse::DeclarationCommandKind::Local
                        && d.unconditional_current_shell
                        && d.options.is_empty()
                        && (d.names.contains(&variable)
                            || d.assignments.iter().any(|a| a.name == variable))
                }) {
                    continue;
                }
                touched.insert(variable.clone());
                if command.guarded || command.control_flow_span.is_some() {
                    bindings.insert_opaque_dynamic(&variable, "conditional function runtime write");
                } else if let Some(value) = result.bindings.get(&variable) {
                    match value.value {
                        SessionValue::ExactScalar(value) => {
                            bindings.insert_exact_scalar(&variable, value)
                        }
                        _ => bindings.insert_opaque_dynamic(&variable, "function runtime write"),
                    }
                } else {
                    bindings.remove(&variable);
                }
                match result.bindings.environment_value(&variable) {
                    caushell_profile::EnvironmentValueRef::Present(_) => bindings.export(&variable),
                    caushell_profile::EnvironmentValueRef::Absent => bindings.unexport(&variable),
                    caushell_profile::EnvironmentValueRef::Unknown => {}
                }
            }
            return (self.can_prove_termination && terminates && !command.conditional_execution)
                .then(|| termination_fence(command, parsed))
                .flatten();
        }
        let Some(name) = name else {
            self.can_prove_termination = false;
            return None;
        };
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
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                self.registry,
                &expanded,
                InvocationRuntimeContext::default(),
                bindings,
            )
        else {
            return None;
        };
        let terminates = self.can_prove_termination
            && !resolved.bound.operation_semantics_unresolved
            && resolved
                .bound
                .effects
                .iter()
                .any(|e| e.kind == caushell_profile::EffectKind::TerminateCurrentShell);
        for variable in runtime_variable_writes(&resolved.bound)
            .names
            .into_iter()
            .filter(|_| visible)
        {
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
