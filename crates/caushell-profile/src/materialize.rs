use crate::binding_map::BindingMap;
use crate::parameter_pattern::{ParameterPattern, PatternUnit, ShellPatternRemovalKind};
use std::collections::BTreeMap;

use caushell_types::{
    CommandSequenceNo, RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind,
    SessionAliasBinding, SessionFunctionBinding, SessionSummary, SessionVariableValue,
    ShellStateKnowledge, ShellStateSnapshot, ShellValueSnapshot,
};

use crate::{
    ImplicitInputSource, ProjectedArg, ProjectedArgKind, ProjectedInvocation,
    RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
    RecursivePayloadFragmentMaterialization, RecursivePayloadInput,
};

pub type SessionValue = SessionVariableValue;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellArrayKind {
    Indexed,
    Associative,
}

/// Static frame facts, separate from observed or materialized variable bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShellVariableFacts {
    /// Nonempty signed decimal scalar, without claiming its current value.
    pub integer_scalar: bool,
    /// Scalar produced by removing the longest prefix ending in '/'.
    /// The remaining component may be empty, "." or "..".
    pub basename_text: bool,
    pub scalar_shape: Option<crate::StdoutScalarShape>,
    pub array_kind: Option<ShellArrayKind>,
    pub element_shape: Option<crate::StdoutScalarShape>,
}

#[derive(Debug, Clone, Default)]
pub struct SessionBindings {
    native_variants: BTreeMap<String, String>,
    pathname_options: Option<caushell_types::ShellPathnameSnapshot>,
    pathname_fields: Vec<caushell_types::PathnameFieldsEvidence>,
    entry_variables: Option<SessionSummary>,
    entry_environment: Option<SessionSummary>,
    shell_kind: Option<caushell_types::ShellKind>,
    command_lookup_domain: crate::CommandLookupDomain,
    shell_state_uncertainty: Option<String>,
    shell_state_join_only: bool,
    variable_facts: BTreeMap<String, ShellVariableFacts>,
    // Account-home fact supplied by the request, not a shell variable or an
    // exported environment entry. Explicit HOME facts override this default.
    default_tilde_home: Option<String>,
    // Static shell frame kind; no process/runtime observation is involved.
    in_function_scope: bool,
    functions: BTreeMap<String, SessionFunctionBinding>,
    // Variable existence is not child-environment presence: an unexported
    // variable still prevents plain unset from falling back to a function.
    variable_presence: BindingMap<VariablePresence>,
    variables_complete: bool,
    /// Statically encountered indirect/array destinations are outside the
    /// scalar assignment contract. This is analysis metadata, not runtime data.
    unresolved_runtime_variable_targets: std::collections::BTreeSet<String>,
    session_variables: BindingMap<SessionValue>,
    profile_shadowing_aliases: std::collections::BTreeSet<String>,
    aliases: BTreeMap<String, SessionAliasBinding>,
    // Local abstract values, not observed bytes and never persisted as a
    // concrete session variable. Scalar writes invalidate this metadata.
    argument_domains: BTreeMap<String, caushell_types::RuntimeArgumentDomain>,
    positional_argument_domains: BTreeMap<usize, caushell_types::RuntimeArgumentDomain>,
    inherited_environment: BindingMap<SessionValue>,
    // $0 belongs to the shell frame, not to the list changed by set/shift.
    shell_program_name: Option<SessionValue>,
    positional_parameters: Vec<SessionValue>,
    // No snapshot is not an empty argv. Exact $@/$* bytes require a complete
    // list; a typed final tail can retain only per-field abstract facts.
    positional_parameters_complete: bool,
    // A final native argv segment has unknown length, but each field retains
    // its own source and domain. This is not a concrete/complete $@ snapshot.
    positional_runtime_tail: Option<(caushell_types::ImplicitInputSource, caushell_types::RuntimeArgumentDomain)>,
    // Separate child-environment view: unexported shell locals are not defaults
    // for an external program. None records a proven absence (e.g. unset).
    child_environment: BindingMap<Option<SessionValue>>,
    child_environment_complete: bool,
}

impl PartialEq for SessionBindings {
    fn eq(&self, other: &Self) -> bool {
        macro_rules! same {
            ($($field:ident),* $(,)?) => { true $(&& self.$field == other.$field)* };
        }
        same!(
            native_variants,
            pathname_options,
            pathname_fields,
            shell_kind,
            command_lookup_domain,
            shell_state_uncertainty,
            shell_state_join_only,
            variable_facts,
            default_tilde_home,
            in_function_scope,
            functions,
            variable_presence,
            variables_complete,
            unresolved_runtime_variable_targets,
            profile_shadowing_aliases,
            aliases,
            argument_domains,
            positional_argument_domains,
            inherited_environment,
            shell_program_name,
            positional_parameters,
            positional_parameters_complete,
            positional_runtime_tail,
            child_environment_complete
        ) && self
            .session_variable_names()
            .filter_map(|name| self.session_value(name).map(|value| (name, value)))
            .collect::<BTreeMap<_, _>>()
            == other
                .session_variable_names()
                .filter_map(|name| other.session_value(name).map(|value| (name, value)))
                .collect::<BTreeMap<_, _>>()
            && self.environment_entries().collect::<BTreeMap<_, _>>()
                == other.environment_entries().collect::<BTreeMap<_, _>>()
    }
}

impl Eq for SessionBindings {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariablePresence {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentValueRef<'a> {
    Present(&'a SessionValue),
    Absent,
    Unknown,
}

impl SessionBindings {
    pub fn command_lookup_domain(&self) -> &crate::CommandLookupDomain {
        &self.command_lookup_domain
    }
    pub fn set_command_lookup_domain(&mut self, domain: crate::CommandLookupDomain) {
        self.command_lookup_domain = domain;
    }
    pub fn pathname_options(&self) -> Option<&caushell_types::ShellPathnameSnapshot> {
        self.pathname_options.as_ref()
    }

    pub fn set_pathname_fields(&mut self, fields: Vec<caushell_types::PathnameFieldsEvidence>) {
        self.pathname_fields = fields;
    }
    pub fn shell_kind(&self) -> caushell_types::ShellKind {
        self.shell_kind.unwrap_or(caushell_types::ShellKind::Bash)
    }
    pub fn set_shell_kind(&mut self, kind: caushell_types::ShellKind) {
        self.shell_kind = (kind != caushell_types::ShellKind::Bash).then_some(kind);
    }
    pub fn shell_state_uncertainty(&self) -> Option<&str> {
        self.shell_state_uncertainty.as_deref()
    }

    pub fn mark_shell_state_uncertain(&mut self, reason: &str) {
        self.shell_state_join_only = false;
        self.shell_state_uncertainty = Some(reason.to_owned());
        let names: Vec<_> = self.variable_names().map(str::to_owned).collect();
        for name in names {
            self.insert_opaque_dynamic(&name, reason);
        }
        self.forget_variable_presence();
        self.forget_environment();
        self.forget_positional_parameters();
    }

    pub fn shell_state_join_only(&self) -> bool {
        self.shell_state_uncertainty.is_some() && self.shell_state_join_only
    }

    pub fn mark_shell_state_join(&mut self, reason: &str) {
        let join_only = self.shell_state_uncertainty.is_none() || self.shell_state_join_only;
        let reason = self
            .shell_state_uncertainty
            .clone()
            .unwrap_or_else(|| reason.into());
        self.mark_shell_state_uncertain(&reason);
        self.shell_state_join_only = join_only;
    }

    /// Join possible continuations in the same shell frame. Common facts survive
    /// unless export membership requires the existing frame-uncertainty boundary;
    /// neither path's last assignment may overwrite the other path's state.
    pub fn join_control_path(&mut self, other: &Self, observed_at: CommandSequenceNo) {
        if self.command_lookup_domain != other.command_lookup_domain {
            self.command_lookup_domain = crate::CommandLookupDomain::Unknown;
        }
        let reason = "shell scope has multiple possible return paths";
        let mut uncertain_environment_values = Vec::new();
        let mut unobserved_environment_entries = Vec::new();
        let partial_function_environments =
            !self.child_environment_complete && self.in_function_scope && other.in_function_scope;
        let environment_differs = self.child_environment_complete
            != other.child_environment_complete
            || {
                let left: BTreeMap<_, _> = self.environment_entries().collect();
                let right: BTreeMap<_, _> = other.environment_entries().collect();
                let names = left.keys().chain(right.keys()).copied().collect::<std::collections::BTreeSet<_>>();
                names.into_iter().any(|name| match (left.get(name), right.get(name)) {
                    (left, right) if left == right => false,
                    (Some(Some(SessionValue::OpaqueDynamic { .. })), Some(Some(_)))
                    | (Some(Some(_)), Some(Some(SessionValue::OpaqueDynamic { .. }))) => {
                        uncertain_environment_values.push(name.to_owned());
                        false
                    }
                    (Some(Some(SessionValue::OpaqueDynamic { .. })), None)
                    | (None, Some(Some(SessionValue::OpaqueDynamic { .. })))
                        if partial_function_environments
                            && [&self.entry_environment, &other.entry_environment]
                                .into_iter()
                                .all(|entry| entry.as_ref().and_then(|s| s.variable_binding(name)).is_none()) =>
                    {
                        unobserved_environment_entries.push(name.to_owned());
                        false
                    }
                    _ => true,
                })
            };
        let names = self
            .variable_names()
            .chain(other.variable_names())
            .chain(self.variable_presence.keys().map(String::as_str))
            .chain(other.variable_presence.keys().map(String::as_str))
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>();
        for name in names {
            let same_value = self.get(&name).map(|v| v.value) == other.get(&name).map(|v| v.value);
            let same_presence = self.variable_presence(&name) == other.variable_presence(&name);
            if !same_value || !same_presence {
                self.insert_opaque_dynamic(&name, reason);
                self.mark_variable_presence_unknown(&name);
            } else if self.variable_facts(&name) != other.variable_facts(&name) {
                self.forget_variable_facts(&name);
            }
        }
        self.variables_complete &= other.variables_complete;
        self.unresolved_runtime_variable_targets
            .extend(other.unresolved_runtime_variable_targets.iter().cloned());
        self.argument_domains
            .retain(|name, domain| other.argument_domains.get(name) == Some(domain));
        self.native_variants
            .retain(|name, value| other.native_variants.get(name) == Some(value));
        if environment_differs {
            // A missing export is not a proved absence. Do not let a safe
            // environment on one path hide configuration on the other.
            self.mark_shell_state_uncertain("return paths have unresolved export membership");
        } else {
            // Keep these entries opaque across the join. A different opaque
            // value does not establish a change in the set of exported names.
            // Forget matching shell values too, so a caller cannot re-export
            // an exact scalar in place of the uncertain child environment.
            for name in uncertain_environment_values {
                self.insert_opaque_dynamic(&name, reason);
                self.child_environment
                    .insert(name, Some(SessionValue::opaque_dynamic(reason)));
            }
            // A missing entry in a partial environment has unknown
            // membership. Joining it with an opaque value cannot establish
            // either presence or absence for the caller or a child process.
            for name in unobserved_environment_entries {
                self.insert_opaque_dynamic(&name, reason);
                self.child_environment.remove(&name);
                self.native_variants.clear();
            }
        }
        if self.positional_parameters_complete != other.positional_parameters_complete
            || self.positional_parameters != other.positional_parameters
            || self.positional_runtime_tail != other.positional_runtime_tail
            || self.shell_program_name != other.shell_program_name
        {
            self.forget_positional_parameters();
            if self.shell_program_name != other.shell_program_name {
                self.shell_program_name = None;
            }
        }
        self.positional_argument_domains.retain(|position, domain| {
            other.positional_argument_domains.get(position) == Some(domain)
        });
        if self.pathname_options != other.pathname_options {
            self.pathname_options = None;
        }
        if self.pathname_fields != other.pathname_fields {
            self.pathname_fields.clear();
        }
        if self.default_tilde_home != other.default_tilde_home {
            self.default_tilde_home = None;
        }
        if self.functions != other.functions || self.aliases != other.aliases {
            let names = self
                .functions
                .keys()
                .chain(other.functions.keys())
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            for name in names {
                if self.functions.get(&name) != other.functions.get(&name) {
                    self.upsert_function_binding(SessionFunctionBinding::uncertain(
                        name,
                        reason,
                        observed_at,
                    ));
                }
            }
            self.mark_shell_state_uncertain(reason);
        }
        self.profile_shadowing_aliases
            .extend(other.profile_shadowing_aliases.iter().cloned());
        if let Some(reason) = self
            .shell_state_uncertainty
            .clone()
            .or_else(|| other.shell_state_uncertainty.clone())
        {
            self.mark_shell_state_uncertain(&reason);
        }
    }
    pub fn variable_facts(&self, name: &str) -> ShellVariableFacts {
        self.variable_facts.get(name).copied().unwrap_or_default()
    }

    pub fn set_variable_facts(&mut self, name: &str, facts: ShellVariableFacts) {
        if facts == ShellVariableFacts::default() {
            self.variable_facts.remove(name);
        } else {
            self.variable_facts.insert(name.into(), facts);
        }
    }

    pub fn forget_variable_facts(&mut self, name: &str) {
        self.variable_facts.remove(name);
    }

    pub fn forget_all_variable_facts(&mut self) {
        self.variable_facts.clear();
        self.native_variants.clear();
    }

    pub fn has_native_variants(&self) -> bool {
        !self.native_variants.is_empty()
    }
    pub fn native_variant(&self, command: &str) -> Option<&str> {
        self.native_variants.get(command).map(String::as_str)
    }
    pub fn forget_native_variants(&mut self) {
        self.native_variants.clear();
    }

    pub fn has_variable_facts(&self) -> bool {
        !self.variable_facts.is_empty()
    }

    pub fn variable_fact_entries(&self) -> impl Iterator<Item = (&str, ShellVariableFacts)> {
        self.variable_facts
            .iter()
            .map(|(name, facts)| (name.as_str(), *facts))
    }

    pub fn set_default_tilde_home(&mut self, home: Option<&str>) {
        self.default_tilde_home = home.map(str::to_owned);
    }

    /// Preserve the request's initial-home default only when the shell and
    /// environment have supplied no HOME fact. Never overwrite a snapshot,
    /// a complete environment, an explicit unknown, or an unset binding.
    pub fn set_request_home_facts(&mut self, home: Option<&str>) {
        self.set_default_tilde_home(home);
        if let Some(home) = home
            && !self.variables_complete
            && !self.child_environment_complete
            && !self.variable_presence.contains_key("HOME")
            && !self.child_environment.contains_key("HOME")
            && self.get("HOME").is_none()
        {
            self.insert_inherited_exact_scalar("HOME", home);
        }
    }

    pub fn tilde_home(&self) -> Option<&str> {
        self.tilde_home_with_default(None)
    }

    pub fn tilde_home_with_default<'a>(&'a self, account_home: Option<&'a str>) -> Option<&'a str> {
        if self.variable_presence.get("HOME") == Some(&VariablePresence::Unknown) {
            return None;
        }
        if let Some(binding) = self.get("HOME") {
            return match binding.value {
                SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. }
                    if !value.contains('\0') =>
                {
                    Some(value)
                }
                _ => None,
            };
        }
        if self.variable_presence("HOME") == VariablePresence::Present {
            return None;
        }
        self.default_tilde_home
            .as_deref()
            .or(account_home)
            .filter(|home| !home.contains('\0'))
    }

    pub fn enter_function_scope(&mut self) {
        self.in_function_scope = true;
    }

    pub fn in_function_scope(&self) -> bool {
        self.in_function_scope
    }
    pub fn variable_presence(&self, name: &str) -> VariablePresence {
        if let Some(presence) = self.variable_presence.get(name) {
            return *presence;
        }
        match self.get(name) {
            Some(binding)
                if matches!(
                    binding.value,
                    SessionValue::ExactScalar(_) | SessionValue::RuntimeProduced { .. }
                ) =>
            {
                VariablePresence::Present
            }
            Some(_) => VariablePresence::Unknown,
            None if self.variables_complete => VariablePresence::Absent,
            None => VariablePresence::Unknown,
        }
    }

    pub fn mark_variable_presence_unknown(&mut self, name: &str) {
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Unknown);
    }

    pub fn mark_variable_present(&mut self, name: &str) {
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
    }

    pub fn forget_variable_presence(&mut self) {
        self.native_variants.clear();
        self.variables_complete = false;
        let names = self
            .variable_presence
            .keys()
            .cloned()
            .chain(self.variable_names().map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>();
        for name in names {
            self.mark_variable_presence_unknown(&name);
        }
    }

    pub fn function_binding(&self, name: &str) -> Option<&SessionFunctionBinding> {
        self.shell_state_uncertainty
            .is_none()
            .then(|| self.functions.get(name))
            .flatten()
    }

    pub fn retained_function_binding(&self, name: &str) -> Option<&SessionFunctionBinding> {
        self.functions.get(name)
    }

    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.functions.keys().map(String::as_str)
    }

    pub fn upsert_function_binding(&mut self, binding: SessionFunctionBinding) {
        self.functions.insert(binding.name.clone(), binding);
    }

    pub fn unset_function(&mut self, name: &str) {
        self.functions.remove(name);
    }

    pub fn replace_function_bindings(
        &mut self,
        bindings: impl IntoIterator<Item = SessionFunctionBinding>,
    ) {
        self.functions = bindings.into_iter().map(|b| (b.name.clone(), b)).collect();
    }
    pub fn mark_unresolved_runtime_variable_target(&mut self, name: &str) {
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.unresolved_runtime_variable_targets.insert(name.into());
    }
    pub fn runtime_variable_target_is_unresolved(&self, name: &str) -> bool {
        self.unresolved_runtime_variable_targets.contains(name)
    }
    pub fn variable_names(&self) -> impl Iterator<Item = &str> {
        self.session_variable_names()
            .chain(self.inherited_environment.keys().map(String::as_str))
            .chain(self.variable_facts.keys().map(String::as_str))
    }

    fn session_variable_names(&self) -> impl Iterator<Item = &str> {
        self.session_variables.keys().map(String::as_str).chain(
            self.entry_variables
                .iter()
                .flat_map(|entry| entry.variable_bindings())
                .filter(|binding| !self.session_variables.overrides(&binding.name))
                .map(|binding| binding.name.as_str()),
        )
    }

    fn session_value(&self, name: &str) -> Option<&SessionValue> {
        if self.session_variables.overrides(name) {
            self.session_variables.get(name)
        } else {
            self.entry_variables
                .as_ref()?
                .variable_binding(name)
                .map(|binding| &binding.value)
        }
    }

    fn environment_entries(&self) -> impl Iterator<Item = (&str, Option<&SessionValue>)> {
        self.child_environment
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_ref()))
            .chain(
                self.entry_environment
                    .iter()
                    .flat_map(|entry| entry.variable_bindings())
                    .filter(|binding| !self.child_environment.overrides(&binding.name))
                    .map(|binding| {
                        (
                            binding.name.as_str(),
                            binding.exported.then_some(&binding.value),
                        )
                    }),
            )
    }
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_profile_shadowing_alias(&mut self, name: &str) {
        self.profile_shadowing_aliases.insert(name.into());
    }

    pub fn profile_has_alias_shadow(&self, name: &str) -> bool {
        self.profile_shadowing_aliases.contains(name)
    }

    pub fn alias_bindings(&self) -> impl Iterator<Item = &SessionAliasBinding> {
        self.aliases
            .values()
            .filter(|_| self.shell_state_uncertainty.is_none())
    }

    pub fn retained_alias_bindings(&self) -> impl Iterator<Item = &SessionAliasBinding> {
        self.aliases.values()
    }

    pub fn upsert_alias_binding(&mut self, binding: SessionAliasBinding) {
        self.mark_profile_shadowing_alias(&binding.name);
        self.aliases.insert(binding.name.clone(), binding);
    }

    pub fn unset_alias(&mut self, name: &str) {
        self.aliases.remove(name);
        self.profile_shadowing_aliases.remove(name);
    }

    pub fn from_session_summary(summary: &SessionSummary) -> Self {
        let mut bindings = Self {
            entry_variables: Some(summary.clone()),
            entry_environment: Some(summary.clone()),
            ..Self::default()
        };
        bindings.replace_function_bindings(summary.function_bindings().cloned());
        for alias in summary.alias_bindings() {
            bindings.upsert_alias_binding(alias.clone());
        }

        if let Some(positional_parameters) = summary.positional_parameters() {
            bindings.replace_positional_parameters(
                positional_parameters
                    .values
                    .iter()
                    .map(SessionValue::from_session_variable_value),
            );
        }

        if let Some(reason) = summary.shell_state_uncertainty() {
            bindings.mark_shell_state_uncertain(reason);
        }
        bindings.freeze_entry_frame();
        bindings
    }

    fn freeze_entry_frame(&mut self) {
        self.variable_presence.freeze();
        self.session_variables.freeze();
        self.inherited_environment.freeze();
        self.child_environment.freeze();
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
        if let Some(reason) = summary.shell_state_uncertainty() {
            bindings.mark_shell_state_uncertain(reason);
        }

        bindings.variables_complete =
            shell_state.observability.variables == ShellStateKnowledge::Complete;
        if shell_state.observability.aliases == ShellStateKnowledge::Complete {
            bindings.aliases.clear();
            bindings.profile_shadowing_aliases.clear();
        } else {
            for alias in summary.alias_bindings() {
                bindings.upsert_alias_binding(alias.clone());
            }
        }
        for alias in &shell_state.aliases {
            bindings.upsert_alias_binding(SessionAliasBinding::new(
                &alias.name,
                &alias.body,
                caushell_types::CommandSequenceNo::new(0),
            ));
        }
        if shell_state.observability.functions != ShellStateKnowledge::Complete {
            bindings.replace_function_bindings(summary.function_bindings().cloned());
        } else {
            bindings.functions.clear();
        }
        if shell_state.observability.functions == ShellStateKnowledge::Complete
            && shell_state.observability.aliases == ShellStateKnowledge::Complete
            && shell_state.observability.variables == ShellStateKnowledge::Complete
            && shell_state.observability.positional_parameters == ShellStateKnowledge::Complete
        {
            bindings.shell_state_uncertainty = None;
        }
        for function in &shell_state.functions {
            bindings.upsert_function_binding(SessionFunctionBinding::new(
                &function.name,
                &function.body,
                caushell_types::CommandSequenceNo::new(0),
            ));
        }

        if shell_state.observability.variables != ShellStateKnowledge::Unknown {
            bindings.child_environment.clear();
            bindings.entry_environment = None;
            bindings.child_environment_complete = true;
        }

        for variable in &shell_state.variables {
            bindings
                .variable_presence
                .insert(variable.name.clone(), VariablePresence::Present);
            if let Some(value) = shell_value_to_session_value(&variable.value) {
                bindings.child_environment.insert(
                    variable.name.clone(),
                    variable.exported.then(|| value.clone()),
                );
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

        for (name, value) in crate::environment_observations(shell_state) {
            bindings.child_environment.insert(name, value);
        }
        // These are partial scalar facts from the owning execution frame.
        // Never infer export status or a child-program default from this view.
        if let Some(frame) = &shell_state.execution_frame {
            for variable in &frame.variables {
                let name = &variable.name;
                bindings.forget_variable_facts(name);
                bindings.argument_domains.remove(name);
                bindings.session_variables.remove(name);
                bindings.inherited_environment.remove(name);
                let (presence, value) = match &variable.value {
                    caushell_types::ShellEnvironmentValue::Present { value } => (
                        VariablePresence::Present,
                        Some(SessionValue::exact_scalar(value)),
                    ),
                    caushell_types::ShellEnvironmentValue::Absent => {
                        (VariablePresence::Absent, None)
                    }
                    caushell_types::ShellEnvironmentValue::Unknown => (
                        VariablePresence::Unknown,
                        Some(if frame.integer_variables.contains(name) {
                            SessionValue::opaque_dynamic("integer scalar value is unobserved")
                        } else {
                            SessionValue::structured(
                                caushell_types::StructuredShellValue::Unknown {
                                    reason: "shell variable attributes are unobserved".into(),
                                },
                            )
                        }),
                    ),
                };
                bindings.variable_presence.insert(name.clone(), presence);
                if let Some(value) = value {
                    bindings.session_variables.insert(name.clone(), value);
                }
                if frame.integer_variables.contains(name) {
                    bindings.set_variable_facts(
                        name,
                        ShellVariableFacts {
                            integer_scalar: true,
                            scalar_shape: Some(crate::StdoutScalarShape::ArithmeticText),
                            ..Default::default()
                        },
                    );
                }
            }
            // Current typed facts replace only their own names. Unknown is an
            // explicit invalidation, never a fallback to a historical value.
            // Do not update child_environment or infer resource permissions.
            for variable in &frame.variable_values {
                use caushell_types::ExecutionFrameVariableValue as V;
                let name = &variable.name;
                bindings.forget_variable_facts(name);
                bindings.argument_domains.remove(name);
                bindings.session_variables.remove(name);
                bindings.inherited_environment.remove(name);
                let presence = match variable.value {
                    V::Absent => VariablePresence::Absent,
                    V::Unknown | V::Unsupported => VariablePresence::Unknown,
                    _ => VariablePresence::Present,
                };
                bindings.variable_presence.insert(name.clone(), presence);
                let value = if matches!(variable.value, V::Unknown)
                    && frame.integer_variables.contains(name)
                {
                    Some(SessionValue::opaque_dynamic(
                        "integer scalar value is unobserved",
                    ))
                } else {
                    variable.value.session_value()
                };
                if let Some(value) = value {
                    bindings.session_variables.insert(name.clone(), value);
                }
                let array_kind = match &variable.value {
                    V::IndexedArray { .. } => Some(ShellArrayKind::Indexed),
                    V::AssociativeArray { .. } => Some(ShellArrayKind::Associative),
                    _ => None,
                };
                if let Some(array_kind) = array_kind {
                    bindings.set_variable_facts(
                        name,
                        ShellVariableFacts {
                            array_kind: Some(array_kind),
                            ..Default::default()
                        },
                    );
                }
                if matches!(variable.value, V::Scalar { integer: true, .. })
                    || matches!(variable.value, V::Unknown)
                        && frame.integer_variables.contains(name)
                {
                    bindings.set_variable_facts(
                        name,
                        ShellVariableFacts {
                            integer_scalar: true,
                            scalar_shape: Some(crate::StdoutScalarShape::ArithmeticText),
                            ..Default::default()
                        },
                    );
                }
            }
            bindings.native_variants = frame.native_variants.clone();
        }
        bindings.pathname_options = crate::pathname::snapshot(shell_state);

        if shell_state.observability.positional_parameters == ShellStateKnowledge::Complete {
            let values = shell_state
                .positional_parameters
                .iter()
                .map(shell_value_to_session_value)
                .collect::<Option<Vec<_>>>();
            if let Some(values) = values {
                bindings.replace_positional_parameters(values);
            } else {
                bindings.forget_positional_parameters();
            }
        }

        bindings.freeze_entry_frame();
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
        if name == "PATH" {
            self.native_variants.clear();
        }
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
        let value = value.into();
        self.update_exported_value(name, SessionValue::exact_scalar(value.clone()));
        self.session_variables
            .insert(name.to_string(), SessionValue::exact_scalar(value));
    }

    pub fn insert_runtime_produced(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: RuntimeProducedValueKind,
    ) {
        if name == "PATH" {
            self.native_variants.clear();
        }
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
        let value = value.into();
        self.update_exported_value(name, SessionValue::runtime_produced(value.clone(), kind));
        self.session_variables.insert(
            name.to_string(),
            SessionValue::runtime_produced(value, kind),
        );
    }

    pub fn insert_opaque_dynamic(&mut self, name: &str, repr: impl Into<String>) {
        if name == "PATH" {
            self.native_variants.clear();
        }
        self.mark_variable_presence_unknown(name);
        let repr = repr.into();
        self.update_exported_value(name, SessionValue::opaque_dynamic(repr.clone()));
        self.session_variables
            .insert(name.to_string(), SessionValue::opaque_dynamic(repr));
    }

    pub fn insert_structured(&mut self, name: &str, value: caushell_types::StructuredShellValue) {
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
        let value = SessionValue::structured(value);
        self.update_exported_value(name, value.clone());
        self.session_variables.insert(name.into(), value);
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
        self.mark_variable_presence_unknown(name);
        self.update_exported_value(name, SessionValue::runtime_input(source, capture.clone()));
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
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
        let value = value.into();
        self.child_environment
            .insert(name.into(), Some(SessionValue::exact_scalar(value.clone())));
        self.inherited_environment
            .insert(name.to_string(), SessionValue::exact_scalar(value));
    }

    pub fn replace_positional_parameters<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = SessionValue>,
    {
        self.positional_parameters = values.into_iter().collect();
        self.positional_parameters_complete = true;
        self.positional_runtime_tail = None;
        self.positional_argument_domains
            .retain(|position, _| *position == 0);
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
            return self.shell_program_name.as_ref();
        }

        self.positional_parameters.get(position - 1)
    }

    pub fn set_shell_program_name(&mut self, value: Option<SessionValue>) {
        self.shell_program_name = value;
        self.positional_argument_domains.remove(&0);
    }

    pub fn set_positional_argument_domain(
        &mut self,
        position: usize,
        domain: caushell_types::RuntimeArgumentDomain,
    ) {
        if self.positional_parameter(position).is_some() {
            self.positional_argument_domains.insert(position, domain);
        }
    }

    pub fn positional_argument_domain(
        &self,
        position: usize,
    ) -> Option<&caushell_types::RuntimeArgumentDomain> {
        self.positional_argument_domains.get(&position)
    }

    pub fn positional_parameters(&self) -> &[SessionValue] {
        &self.positional_parameters
    }

    pub fn positional_parameters_are_complete(&self) -> bool {
        self.positional_parameters_complete
    }

    /// Shared function/interpreter argv frame admission. Preserve a fixed
    /// prefix plus one final typed native tail; other uncertain layouts keep
    /// the unknown-frame fallback. Never guess bytes or an exact field count.
    pub fn bind_positional_arguments(
        &mut self,
        args: &[ProjectedArg],
        resolutions: &[ValueMaterialization],
    ) {
        let prefix_len = args
            .iter()
            .position(|arg| {
                crate::argument_structure(arg).fields != crate::ArgumentFieldCount::ExactlyOne
            })
            .unwrap_or(args.len());
        let tail = if prefix_len < args.len() {
            let arg = &args[prefix_len];
            match (arg.implicit_input_source, &arg.runtime_argument_domain) {
                (Some(source), Some(domain))
                    if prefix_len + 1 == args.len() && arg.node_kind == "runtime_argument_list" =>
                {
                    Some((source, domain.clone()))
                }
                _ => {
                    self.forget_positional_parameters();
                    return;
                }
            }
        } else {
            None
        };
        let values = args[..prefix_len]
            .iter()
            .enumerate()
            .map(|(index, arg)| {
                if arg.implicit_input_source.is_some() {
                    return SessionValue::opaque_dynamic("native positional argument");
                }
                if let Some(ValueMaterialization::ResolvedRuntimeProduced { kind, .. }) =
                    resolutions.get(index)
                {
                    return SessionValue::runtime_produced(arg.text.clone(), *kind);
                }
                if arg.runtime_data {
                    return SessionValue::exact_scalar(arg.text.clone());
                }
                caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
                    .map(SessionValue::exact_scalar)
                    .unwrap_or_else(|| SessionValue::opaque_dynamic("dynamic positional argument"))
            })
            .collect::<Vec<_>>();
        self.replace_positional_parameters(values);
        for (index, arg) in args[..prefix_len].iter().enumerate() {
            if let Some(domain) = &arg.runtime_argument_domain {
                self.set_positional_argument_domain(index + 1, domain.clone());
            }
        }
        self.positional_parameters_complete = tail.is_none();
        self.positional_runtime_tail = tail;
    }

    pub fn has_positional_runtime_tail(&self) -> bool {
        self.positional_runtime_tail.is_some()
    }

    /// Only a proven prefix can be removed with certainty. A larger shift
    /// may fail and leave the old argv, so do not discard that alternative.
    pub fn shift_positional_frame(&mut self, count: usize) {
        if count > self.positional_parameters.len()
            || !self.positional_parameters_complete && self.positional_runtime_tail.is_none()
        {
            self.forget_positional_parameters();
            return;
        }
        let tail = self.positional_runtime_tail.clone();
        let domains = self
            .positional_argument_domains
            .iter()
            .filter(|(position, _)| **position > count)
            .map(|(position, domain)| (position - count, domain.clone()))
            .collect::<Vec<_>>();
        let values = self
            .positional_parameters
            .iter()
            .skip(count)
            .cloned()
            .collect::<Vec<_>>();
        self.replace_positional_parameters(values);
        for (position, domain) in domains {
            self.set_positional_argument_domain(position, domain);
        }
        self.positional_parameters_complete = tail.is_none();
        self.positional_runtime_tail = tail;
    }

    pub fn forget_positional_parameters(&mut self) {
        self.positional_parameters.clear();
        self.positional_parameters_complete = false;
        self.positional_runtime_tail = None;
        self.positional_argument_domains
            .retain(|position, _| *position == 0);
    }

    pub fn remove(&mut self, name: &str) {
        self.native_variants.clear();
        self.forget_variable_facts(name);
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Absent);
        self.session_variables.remove(name);
        self.inherited_environment.remove(name);
        self.child_environment.insert(name.into(), None);
    }

    pub fn insert_argument_domain(
        &mut self,
        name: &str,
        domain: caushell_types::RuntimeArgumentDomain,
    ) {
        self.insert_opaque_dynamic(name, "bounded shell iteration value");
        self.set_argument_domain(name, domain);
    }

    pub fn set_argument_domain(
        &mut self,
        name: &str,
        domain: caushell_types::RuntimeArgumentDomain,
    ) {
        self.argument_domains.insert(name.into(), domain);
    }

    pub fn argument_domain(&self, name: &str) -> Option<&caushell_types::RuntimeArgumentDomain> {
        self.argument_domains.get(name)
    }

    pub fn environment_value(&self, name: &str) -> EnvironmentValueRef<'_> {
        if let Some(value) = self.child_environment.get(name) {
            return value
                .as_ref()
                .map_or(EnvironmentValueRef::Absent, EnvironmentValueRef::Present);
        }
        if let Some(binding) = self
            .entry_environment
            .as_ref()
            .and_then(|entry| entry.variable_binding(name))
        {
            return if binding.exported {
                EnvironmentValueRef::Present(&binding.value)
            } else {
                EnvironmentValueRef::Absent
            };
        }
        if self.child_environment_complete {
            EnvironmentValueRef::Absent
        } else {
            EnvironmentValueRef::Unknown
        }
    }

    pub fn environment_is_complete(&self) -> bool {
        self.child_environment_complete
    }

    pub fn environment_names(&self) -> std::collections::BTreeSet<String> {
        self.child_environment
            .keys()
            .cloned()
            .chain(
                self.entry_environment
                    .iter()
                    .flat_map(|s| s.variable_bindings().map(|v| v.name.clone())),
            )
            .collect()
    }

    pub fn export(&mut self, name: &str) {
        let value = self
            .get(name)
            .map(|binding| binding.value.clone())
            .unwrap_or_else(|| SessionValue::opaque_dynamic("exported value unavailable"));
        self.child_environment.insert(name.into(), Some(value));
    }

    pub fn unexport(&mut self, name: &str) {
        self.child_environment.insert(name.into(), None);
    }

    pub fn forget_environment(&mut self) {
        self.native_variants.clear();
        self.child_environment.clear();
        self.entry_environment = None;
        self.child_environment_complete = false;
    }

    /// Enter a child process after a wrapper resets (or obscures) its env.
    /// Its old shell locals must not survive as facts for a nested shell.
    pub fn reset_child_environment(&mut self, complete: bool) {
        self.native_variants.clear();
        self.argument_domains.clear();
        self.functions.clear();
        self.variable_presence.clear();
        self.variables_complete = complete;
        self.session_variables.clear();
        self.entry_variables = None;
        self.inherited_environment.clear();
        self.child_environment.clear();
        self.entry_environment = None;
        self.child_environment_complete = complete;
    }

    pub fn set_environment_value(&mut self, name: &str, value: SessionValue) {
        self.native_variants.clear();
        self.child_environment.insert(name.into(), Some(value));
    }

    pub fn set_child_environment_value(&mut self, name: &str, value: SessionValue) {
        self.argument_domains.remove(name);
        self.variable_presence
            .insert(name.into(), VariablePresence::Present);
        self.session_variables.remove(name);
        self.inherited_environment
            .insert(name.into(), value.clone());
        self.set_environment_value(name, value);
    }

    pub fn set_child_environment_domain(
        &mut self,
        name: &str,
        domain: Option<caushell_types::RuntimeArgumentDomain>,
    ) {
        self.set_child_environment_value(
            name,
            SessionValue::opaque_dynamic("tool-generated environment value"),
        );
        if let Some(domain) = domain {
            self.argument_domains.insert(name.into(), domain);
        }
    }

    pub fn enter_child_shell_environment(&mut self) {
        self.command_lookup_domain = crate::CommandLookupDomain::Shell;
        // Only a proof about exported scalar bytes can cross this boundary.
        // Shell array attributes and unexported frame locals cannot.
        let exported_scalars: std::collections::BTreeSet<_> = self
            .variable_fact_entries()
            .filter(|(name, facts)| {
                facts.array_kind.is_none()
                    && self.get(name).is_some_and(|b| {
                        self.environment_value(name) == EnvironmentValueRef::Present(b.value)
                    })
            })
            .map(|(name, _)| name.to_owned())
            .collect();
        self.variable_facts
            .retain(|name, _| exported_scalars.contains(name));
        self.native_variants.clear();
        self.pathname_options = None;
        self.pathname_fields.clear();
        self.aliases.clear();
        self.profile_shadowing_aliases.clear();
        self.positional_argument_domains.clear();
        self.positional_runtime_tail = None;
        let exported: std::collections::BTreeSet<_> = self
            .argument_domains
            .keys()
            .filter(|name| {
                self.get(name).is_some_and(|binding| {
                    self.environment_value(name) == EnvironmentValueRef::Present(binding.value)
                })
            })
            .cloned()
            .collect();
        self.argument_domains
            .retain(|name, _| exported.contains(name));
        self.in_function_scope = false;
        // Function export is deliberately not modeled. Ordinary shell
        // functions must not leak into a new interpreter's namespace.
        self.functions.clear();
        self.variable_presence.clear();
        self.variables_complete = self.child_environment_complete;
        self.unresolved_runtime_variable_targets.clear();
        // Keep the origin of exported session values: converting all of them
        // into anonymous inherited values would sever their Graph provenance.
        self.session_variables = self
            .session_variable_names()
            .filter_map(|name| {
                let value = self.session_value(name)?;
                (self.environment_value(name) == EnvironmentValueRef::Present(value))
                    .then(|| (name.to_owned(), value.clone()))
            })
            .collect();
        self.entry_variables = None;
        self.inherited_environment = self
            .environment_entries()
            .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.clone())))
            .collect();
    }

    fn update_exported_value(&mut self, name: &str, value: SessionValue) {
        if matches!(
            self.environment_value(name),
            EnvironmentValueRef::Present(_)
        ) {
            self.native_variants.clear();
        }
        if matches!(
            self.environment_value(name),
            EnvironmentValueRef::Present(_)
        ) {
            self.child_environment.insert(name.into(), Some(value));
        }
    }

    pub fn get(&self, name: &str) -> Option<BindingValueRef<'_>> {
        if let Some(value) = self.session_value(name) {
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
    ArrayElement {
        name: String,
        index: String,
    },
    ArrayValues {
        name: String,
    },
    Indirect {
        name: String,
    },
    Positional(usize),
    AllPositionals(ShellAllPositionalsKind),
    Expansion {
        parameter: ShellParameterName,
        operator: ShellParameterExpansionOperator,
        word: String,
    },
    PatternSubstitution {
        parameter: ShellParameterName,
        replace_all: bool,
        pattern: String,
        replacement: String,
    },
    PatternRemoval {
        parameter: ShellParameterName,
        kind: ShellPatternRemovalKind,
        pattern: String,
    },
    Substring {
        name: String,
        offset: usize,
        length: Option<usize>,
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
        let body = braced_parameter_body(chars)?;
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
        if let Some(name) = body
            .strip_prefix('!')
            .filter(|name| is_valid_variable_name(name))
        {
            return Some(ShellParameterReference::Indirect { name: name.into() });
        }
        if let Some((name, index)) = body.split_once('[')
            && is_valid_variable_name(name)
            && let Some(index) = index.strip_suffix(']')
        {
            return Some(if index == "@" {
                ShellParameterReference::ArrayValues { name: name.into() }
            } else {
                ShellParameterReference::ArrayElement {
                    name: name.into(),
                    index: index.into(),
                }
            });
        }
        return parse_braced_shell_parameter_expansion(&body)
            .or_else(|| parse_braced_shell_parameter_substitution(&body))
            .or_else(|| parse_braced_shell_substring(&body));
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

fn braced_parameter_body<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
) -> Option<String> {
    let mut body = String::new();
    let mut quote = ShellWordQuote::None;
    let mut frames = Vec::new();
    while let Some(ch) = chars.next() {
        if body.len() > 4096 || frames.len() >= 16 {
            return None;
        }
        match ch {
            '\\' if quote != ShellWordQuote::Single => {
                body.push(ch);
                body.push(chars.next()?);
                continue;
            }
            '\'' if quote != ShellWordQuote::Double => {
                quote = if quote == ShellWordQuote::Single {
                    ShellWordQuote::None
                } else {
                    ShellWordQuote::Single
                };
            }
            '"' if quote != ShellWordQuote::Single => {
                quote = if quote == ShellWordQuote::Double {
                    ShellWordQuote::None
                } else {
                    ShellWordQuote::Double
                };
            }
            '$' if quote != ShellWordQuote::Single && chars.peek() == Some(&'{') => {
                frames.push(quote);
                quote = ShellWordQuote::None;
                body.push('$');
                body.push(chars.next()?);
                continue;
            }
            '}' if quote == ShellWordQuote::None => {
                if let Some(parent) = frames.pop() {
                    quote = parent;
                } else {
                    return Some(body);
                }
            }
            _ => (),
        }
        body.push(ch);
    }
    None
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
    exact_scalar_shell_parameter_value_at_depth(bindings, reference, 0)
}

fn resolved_parameter(
    bindings: &SessionBindings,
    reference: &ShellParameterReference,
) -> Option<crate::ResolvedShellValue> {
    use caushell_types::{ShellReferenceTarget as T, StructuredShellValue as V};
    match reference {
        ShellParameterReference::Variable(name) => {
            crate::resolve_shell_reference(bindings, T::Variable { name: name.clone() }).ok()
        }
        ShellParameterReference::Substring { name, offset, length } => {
            if bindings.shell_kind() != caushell_types::ShellKind::Bash {
                return None;
            }
            let binding = bindings.get(name)?;
            // Printable ASCII has stable byte and character boundaries. Keep
            // stateful encodings, controls and other source kinds out of this proof.
            let SessionValue::ExactScalar(value) = binding.value else {
                return None;
            };
            if !value.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' ') {
                return None;
            }
            let start = (*offset).min(value.len());
            let end = length.map_or(value.len(), |length| {
                start.saturating_add(length).min(value.len())
            });
            Some(crate::ResolvedShellValue {
                name: name.clone(),
                value: SessionValue::exact_scalar(&value[start..end]),
                origin: binding.origin,
                dependencies: vec![name.clone()],
            })
        }
        ShellParameterReference::ArrayElement { name, index } => {
            let target = crate::shell_reference_target(&format!("{name}[{index}]"), bindings)?;
            crate::resolve_shell_reference(bindings, target).ok()
        }
        ShellParameterReference::Indirect { name } => {
            let first = bindings.get(name)?;
            if let SessionValue::Structured(V::NameReference { target }) = first.value {
                let value = match target {
                    T::Variable { name } => name.clone(),
                    T::IndexedElement { name, index } => format!("{name}[{index}]"),
                    T::AssociativeElement { .. } | T::Unknown { .. } => return None,
                };
                return Some(crate::ResolvedShellValue {
                    name: name.clone(),
                    value: SessionValue::exact_scalar(value),
                    origin: first.origin,
                    dependencies: vec![name.clone()],
                });
            }
            let target = exact_scalar_session_value(first.value)?;
            let mut resolved = crate::resolve_shell_reference(
                bindings,
                crate::shell_reference_target(&target, bindings)?,
            )
            .ok()?;
            resolved.dependencies.insert(0, name.clone());
            Some(resolved)
        }
        _ => None,
    }
}

pub fn shell_parameter_dependencies(arg: &ProjectedArg, bindings: &SessionBindings) -> Vec<String> {
    if arg.runtime_data || matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string") {
        return Vec::new();
    }
    let references = exact_shell_parameter_reference(&arg.text)
        .map(|r| vec![r])
        .or_else(|| {
            // Dependency identity does not require an exact scalar value.
            // Reuse the quote/escape/reference grammar with inert placeholders;
            // this result is never a value, field-count or safety certificate.
            materialize_shell_word_with_resolver(
                &arg.text,
                bindings,
                ShellWordMode::Scalar,
                if arg.quoted && arg.node_kind == "string" {
                    ShellWordQuote::Double
                } else {
                    ShellWordQuote::None
                },
                false,
                |_| Some(String::new()),
            )
            .map(|(_, refs)| refs)
        })
        .unwrap_or_default();
    let mut names = Vec::new();
    for reference in references {
        let selection = match &reference {
            ShellParameterReference::ArrayElement { name, index } => {
                Some(format!("{name}[{index}]"))
            }
            ShellParameterReference::Indirect { name } => bindings
                .get(name)
                .and_then(|value| exact_scalar_session_value(value.value)),
            _ => None,
        };
        if let Some(selection) = selection {
            for name in crate::structured_parameters::subscript_dependencies(&selection, bindings) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        let resolved = if let ShellParameterReference::ArrayValues { name } = &reference {
            crate::resolve_shell_container(bindings, name).ok()
        } else {
            resolved_parameter(bindings, &reference)
        };
        for name in resolved
            .map(|v| v.dependencies)
            .unwrap_or_else(|| vec![shell_parameter_reference_name(&reference)])
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

fn exact_scalar_shell_parameter_value_at_depth(
    bindings: &SessionBindings,
    reference: &ShellParameterReference,
    depth: usize,
) -> Option<String> {
    if depth >= 16 {
        return None;
    }
    match reference {
        ShellParameterReference::Variable(name) => exact_scalar_session_value(
            &crate::resolve_shell_reference(
                bindings,
                caushell_types::ShellReferenceTarget::Variable { name: name.clone() },
            )
            .ok()?
            .value,
        ),
        ShellParameterReference::ArrayElement { .. }
        | ShellParameterReference::Indirect { .. }
        | ShellParameterReference::Substring { .. } => {
            exact_scalar_session_value(&resolved_parameter(bindings, reference)?.value)
        }
        ShellParameterReference::ArrayValues { .. } => None,
        ShellParameterReference::Positional(position) => {
            match bindings.positional_parameter(*position) {
                Some(value) => exact_scalar_session_value(value),
                None if *position > 0 && bindings.positional_parameters_are_complete() => {
                    Some(String::new())
                }
                None => None,
            }
        }
        ShellParameterReference::AllPositionals(kind) => {
            exact_scalar_all_positional_parameters(bindings, *kind)
        }
        ShellParameterReference::Expansion {
            parameter,
            operator,
            word,
        } => exact_scalar_shell_parameter_expansion_value(bindings, parameter, *operator, word),
        ShellParameterReference::PatternSubstitution {
            parameter,
            replace_all,
            pattern,
            replacement,
        } => exact_scalar_shell_parameter_substitution_value(
            bindings,
            parameter,
            *replace_all,
            pattern,
            replacement,
        ),
        ShellParameterReference::PatternRemoval {
            parameter,
            kind,
            pattern,
        } => {
            let value = known_parameter_scalar(bindings, parameter)?;
            removal_pattern(pattern, bindings, depth + 1)?.remove(&value, *kind)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellWordQuote {
    None,
    Single,
    Double,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellWordMode {
    CommandName,
    PositionalArgument,
    Assignment,
    Scalar,
}

/// Resolves a shell command word only when it is known to produce one exact field.
///
/// This intentionally excludes command substitution, globbing, and unquoted values that would
/// undergo field splitting. Those forms require runtime information and must remain unresolved.
pub fn materialize_command_name(text: &str, bindings: &SessionBindings) -> Option<String> {
    materialize_shell_word(
        text,
        bindings,
        ShellWordMode::CommandName,
        ShellWordQuote::None,
    )
}

pub fn materialize_shell_assignment_value(
    text: &str,
    quoted: bool,
    node_kind: &str,
    bindings: &SessionBindings,
) -> Option<String> {
    if matches!(node_kind, "raw_string" | "ansi_c_string" | "number") {
        return Some(text.to_string());
    }

    materialize_shell_word(
        text,
        bindings,
        ShellWordMode::Assignment,
        if quoted {
            ShellWordQuote::Double
        } else {
            ShellWordQuote::None
        },
    )
}

/// Join the supported entry-frame and sequential prefix-assignment semantics.
/// Bash dialects differ here; ShellKind alone is not a proof of one order.
/// Ordinary argv still uses the caller frame, and this never mutates it.
pub fn materialize_prefix_environment(
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
) -> Vec<(String, SessionValue)> {
    let sequential = materialize_prefix_in_order(command, bindings, true);
    let entry = materialize_prefix_in_order(command, bindings, false);
    sequential
        .into_iter()
        .zip(entry)
        .map(|((name, a), (_, b))| {
            (
                name,
                if a == b {
                    a
                } else {
                    SessionValue::opaque_dynamic(
                        "prefix assignment depends on unobserved shell evaluation order",
                    )
                },
            )
        })
        .collect()
}

fn materialize_prefix_in_order(
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
    sequential: bool,
) -> Vec<(String, SessionValue)> {
    if command.prefix_assignments.is_empty() {
        return Vec::new();
    }
    let mut rhs = bindings.clone();
    let mut values = Vec::with_capacity(command.prefix_assignments.len());
    for assignment in &command.prefix_assignments {
        let text = (assignment.operator == caushell_parse::AssignmentOperator::Assign)
            .then(|| {
                if assignment.value.node_kind == "empty" {
                    Some(String::new())
                } else {
                    materialize_shell_assignment_value(
                        &assignment.value.text,
                        assignment.value.quoted,
                        &assignment.value.node_kind,
                        if sequential { &rhs } else { bindings },
                    )
                }
            })
            .flatten();
        let value = if let Some(text) = text {
            rhs.insert_exact_scalar(&assignment.name, text.clone());
            SessionValue::exact_scalar(text)
        } else {
            rhs.insert_opaque_dynamic(&assignment.name, "unresolved prefix assignment");
            SessionValue::opaque_dynamic("unresolved prefix assignment")
        };
        values.push((assignment.name.clone(), value));
    }
    values
}

fn materialize_shell_word(
    text: &str,
    bindings: &SessionBindings,
    mode: ShellWordMode,
    initial_quote: ShellWordQuote,
) -> Option<String> {
    materialize_shell_word_with_references(text, bindings, mode, initial_quote, true)
        .map(|(value, _)| value)
}

fn materialize_shell_word_with_references(
    text: &str,
    bindings: &SessionBindings,
    mode: ShellWordMode,
    initial_quote: ShellWordQuote,
    allow_tilde_expansion: bool,
) -> Option<(String, Vec<ShellParameterReference>)> {
    materialize_shell_word_with_resolver(
        text,
        bindings,
        mode,
        initial_quote,
        allow_tilde_expansion,
        |reference| exact_scalar_shell_parameter_value(bindings, reference),
    )
}

fn materialize_shell_word_with_resolver(
    text: &str,
    bindings: &SessionBindings,
    mode: ShellWordMode,
    initial_quote: ShellWordQuote,
    allow_tilde_expansion: bool,
    mut resolve: impl FnMut(&ShellParameterReference) -> Option<String>,
) -> Option<(String, Vec<ShellParameterReference>)> {
    let mut out = String::with_capacity(text.len());
    let mut references = Vec::new();
    let mut chars = text.chars().peekable();
    let mut quote = initial_quote;
    let mut at_word_start = initial_quote == ShellWordQuote::None;
    let mut tilde_expanded = false;

    while let Some(ch) = chars.next() {
        let lexical_start = at_word_start;
        at_word_start = false;
        match quote {
            ShellWordQuote::Single => {
                if ch == '\'' {
                    quote = ShellWordQuote::None;
                } else {
                    out.push(ch);
                }
            }
            ShellWordQuote::Double => match ch {
                '"' if initial_quote == ShellWordQuote::None => quote = ShellWordQuote::None,
                '\\' => match chars.peek().copied() {
                    Some(next @ ('$' | '`' | '"' | '\\')) => {
                        chars.next();
                        out.push(next);
                    }
                    Some('\n') => {
                        chars.next();
                    }
                    Some(_) => out.push('\\'),
                    None => return None,
                },
                '$' if matches!(bindings.shell_kind(), caushell_types::ShellKind::Bash | caushell_types::ShellKind::Sh)
                    && chars.peek().copied().is_some_and(caushell_parse::is_literal_dollar_follower) =>
                {
                    out.push('$');
                }
                '$' => {
                    let reference = parse_shell_parameter_reference_after_dollar(&mut chars)?;
                    if mode == ShellWordMode::PositionalArgument
                        && !matches!(
                            reference,
                            ShellParameterReference::Variable(_)
                                | ShellParameterReference::ArrayElement { .. }
                                | ShellParameterReference::Indirect { .. }
                                | ShellParameterReference::Positional(_)
                                | ShellParameterReference::PatternRemoval { .. }
                                | ShellParameterReference::Substring { .. }
                        )
                    {
                        return None;
                    }
                    let value = resolve(&reference)?;
                    if value.contains('\0') {
                        return None;
                    }
                    out.push_str(&value);
                    references.push(reference);
                }
                '`' => return None,
                _ => out.push(ch),
            },
            ShellWordQuote::None => match ch {
                '\'' => quote = ShellWordQuote::Single,
                '"' => quote = ShellWordQuote::Double,
                '\\' => match chars.next()? {
                    '\n' => at_word_start = lexical_start,
                    escaped => out.push(escaped),
                },
                '$' => {
                    let reference = parse_shell_parameter_reference_after_dollar(&mut chars)?;
                    if mode == ShellWordMode::CommandName
                        && matches!(reference, ShellParameterReference::Substring { .. })
                    {
                        return None;
                    }
                    if mode == ShellWordMode::PositionalArgument
                        && !matches!(
                            reference,
                            ShellParameterReference::Variable(_)
                                | ShellParameterReference::ArrayElement { .. }
                                | ShellParameterReference::Indirect { .. }
                                | ShellParameterReference::Positional(_)
                                | ShellParameterReference::PatternRemoval { .. }
                        )
                    {
                        return None;
                    }
                    let value = resolve(&reference)?;
                    if value.contains('\0')
                        || (matches!(
                            mode,
                            ShellWordMode::CommandName | ShellWordMode::PositionalArgument
                        ) && !value.is_empty()
                            && !is_safe_unquoted_scalar(&value))
                    {
                        return None;
                    }
                    out.push_str(&value);
                    references.push(reference);
                }
                '`' => return None,
                '*' | '?' | '['
                    if matches!(
                        mode,
                        ShellWordMode::CommandName | ShellWordMode::PositionalArgument
                    ) =>
                {
                    return None;
                }
                // Brace expansion can produce multiple fields before parameter
                // expansion. This scalar query must not collapse those fields.
                '{' | '}' if mode == ShellWordMode::PositionalArgument => return None,
                '~' if allow_tilde_expansion
                    && lexical_start
                    && matches!(chars.peek(), None | Some('/')) =>
                {
                    out.push_str(bindings.tilde_home()?);
                    tilde_expanded = true;
                }
                '~' if allow_tilde_expansion && lexical_start => return None,
                _ => out.push(ch),
            },
        }
    }

    let quote_complete = quote == initial_quote;
    let value_allowed = mode == ShellWordMode::Assignment
        || mode == ShellWordMode::Scalar
        || !out.is_empty()
        || tilde_expanded
        || (mode == ShellWordMode::PositionalArgument && initial_quote == ShellWordQuote::Double);
    (quote_complete && value_allowed).then_some((out, references))
}

fn exact_scalar_all_positional_parameters(
    bindings: &SessionBindings,
    kind: ShellAllPositionalsKind,
) -> Option<String> {
    if !bindings.positional_parameters_are_complete() {
        return None;
    }
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
        SessionValue::OpaqueDynamic { .. }
        | SessionValue::RuntimeInput { .. }
        | SessionValue::Structured(_) => None,
    }
}

fn parse_braced_shell_parameter_expansion(body: &str) -> Option<ShellParameterReference> {
    let (parameter, rest) = parse_shell_parameter_name_prefix(body)?;
    for (word, kind) in [
        ("##", ShellPatternRemovalKind::LongestPrefix),
        ("#", ShellPatternRemovalKind::ShortestPrefix),
        ("%%", ShellPatternRemovalKind::LongestSuffix),
        ("%", ShellPatternRemovalKind::ShortestSuffix),
    ] {
        if let Some(pattern) = rest.strip_prefix(word) {
            return Some(ShellParameterReference::PatternRemoval {
                parameter,
                kind,
                pattern: pattern.into(),
            });
        }
    }
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

fn parse_braced_shell_parameter_substitution(body: &str) -> Option<ShellParameterReference> {
    let (parameter, rest) = parse_shell_parameter_name_prefix(body)?;
    let (replace_all, rest) = if let Some(rest) = rest.strip_prefix("//") {
        (true, rest)
    } else if let Some(rest) = rest.strip_prefix('/') {
        (false, rest)
    } else {
        return None;
    };

    let (pattern, replacement) = rest.split_once('/')?;
    if !is_literal_parameter_substitution_pattern(pattern)
        || !is_literal_parameter_substitution_replacement(replacement)
    {
        return None;
    }

    Some(ShellParameterReference::PatternSubstitution {
        parameter,
        replace_all,
        pattern: pattern.to_string(),
        replacement: replacement.to_string(),
    })
}

fn parse_braced_shell_substring(body: &str) -> Option<ShellParameterReference> {
    fn literal_bound(text: &str) -> Option<usize> {
        // A leading zero otherwise changes the base in Bash arithmetic.
        if (text.starts_with('0') && text.len() > 1) || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        usize::try_from(text.parse::<i32>().ok()?).ok()
    }

    let (ShellParameterName::Variable(name), rest) = parse_shell_parameter_name_prefix(body)? else {
        return None;
    };
    let bounds = rest.strip_prefix(':')?;
    let (offset, length) = if let Some((offset, length)) = bounds.split_once(':') {
        (literal_bound(offset)?, Some(literal_bound(length)?))
    } else {
        (literal_bound(bounds)?, None)
    };
    Some(ShellParameterReference::Substring {
        name,
        offset,
        length,
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

struct ShellParameterBindingRef<'a> {
    presence: VariablePresence,
    value: Option<&'a SessionValue>,
}

impl ShellParameterBindingRef<'_> {
    fn exact_scalar(&self) -> Option<String> {
        (self.presence == VariablePresence::Present)
            .then(|| self.value.and_then(exact_scalar_session_value))
            .flatten()
    }
}

fn shell_parameter_binding<'a>(
    bindings: &'a SessionBindings,
    parameter: &ShellParameterName,
) -> ShellParameterBindingRef<'a> {
    match parameter {
        ShellParameterName::Variable(name) => {
            let value = bindings.get(name).map(|binding| binding.value);
            ShellParameterBindingRef {
                // Namespace presence also covers `export V` without a value.
                // It is not by itself proof that ${V+word} selects `word`.
                presence: match bindings.variable_presence(name) {
                    VariablePresence::Absent => VariablePresence::Absent,
                    VariablePresence::Present
                        if value.is_some_and(|value| {
                            matches!(
                                value,
                                SessionValue::ExactScalar(_) | SessionValue::RuntimeProduced { .. }
                            )
                        }) =>
                    {
                        VariablePresence::Present
                    }
                    _ => VariablePresence::Unknown,
                },
                value,
            }
        }
        ShellParameterName::Positional(position) => {
            let value = bindings.positional_parameter(*position);
            ShellParameterBindingRef {
                presence: if value.is_some() {
                    // A supplied fixed-width argv item exists even when its
                    // bytes are unknown. Missing snapshot data proves nothing.
                    VariablePresence::Present
                } else if *position > 0 && bindings.positional_parameters_are_complete() {
                    VariablePresence::Absent
                } else {
                    VariablePresence::Unknown
                },
                value,
            }
        }
    }
}

fn exact_scalar_shell_parameter_expansion_value(
    bindings: &SessionBindings,
    parameter: &ShellParameterName,
    operator: ShellParameterExpansionOperator,
    word: &str,
) -> Option<String> {
    use ShellParameterExpansionOperator::*;
    use VariablePresence::*;
    let binding = shell_parameter_binding(bindings, parameter);
    match (operator, binding.presence) {
        (UseDefaultIfUnset | UseDefaultIfUnsetOrNull, Absent) => {
            literal_parameter_expansion_word(word)
        }
        (UseDefaultIfUnset, Present) => binding.exact_scalar(),
        (UseDefaultIfUnsetOrNull, Present) => {
            let value = binding.exact_scalar()?;
            if value.is_empty() {
                literal_parameter_expansion_word(word)
            } else {
                Some(value)
            }
        }
        (UseAlternateIfSet | UseAlternateIfSetAndNotNull, Absent) => Some(String::new()),
        (UseAlternateIfSet, Present) => literal_parameter_expansion_word(word),
        // Both outcomes are empty. No existence/nullness guess is required.
        (UseAlternateIfSet | UseAlternateIfSetAndNotNull, _) if word.is_empty() => {
            Some(String::new())
        }
        (UseAlternateIfSetAndNotNull, Present) => {
            let value = binding.exact_scalar()?;
            if value.is_empty() {
                Some(String::new())
            } else {
                literal_parameter_expansion_word(word)
            }
        }
        (_, Unknown) => None,
    }
}

fn exact_scalar_shell_parameter_substitution_value(
    bindings: &SessionBindings,
    parameter: &ShellParameterName,
    replace_all: bool,
    pattern: &str,
    replacement: &str,
) -> Option<String> {
    let value = known_parameter_scalar(bindings, parameter)?;

    if replace_all {
        Some(value.replace(pattern, replacement))
    } else {
        Some(value.replacen(pattern, replacement, 1))
    }
}

fn known_parameter_scalar(
    bindings: &SessionBindings,
    parameter: &ShellParameterName,
) -> Option<String> {
    let binding = shell_parameter_binding(bindings, parameter);
    match binding.presence {
        VariablePresence::Present => binding.exact_scalar(),
        VariablePresence::Absent => Some(String::new()),
        VariablePresence::Unknown => None,
    }
}

fn removal_pattern(
    raw: &str,
    bindings: &SessionBindings,
    depth: usize,
) -> Option<ParameterPattern> {
    if raw.len() > 4096 || depth >= 16 {
        return None;
    }
    let mut units = Vec::new();
    let mut chars = raw.chars().peekable();
    let mut quote = ShellWordQuote::None;
    let mut first = true;
    while let Some(ch) = chars.next() {
        let initial = first;
        first = false;
        if units.len() > 4096 {
            return None;
        }
        match ch {
            '\'' if quote != ShellWordQuote::Double => {
                quote = if quote == ShellWordQuote::Single {
                    ShellWordQuote::None
                } else {
                    ShellWordQuote::Single
                };
            }
            '"' if quote != ShellWordQuote::Single => {
                quote = if quote == ShellWordQuote::Double {
                    ShellWordQuote::None
                } else {
                    ShellWordQuote::Double
                };
            }
            '\\' if quote != ShellWordQuote::Single => {
                let next = chars.next()?;
                if quote == ShellWordQuote::Double && !matches!(next, '$' | '`' | '"' | '\\' | '\n')
                {
                    units.push(PatternUnit {
                        ch: '\\',
                        literal: true,
                    });
                }
                if next != '\n' {
                    units.push(PatternUnit {
                        ch: next,
                        literal: true,
                    });
                }
            }
            '$' if quote != ShellWordQuote::Single => {
                let reference = parse_shell_parameter_reference_after_dollar(&mut chars)?;
                let value = match &reference {
                    ShellParameterReference::Variable(name) => known_parameter_scalar(
                        bindings,
                        &ShellParameterName::Variable(name.clone()),
                    )?,
                    ShellParameterReference::Positional(position) => known_parameter_scalar(
                        bindings,
                        &ShellParameterName::Positional(*position),
                    )?,
                    _ => exact_scalar_shell_parameter_value_at_depth(
                        bindings,
                        &reference,
                        depth + 1,
                    )?,
                };
                if value.len() > 4096 || value.contains('\0') {
                    return None;
                }
                units.extend(value.chars().map(|ch| PatternUnit {
                    ch,
                    literal: quote != ShellWordQuote::None,
                }));
            }
            '`' if quote != ShellWordQuote::Single => return None,
            '~' if quote == ShellWordQuote::None && initial => {
                if !matches!(chars.peek(), None | Some('/')) {
                    return None;
                }
                let home = bindings.tilde_home()?;
                if home.len() > 4096 {
                    return None;
                }
                units.extend(home.chars().map(|ch| PatternUnit { ch, literal: true }));
            }
            '\0' => return None,
            _ => units.push(PatternUnit {
                ch,
                literal: quote != ShellWordQuote::None,
            }),
        }
    }
    if quote != ShellWordQuote::None {
        return None;
    }
    ParameterPattern::compile(&units)
}

fn removal_source_binding<'a>(
    bindings: &'a SessionBindings,
    reference: &ShellParameterReference,
) -> Option<BindingValueRef<'a>> {
    let ShellParameterReference::PatternRemoval { parameter, .. } = reference else {
        return None;
    };
    match parameter {
        ShellParameterName::Variable(name) => bindings.get(name),
        ShellParameterName::Positional(position) => {
            bindings
                .positional_parameter(*position)
                .map(|value| BindingValueRef {
                    value,
                    origin: BindingOrigin::SessionBinding,
                })
        }
    }
}

fn removal_has_proven_unset_source(
    bindings: &SessionBindings,
    reference: &ShellParameterReference,
) -> bool {
    match reference {
        ShellParameterReference::PatternRemoval {
            parameter: ShellParameterName::Variable(name),
            ..
        } => {
            bindings.get(name).is_none()
                && bindings.variable_presence(name) == VariablePresence::Absent
        }
        ShellParameterReference::PatternRemoval {
            parameter: ShellParameterName::Positional(position),
            ..
        } => {
            *position > 0
                && bindings.positional_parameters_are_complete()
                && bindings.positional_parameter(*position).is_none()
        }
        _ => false,
    }
}

fn resolved_removal(
    bindings: &SessionBindings,
    reference: &ShellParameterReference,
    value: String,
) -> ValueMaterialization {
    let variable_name = shell_parameter_reference_name(reference);
    match removal_source_binding(bindings, reference) {
        Some(BindingValueRef {
            value: SessionValue::RuntimeProduced { kind, .. },
            origin,
        }) => ValueMaterialization::ResolvedRuntimeProduced {
            variable_name,
            value,
            kind: *kind,
            origin,
        },
        source => ValueMaterialization::ResolvedExactScalar {
            variable_name,
            value,
            origin: source
                .map(|s| s.origin)
                .unwrap_or(BindingOrigin::SessionBinding),
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

fn is_literal_parameter_substitution_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && is_literal_parameter_substitution_word(pattern)
        && !pattern.chars().any(|ch| matches!(ch, '*' | '?' | '['))
}

fn is_literal_parameter_substitution_replacement(replacement: &str) -> bool {
    is_literal_parameter_substitution_word(replacement)
}

fn is_literal_parameter_substitution_word(word: &str) -> bool {
    !contains_unescaped_dynamic_syntax(word)
        && !word.chars().any(|ch| matches!(ch, '\'' | '"' | '\\'))
}

fn shell_value_to_session_value(value: &ShellValueSnapshot) -> Option<SessionValue> {
    Some(value.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueMaterialization {
    Static,
    /// An expanded shell word, not a fabricated HOME variable reference.
    ResolvedShellWord {
        value: String,
    },
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
        source: RuntimeInputSource,
        capture: Option<RuntimeInputCapture>,
        variable_name: Option<String>,
        origin: Option<BindingOrigin>,
    },
    /// Unknown bytes supplied by a non-stream implicit source. These cannot
    /// be represented as stdin or as a captured runtime-input binding.
    RequiresImplicitInput {
        source: ImplicitInputSource,
    },
}

impl ValueMaterialization {
    pub fn requires_implicit_input(source: ImplicitInputSource) -> Self {
        match source.to_runtime_input_source() {
            Some(source) => Self::RequiresRuntimeInput {
                source,
                capture: None,
                variable_name: None,
                origin: None,
            },
            None => Self::RequiresImplicitInput { source },
        }
    }
}

/// Why exact shell argv could not be materialized. A resource budget is not
/// itself evidence of an unknown shell effect; consumers still need slot and
/// native-effect proofs before using an inexact argument as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellExpansionGapKind {
    ExactPathnameFieldsUnavailable,
    BraceBudgetExhausted,
    UnsupportedBraceSyntax,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellExpansionGap {
    pub span: caushell_parse::SourceSpan,
    pub kind: ShellExpansionGapKind,
    /// Internal budget proof only, never an exact argv/output certificate.
    pub bounded_literal_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedProjectedInvocation {
    pub invocation: ProjectedInvocation,
    pub arg_resolutions: Vec<ValueMaterialization>,
    pub shell_expansion_unresolved: bool,
    pub shell_expansion_gaps: Vec<ShellExpansionGap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedShellField {
    pub text: String,
    pub resolution: ValueMaterialization,
}

/// Analysis-produced fields for one original source word. The caller owns
/// producer, quoting and pathname proofs. These facts are not runtime input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentFieldsProof {
    pub span: caushell_parse::SourceSpan,
    pub source_word: String,
    pub layout: ArgumentFieldLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentFieldLayout {
    Exact(Vec<String>),
    Optional(crate::OptionalBashField),
}

impl ArgumentFieldsProof {
    pub fn exact_fields(&self) -> Option<&[String]> {
        match &self.layout {
            ArgumentFieldLayout::Exact(fields) => Some(fields),
            ArgumentFieldLayout::Optional(_) => None,
        }
    }
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
    materialize_projected_invocation_with_argument_fields(projection, bindings, &[], false)
}

pub(crate) fn materialize_projected_invocation_with_argument_fields(
    projection: &ProjectedInvocation,
    bindings: &SessionBindings,
    proofs: &[ArgumentFieldsProof],
    supports_region_alternatives: bool,
) -> MaterializedProjectedInvocation {
    let dialect;
    let bindings = if bindings.shell_kind() != projection.shell_kind {
        dialect = {
            let mut value = bindings.clone();
            value.set_shell_kind(projection.shell_kind);
            value
        };
        &dialect
    } else {
        bindings
    };
    let mut args = Vec::with_capacity(projection.args.len());
    let mut arg_resolutions = Vec::with_capacity(projection.args.len());
    let mut brace_budget = crate::brace_expansion::BraceBudget::default();
    let mut shell_expansion_unresolved = false;
    let mut shell_expansion_gaps = Vec::new();

    // An invalid/over-budget proof set never supplies a safe partial prefix.
    let exact_fields = || proofs.iter().filter_map(ArgumentFieldsProof::exact_fields).flatten();
    let proof_budget_valid = proofs.len() <= 256
        && exact_fields().count() <= 4096
        && exact_fields().try_fold(0usize, |n, s| {
            (!s.contains('\0')).then(|| n.checked_add(s.len())).flatten()
        }).is_some_and(|n| n <= 262_144);

    for original in &projection.args {
        if proof_budget_valid
            && !original.runtime_data
            && original.implicit_input_source.is_none()
            && original.runtime_argument_domain.is_none()
            && original.word_context == crate::WordContext::ShellArgument
        {
            let mut matching = proofs.iter().filter(|p| {
                p.span == original.span && p.source_word == original.text
            });
            if let Some(proof) = matching.next()
                && matching.next().is_none()
            {
                match &proof.layout {
                    ArgumentFieldLayout::Exact(fields) => {
                        for text in fields {
                            let mut field = original.clone();
                            field.text = text.clone();
                            field.runtime_data = true;
                            field.quoted = true;
                            field.node_kind = "substitution_field".into();
                            field.substitution_shape = None;
                            field.lexical_field_prefix = None;
                            args.push(field);
                            arg_resolutions.push(ValueMaterialization::ResolvedShellWord { value: text.clone() });
                        }
                        continue;
                    }
                    ArgumentFieldLayout::Optional(shape) if supports_region_alternatives => {
                        let mut field = original.clone();
                        field.native_region_field = Some(*shape);
                        field.substitution_shape = None;
                        field.lexical_field_prefix = None;
                        args.push(field);
                        arg_resolutions.push(ValueMaterialization::UnsupportedDynamicText {
                            text: original.text.clone(),
                        });
                        continue;
                    }
                    ArgumentFieldLayout::Optional(_) => {}
                }
            }
        }
        if !original.runtime_data
            && original.word_context == crate::WordContext::ShellArgument
            && let Some(proof) = bindings.pathname_fields.iter().find(|proof| {
                proof.start_byte == original.span.start_byte
                    && proof.end_byte == original.span.end_byte
                    && proof.source_word == original.text
            })
        {
            if proof.complete && proof.gap.is_none() {
                for text in &proof.fields {
                    let mut field = original.clone();
                    field.text = text.clone();
                    field.runtime_data = true;
                    field.quoted = true;
                    field.node_kind = "pathname_field".into();
                    field.implicit_input_source = None;
                    field.runtime_argument_domain = None;
                    field.lexical_field_prefix = None;
                    args.push(field);
                    arg_resolutions.push(ValueMaterialization::ResolvedShellWord {
                        value: text.clone(),
                    });
                }
                continue;
            }
            if proof.exact_fields_required {
                shell_expansion_unresolved = true;
                shell_expansion_gaps.push(ShellExpansionGap { span: original.span.clone(), kind: ShellExpansionGapKind::ExactPathnameFieldsUnavailable, bounded_literal_bytes: None });
            }
        }
        let expanded = if projection.shell_kind == caushell_types::ShellKind::Bash
            && original.word_context == crate::WordContext::ShellArgument
            && !original.runtime_data
            && original.implicit_input_source.is_none()
            && matches!(
                original.node_kind.as_str(),
                "word" | "concatenation" | "brace_expression"
            )
            && original.text.contains('{')
        {
            match crate::brace_expansion::expand(&original.text, &mut brace_budget) {
                Ok(Some(words)) => Some(
                    words
                        .into_iter()
                        .map(|text| {
                            let mut arg = original.clone();
                            arg.text = text;
                            if arg.node_kind == "brace_expression" {
                                arg.node_kind = "word".into();
                            }
                            arg
                        })
                        .collect::<Vec<_>>(),
                ),
                Ok(None) => None,
                Err(error) => {
                    shell_expansion_unresolved = true;
                    let bounded_literal_bytes = (error == crate::brace_expansion::BraceExpansionError::BudgetExhausted)
                        .then(|| crate::brace_expansion::retain_bounded_numeric_data(&original.text, &mut brace_budget)).flatten();
                    shell_expansion_gaps.push(ShellExpansionGap {
                        span: original.span.clone(),
                        bounded_literal_bytes,
                        kind: match error {
                            crate::brace_expansion::BraceExpansionError::BudgetExhausted => ShellExpansionGapKind::BraceBudgetExhausted,
                            crate::brace_expansion::BraceExpansionError::Unsupported => ShellExpansionGapKind::UnsupportedBraceSyntax,
                        },
                    });
                    // Preserve the original symbolic word and its span. A
                    // retained spelling is never a literal argv field or a
                    // partial prefix of the expansion that ran out of budget.
                    args.push(original.clone());
                    arg_resolutions.push(ValueMaterialization::UnsupportedDynamicText { text: original.text.clone() });
                    continue;
                }
            }
        } else {
            None
        };
        for arg in expanded
            .as_deref()
            .unwrap_or(std::slice::from_ref(original))
        {
            if let Some(fields) = materialize_positional_vector(arg, bindings) {
                for (field, resolution) in fields {
                    args.push(field);
                    arg_resolutions.push(resolution);
                }
                continue;
            }
            let render_fields = || {
                materialize_argument_fields(
                    arg,
                    bindings,
                    supports_region_alternatives
                        && projection.shell_kind == caushell_types::ShellKind::Bash,
                )
            };
            let mut exact_integer_fields = None;
            let domain = if arg.word_context == crate::WordContext::ShellArgument {
                if let Some(domain) = integer_argument_domain(arg, bindings) {
                    let fields = render_fields();
                    // An integer shape is a fallback for unknown bytes. Keep
                    // exact argv and its origin when the same frame proves it.
                    if matches!(
                        fields.as_slice(),
                        [MaterializedText {
                            resolution: ValueMaterialization::ResolvedExactScalar { .. }
                                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                                | ValueMaterialization::ResolvedShellWord { .. },
                            ..
                        }]
                    ) {
                        exact_integer_fields = Some(fields);
                        None
                    } else {
                        Some(domain)
                    }
                } else {
                    materialize_argument_domain(arg, bindings)
                }
            } else {
                None
            };
            if let Some(domain) = domain {
                let source = if matches!(
                    domain,
                    caushell_types::RuntimeArgumentDomain::GeneratedFileName { .. }
                        | caushell_types::RuntimeArgumentDomain::TextTemplate { .. }
                ) {
                    ImplicitInputSource::InheritedEnvironment
                } else {
                    ImplicitInputSource::ShellIteration
                };
                let mut argument = arg.clone();
                argument.implicit_input_source = Some(match source {
                    ImplicitInputSource::InheritedEnvironment => {
                        caushell_types::ImplicitInputSource::InheritedEnvironment
                    }
                    _ => caushell_types::ImplicitInputSource::ShellIteration,
                });
                argument.runtime_argument_domain = Some(domain);
                argument.runtime_data = true;
                argument.node_kind = "runtime_scalar".into();
                args.push(argument);
                arg_resolutions.push(ValueMaterialization::RequiresImplicitInput { source });
                continue;
            }
            for materialized in exact_integer_fields.unwrap_or_else(render_fields) {
                args.push(ProjectedArg {
                    word_context: arg.word_context,
                    text: materialized.text,
                    implicit_input_source: arg.implicit_input_source,
                    runtime_argument_domain: arg.runtime_argument_domain.clone(),
                    substitution_shape: arg.substitution_shape,
                    native_region_field: arg.native_region_field,
                    lexical_field_prefix: arg.lexical_field_prefix.clone().or_else(|| {
                        if arg.runtime_data
                            || arg.implicit_input_source.is_some()
                            || arg.quoted
                            || !matches!(arg.node_kind.as_str(), "word" | "concatenation")
                            || !(arg.text == "~" || arg.text.starts_with("~/"))
                            || arg.text[1..].contains(['$', '`', '\'', '"', '\\', '~'])
                        {
                            return None;
                        }
                        // Tilde's value is not field-split or glob-expanded. A pure
                        // pathname suffix may generate many fields, all retaining
                        // this spelling prefix. Use supplied bindings, no lookup.
                        let prefix = bindings.tilde_home()?;
                        prefix.starts_with('/').then(|| prefix.to_owned())
                    }),
                    // A resolved field is argv data, not shell source to decode
                    // again. Its binding origin stays in arg_resolutions below.
                    runtime_data: arg.runtime_data
                        || matches!(
                            materialized.resolution,
                            ValueMaterialization::ResolvedExactScalar { .. }
                                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                                | ValueMaterialization::ResolvedShellWord { .. }
                        ),
                    kind: arg.kind,
                    quoted: arg.quoted,
                    node_kind: arg.node_kind.clone(),
                    span: arg.span.clone(),
                });
                arg_resolutions.push(materialized.resolution);
            }
        }
    }

    reclassify_projected_args(&mut args);

    MaterializedProjectedInvocation {
        invocation: ProjectedInvocation {
            shell_kind: projection.shell_kind,
            option_prefixes: projection.option_prefixes,
            command_name: projection.command_name.clone(),
            args,
            stdin_payload_available: projection.stdin_payload_available,
            interactive_session: projection.interactive_session,
        },
        arg_resolutions,
        shell_expansion_unresolved,
        shell_expansion_gaps,
    }
}

fn integer_argument_domain(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    if arg.runtime_data
        || arg.implicit_input_source.is_some()
        || arg.word_context != crate::WordContext::ShellArgument
    {
        return None;
    }
    // Quotes suppress splitting. Otherwise require the actual owning IFS, not
    // an assumption based on a missing observation. Decimal integers contain
    // no glob syntax, and literal affixes with glob syntax are rejected below.
    let quoted = arg.quoted && arg.node_kind == "string";
    let safe_ifs = bindings.variable_presence("IFS") == VariablePresence::Absent
        || bindings.get("IFS").is_some_and(|b| {
            matches!(b.value, SessionValue::ExactScalar(v)
            if !v.chars().any(|c| c.is_ascii_digit() || matches!(c, '+' | '-')))
        });
    if !quoted && !safe_ifs {
        return None;
    }
    let parts = caushell_parse::scalar_word_parts(&arg.text, arg.quoted, &arg.node_kind, true)?;
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut dynamic = false;
    for part in parts {
        match part {
            caushell_parse::ScalarArgumentPart::Literal(value) => {
                if value.contains(['*', '?', '[', '~']) {
                    return None;
                }
                if dynamic {
                    suffix.push_str(&value);
                } else {
                    prefix.push_str(&value);
                }
            }
            caushell_parse::ScalarArgumentPart::Parameter(text)
            | caushell_parse::ScalarArgumentPart::UnquotedParameter(text) => {
                let ShellParameterReference::Variable(name) =
                    exact_shell_parameter_reference(&text)?
                else {
                    return None;
                };
                if !bindings.variable_facts(&name).integer_scalar {
                    return None;
                }
                // A second unknown number keeps only outer affixes. Never
                // concatenate an internal literal into an exact numeric value.
                suffix.clear();
                dynamic = true;
            }
            _ => return None,
        }
    }
    dynamic.then_some(caushell_types::RuntimeArgumentDomain::TextTemplate { prefix, suffix })
}

fn materialize_positional_vector(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
) -> Option<Vec<(ProjectedArg, ValueMaterialization)>> {
    if arg.word_context != crate::WordContext::ShellArgument
        || arg.runtime_data
        || arg.implicit_input_source.is_some()
        || !arg.quoted
        || arg.node_kind != "string"
        || exact_shell_parameter_reference(&arg.text)
            != Some(ShellParameterReference::AllPositionals(
                ShellAllPositionalsKind::At,
            ))
        || !bindings.positional_parameters_complete && bindings.positional_runtime_tail.is_none()
    {
        return None;
    }
    let native = |source, domain: caushell_types::RuntimeArgumentDomain, batch| {
        let mut field = arg.clone();
        field.text.clear();
        field.implicit_input_source = Some(source);
        field.runtime_argument_domain = Some(domain);
        field.runtime_data = false;
        field.substitution_shape = None;
        field.lexical_field_prefix = None;
        field.node_kind = if batch {
            "runtime_argument_list"
        } else {
            "runtime_scalar"
        }
        .into();
        (
            field,
            ValueMaterialization::requires_implicit_input(
                ImplicitInputSource::from_caushell_types_implicit_input_source(source),
            ),
        )
    };
    let mut result = Vec::new();
    for (index, value) in bindings.positional_parameters.iter().enumerate() {
        if let Some(domain) = bindings.positional_argument_domain(index + 1) {
            result.push(native(
                caushell_types::ImplicitInputSource::ShellIteration,
                domain.clone(),
                false,
            ));
            continue;
        }
        let scalar = materialize_session_value_field(
            (index + 1).to_string(),
            value,
            BindingOrigin::SessionBinding,
            true,
        )?;
        let mut field = arg.clone();
        field.text = scalar.text;
        field.runtime_data = true;
        field.substitution_shape = None;
        field.lexical_field_prefix = None;
        result.push((field, scalar.resolution));
    }
    if let Some((source, domain)) = &bindings.positional_runtime_tail {
        result.push(native(*source, domain.clone(), true));
    }
    Some(result)
}

pub fn materialize_argument_domain(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    // Unquoted fields need a positive no-splitting/no-globbing proof.
    let whole_double_quoted = arg.quoted && arg.node_kind == "string";
    let ordinary_field_separators = bindings.get("IFS").is_none_or(|binding| {
        matches!(binding.value, SessionValue::ExactScalar(value) if value.chars().all(char::is_whitespace))
    });
    if bindings.argument_domains.is_empty() && bindings.positional_argument_domains.is_empty()
        || arg.text.len() > 4096
        || arg.runtime_data
        || !matches!(
            arg.node_kind.as_str(),
            "string" | "word" | "simple_expansion" | "expansion" | "concatenation"
        )
        || arg.implicit_input_source.is_some()
    {
        return None;
    }
    let reference = exact_shell_parameter_reference(&arg.text);
    if whole_double_quoted
        && bindings.shell_kind() == caushell_types::ShellKind::Bash
        && let Some(domain) = compose_dot_relative_path(&arg.text, bindings)
            .or_else(|| compose_execdir_leaf_path(&arg.text, bindings))
    {
        return Some(domain);
    }
    if whole_double_quoted
        && bindings.shell_kind() == caushell_types::ShellKind::Bash
        && let Some(ShellParameterReference::PatternSubstitution {
            parameter,
            pattern,
            replacement,
            ..
        }) = &reference
    {
        return substitute_within_path_anchor(
            parameter_argument_domain(bindings, parameter)?.clone(),
            pattern,
            replacement,
        );
    }
    if whole_double_quoted || ordinary_field_separators {
        if let Some(domain) = removal_argument_domain(arg, bindings, whole_double_quoted) {
            return Some(domain);
        }
    }
    if let Some(ShellParameterReference::Variable(name)) = reference {
        return bindings
            .argument_domain(&name)
            .filter(|domain| {
                whole_double_quoted
                    || ordinary_field_separators && domain.unquoted_generated_field()
            })
            .cloned();
    }
    const MARKER: &str = "__CAUSHELL_ABSTRACT_VALUE__";
    if arg.text.contains(MARKER) {
        return None;
    }
    for (name, domain) in &bindings.argument_domains {
        if !whole_double_quoted
            && (!ordinary_field_separators || !domain.unquoted_generated_field())
        {
            continue;
        }
        let mut proof_bindings = bindings.clone();
        proof_bindings.insert_exact_scalar(name, MARKER);
        let Some((template, refs)) = materialize_shell_word_with_references(
            &arg.text,
            &proof_bindings,
            ShellWordMode::PositionalArgument,
            if whole_double_quoted {
                ShellWordQuote::Double
            } else {
                ShellWordQuote::None
            },
            false,
        ) else {
            continue;
        };
        if refs != [ShellParameterReference::Variable(name.clone())] {
            continue;
        }
        let result = domain.substitute_into(&template, MARKER);
        if whole_double_quoted || result.unquoted_generated_field() {
            return Some(result);
        }
    }
    None
}

fn parameter_argument_domain<'a>(
    bindings: &'a SessionBindings,
    parameter: &ShellParameterName,
) -> Option<&'a caushell_types::RuntimeArgumentDomain> {
    match parameter {
        ShellParameterName::Variable(name) => bindings.argument_domain(name),
        ShellParameterName::Positional(position) => bindings.positional_argument_domain(*position),
    }
}

/// An ordinary scalar assignment can preserve the parent of a proved native
/// relative path. Only the exact quoted parameter operation is covered.
pub fn dot_relative_parent_assignment(
    value: &caushell_parse::AssignmentValueFact,
    bindings: &SessionBindings,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    if !value.quoted || value.node_kind != "string" || !value.command_substitutions.is_empty()
        || bindings.shell_kind() != caushell_types::ShellKind::Bash
    {
        return None;
    }
    let ShellParameterReference::PatternRemoval { parameter, kind, pattern } =
        exact_shell_parameter_reference(&value.text)?
    else {
        return None;
    };
    if kind != ShellPatternRemovalKind::ShortestSuffix || pattern != "/*"
        || !parameter_argument_domain(bindings, &parameter)?.has_dot_relative_components()
    {
        return None;
    }
    Some(dot_relative_path_domain())
}

fn dot_relative_path_domain() -> caushell_types::RuntimeArgumentDomain {
    caushell_types::RuntimeArgumentDomain::PathSet {
        roots: vec![".".into()],
        may_escape: false,
        basename_suffix: None,
        no_adjacent_slashes: false,
        dot_relative_components: true,
        execdir_leaf: false,
    }
}

fn compose_dot_relative_path(
    text: &str,
    bindings: &SessionBindings,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    const PATH: &str = "__CAUSHELL_RELATIVE_PATH_PART__";
    const BASENAME: &str = "__CAUSHELL_BASENAME_PART__";
    if text.contains(PATH) || text.contains(BASENAME) {
        return None;
    }
    let mut path_count = 0;
    let mut basename_count = 0;
    let (template, references) = materialize_shell_word_with_resolver(
        text, bindings, ShellWordMode::PositionalArgument, ShellWordQuote::Double, false,
        |reference| {
            let (parameter, marker) = match reference {
                ShellParameterReference::Variable(name) => (ShellParameterName::Variable(name.clone()), PATH),
                ShellParameterReference::Positional(index) => (ShellParameterName::Positional(*index), PATH),
                ShellParameterReference::PatternRemoval { parameter, kind, pattern }
                    if *kind == ShellPatternRemovalKind::LongestPrefix && pattern == "*/" =>
                {
                    (parameter.clone(), BASENAME)
                }
                _ => return None,
            };
            if !parameter_argument_domain(bindings, &parameter)?.has_dot_relative_components() {
                return None;
            }
            if marker == PATH {
                path_count += 1;
            } else {
                basename_count += 1;
            }
            Some(marker.into())
        },
    )?;
    let tail = template.strip_prefix(PATH)?.strip_prefix('/')?;
    if references.len() < 2
        || template.matches(PATH).count() != path_count
        || template.matches(BASENAME).count() != basename_count
        || !tail.ends_with(BASENAME)
    {
        return None;
    }
    if !tail.split('/').all(|component| {
        let path_prefix = component.starts_with(PATH);
        let suffix = component.strip_prefix(PATH).unwrap_or(component);
        if path_prefix && suffix.is_empty() {
            return true;
        }
        let literal = suffix.strip_suffix(BASENAME).unwrap_or(suffix);
        // A separator with a non-dot byte keeps the combined component
        // from becoming "..", even when either input is literally ".".
        literal.as_bytes().first().is_some_and(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
            && literal.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            && !literal.contains(PATH)
            && !literal.contains(BASENAME)
    }) {
        return None;
    }
    Some(dot_relative_path_domain())
}

fn compose_execdir_leaf_path(
    text: &str,
    bindings: &SessionBindings,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    const PARENT: &str = "__CAUSHELL_EXEC_DIR_NAME__";
    const ENTRY: &str = "__CAUSHELL_EXEC_DIR_ENTRY__";
    if !text.starts_with("./") || text.contains(PARENT) || text.contains(ENTRY)
        || bindings.shell_state_uncertainty().is_some()
    {
        return None;
    }
    let (template, references) = materialize_shell_word_with_resolver(
        text, bindings, ShellWordMode::PositionalArgument, ShellWordQuote::Double, false,
        |reference| match reference {
            ShellParameterReference::Variable(name) if bindings.variable_facts(name).basename_text => {
                Some(PARENT.into())
            }
            ShellParameterReference::Positional(index)
                if bindings.positional_argument_domain(*index)?.has_execdir_leaf() =>
            {
                Some(ENTRY.into())
            }
            _ => None,
        },
    )?;
    let separator = template.strip_prefix("./")?.strip_prefix(PARENT)?.strip_suffix(ENTRY)?;
    // Keep the first component non-dot even when the extracted basename
    // is empty. The callback supplies either a leaf or "./" plus that leaf.
    (references.len() == 2
        && !separator.is_empty()
        && separator.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        .then(dot_relative_path_domain)
}

fn removal_argument_domain(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
    quoted: bool,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    if !arg.text.contains(['#', '%']) && bindings.positional_argument_domains.is_empty() {
        return None;
    }
    const MARKER: &str = "__CAUSHELL_PARAMETER_DOMAIN__";
    if arg.text.contains(MARKER) {
        return None;
    }
    let mut selected = None;
    let mut count = 0;
    let (template, _) = materialize_shell_word_with_resolver(
        &arg.text,
        bindings,
        ShellWordMode::PositionalArgument,
        if quoted {
            ShellWordQuote::Double
        } else {
            ShellWordQuote::None
        },
        false,
        |reference| {
            let parameter = match reference {
                ShellParameterReference::Variable(name) => {
                    Some(ShellParameterName::Variable(name.clone()))
                }
                ShellParameterReference::Positional(position) => {
                    Some(ShellParameterName::Positional(*position))
                }
                ShellParameterReference::PatternRemoval { parameter, .. } => {
                    Some(parameter.clone())
                }
                _ => None,
            };
            if let Some(domain) = parameter
                .as_ref()
                .and_then(|p| parameter_argument_domain(bindings, p))
            {
                count += 1;
                if count > 1 || !quoted && !domain.unquoted_generated_field() {
                    return None;
                }
                selected = Some((domain.clone(), reference.clone()));
                Some(MARKER.into())
            } else {
                exact_scalar_shell_parameter_value(bindings, reference)
            }
        },
    )?;
    let (domain, reference) = selected?;
    if template.matches(MARKER).count() != 1 {
        return None;
    }
    let result = match reference {
        ShellParameterReference::PatternRemoval { kind, pattern, .. } => {
            removal_pattern(&pattern, bindings, 0)?
                .transfer_domain(&domain, kind, &template, MARKER)?
        }
        _ => domain.substitute_into(&template, MARKER),
    };
    (quoted || result.unquoted_generated_field()).then_some(result)
}

fn substitute_within_path_anchor(
    domain: caushell_types::RuntimeArgumentDomain,
    pattern: &str,
    replacement: &str,
) -> Option<caushell_types::RuntimeArgumentDomain> {
    use caushell_types::RuntimeArgumentDomain::PathSet;

    let PathSet {
        roots,
        may_escape: false,
        no_adjacent_slashes,
        ..
    } = domain
    else {
        return None;
    };
    // A match and its replacement both stay within one path component.
    // Every changed component retains an alphanumeric byte, so it cannot
    // become empty, "." or "..". Check anchors even with nocasematch set.
    let alphanumeric =
        |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if !alphanumeric(pattern) || !alphanumeric(replacement) {
        return None;
    }
    let pattern = pattern.to_ascii_lowercase();
    if roots.is_empty()
        || roots.iter().any(|root| {
            root.is_empty()
                || !root.is_ascii()
                || root.contains('\0')
                || root.to_ascii_lowercase().contains(&pattern)
        })
    {
        return None;
    }
    Some(PathSet {
        roots,
        may_escape: false,
        basename_suffix: None,
        no_adjacent_slashes,
        dot_relative_components: false,
        execdir_leaf: false,
    })
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
                let materialization = match &materialized.resolution {
                    ValueMaterialization::Static
                    | ValueMaterialization::ResolvedShellWord { .. } => {
                        if fragment.materialization
                            == RecursivePayloadFragmentMaterialization::RuntimeData
                        {
                            RecursivePayloadFragmentMaterialization::RuntimeData
                        } else {
                            RecursivePayloadFragmentMaterialization::DecodedLiteral
                        }
                    }
                    ValueMaterialization::ResolvedExactScalar { variable_name, .. } => {
                        RecursivePayloadFragmentMaterialization::ResolvedExactScalar {
                            variable_name: variable_name.clone(),
                        }
                    }
                    ValueMaterialization::ResolvedRuntimeProduced { variable_name, .. } => {
                        RecursivePayloadFragmentMaterialization::ResolvedRuntimeProduced {
                            variable_name: variable_name.clone(),
                        }
                    }
                    _ => fragment.materialization.clone(),
                };

                materialized_fragments.push(RecursivePayloadArgumentFragment {
                    text: materialized.text,
                    quoted: fragment.quoted,
                    node_kind: fragment.node_kind.clone(),
                    span: fragment.span.clone(),
                    materialization,
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
        RecursivePayloadInput::ImplicitInput { source, .. } => {
            MaterializedRecursivePayloadCandidate {
                candidate: candidate.clone(),
                resolution: ValueMaterialization::requires_implicit_input(*source),
                fragment_resolutions: Vec::new(),
            }
        }
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
        RecursivePayloadFragmentMaterialization::DecodedLiteral
        | RecursivePayloadFragmentMaterialization::RuntimeData => {
            return MaterializedText {
                text: fragment.text.clone(),
                resolution: ValueMaterialization::Static,
            };
        }
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
            // The text is already argv data. Losing its origin cannot justify
            // reinterpreting its dollar signs or backslashes as shell syntax.
            return MaterializedText {
                text: fragment.text.clone(),
                resolution: ValueMaterialization::UnsupportedDynamicBinding {
                    variable_name: variable_name.clone(),
                    repr: "runtime-produced argv origin unavailable".into(),
                    origin: BindingOrigin::SessionBinding,
                },
            };
        }
        RecursivePayloadFragmentMaterialization::Literal => {}
    }

    // Reuse the existing quote-aware lexical decoder. It never evaluates
    // substitutions or accepts a partial static prefix as complete argv.
    let (decoded, complete) = crate::value_projection::decode_argument_prefix(
        &fragment.text,
        fragment.quoted,
        &fragment.node_kind,
    );
    if complete {
        return MaterializedText {
            text: decoded,
            resolution: ValueMaterialization::Static,
        };
    }

    let materialized = materialize_argument_text(
        &fragment.text,
        fragment.quoted,
        &fragment.node_kind,
        bindings,
    );
    if matches!(materialized.resolution, ValueMaterialization::Static) {
        // No lexical completion and no exact scalar: retain an unknown payload,
        // rather than parsing raw outer-shell syntax as the child program.
        return MaterializedText {
            text: fragment.text.clone(),
            resolution: ValueMaterialization::UnsupportedDynamicText {
                text: fragment.text.clone(),
            },
        };
    }
    materialized
}

fn aggregate_recursive_payload_resolution(
    fragment_resolutions: &[ValueMaterialization],
) -> ValueMaterialization {
    if let Some(resolution) = fragment_resolutions.iter().find(|resolution| {
        matches!(
            resolution,
            ValueMaterialization::RequiresRuntimeInput { .. }
                | ValueMaterialization::RequiresImplicitInput { .. }
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
                | ValueMaterialization::ResolvedShellWord { .. }
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
    exact_region_fields: bool,
) -> Vec<MaterializedText> {
    if let Some(source) = arg.implicit_input_source {
        return vec![MaterializedText {
            text: arg.text.clone(),
            resolution: ValueMaterialization::requires_implicit_input(
                ImplicitInputSource::from_caushell_types_implicit_input_source(source),
            ),
        }];
    }
    if arg.runtime_data {
        return vec![MaterializedText {
            text: arg.text.clone(),
            resolution: ValueMaterialization::Static,
        }];
    }
    if exact_region_fields
        && arg.word_context == crate::WordContext::ShellArgument
        && arg.text.contains('$')
        && let Some(parts) = caushell_parse::scalar_word_parts(
            &arg.text, arg.quoted, &arg.node_kind, true,
        )
    {
        use caushell_parse::ScalarArgumentPart::{CommandSubstitution, Parameter, UnquotedCommandSubstitution, UnquotedParameter};
        if parts.iter().any(|part| matches!(part, Parameter(_) | UnquotedParameter(_)))
            && !parts.iter().any(|part| matches!(part, CommandSubstitution(_) | UnquotedCommandSubstitution(_)))
        {
            let has_unquoted = parts.iter().any(|part| matches!(part, UnquotedParameter(_)));
            let exact = crate::materialize_shell_field_fragments(parts, bindings, |_| None)
                .and_then(|fragments| crate::materialize_bash_field_fragments(&fragments, bindings));
            if let Some(fields) = exact {
                return fields.into_iter().map(|value| MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedShellWord { value },
                }).collect();
            }
            if has_unquoted && crate::observed_ifs_value(bindings).is_some() {
                // An observed splitter takes precedence over the legacy
                // scalar fallback, including unsupported/native-glob cases.
                return vec![MaterializedText {
                    text: arg.text.clone(),
                    resolution: ValueMaterialization::UnsupportedDynamicText { text: arg.text.clone() },
                }];
            }
        }
    }
    if arg.word_context == crate::WordContext::ShellArgument
        && !matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string")
        && exact_shell_parameter_reference(&arg.text).is_some()
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

    vec![materialize_argument_text_in_context(
        &arg.text,
        arg.quoted,
        &arg.node_kind,
        bindings,
        true,
        arg.word_context,
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

pub fn materialize_shell_array_element(
    value: &caushell_parse::AssignmentValueFact,
    bindings: &SessionBindings,
) -> Option<Vec<SessionValue>> {
    let literal = matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string");
    if !literal {
        if let Some(fields) =
            materialize_exact_shell_parameter_reference_fields(&value.text, value.quoted, bindings)
        {
            return fields
                .into_iter()
                .map(|field| match field.resolution {
                    ValueMaterialization::ResolvedRuntimeProduced { kind, .. } => {
                        Some(SessionValue::runtime_produced(field.text, kind))
                    }
                    ValueMaterialization::ResolvedExactScalar { .. }
                    | ValueMaterialization::ResolvedShellWord { .. } => {
                        Some(SessionValue::exact_scalar(field.text))
                    }
                    _ => None,
                })
                .collect();
        }
        if matches!(
            exact_shell_parameter_reference(&value.text),
            Some(
                ShellParameterReference::AllPositionals(_)
                    | ShellParameterReference::ArrayValues { .. }
            )
        ) {
            return None;
        }
    }
    let field = materialize_argument_text_in_context(
        &value.text,
        value.quoted,
        &value.node_kind,
        bindings,
        true,
        crate::WordContext::ShellArgument,
    );
    let scalar = match field.resolution {
        ValueMaterialization::Static
            if crate::shell_word_structure(&value.text, value.quoted, &value.node_kind).exact =>
        {
            SessionValue::exact_scalar(field.text)
        }
        ValueMaterialization::ResolvedExactScalar { .. }
        | ValueMaterialization::ResolvedShellWord { .. } => SessionValue::exact_scalar(field.text),
        ValueMaterialization::ResolvedRuntimeProduced { kind, .. } => {
            SessionValue::runtime_produced(field.text, kind)
        }
        ValueMaterialization::RequiresRuntimeInput {
            source,
            capture: Some(capture),
            ..
        } if value.quoted => SessionValue::runtime_input(source, capture),
        _ if value.quoted || literal => SessionValue::opaque_dynamic(&value.text),
        _ => return None,
    };
    Some(vec![scalar])
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
        ShellParameterReference::Substring { .. } if !quoted => None,
        ShellParameterReference::Variable(_) | ShellParameterReference::Substring { .. } => {
            let binding = resolved_parameter(bindings, reference)?;
            materialize_session_value_field(binding.name, &binding.value, binding.origin, quoted)
                .map(|field| vec![field])
        }
        ShellParameterReference::ArrayElement { .. } | ShellParameterReference::Indirect { .. } => {
            let binding = resolved_parameter(bindings, reference)?;
            materialize_session_value_field(binding.name, &binding.value, binding.origin, quoted)
                .map(|field| vec![field])
        }
        ShellParameterReference::ArrayValues { name } => {
            if !quoted {
                return None;
            }
            let binding = crate::resolve_shell_container(bindings, name).ok()?;
            let SessionValue::Structured(caushell_types::StructuredShellValue::IndexedArray {
                elements,
                complete: true,
            }) = binding.value
            else {
                return None;
            };
            if elements.len() > crate::structured_parameters::MAX_ARRAY_FIELDS {
                return None;
            }
            let mut bytes = 0usize;
            elements
                .values()
                .map(|value| {
                    bytes = bytes.saturating_add(value.retained_bytes());
                    if bytes > crate::structured_parameters::MAX_EXPANDED_BYTES {
                        return None;
                    }
                    materialize_session_value_field(
                        binding.name.clone(),
                        &SessionValue::from(value),
                        binding.origin,
                        true,
                    )
                })
                .collect()
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
        ShellParameterReference::Expansion { .. }
        | ShellParameterReference::PatternSubstitution { .. }
        | ShellParameterReference::PatternRemoval { .. } => {
            let value = exact_scalar_shell_parameter_value(bindings, reference)?;
            if !quoted && !is_safe_unquoted_scalar(&value) {
                return None;
            }

            Some(vec![MaterializedShellField {
                text: value.clone(),
                resolution: if matches!(reference, ShellParameterReference::PatternRemoval { .. }) {
                    resolved_removal(bindings, reference, value)
                } else {
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: shell_parameter_reference_name(reference),
                        value,
                        origin: BindingOrigin::SessionBinding,
                    }
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
    if !bindings.positional_parameters_are_complete() {
        return None;
    }
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
        SessionValue::OpaqueDynamic { .. }
        | SessionValue::RuntimeInput { .. }
        | SessionValue::Structured(_) => None,
    }
}

pub(crate) fn materialize_argument_text(
    text: &str,
    quoted: bool,
    node_kind: &str,
    bindings: &SessionBindings,
) -> MaterializedText {
    materialize_argument_text_with_tilde(text, quoted, node_kind, bindings, true)
}

pub(crate) fn materialize_argument_text_with_tilde(
    text: &str,
    quoted: bool,
    node_kind: &str,
    bindings: &SessionBindings,
    allow_tilde_expansion: bool,
) -> MaterializedText {
    materialize_argument_text_in_context(
        text,
        quoted,
        node_kind,
        bindings,
        allow_tilde_expansion,
        crate::WordContext::ShellArgument,
    )
}

fn materialize_argument_text_in_context(
    text: &str,
    quoted: bool,
    node_kind: &str,
    bindings: &SessionBindings,
    allow_tilde_expansion: bool,
    context: crate::WordContext,
) -> MaterializedText {
    let scalar = context == crate::WordContext::Scalar;
    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return MaterializedText {
            text: text.to_string(),
            resolution: ValueMaterialization::Static,
        };
    }

    // A dollar sign inside a single-quoted segment is literal, including
    // concatenated flag operands. Keep the source for its first lexical
    // decode; do not invent a variable origin from the whole source word.
    let tilde_word = allow_tilde_expansion && !quoted && (text == "~" || text.starts_with("~/"));
    let tilde_literal_composite = node_kind == "concatenation" && text.contains('~');
    if !tilde_word && !tilde_literal_composite {
        let (value, complete) =
            crate::value_projection::decode_argument_prefix(text, quoted, node_kind);
        if complete {
            // Selection/binding consume native argv, not source spelling.
            // Retain the ordinary literal fast path, but mark quote/escape
            // removal as resolved data so later consumers cannot decode it
            // twice (or miss an option hidden by a lexical continuation).
            return if value == text {
                MaterializedText {
                    text: value,
                    resolution: ValueMaterialization::Static,
                }
            } else {
                MaterializedText {
                    text: value.clone(),
                    resolution: ValueMaterialization::ResolvedShellWord { value },
                }
            };
        }
    }

    if let Some(variable_name) = exact_variable_reference(text) {
        let resolved = match crate::resolve_shell_reference(
            bindings,
            caushell_types::ShellReferenceTarget::Variable {
                name: variable_name.into(),
            },
        ) {
            Ok(value) => value,
            Err(_) if bindings.get(variable_name).is_none() => {
                return MaterializedText {
                    text: text.into(),
                    resolution: ValueMaterialization::MissingBinding {
                        variable_name: variable_name.into(),
                    },
                };
            }
            Err(reason) => {
                return MaterializedText {
                    text: text.into(),
                    resolution: ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: variable_name.into(),
                        repr: reason.into(),
                        origin: BindingOrigin::SessionBinding,
                    },
                };
            }
        };
        let binding = BindingValueRef {
            value: &resolved.value,
            origin: resolved.origin,
        };
        let variable_name = &resolved.name;

        match binding.value {
            SessionValue::ExactScalar(value) => {
                let value = value.clone();

                if !scalar && !quoted && !is_safe_unquoted_scalar(&value) {
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

                if !scalar && !quoted && !is_safe_unquoted_scalar(&value) {
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
            SessionValue::Structured(_) => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: variable_name.to_string(),
                        repr: "structured shell value requires native expansion".into(),
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
                        source: *source,
                        capture: Some(capture.clone()),
                        variable_name: Some(variable_name.to_string()),
                        origin: Some(binding.origin),
                    },
                };
            }
        }
    }

    if let Some(
        reference @ (ShellParameterReference::ArrayElement { .. }
        | ShellParameterReference::Indirect { .. }
        | ShellParameterReference::Substring { .. }),
    ) = exact_shell_parameter_reference(text)
        && (!matches!(reference, ShellParameterReference::Substring { .. }) || quoted || scalar)
    {
        if let Some(binding) = resolved_parameter(bindings, &reference) {
            let resolution = match &binding.value {
                SessionValue::RuntimeInput { source, capture } => {
                    ValueMaterialization::RequiresRuntimeInput {
                        source: *source,
                        capture: Some(capture.clone()),
                        variable_name: Some(binding.name),
                        origin: Some(binding.origin),
                    }
                }
                value => {
                    if let Some(field) = materialize_session_value_field(
                        binding.name.clone(),
                        value,
                        binding.origin,
                        quoted || scalar,
                    ) {
                        return MaterializedText {
                            text: field.text,
                            resolution: field.resolution,
                        };
                    }
                    ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: binding.name,
                        repr: "shell reference value is unresolved or requires field splitting"
                            .into(),
                        origin: binding.origin,
                    }
                }
            };
            return MaterializedText {
                text: text.into(),
                resolution,
            };
        }
        return MaterializedText {
            text: text.into(),
            resolution: ValueMaterialization::UnsupportedDynamicBinding {
                variable_name: shell_parameter_reference_name(&reference),
                repr: "shell reference target is unresolved".into(),
                origin: BindingOrigin::SessionBinding,
            },
        };
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

                if !scalar && !quoted && !is_safe_unquoted_scalar(&value) {
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

                if !scalar && !quoted && !is_safe_unquoted_scalar(&value) {
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
            SessionValue::Structured(_) => {
                return MaterializedText {
                    text: text.to_string(),
                    resolution: ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: position.to_string(),
                        repr: "structured shell value requires native expansion".into(),
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
                        source: *source,
                        capture: Some(capture.clone()),
                        variable_name: Some(position.to_string()),
                        origin: Some(BindingOrigin::SessionBinding),
                    },
                };
            }
        }
    }

    if let Some(
        reference @ (ShellParameterReference::Expansion { .. }
        | ShellParameterReference::PatternSubstitution { .. }
        | ShellParameterReference::PatternRemoval { .. }),
    ) = exact_shell_parameter_reference(text)
    {
        if let Some(value) = exact_scalar_shell_parameter_value(bindings, &reference) {
            if !scalar && !quoted && !is_safe_unquoted_scalar(&value) {
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
                resolution: if matches!(reference, ShellParameterReference::PatternRemoval { .. }) {
                    resolved_removal(bindings, &reference, value)
                } else if let Some(binding) = resolved_parameter(bindings, &reference) {
                    materialize_session_value_field(
                        binding.name,
                        &binding.value,
                        binding.origin,
                        true,
                    )
                    .map(|field| field.resolution)
                    .unwrap_or(ValueMaterialization::UnsupportedDynamicText { text: text.into() })
                } else {
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: shell_parameter_reference_name(&reference),
                        value,
                        origin: BindingOrigin::SessionBinding,
                    }
                },
            };
        }
    }

    if tilde_word || tilde_literal_composite || contains_unescaped_dynamic_syntax(text) {
        // Composite positional words (e.g. "$10", "${1}0")
        // use the same parameter grammar as command names/assignments. Only
        // statically proven single-field expansions are materialized; unknown
        // bindings, splitting, pathname generation and substitutions stay
        // unresolved. Resolved bytes remain argv data, never shell source.
        if let Some((value, references)) = materialize_shell_word_with_references(
            text,
            bindings,
            if scalar {
                ShellWordMode::Scalar
            } else {
                ShellWordMode::PositionalArgument
            },
            if quoted && node_kind == "string" {
                ShellWordQuote::Double
            } else {
                ShellWordQuote::None
            },
            allow_tilde_expansion,
        ) {
            // Preserve the actual variable's origin for attached operands
            // such as -e"$CODE". Expanded bytes are argv data and must never
            // be decoded/expanded again as outer-shell source.
            let reference_value = |reference: &ShellParameterReference| match reference {
                ShellParameterReference::Variable(_)
                | ShellParameterReference::ArrayElement { .. }
                | ShellParameterReference::Indirect { .. }
                | ShellParameterReference::Substring { .. } => {
                    resolved_parameter(bindings, reference)
                        .map(|binding| (binding.value, binding.origin))
                }
                ShellParameterReference::Positional(position) => bindings
                    .positional_parameter(*position)
                    .map(|value| (value.clone(), BindingOrigin::SessionBinding)),
                ShellParameterReference::PatternRemoval { .. } => {
                    removal_source_binding(bindings, reference).map(|b| (b.value.clone(), b.origin))
                }
                _ => None,
            };
            let resolution = if references.is_empty() && (tilde_word || tilde_literal_composite) {
                Some(match tilde_word.then(|| bindings.get("HOME")).flatten() {
                    Some(binding) => match binding.value {
                        SessionValue::RuntimeProduced { kind, .. } => {
                            ValueMaterialization::ResolvedRuntimeProduced {
                                variable_name: "HOME".into(),
                                value: value.clone(),
                                kind: *kind,
                                origin: binding.origin,
                            }
                        }
                        _ => ValueMaterialization::ResolvedExactScalar {
                            variable_name: "HOME".into(),
                            value: value.clone(),
                            origin: binding.origin,
                        },
                    },
                    None => ValueMaterialization::ResolvedShellWord {
                        value: value.clone(),
                    },
                })
            } else if references.len() == 1 {
                let variable_name = resolved_parameter(bindings, &references[0])
                    .map(|v| v.name)
                    .unwrap_or_else(|| shell_parameter_reference_name(&references[0]));
                match reference_value(&references[0]) {
                    Some((SessionValue::RuntimeProduced { kind, .. }, origin)) => {
                        Some(ValueMaterialization::ResolvedRuntimeProduced {
                            variable_name,
                            value: value.clone(),
                            kind,
                            origin,
                        })
                    }
                    Some((SessionValue::ExactScalar(_), origin)) => {
                        Some(ValueMaterialization::ResolvedExactScalar {
                            variable_name,
                            value: value.clone(),
                            origin,
                        })
                    }
                    None if removal_has_proven_unset_source(bindings, &references[0]) => {
                        Some(resolved_removal(bindings, &references[0], value.clone()))
                    }
                    // Complete positional bindings prove absent positions
                    // expand to empty strings; the lexical prefix may remain.
                    None if matches!(references[0], ShellParameterReference::Positional(_))
                        && bindings.positional_parameters_are_complete() =>
                    {
                        Some(ValueMaterialization::ResolvedExactScalar {
                            variable_name,
                            value: value.clone(),
                            origin: BindingOrigin::SessionBinding,
                        })
                    }
                    _ => None,
                }
            } else if !references.is_empty()
                && references.iter().all(|reference| {
                    matches!(
                        reference_value(reference),
                        Some((SessionValue::ExactScalar(_), _))
                    ) || removal_has_proven_unset_source(bindings, reference)
                        || (matches!(reference, ShellParameterReference::Positional(_))
                            && reference_value(reference).is_none()
                            && bindings.positional_parameters_are_complete())
                })
            {
                Some(ValueMaterialization::ResolvedExactScalar {
                    variable_name: text.to_string(),
                    value: value.clone(),
                    origin: BindingOrigin::SessionBinding,
                })
            } else {
                // The present origin model cannot express multiple runtime
                // producers. Do not collapse them into an exact literal.
                None
            };
            if let Some(resolution) = resolution {
                return MaterializedText {
                    text: value,
                    resolution,
                };
            }
        }
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
        ShellParameterReference::Variable(name) | ShellParameterReference::Substring { name, .. } => {
            name.clone()
        }
        ShellParameterReference::ArrayElement { name, .. }
        | ShellParameterReference::ArrayValues { name }
        | ShellParameterReference::Indirect { name } => name.clone(),
        ShellParameterReference::Positional(position) => position.to_string(),
        ShellParameterReference::AllPositionals(ShellAllPositionalsKind::At) => "@".to_string(),
        ShellParameterReference::AllPositionals(ShellAllPositionalsKind::Star) => "*".to_string(),
        ShellParameterReference::Expansion { parameter, .. } => shell_parameter_name(parameter),
        ShellParameterReference::PatternSubstitution { parameter, .. } => {
            shell_parameter_name(parameter)
        }
        ShellParameterReference::PatternRemoval { parameter, .. } => {
            shell_parameter_name(parameter)
        }
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

pub(crate) fn is_valid_variable_name(name: &str) -> bool {
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

fn is_safe_unquoted_scalar(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| !ch.is_whitespace() && !matches!(ch, '*' | '?' | '[' | ']'))
}

fn reclassify_projected_args(args: &mut [ProjectedArg]) {
    let mut dashdash_seen = false;

    for arg in args {
        arg.kind = if arg.word_context == crate::WordContext::Scalar {
            ProjectedArgKind::Positional
        } else if arg.text == "--" {
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
    #[test]
    fn incomplete_shell_state_retains_definitions_without_resolving_them() {
        let mut bindings = super::SessionBindings::new();
        bindings.upsert_function_binding(caushell_types::SessionFunctionBinding::new(
            "f",
            "printf SAFE;",
            caushell_types::CommandSequenceNo::new(1),
        ));
        bindings.upsert_alias_binding(caushell_types::SessionAliasBinding::new(
            "a",
            "printf SAFE",
            caushell_types::CommandSequenceNo::new(1),
        ));
        bindings.mark_shell_state_uncertain("incomplete source");
        assert!(bindings.function_binding("f").is_none());
        assert_eq!(bindings.alias_bindings().count(), 0);
        assert!(bindings.retained_function_binding("f").is_some());
        assert_eq!(bindings.retained_alias_bindings().count(), 1);
    }

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
    fn numeric_reference_grammar_distinguishes_braces_and_suffixes() {
        for (text, expected) in [("$1", 1), ("${1}", 1), ("${10}", 10), ("${00}", 0)] {
            assert_eq!(
                super::exact_shell_parameter_reference(text),
                Some(super::ShellParameterReference::Positional(expected)),
                "{text}"
            );
        }
        for text in ["$10", "$00", "$99", "${1}0", r"\$10"] {
            assert_eq!(super::exact_shell_parameter_reference(text), None, "{text}");
        }
    }

    #[test]
    fn bash_substrings_resolve_known_ascii_and_keep_quote_boundaries() {
        let mut bindings = SessionBindings::new();
        bindings.insert_exact_scalar("word", "a bc%nx");
        bindings.insert_exact_scalar("unicode", "éx");
        bindings.insert_exact_scalar("controls", "a\x1bb");
        for (source, expected) in [
            ("${word:0:1}", "a"),
            ("${word:1:3}", " bc"),
            ("${word:4}", "%nx"),
            ("${word:4:2}", "%n"),
            ("${word:80:1}", ""),
            ("${word:2:0}", ""),
            ("pre${word:2:2}post", "prebcpost"),
        ] {
            let result = super::materialize_argument_text(source, true, "string", &bindings);
            assert_eq!(result.text, expected, "{source}");
            assert!(matches!(
                result.resolution,
                ValueMaterialization::ResolvedExactScalar { .. }
            ));
        }
        for source in [
            "${word:$offset:1}",
            "${word:1+1:1}",
            "${word:01:1}",
            "${word: -1:1}",
            "${word:0:-1}",
            "${word:2147483648}",
            "${absent:0:1}",
            "${unicode:0:1}",
            "${controls:0:1}",
        ] {
            assert!(
                super::exact_scalar_shell_parameter_reference_value(source, &bindings).is_none(),
                "{source}"
            );
        }
        assert!(
            super::materialize_exact_shell_parameter_reference_fields("${word:0:1}", false, &bindings,)
                .is_none()
        );
        bindings.set_shell_kind(ShellKind::Sh);
        assert!(
            super::exact_scalar_shell_parameter_reference_value("${word:0:1}", &bindings).is_none()
        );
    }

    #[test]
    fn composite_positionals_materialize_single_fields_not_fictitious_indices() {
        let mut bindings = SessionBindings::new();
        bindings.set_shell_program_name(Some(crate::SessionValue::exact_scalar("/opt/program")));
        bindings.replace_positional_parameters_with_exact_scalars([
            "/opt/first",
            "a2",
            "a3",
            "a4",
            "a5",
            "a6",
            "a7",
            "a8",
            "a9",
            "./tenth",
        ]);
        for (text, expected) in [
            ("$10", "/opt/first0"),
            ("${10}", "./tenth"),
            ("${1}0", "/opt/first0"),
            ("$00", "/opt/program0"),
            ("${00}", "/opt/program"),
        ] {
            let result = super::materialize_argument_text(text, true, "string", &bindings);
            assert_eq!(result.text, expected, "{text}");
            assert!(
                matches!(
                    result.resolution,
                    ValueMaterialization::ResolvedExactScalar { .. }
                ),
                "{text}"
            );
        }
        bindings.replace_positional_parameters_with_exact_scalars(["./changed"]);
        assert_eq!(
            super::materialize_argument_text("$00", true, "string", &bindings).text,
            "/opt/program0"
        );
        bindings.replace_positional_parameters_with_exact_scalars(std::iter::empty::<&str>());
        assert_eq!(
            super::materialize_argument_text("$10", true, "string", &bindings).text,
            "0"
        );
        bindings.forget_positional_parameters();
        assert!(matches!(
            super::materialize_argument_text("$10", true, "string", &bindings).resolution,
            ValueMaterialization::UnsupportedDynamicText { .. }
        ));
    }

    #[test]
    fn exact_integer_arguments_keep_their_bytes_and_unknown_integers_keep_their_shape() {
        let source =
            parse_command(r#"printf '%s' "$number" "n=${number}""#, ShellKind::Bash).unwrap();
        let projection = project_invocation(
            &source.commands[0],
            crate::InvocationRuntimeContext::default().with_shell_kind(ShellKind::Bash),
        );
        let facts = super::ShellVariableFacts {
            integer_scalar: true,
            ..Default::default()
        };
        let mut exact = SessionBindings::new().with_exact_scalar("number", "7");
        exact.set_variable_facts("number", facts);
        let result = materialize_projected_invocation(&projection, &exact);
        for (index, text) in [(1, "7"), (2, "n=7")] {
            let argument = &result.invocation.args[index];
            assert_eq!(argument.text, text, "{:#?}", result.arg_resolutions);
            assert!(argument.runtime_data && argument.runtime_argument_domain.is_none());
            assert!(matches!(
                result.arg_resolutions[index],
                ValueMaterialization::ResolvedExactScalar { .. }
            ));
        }

        let mut produced = SessionBindings::new().with_runtime_produced(
            "number",
            "7",
            RuntimeProducedValueKind::Scalar,
        );
        produced.set_variable_facts("number", facts);
        let result = materialize_projected_invocation(&projection, &produced);
        assert!(matches!(
            &result.arg_resolutions[1],
            ValueMaterialization::ResolvedRuntimeProduced {
                kind: RuntimeProducedValueKind::Scalar, value, ..
            } if value == "7"
        ));

        let mut symbolic = SessionBindings::new().with_opaque_dynamic("number", "fixture");
        symbolic.set_variable_facts("number", facts);
        let result = materialize_projected_invocation(&projection, &symbolic);
        for (index, prefix) in [(1, ""), (2, "n=")] {
            assert!(matches!(
                &result.invocation.args[index].runtime_argument_domain,
                Some(caushell_types::RuntimeArgumentDomain::TextTemplate { prefix: actual, suffix })
                    if actual == prefix && suffix.is_empty()
            ));
            assert!(matches!(
                result.arg_resolutions[index],
                ValueMaterialization::RequiresImplicitInput { .. }
            ));
        }
    }

    #[test]
    fn composite_positionals_keep_quoting_and_uncertainty_boundaries() {
        let mut bindings = SessionBindings::new();
        bindings.replace_positional_parameters_with_exact_scalars(["/opt/a b$literal*"]);
        let result = super::materialize_argument_text("$10", true, "string", &bindings);
        assert_eq!(result.text, "/opt/a b$literal*0");
        assert!(matches!(
            result.resolution,
            ValueMaterialization::ResolvedExactScalar { .. }
        ));
        for (text, quoted, kind) in [
            ("$10", false, "concatenation"),
            ("$10*", false, "concatenation"),
            ("${1}{a,b}", false, "concatenation"),
            ("$(echo x)$10", true, "string"),
            ("$unknown$10", true, "string"),
        ] {
            let result = super::materialize_argument_text(text, quoted, kind, &bindings);
            assert!(
                matches!(
                    result.resolution,
                    ValueMaterialization::UnsupportedDynamicText { .. }
                ),
                "{text}: {:?}",
                result.resolution
            );
        }
        let result = super::materialize_argument_text("$10", true, "raw_string", &bindings);
        assert_eq!(result.text, "$10");
        assert_eq!(result.resolution, ValueMaterialization::Static);
        let artifact = parse_command(r#"touch "$10""#, ShellKind::Bash).unwrap();
        let projection = project_invocation(
            &artifact.commands[0],
            crate::InvocationRuntimeContext::new(),
        );
        let result = materialize_projected_invocation(&projection, &bindings);
        assert_eq!(result.invocation.args[0].text, "/opt/a b$literal*0");
        assert!(result.invocation.args[0].runtime_data);
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
    fn quoted_composite_scalar_preserves_its_origin_and_unknown_boundary() {
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
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "cmd".into(),
                value: "prefixecho ok".into(),
                origin: BindingOrigin::SessionBinding,
            }
        );
        let unknown = materialize_recursive_payload_candidate(&candidate, &SessionBindings::new());
        assert_eq!(
            unknown.resolution,
            ValueMaterialization::UnsupportedDynamicText {
                text: "prefix$cmd".into(),
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
    fn forgotten_positional_list_is_not_a_proven_empty_argv() {
        let mut bindings = SessionBindings::new();
        bindings.replace_positional_parameters_with_exact_scalars(["before"]);
        bindings.forget_positional_parameters();
        assert!(!bindings.positional_parameters_are_complete());
        assert!(bindings.positional_parameter(1).is_none());
        let parsed = parse_command("echo \"$@\"", ShellKind::Bash).unwrap();
        let projection = crate::project_invocation(
            &parsed.commands[0],
            crate::InvocationRuntimeContext::default(),
        );
        let result = materialize_projected_invocation(&projection, &bindings);
        assert!(
            !result.invocation.args.is_empty(),
            "unknown argv must not disappear"
        );
        assert!(result.arg_resolutions.iter().all(|r| !matches!(
            r,
            ValueMaterialization::Static | ValueMaterialization::ResolvedExactScalar { .. }
        )));
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
    fn projected_invocation_materializes_literal_parameter_substitution() {
        let artifact = parse_command(r#"rm -rf "${TARGET//XXX//}""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let bindings = SessionBindings::new().with_exact_scalar("TARGET", "XXXetc");
        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "/etc");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "TARGET".to_string(),
                value: "/etc".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn projected_invocation_materializes_literal_parameter_substitution_empty_replacement() {
        let artifact = parse_command(r#"rm -rf "${TARGET//XXX/}""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let bindings = SessionBindings::new().with_exact_scalar("TARGET", "/etXXXc");
        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "/etc");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::ResolvedExactScalar {
                variable_name: "TARGET".to_string(),
                value: "/etc".to_string(),
                origin: BindingOrigin::SessionBinding,
            }
        );
    }

    #[test]
    fn projected_invocation_leaves_glob_parameter_substitution_dynamic() {
        let artifact = parse_command(r#"rm -rf "${TARGET//X*/}""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, crate::InvocationRuntimeContext::new());

        let bindings = SessionBindings::new().with_exact_scalar("TARGET", "/etc");
        let materialized = materialize_projected_invocation(&projection, &bindings);

        assert_eq!(materialized.invocation.args[1].text, "${TARGET//X*/}");
        assert_eq!(
            materialized.arg_resolutions[1],
            ValueMaterialization::UnsupportedDynamicText {
                text: "${TARGET//X*/}".to_string(),
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
                domain: None,
            },
        };

        let materialized =
            materialize_recursive_payload_candidate(&candidate, &SessionBindings::new());

        assert_eq!(
            materialized.resolution,
            ValueMaterialization::RequiresRuntimeInput {
                source: RuntimeInputSource::StdinPayload,
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
                source: RuntimeInputSource::StdinData,
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
