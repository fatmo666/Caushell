use std::collections::BTreeSet;

use regex::Regex;

use crate::{
    ArgumentBindingSource, BindingSpec, BoundImplicitInput, BoundInvocation, BoundParameter,
    BoundValue, CommandProfile, DefaultSubcommandBehavior, Effect, EffectTarget, FlagName,
    FlagOperandMode, Form, FormId, Modifier, ModifierMatcher, Parameter, PositionalBindingSource,
    ProjectedArgKind, ProjectedInvocation, Residual, ResidualKind, ResidualSurface, RuntimeFeature,
    SelectorExpr, SelectorPredicate, SemanticType, StructuredValueContext, SubcommandNode,
    SubcommandTree, ValueConstraint, ValueMatcher, parse_owner_group_spec,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvocationShape {
    pub flags: Vec<FlagName>,
    pub matched_modifiers: Vec<crate::ModifierId>,
    pub matched_modifier_parameters: Vec<MatchedModifierParameter>,
    pub positional_args: Vec<String>,
    pub positional_args_before_dashdash: Vec<String>,
    pub has_dashdash: bool,
    pub subcommand_path: Vec<String>,
    pub stdin_payload_available: bool,
    pub interactive_session: bool,
}

impl InvocationShape {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_flag(mut self, flag_name: &str) -> Self {
        self.flags.push(FlagName::new(flag_name));
        self
    }

    pub fn with_modifier(mut self, modifier_id: &str) -> Self {
        self.matched_modifiers
            .push(crate::ModifierId::new(modifier_id));
        self
    }

    pub fn with_positional_arg(mut self, value: impl Into<String>) -> Self {
        let value = value.into();
        self.positional_args.push(value.clone());
        self.positional_args_before_dashdash.push(value);
        self
    }

    pub fn with_subcommand_path(mut self, path: Vec<String>) -> Self {
        self.subcommand_path = path;
        self
    }

    pub fn with_stdin_payload_available(mut self) -> Self {
        self.stdin_payload_available = true;
        self
    }

    pub fn with_interactive_session(mut self) -> Self {
        self.interactive_session = true;
        self
    }

    pub fn has_flag(&self, flag_name: &str) -> bool {
        self.flags
            .iter()
            .any(|candidate| flag_token_matches_name(candidate.as_str(), flag_name))
    }

    pub fn flag_count(&self, flag_name: &str) -> usize {
        self.flags
            .iter()
            .filter(|candidate| flag_token_matches_name(candidate.as_str(), flag_name))
            .count()
    }

    pub fn has_modifier(&self, modifier_id: &str) -> bool {
        self.matched_modifiers
            .iter()
            .any(|candidate| candidate.as_str() == modifier_id)
    }

    pub fn has_positional_at(&self, index: usize) -> bool {
        self.positional_args.get(index).is_some()
    }

    pub fn has_modifier_parameter_matching(
        &self,
        modifier_id: &str,
        parameter_name: &str,
        matcher: &ValueMatcher,
    ) -> bool {
        self.matched_modifier_parameters.iter().any(|parameter| {
            parameter.modifier_id.as_str() == modifier_id
                && parameter.parameter_name.as_str() == parameter_name
                && argument_matches_value_matcher(parameter.value.as_str(), matcher)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedModifierParameter {
    pub modifier_id: crate::ModifierId,
    pub parameter_name: crate::SlotName,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgumentScope {
    pub start_index: usize,
    pub end_index: usize,
}

impl ArgumentScope {
    pub fn new(start_index: usize, end_index: usize) -> Self {
        Self {
            start_index,
            end_index,
        }
    }

    pub fn for_invocation(projection: &ProjectedInvocation) -> Self {
        Self::new(0, projection.args.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedModifier<'a> {
    pub modifier: &'a Modifier,
    pub scope: ArgumentScope,
}

impl std::ops::Deref for SelectedModifier<'_> {
    type Target = Modifier;

    fn deref(&self) -> &Self::Target {
        self.modifier
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationSelection<'a> {
    pub form: &'a Form,
    pub form_scope: ArgumentScope,
    pub modifiers: Vec<SelectedModifier<'a>>,
    pub subcommand_path: Vec<String>,
    pub residuals: Vec<Residual>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTokenMatch<'a> {
    Exact,
    ClusterMember,
    LongInlineOperand(&'a str),
    ShortAttachedOperand(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    NoFormMatched {
        command_name: String,
    },
    MultipleFormsMatched {
        command_name: String,
        form_ids: Vec<String>,
    },
    UnknownSubcommand {
        command_name: String,
        attempted_path: Vec<String>,
    },
    UnsupportedProfileFeature {
        command_name: String,
        reason: String,
    },
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFormMatched { command_name } => {
                write!(f, "no form matched for command {command_name:?}")
            }
            Self::MultipleFormsMatched {
                command_name,
                form_ids,
            } => write!(
                f,
                "multiple forms matched for command {command_name:?}: {:?}",
                form_ids
            ),
            Self::UnknownSubcommand {
                command_name,
                attempted_path,
            } => write!(
                f,
                "unknown subcommand path for command {command_name:?}: {:?}",
                attempted_path
            ),
            Self::UnsupportedProfileFeature {
                command_name,
                reason,
            } => write!(
                f,
                "profile for command {command_name:?} uses unsupported binding feature: {reason}"
            ),
        }
    }
}

impl std::error::Error for BindError {}

pub fn select_invocation<'a>(
    profile: &'a CommandProfile,
    projection: &ProjectedInvocation,
) -> Result<InvocationSelection<'a>, BindError> {
    if let Some(subcommands) = &profile.subcommands {
        return select_subcommand_invocation(profile, projection, subcommands);
    }

    let scope = ArgumentScope::for_invocation(projection);
    let modifiers = match_scoped_modifiers(&profile.modifiers, projection, scope, None, &[]);
    let mut scan_state = BindingState::with_modifier_context(projection, &modifiers);

    consume_selected_modifiers_for_scanning(&modifiers, &mut scan_state);

    let form = select_form_for_scope(
        profile.primary_name(),
        &profile.forms,
        projection,
        scope,
        &scan_state.consumed,
        &modifiers,
        &[],
    )?;

    Ok(InvocationSelection {
        form,
        form_scope: scope,
        modifiers,
        subcommand_path: Vec::new(),
        residuals: Vec::new(),
    })
}

pub fn bind_invocation(
    profile: &CommandProfile,
    projection: &ProjectedInvocation,
    selection: &InvocationSelection<'_>,
) -> BoundInvocation {
    let targets = collect_parameter_targets(selection);
    let mut state = BindingState::with_modifier_context(projection, &selection.modifiers);
    let mut parameter_results = vec![None; targets.len()];
    let mut residuals = selection.residuals.clone();

    consume_flag_only_modifiers_for_binding(&selection.modifiers, &mut state);

    // Bind flag-attached values first so they are not later mistaken as plain positionals.
    for (index, target) in targets.iter().enumerate() {
        if is_flag_binding(&target.parameter.binding) {
            parameter_results[index] = bind_parameter_target(target, &mut state, &mut residuals);
        }
    }

    for (index, target) in targets.iter().enumerate() {
        if !is_flag_binding(&target.parameter.binding) {
            parameter_results[index] = bind_parameter_target(target, &mut state, &mut residuals);
        }
    }

    let mut bound = BoundInvocation::new(
        profile.identity.canonical_name.clone(),
        selection.form.id.clone(),
    )
    .with_subcommand_path(selection.subcommand_path.clone());

    for bound_parameter in parameter_results.into_iter().flatten() {
        bound.bound_parameters.push(bound_parameter);
    }

    for implicit_input in &selection.form.implicit_inputs {
        bound.bound_implicit_inputs.push(BoundImplicitInput::new(
            implicit_input.source,
            implicit_input.semantic.clone(),
        ));
    }

    for selected_modifier in selection.modifiers.iter().copied() {
        bound
            .applied_modifiers
            .push(selected_modifier.modifier.id.clone());
    }

    let bound_slots: BTreeSet<_> = bound
        .bound_parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect();

    let bound_implicit_sources: BTreeSet<_> = bound
        .bound_implicit_inputs
        .iter()
        .map(|input| input.source)
        .collect();

    emit_effects(
        &selection.form.effects,
        &bound_slots,
        &bound_implicit_sources,
        &mut bound,
    );

    if !form_suppresses_modifier_effects(selection.form) {
        for selected_modifier in selection.modifiers.iter().copied() {
            emit_effects(
                &selected_modifier.modifier.effects,
                &bound_slots,
                &bound_implicit_sources,
                &mut bound,
            );
        }
    }

    bound.residuals = residuals;
    bound
}

pub(crate) fn bind_modifier_only_invocation(
    profile: &CommandProfile,
    projection: &ProjectedInvocation,
) -> Option<BoundInvocation> {
    let scope = ArgumentScope::for_invocation(projection);
    let modifiers = match_scoped_modifiers(&profile.modifiers, projection, scope, None, &[]);

    if modifiers.is_empty() {
        return None;
    }

    let targets = collect_modifier_parameter_targets(&modifiers);
    let mut state = BindingState::with_modifier_context(projection, &modifiers);
    let mut parameter_results = vec![None; targets.len()];
    let mut residuals = Vec::new();

    for (index, target) in targets.iter().enumerate() {
        if is_flag_binding(&target.parameter.binding) {
            parameter_results[index] = bind_parameter_target(target, &mut state, &mut residuals);
        }
    }

    for (index, target) in targets.iter().enumerate() {
        if !is_flag_binding(&target.parameter.binding) {
            parameter_results[index] = bind_parameter_target(target, &mut state, &mut residuals);
        }
    }

    let mut bound = BoundInvocation::new(
        profile.identity.canonical_name.clone(),
        FormId::new("__modifier_only__"),
    );

    for bound_parameter in parameter_results.into_iter().flatten() {
        bound.bound_parameters.push(bound_parameter);
    }

    for selected_modifier in modifiers.iter().copied() {
        bound
            .applied_modifiers
            .push(selected_modifier.modifier.id.clone());
    }

    let bound_slots: BTreeSet<_> = bound
        .bound_parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect();
    let bound_implicit_sources = BTreeSet::new();

    for selected_modifier in modifiers.iter().copied() {
        emit_effects(
            &selected_modifier.modifier.effects,
            &bound_slots,
            &bound_implicit_sources,
            &mut bound,
        );
    }

    bound.residuals = residuals;
    Some(bound)
}

pub fn select_form<'a>(
    profile: &'a CommandProfile,
    shape: &InvocationShape,
) -> Result<&'a Form, BindError> {
    select_form_from_forms(profile.primary_name(), &profile.forms, shape)
}

pub fn match_modifiers<'a>(
    profile: &'a CommandProfile,
    shape: &InvocationShape,
) -> Vec<&'a Modifier> {
    let declared_short_flags = declared_short_modifier_flags(&profile.modifiers);
    let short_flags_allowing_attached_operands =
        short_flags_allowing_attached_operands(&profile.modifiers);
    let candidates: Vec<&Modifier> = profile
        .modifiers
        .iter()
        .filter(|modifier| modifier_matches(modifier, shape))
        .collect();

    filter_modifier_candidates_by_constraints(
        candidates,
        |flag_name| {
            constraint_flag_matches_in_shape(
                shape,
                flag_name,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        },
        &shape.matched_modifiers,
    )
}

fn select_subcommand_invocation<'a>(
    profile: &'a CommandProfile,
    projection: &ProjectedInvocation,
    subcommands: &'a SubcommandTree,
) -> Result<InvocationSelection<'a>, BindError> {
    let root_scope = ArgumentScope::for_invocation(projection);
    let mut selected_modifiers =
        match_leading_root_modifiers(&profile.modifiers, projection, root_scope, subcommands);
    let mut scan_state = BindingState::with_modifier_context(projection, &selected_modifiers);

    consume_selected_modifiers_for_scanning(&selected_modifiers, &mut scan_state);

    let mut path = Vec::new();
    let mut scan_start = 0;
    let mut children = subcommands.roots.as_slice();
    let mut selected_node = None;

    while let Some((index, text)) =
        next_unconsumed_positional_from(projection, &scan_state.consumed, scan_start)
    {
        let Some(node) = find_subcommand_node(children, text) else {
            break;
        };

        path.push(node.name.clone());
        scan_state.consumed[index] = true;
        scan_start = index + 1;

        let node_scope = ArgumentScope::new(scan_start, projection.args.len());
        let node_modifiers = match_scoped_modifiers(
            &node.modifiers,
            projection,
            node_scope,
            Some(&scan_state.consumed),
            &selected_modifiers,
        );

        selected_modifiers.extend(node_modifiers.iter().copied());
        scan_state.set_modifier_context(&selected_modifiers);
        consume_selected_modifiers_for_scanning(&node_modifiers, &mut scan_state);

        selected_node = Some(node);
        children = node.children.as_slice();
    }

    let Some(node) = selected_node else {
        if !profile.forms.is_empty() {
            let form = select_form_for_scope(
                profile.primary_name(),
                &profile.forms,
                projection,
                root_scope,
                &scan_state.consumed,
                &selected_modifiers,
                &[],
            )?;

            return Ok(InvocationSelection {
                form,
                form_scope: root_scope,
                modifiers: selected_modifiers,
                subcommand_path: Vec::new(),
                residuals: Vec::new(),
            });
        }

        if let Some((_, text)) =
            next_unconsumed_positional_from(projection, &scan_state.consumed, 0)
        {
            return Err(BindError::UnknownSubcommand {
                command_name: profile.primary_name().to_string(),
                attempted_path: vec![text.to_string()],
            });
        }

        return Err(BindError::NoFormMatched {
            command_name: profile.primary_name().to_string(),
        });
    };

    let form_scope = ArgumentScope::new(scan_start, projection.args.len());
    match select_form_for_scope(
        profile.primary_name(),
        &node.forms,
        projection,
        form_scope,
        &scan_state.consumed,
        &selected_modifiers,
        &path,
    ) {
        Ok(form) => Ok(InvocationSelection {
            form,
            form_scope,
            modifiers: selected_modifiers,
            subcommand_path: path,
            residuals: Vec::new(),
        }),
        Err(BindError::NoFormMatched { .. }) => {
            if let Some((_, text)) =
                next_unconsumed_positional_from(projection, &scan_state.consumed, scan_start)
            {
                let mut attempted_path = path;
                attempted_path.push(text.to_string());

                return unknown_subcommand_error(profile.primary_name(), attempted_path, node);
            }

            Err(BindError::NoFormMatched {
                command_name: profile.primary_name().to_string(),
            })
        }
        Err(error) => Err(error),
    }
}

fn unknown_subcommand_error<'a>(
    command_name: &str,
    attempted_path: Vec<String>,
    node: &SubcommandNode,
) -> Result<InvocationSelection<'a>, BindError> {
    match node
        .default_behavior
        .unwrap_or(DefaultSubcommandBehavior::RejectUnknown)
    {
        DefaultSubcommandBehavior::RejectUnknown
        | DefaultSubcommandBehavior::ResidualUnknownSubcommand => {
            Err(BindError::UnknownSubcommand {
                command_name: command_name.to_string(),
                attempted_path,
            })
        }
    }
}

fn select_form_from_forms<'a>(
    command_name: &str,
    forms: &'a [Form],
    shape: &InvocationShape,
) -> Result<&'a Form, BindError> {
    resolve_matched_forms(
        command_name,
        forms.iter().filter(|form| form_matches(form, shape)),
    )
}

fn select_form_for_scope<'a>(
    command_name: &str,
    forms: &'a [Form],
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    consumed: &[bool],
    modifiers: &[SelectedModifier<'_>],
    subcommand_path: &[String],
) -> Result<&'a Form, BindError> {
    let shape =
        shape_for_scope_with_consumed(projection, scope, consumed, modifiers, subcommand_path);
    let matched_forms: Vec<FormConsumptionPreview<'a>> = forms
        .iter()
        .filter(|form| form_matches(form, &shape))
        .map(|form| preview_form_consumption(form, projection, scope, consumed))
        .filter(|preview| {
            let remaining_shape = shape_for_scope_with_consumed(
                projection,
                scope,
                &preview.consumed,
                modifiers,
                subcommand_path,
            );

            remaining_selector_matches(preview.form, &remaining_shape)
        })
        .collect();

    resolve_matched_forms(
        command_name,
        matched_forms.into_iter().map(|preview| preview.form),
    )
}

fn resolve_matched_forms<'a>(
    command_name: &str,
    matched_forms: impl IntoIterator<Item = &'a Form>,
) -> Result<&'a Form, BindError> {
    let matched_forms: Vec<&Form> = matched_forms.into_iter().collect();

    if matched_forms.is_empty() {
        return Err(BindError::NoFormMatched {
            command_name: command_name.to_string(),
        });
    }

    if matched_forms.len() > 1 {
        return Err(BindError::MultipleFormsMatched {
            command_name: command_name.to_string(),
            form_ids: matched_forms
                .iter()
                .map(|form| form.id.as_str().to_string())
                .collect(),
        });
    }

    Ok(matched_forms[0])
}

fn match_leading_root_modifiers<'a>(
    modifiers: &'a [Modifier],
    projection: &ProjectedInvocation,
    root_scope: ArgumentScope,
    subcommands: &SubcommandTree,
) -> Vec<SelectedModifier<'a>> {
    let mut selected = match_root_flag_only_modifiers(modifiers, projection, root_scope);
    let mut consumed = vec![false; projection.args.len()];

    loop {
        let first_positional = next_unconsumed_positional_from(projection, &consumed, 0);
        if first_positional
            .is_some_and(|(_, text)| find_subcommand_node(&subcommands.roots, text).is_some())
        {
            break;
        }

        let leading_end = first_positional
            .map(|(index, _)| index)
            .unwrap_or(projection.args.len());
        let leading_scope = ArgumentScope::new(root_scope.start_index, leading_end);
        if leading_scope.start_index >= leading_scope.end_index {
            break;
        }

        let mut next = match_leading_parameterized_modifiers(
            modifiers,
            projection,
            leading_scope,
            &consumed,
            &selected,
        );
        if next.is_empty() {
            break;
        }

        for modifier in &mut next {
            modifier.scope = root_scope;
        }

        let before = consumed.clone();
        let mut scan_state = BindingState::with_modifier_context(projection, &next);
        scan_state.consumed = consumed;
        consume_selected_modifiers_for_scanning(&next, &mut scan_state);
        consume_flag_only_modifiers_for_binding(&next, &mut scan_state);
        consumed = scan_state.consumed;
        selected.extend(next);

        if consumed == before {
            break;
        }
    }

    selected
}

fn match_root_flag_only_modifiers<'a>(
    modifiers: &'a [Modifier],
    projection: &ProjectedInvocation,
    root_scope: ArgumentScope,
) -> Vec<SelectedModifier<'a>> {
    let declared_short_flags = declared_short_modifier_flags(modifiers);
    let short_flags_allowing_attached_operands = short_flags_allowing_attached_operands(modifiers);
    let candidates: Vec<&Modifier> = modifiers
        .iter()
        .filter(|modifier| modifier.parameters.is_empty())
        .filter(|modifier| {
            modifier_matches_in_scope(
                modifier,
                projection,
                root_scope,
                None,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        })
        .collect();

    filter_modifier_candidates_by_constraints(
        candidates,
        |flag_name| {
            constraint_flag_matches_in_scope(
                projection,
                root_scope,
                None,
                flag_name,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        },
        &[],
    )
    .into_iter()
    .map(|modifier| SelectedModifier {
        modifier,
        scope: root_scope,
    })
    .collect()
}

fn match_leading_parameterized_modifiers<'a>(
    modifiers: &'a [Modifier],
    projection: &ProjectedInvocation,
    leading_scope: ArgumentScope,
    consumed: &[bool],
    preselected_modifiers: &[SelectedModifier<'_>],
) -> Vec<SelectedModifier<'a>> {
    let declared_short_flags = declared_short_modifier_flags(modifiers);
    let short_flags_allowing_attached_operands = short_flags_allowing_attached_operands(modifiers);
    let preselected_modifier_ids: Vec<_> = preselected_modifiers
        .iter()
        .map(|selected| selected.modifier.id.clone())
        .collect();

    let candidates: Vec<&Modifier> = modifiers
        .iter()
        .filter(|modifier| !modifier.parameters.is_empty())
        .filter(|modifier| {
            modifier_matches_in_scope(
                modifier,
                projection,
                leading_scope,
                Some(consumed),
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        })
        .collect();

    filter_modifier_candidates_by_constraints(
        candidates,
        |flag_name| {
            constraint_flag_matches_in_scope(
                projection,
                leading_scope,
                Some(consumed),
                flag_name,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        },
        &preselected_modifier_ids,
    )
    .into_iter()
    .map(|modifier| SelectedModifier {
        modifier,
        scope: leading_scope,
    })
    .collect()
}

fn match_scoped_modifiers<'a>(
    modifiers: &'a [Modifier],
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    consumed: Option<&[bool]>,
    preselected_modifiers: &[SelectedModifier<'_>],
) -> Vec<SelectedModifier<'a>> {
    let declared_short_flags = declared_short_modifier_flags(modifiers);
    let short_flags_allowing_attached_operands = short_flags_allowing_attached_operands(modifiers);
    let preselected_modifier_ids: Vec<_> = preselected_modifiers
        .iter()
        .map(|selected| selected.modifier.id.clone())
        .collect();

    let candidates: Vec<&Modifier> = modifiers
        .iter()
        .filter(|modifier| {
            modifier_matches_in_scope(
                modifier,
                projection,
                scope,
                consumed,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        })
        .collect();

    filter_modifier_candidates_by_constraints(
        candidates,
        |flag_name| {
            constraint_flag_matches_in_scope(
                projection,
                scope,
                consumed,
                flag_name,
                &declared_short_flags,
                &short_flags_allowing_attached_operands,
            )
        },
        &preselected_modifier_ids,
    )
    .into_iter()
    .map(|modifier| SelectedModifier { modifier, scope })
    .collect()
}

fn consume_selected_modifiers_for_scanning(
    modifiers: &[SelectedModifier<'_>],
    state: &mut BindingState<'_>,
) {
    for selected_modifier in modifiers {
        for parameter in &selected_modifier.modifier.parameters {
            let target = ParameterTarget {
                parameter,
                modifier: Some(selected_modifier.modifier),
                scope: selected_modifier.scope,
            };

            let _ = state.bind_parameter_values(&target);
        }
    }
}

fn consume_flag_only_modifiers_for_binding(
    modifiers: &[SelectedModifier<'_>],
    state: &mut BindingState<'_>,
) {
    for selected_modifier in modifiers {
        if !selected_modifier.modifier.parameters.is_empty() {
            continue;
        }

        state.consume_modifier_flags(selected_modifier.modifier, selected_modifier.scope);
    }
}

fn shape_for_scope_with_consumed<'a>(
    projection: &'a ProjectedInvocation,
    scope: ArgumentScope,
    consumed: &[bool],
    modifiers: &[SelectedModifier<'_>],
    subcommand_path: &[String],
) -> InvocationShape {
    shape_for_scope_internal(
        projection,
        scope,
        Some(consumed),
        modifiers,
        subcommand_path,
    )
}

fn shape_for_scope_internal<'a>(
    projection: &'a ProjectedInvocation,
    scope: ArgumentScope,
    consumed: Option<&[bool]>,
    modifiers: &[SelectedModifier<'_>],
    subcommand_path: &[String],
) -> InvocationShape {
    let mut shape = InvocationShape::new().with_subcommand_path(subcommand_path.to_vec());

    for modifier in modifiers {
        shape.matched_modifiers.push(modifier.modifier.id.clone());
    }
    populate_modifier_parameters_for_shape(projection, modifiers, &mut shape);

    let mut before_dashdash = true;
    for (index, arg) in args_in_scope(projection, scope) {
        if consumed.is_some_and(|consumed| consumed[index]) {
            continue;
        }

        match arg.kind {
            ProjectedArgKind::Flag => shape.flags.push(FlagName::new(arg.text.clone())),
            ProjectedArgKind::Positional => {
                shape.positional_args.push(arg.text.clone());
                if before_dashdash {
                    shape.positional_args_before_dashdash.push(arg.text.clone());
                }
            }
            ProjectedArgKind::DashDash => {
                shape.has_dashdash = true;
                before_dashdash = false;
            }
        }
    }

    shape.stdin_payload_available = projection.stdin_payload_available;
    shape.interactive_session = projection.interactive_session;
    shape
}

fn populate_modifier_parameters_for_shape(
    projection: &ProjectedInvocation,
    modifiers: &[SelectedModifier<'_>],
    shape: &mut InvocationShape,
) {
    for selected_modifier in modifiers {
        for parameter in &selected_modifier.modifier.parameters {
            let target = ParameterTarget {
                parameter,
                modifier: Some(selected_modifier.modifier),
                scope: selected_modifier.scope,
            };

            let mut state = BindingState::with_modifier_context(projection, modifiers);
            let values = state.bind_parameter_values(&target);
            for value in values {
                if let BoundValue::Argument { text, .. } = value {
                    shape
                        .matched_modifier_parameters
                        .push(MatchedModifierParameter {
                            modifier_id: selected_modifier.modifier.id.clone(),
                            parameter_name: parameter.name.clone(),
                            value: text,
                        });
                }
            }
        }
    }
}

fn args_in_scope(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
) -> impl Iterator<Item = (usize, &crate::ProjectedArg)> {
    projection.args[scope.start_index..scope.end_index]
        .iter()
        .enumerate()
        .map(move |(offset, arg)| (scope.start_index + offset, arg))
}

fn next_unconsumed_positional_from<'a>(
    projection: &'a ProjectedInvocation,
    consumed: &[bool],
    start_index: usize,
) -> Option<(usize, &'a str)> {
    projection
        .args
        .iter()
        .enumerate()
        .skip(start_index)
        .find(|(index, arg)| !consumed[*index] && arg.kind == ProjectedArgKind::Positional)
        .map(|(index, arg)| (index, arg.text.as_str()))
}

fn find_subcommand_node<'a>(nodes: &'a [SubcommandNode], text: &str) -> Option<&'a SubcommandNode> {
    nodes
        .iter()
        .find(|node| node.name == text || node.aliases.iter().any(|alias| alias == text))
}

struct ParameterTarget<'a> {
    parameter: &'a Parameter,
    modifier: Option<&'a Modifier>,
    scope: ArgumentScope,
}

struct FormConsumptionPreview<'a> {
    form: &'a Form,
    consumed: Vec<bool>,
}

fn collect_parameter_targets<'a>(selection: &InvocationSelection<'a>) -> Vec<ParameterTarget<'a>> {
    let mut targets = Vec::new();

    for parameter in &selection.form.parameters {
        targets.push(ParameterTarget {
            parameter,
            modifier: None,
            scope: selection.form_scope,
        });
    }

    for selected_modifier in selection.modifiers.iter().copied() {
        for parameter in &selected_modifier.modifier.parameters {
            targets.push(ParameterTarget {
                parameter,
                modifier: Some(selected_modifier.modifier),
                scope: selected_modifier.scope,
            });
        }
    }

    targets
}

fn collect_form_parameter_targets<'a>(
    form: &'a Form,
    scope: ArgumentScope,
) -> Vec<ParameterTarget<'a>> {
    let mut targets = Vec::new();

    for parameter in &form.parameters {
        targets.push(ParameterTarget {
            parameter,
            modifier: None,
            scope,
        });
    }

    targets
}

fn collect_modifier_parameter_targets<'a>(
    modifiers: &[SelectedModifier<'a>],
) -> Vec<ParameterTarget<'a>> {
    let mut targets = Vec::new();

    for selected_modifier in modifiers.iter().copied() {
        for parameter in &selected_modifier.modifier.parameters {
            targets.push(ParameterTarget {
                parameter,
                modifier: Some(selected_modifier.modifier),
                scope: selected_modifier.scope,
            });
        }
    }

    targets
}

fn preview_form_consumption<'a>(
    form: &'a Form,
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    base_consumed: &[bool],
) -> FormConsumptionPreview<'a> {
    let targets = collect_form_parameter_targets(form, scope);
    let mut state = BindingState::with_consumed(projection, base_consumed);

    for target in &targets {
        if is_flag_binding(&target.parameter.binding) {
            let _ = state.bind_parameter_values(target);
        }
    }

    for target in &targets {
        if !is_flag_binding(&target.parameter.binding) {
            let _ = state.bind_parameter_values(target);
        }
    }

    FormConsumptionPreview {
        form,
        consumed: state.consumed,
    }
}

fn remaining_selector_matches(form: &Form, shape: &InvocationShape) -> bool {
    selector_matches(&form.remaining_selector, shape)
}

fn form_suppresses_modifier_effects(form: &Form) -> bool {
    matches!(
        form.id.as_str(),
        "show_help" | "show_version" | "show_usage"
    )
}

fn emit_effects(
    effects: &[Effect],
    bound_slots: &BTreeSet<crate::SlotName>,
    bound_implicit_sources: &BTreeSet<crate::ImplicitInputSource>,
    bound: &mut BoundInvocation,
) {
    for effect in effects {
        let should_emit = match &effect.target {
            EffectTarget::Slot(slot) => bound_slots.contains(slot),
            EffectTarget::ToolConventionPath(_) => true,
            EffectTarget::DerivedPath(target) => {
                let source_bound = match &target.source {
                    crate::DerivedPathSource::Slot(slot) => bound_slots.contains(slot),
                    crate::DerivedPathSource::ToolConventionRoot { .. } => true,
                };
                let root_bound = match &target.root {
                    Some(crate::DerivedPathSource::Slot(slot)) => bound_slots.contains(slot),
                    Some(crate::DerivedPathSource::ToolConventionRoot { .. }) | None => true,
                };

                source_bound && root_bound
            }
            EffectTarget::MutationScope(target) => match target {
                crate::MutationScopeTarget::RepositoryWorktree { subtree, .. } => subtree
                    .as_ref()
                    .is_none_or(|slot| bound_slots.contains(slot)),
            },
            EffectTarget::ImplicitInput(source) => bound_implicit_sources.contains(source),
            EffectTarget::Dispatch(dispatch) => bound_slots.contains(&dispatch.command),
            EffectTarget::None => true,
        };

        if should_emit {
            bound.effects.push(effect.clone());
        }
    }
}

fn is_flag_binding(binding: &BindingSpec) -> bool {
    matches!(
        binding,
        BindingSpec::FollowingFlag { .. } | BindingSpec::FollowingMatchedFlag { .. }
    )
}

fn bind_parameter_target(
    target: &ParameterTarget<'_>,
    state: &mut BindingState<'_>,
    residuals: &mut Vec<Residual>,
) -> Option<BoundParameter> {
    let values = state.bind_parameter_values(target);

    if values.is_empty() {
        if !target.parameter.cardinality.is_optional() {
            residuals.push(
                Residual::new(
                    residual_kind_for_semantic(&target.parameter.semantic),
                    residual_surface_for_semantic(&target.parameter.semantic),
                    format!(
                        "required parameter {} could not be bound from {}",
                        target.parameter.name.as_str(),
                        describe_binding(&target.parameter.binding, target.modifier),
                    ),
                )
                .for_slot(target.parameter.name.as_str()),
            );
        }

        return None;
    }

    if values.len() > 1 && !target.parameter.cardinality.is_variadic() {
        residuals.push(
            Residual::new(
                ResidualKind::AmbiguousBinding,
                residual_surface_for_semantic(&target.parameter.semantic),
                format!(
                    "parameter {} matched {} values from {} but is not variadic",
                    target.parameter.name.as_str(),
                    values.len(),
                    describe_binding(&target.parameter.binding, target.modifier),
                ),
            )
            .for_slot(target.parameter.name.as_str()),
        );
    }

    Some(BoundParameter {
        name: target.parameter.name.clone(),
        semantic: target.parameter.semantic.clone(),
        values,
    })
}

fn residual_kind_for_semantic(semantic: &SemanticType) -> ResidualKind {
    match semantic {
        SemanticType::Path(_) => ResidualKind::UnboundPath,
        SemanticType::Payload(_) => ResidualKind::UnboundPayload,
        SemanticType::CommandRef(_)
        | SemanticType::InProcessCodeLoad(_)
        | SemanticType::ProcessTarget(_) => ResidualKind::UnboundControlSurface,
        SemanticType::PlainValue
        | SemanticType::StructuredValue(_)
        | SemanticType::Endpoint(_)
        | SemanticType::PackageLocator(_) => ResidualKind::UnboundData,
    }
}

fn residual_surface_for_semantic(semantic: &SemanticType) -> ResidualSurface {
    match semantic {
        SemanticType::Path(_) => ResidualSurface::Path,
        SemanticType::Payload(_) => ResidualSurface::Payload,
        SemanticType::CommandRef(_)
        | SemanticType::InProcessCodeLoad(_)
        | SemanticType::ProcessTarget(_) => ResidualSurface::Control,
        SemanticType::PlainValue
        | SemanticType::StructuredValue(_)
        | SemanticType::Endpoint(_)
        | SemanticType::PackageLocator(_) => ResidualSurface::Data,
    }
}

fn describe_binding(binding: &BindingSpec, modifier: Option<&Modifier>) -> String {
    match binding {
        BindingSpec::NextPositional => "next unconsumed positional argument".to_string(),
        BindingSpec::NextPositionalAfterDashDash => {
            "first positional argument after `--`".to_string()
        }
        BindingSpec::PositionalAt(index) => {
            format!("unconsumed positional argument at index {index}")
        }
        BindingSpec::RemainingPositionals => {
            "remaining unconsumed positional arguments".to_string()
        }
        BindingSpec::RemainingPositionalsAfterDashDash => {
            "remaining positional arguments after `--`".to_string()
        }
        BindingSpec::RemainingPositionalsBeforeLast => {
            "remaining unconsumed positional arguments except the last one".to_string()
        }
        BindingSpec::RemainingArgs => "remaining unconsumed argv arguments".to_string(),
        BindingSpec::ArgsUntilLiteral { terminator, .. } => {
            format!("unconsumed argv arguments until literal {terminator:?}")
        }
        BindingSpec::LastPositional => "last unconsumed positional argument".to_string(),
        BindingSpec::LastPositionalBeforeLast => {
            "last unconsumed positional argument before the trailing positional".to_string()
        }
        BindingSpec::FollowingFlag { flag_name, .. } => {
            format!("value following flag {}", flag_name.as_str())
        }
        BindingSpec::FollowingMatchedFlag { .. } => {
            let modifier =
                modifier.expect("FollowingMatchedFlag should only be used by modifier parameters");
            let joined = modifier
                .matcher
                .flag_names()
                .iter()
                .map(|flag_name| flag_name.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            format!("value following matched modifier flag [{joined}]")
        }
        BindingSpec::ArgsWithPrefix(prefix) => {
            format!("argv arguments prefixed with {prefix:?}")
        }
        BindingSpec::LeadingPositionalsWhile(_) => {
            "leading positional arguments matching a constrained semantic pattern".to_string()
        }
    }
}

struct BindingState<'a> {
    projection: &'a ProjectedInvocation,
    consumed: Vec<bool>,
    declared_short_flags: BTreeSet<String>,
    short_flags_allowing_attached_operands: BTreeSet<String>,
}

impl<'a> BindingState<'a> {
    fn new(projection: &'a ProjectedInvocation) -> Self {
        Self {
            projection,
            consumed: vec![false; projection.args.len()],
            declared_short_flags: BTreeSet::new(),
            short_flags_allowing_attached_operands: BTreeSet::new(),
        }
    }

    fn with_consumed(projection: &'a ProjectedInvocation, consumed: &[bool]) -> Self {
        Self {
            projection,
            consumed: consumed.to_vec(),
            declared_short_flags: BTreeSet::new(),
            short_flags_allowing_attached_operands: BTreeSet::new(),
        }
    }

    fn with_modifier_context(
        projection: &'a ProjectedInvocation,
        modifiers: &[SelectedModifier<'_>],
    ) -> Self {
        let mut state = Self::new(projection);
        state.set_modifier_context(modifiers);
        state
    }

    fn set_modifier_context(&mut self, modifiers: &[SelectedModifier<'_>]) {
        self.declared_short_flags = declared_short_modifier_flags_from_selected(modifiers);
        self.short_flags_allowing_attached_operands =
            short_flags_allowing_attached_operands_from_selected(modifiers);
    }

    fn bind_parameter_values(&mut self, target: &ParameterTarget<'_>) -> Vec<BoundValue> {
        let value_constraints = &target.parameter.value_constraints;

        match &target.parameter.binding {
            BindingSpec::FollowingFlag {
                flag_name,
                operand_mode,
            } => self.consume_values_following_flags(
                std::slice::from_ref(flag_name),
                *operand_mode,
                target.scope,
                None,
                value_constraints,
            ),
            BindingSpec::FollowingMatchedFlag { operand_mode } => {
                let modifier = target
                    .modifier
                    .expect("FollowingMatchedFlag should only be used by modifier parameters");
                self.consume_values_following_flags(
                    modifier.matcher.flag_names(),
                    *operand_mode,
                    target.scope,
                    Some(modifier),
                    value_constraints,
                )
            }
            BindingSpec::ArgsWithPrefix(prefix) => {
                self.consume_args_with_prefix(target.scope, prefix, value_constraints)
            }
            BindingSpec::NextPositional => self
                .consume_next_positional(
                    target.scope,
                    PositionalBindingSource::NextPositional,
                    value_constraints,
                )
                .into_iter()
                .collect(),
            BindingSpec::NextPositionalAfterDashDash => self
                .consume_next_positional_after_dashdash(target.scope, value_constraints)
                .into_iter()
                .collect(),
            BindingSpec::PositionalAt(index) => self
                .consume_positional_at(target.scope, *index, value_constraints)
                .into_iter()
                .collect(),
            BindingSpec::RemainingPositionals => {
                self.consume_remaining_positionals(target.scope, value_constraints)
            }
            BindingSpec::RemainingPositionalsAfterDashDash => {
                self.consume_remaining_positionals_after_dashdash(target.scope, value_constraints)
            }
            BindingSpec::RemainingPositionalsBeforeLast => {
                self.consume_remaining_positionals_before_last(target.scope, value_constraints)
            }
            BindingSpec::RemainingArgs => {
                self.consume_remaining_args(target.scope, value_constraints)
            }
            BindingSpec::ArgsUntilLiteral {
                terminator,
                include_terminator,
            } => self.consume_args_until_literal(
                target.scope,
                terminator,
                *include_terminator,
                value_constraints,
            ),
            BindingSpec::LastPositional => self
                .consume_last_positional(
                    target.scope,
                    PositionalBindingSource::LastPositional,
                    value_constraints,
                )
                .into_iter()
                .collect(),
            BindingSpec::LastPositionalBeforeLast => self
                .consume_last_positional_before_last(target.scope, value_constraints)
                .into_iter()
                .collect(),
            BindingSpec::LeadingPositionalsWhile(matcher) => {
                self.consume_leading_positionals_while(target.scope, matcher, value_constraints)
            }
        }
    }

    fn consume_modifier_flags(&mut self, modifier: &Modifier, scope: ArgumentScope) {
        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Flag {
                continue;
            }

            if modifier
                .matcher
                .flag_names()
                .iter()
                .any(|flag_name| flag_token_matches_name(arg.text.as_str(), flag_name.as_str()))
            {
                self.consumed[index] = true;
            }
        }
    }

    fn consume_values_following_flags(
        &mut self,
        flag_names: &[FlagName],
        operand_mode: FlagOperandMode,
        scope: ArgumentScope,
        modifier: Option<&Modifier>,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let mut values = Vec::new();
        let allow_short_attached = modifier.is_some()
            && matches!(
                operand_mode,
                FlagOperandMode::NextArg | FlagOperandMode::InlineOrShortAttached
            );
        let declared_short_flags = modifier
            .map(|modifier| declared_short_modifier_flags(std::slice::from_ref(modifier)))
            .unwrap_or_default();
        let mut saw_positional = false;

        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind == ProjectedArgKind::Positional {
                saw_positional = true;
                continue;
            }

            if arg.kind != ProjectedArgKind::Flag {
                continue;
            }

            let Some((matched_flag_name, flag_match)) = flag_names.iter().find_map(|flag_name| {
                flag_token_binding_match(
                    arg.text.as_str(),
                    flag_name.as_str(),
                    allow_short_attached && !saw_positional,
                    matches!(operand_mode, FlagOperandMode::InlineOrShortAttached),
                    &declared_short_flags,
                    &self.declared_short_flags,
                    &self.short_flags_allowing_attached_operands,
                    true,
                )
                .or_else(|| {
                    (modifier.is_none()
                        && short_flag_cluster_contains_name(arg.text.as_str(), flag_name.as_str()))
                    .then_some(FlagTokenMatch::ClusterMember)
                })
                .map(|flag_match| (flag_name, flag_match))
            }) else {
                continue;
            };

            let binding_source = match modifier {
                Some(modifier) => ArgumentBindingSource::MatchedModifierFlag {
                    modifier_id: modifier.id.clone(),
                    flag_name: matched_flag_name.clone(),
                    flag_span: arg.span.clone(),
                },
                None => ArgumentBindingSource::FollowingFlag {
                    flag_name: matched_flag_name.clone(),
                    flag_span: arg.span.clone(),
                },
            };

            self.consumed[index] = true;

            match flag_match {
                FlagTokenMatch::Exact | FlagTokenMatch::ClusterMember => {
                    if matches!(
                        operand_mode,
                        FlagOperandMode::InlineOnly | FlagOperandMode::InlineOrShortAttached
                    ) {
                        continue;
                    }

                    if let Some(value) = self.consume_flag_operand_after(
                        index,
                        scope,
                        binding_source,
                        operand_mode,
                        value_constraints,
                    ) {
                        values.push(value);
                    }
                }
                FlagTokenMatch::LongInlineOperand(inline_operand)
                | FlagTokenMatch::ShortAttachedOperand(inline_operand) => {
                    if matches!(operand_mode, FlagOperandMode::SecondArg) {
                        continue;
                    }

                    if argument_satisfies_value_constraints(inline_operand, value_constraints) {
                        values.push(BoundValue::argument_with_node_kind(
                            inline_operand.to_string(),
                            arg.quoted,
                            arg.node_kind.clone(),
                            arg.span.clone(),
                            binding_source,
                        ));
                    }
                }
            }
        }

        values
    }

    fn consume_flag_operand_after(
        &mut self,
        flag_index: usize,
        scope: ArgumentScope,
        binding_source: ArgumentBindingSource,
        operand_mode: FlagOperandMode,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        match operand_mode {
            FlagOperandMode::NextPositional => self.consume_immediate_positional_after(
                flag_index,
                scope,
                binding_source,
                value_constraints,
            ),
            FlagOperandMode::NextArg => self.consume_immediate_arg_after(
                flag_index,
                scope,
                binding_source,
                value_constraints,
            ),
            FlagOperandMode::SecondArg => self.consume_second_immediate_arg_after(
                flag_index,
                scope,
                binding_source,
                value_constraints,
            ),
            FlagOperandMode::InlineOnly | FlagOperandMode::InlineOrShortAttached => None,
            FlagOperandMode::NextPositionalAfterDashDash => self
                .consume_positional_after_optional_dashdash(
                    flag_index,
                    scope,
                    binding_source,
                    value_constraints,
                ),
        }
    }

    fn consume_immediate_arg_after(
        &mut self,
        flag_index: usize,
        scope: ArgumentScope,
        binding_source: ArgumentBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let value_index = flag_index.checked_add(1)?;
        if value_index >= scope.end_index || self.consumed[value_index] {
            return None;
        }

        let arg = self.projection.args.get(value_index)?;
        self.consumed[value_index] = true;

        argument_satisfies_value_constraints(arg.text.as_str(), value_constraints).then(|| {
            BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                binding_source,
            )
        })
    }

    fn consume_second_immediate_arg_after(
        &mut self,
        flag_index: usize,
        scope: ArgumentScope,
        binding_source: ArgumentBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let skipped_index = flag_index.checked_add(1)?;
        let value_index = flag_index.checked_add(2)?;

        if value_index >= scope.end_index {
            return None;
        }

        if self.consumed.get(skipped_index).copied().unwrap_or(true)
            || self.consumed.get(value_index).copied().unwrap_or(true)
        {
            return None;
        }

        self.consumed[skipped_index] = true;
        let arg = self.projection.args.get(value_index)?;
        self.consumed[value_index] = true;

        argument_satisfies_value_constraints(arg.text.as_str(), value_constraints).then(|| {
            BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                binding_source,
            )
        })
    }

    fn consume_immediate_positional_after(
        &mut self,
        flag_index: usize,
        scope: ArgumentScope,
        binding_source: ArgumentBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let value_index = flag_index.checked_add(1)?;
        if value_index >= scope.end_index {
            return None;
        }

        let arg = self.projection.args.get(value_index)?;

        if self.consumed[value_index] || arg.kind != ProjectedArgKind::Positional {
            return None;
        }

        self.consumed[value_index] = true;

        argument_satisfies_value_constraints(arg.text.as_str(), value_constraints).then(|| {
            BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                binding_source,
            )
        })
    }

    fn consume_positional_after_optional_dashdash(
        &mut self,
        flag_index: usize,
        scope: ArgumentScope,
        binding_source: ArgumentBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let mut value_index = flag_index.checked_add(1)?;
        if value_index >= scope.end_index || self.consumed[value_index] {
            return None;
        }

        if self.projection.args.get(value_index)?.kind == ProjectedArgKind::DashDash {
            self.consumed[value_index] = true;
            value_index += 1;

            if value_index >= scope.end_index || self.consumed[value_index] {
                return None;
            }
        }

        let arg = self.projection.args.get(value_index)?;
        if arg.kind != ProjectedArgKind::Positional {
            return None;
        }

        self.consumed[value_index] = true;

        argument_satisfies_value_constraints(arg.text.as_str(), value_constraints).then(|| {
            BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                binding_source,
            )
        })
    }

    fn consume_next_positional(
        &mut self,
        scope: ArgumentScope,
        binding_kind: PositionalBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                continue;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional { kind: binding_kind },
            );
            self.consumed[index] = true;
            return Some(value);
        }

        None
    }

    fn consume_positional_at(
        &mut self,
        scope: ArgumentScope,
        positional_index: usize,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let mut seen_positionals = 0usize;

        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if seen_positionals != positional_index {
                seen_positionals += 1;
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                return None;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional {
                    kind: PositionalBindingSource::PositionalAt(positional_index),
                },
            );
            self.consumed[index] = true;
            return Some(value);
        }

        None
    }

    fn consume_remaining_positionals(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let mut values = Vec::new();

        while let Some(value) = self.consume_next_positional(
            scope,
            PositionalBindingSource::RemainingPositionals,
            value_constraints,
        ) {
            values.push(value);
        }

        values
    }

    fn consume_next_positional_after_dashdash(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let dashdash_index = (scope.start_index..scope.end_index).find(|index| {
            !self.consumed[*index]
                && self.projection.args[*index].kind == ProjectedArgKind::DashDash
        })?;

        self.consumed[dashdash_index] = true;

        for index in dashdash_index + 1..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                continue;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional {
                    kind: PositionalBindingSource::NextPositionalAfterDashDash,
                },
            );
            self.consumed[index] = true;
            return Some(value);
        }

        None
    }

    fn consume_remaining_positionals_after_dashdash(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let Some(mut start_index) = (scope.start_index..scope.end_index).find(|index| {
            !self.consumed[*index]
                && self.projection.args[*index].kind == ProjectedArgKind::DashDash
        }) else {
            return Vec::new();
        };

        self.consumed[start_index] = true;
        start_index += 1;

        let mut values = Vec::new();

        for index in start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                continue;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional {
                    kind: PositionalBindingSource::RemainingPositionals,
                },
            );
            self.consumed[index] = true;
            values.push(value);
        }

        values
    }

    fn consume_remaining_positionals_before_last(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let mut values = Vec::new();

        while self.count_unconsumed_positionals(scope, value_constraints) > 1 {
            let Some(value) = self.consume_next_positional(
                scope,
                PositionalBindingSource::RemainingPositionalsBeforeLast,
                value_constraints,
            ) else {
                break;
            };

            values.push(value);
        }

        values
    }

    fn consume_last_positional(
        &mut self,
        scope: ArgumentScope,
        binding_kind: PositionalBindingSource,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        for index in (scope.start_index..scope.end_index).rev() {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                continue;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional { kind: binding_kind },
            );
            self.consumed[index] = true;
            return Some(value);
        }

        None
    }

    fn consume_last_positional_before_last(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Option<BoundValue> {
        let mut matched_indices = Vec::new();

        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                continue;
            }

            if !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                continue;
            }

            matched_indices.push(index);
        }

        let index = *matched_indices.get(matched_indices.len().checked_sub(2)?)?;
        let arg = &self.projection.args[index];
        self.consumed[index] = true;

        Some(BoundValue::argument_with_node_kind(
            arg.text.clone(),
            arg.quoted,
            arg.node_kind.clone(),
            arg.span.clone(),
            ArgumentBindingSource::Positional {
                kind: PositionalBindingSource::LastPositionalBeforeLast,
            },
        ))
    }

    fn count_unconsumed_positionals(
        &self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> usize {
        (scope.start_index..scope.end_index)
            .filter(|index| {
                !self.consumed[*index]
                    && self.projection.args[*index].kind == ProjectedArgKind::Positional
                    && argument_satisfies_value_constraints(
                        self.projection.args[*index].text.as_str(),
                        value_constraints,
                    )
            })
            .count()
    }

    fn consume_remaining_args(
        &mut self,
        scope: ArgumentScope,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let start_index = self
            .consumed
            .iter()
            .enumerate()
            .take(scope.end_index)
            .skip(scope.start_index)
            .filter_map(|(index, consumed)| consumed.then_some(index + 1))
            .max()
            .unwrap_or(scope.start_index);

        let mut values = Vec::new();

        for index in start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            self.consumed[index] = true;

            if argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                values.push(BoundValue::argument_with_node_kind(
                    arg.text.clone(),
                    arg.quoted,
                    arg.node_kind.clone(),
                    arg.span.clone(),
                    ArgumentBindingSource::RemainingArg,
                ));
            }
        }

        values
    }

    fn consume_args_until_literal(
        &mut self,
        scope: ArgumentScope,
        terminator: &str,
        include_terminator: bool,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let start_index = self
            .consumed
            .iter()
            .enumerate()
            .take(scope.end_index)
            .skip(scope.start_index)
            .filter_map(|(index, consumed)| consumed.then_some(index + 1))
            .max()
            .unwrap_or(scope.start_index);

        let mut values = Vec::new();

        for index in start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.text == terminator {
                self.consumed[index] = true;

                if include_terminator
                    && argument_satisfies_value_constraints(arg.text.as_str(), value_constraints)
                {
                    values.push(BoundValue::argument_with_node_kind(
                        arg.text.clone(),
                        arg.quoted,
                        arg.node_kind.clone(),
                        arg.span.clone(),
                        ArgumentBindingSource::RemainingArg,
                    ));
                }

                break;
            }

            self.consumed[index] = true;

            if argument_satisfies_value_constraints(arg.text.as_str(), value_constraints) {
                values.push(BoundValue::argument_with_node_kind(
                    arg.text.clone(),
                    arg.quoted,
                    arg.node_kind.clone(),
                    arg.span.clone(),
                    ArgumentBindingSource::RemainingArg,
                ));
            }
        }

        values
    }

    fn consume_leading_positionals_while(
        &mut self,
        scope: ArgumentScope,
        matcher: &ValueMatcher,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let mut values = Vec::new();

        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            if arg.kind != ProjectedArgKind::Positional {
                break;
            }

            if !argument_matches_value_matcher(&arg.text, matcher)
                || !argument_satisfies_value_constraints(arg.text.as_str(), value_constraints)
            {
                break;
            }

            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::Positional {
                    kind: PositionalBindingSource::LeadingPositionals,
                },
            );
            self.consumed[index] = true;
            values.push(value);
        }

        values
    }

    fn consume_args_with_prefix(
        &mut self,
        scope: ArgumentScope,
        prefix: &str,
        value_constraints: &[ValueConstraint],
    ) -> Vec<BoundValue> {
        let mut values = Vec::new();

        for index in scope.start_index..scope.end_index {
            if self.consumed[index] {
                continue;
            }

            let arg = &self.projection.args[index];
            let Some(stripped) = arg.text.strip_prefix(prefix) else {
                continue;
            };

            self.consumed[index] = true;

            if argument_satisfies_value_constraints(stripped, value_constraints) {
                values.push(BoundValue::argument_with_node_kind(
                    stripped.to_string(),
                    arg.quoted,
                    arg.node_kind.clone(),
                    arg.span.clone(),
                    ArgumentBindingSource::ArgumentPrefix {
                        prefix: prefix.to_string(),
                    },
                ));
            }
        }

        values
    }
}

fn argument_satisfies_value_constraints(text: &str, value_constraints: &[ValueConstraint]) -> bool {
    value_constraints.iter().all(|constraint| match constraint {
        ValueConstraint::ExcludeLiteral(value) => text != value,
    })
}

fn form_matches(form: &Form, shape: &InvocationShape) -> bool {
    selector_matches(&form.selector, shape)
}

fn selector_matches(selector: &SelectorExpr, shape: &InvocationShape) -> bool {
    match selector {
        SelectorExpr::All(items) => items.iter().all(|item| selector_matches(item, shape)),
        SelectorExpr::Any(items) => items.iter().any(|item| selector_matches(item, shape)),
        SelectorExpr::Not(item) => !selector_matches(item, shape),
        SelectorExpr::Predicate(predicate) => predicate_matches(predicate, shape),
    }
}

fn predicate_matches(predicate: &SelectorPredicate, shape: &InvocationShape) -> bool {
    match predicate {
        SelectorPredicate::HasFlag(flag_name) => shape.has_flag(flag_name.as_str()),
        SelectorPredicate::HasFlagAtLeast(flag_name, count) => {
            shape.flag_count(flag_name.as_str()) >= *count
        }
        SelectorPredicate::LacksFlag(flag_name) => !shape.has_flag(flag_name.as_str()),
        SelectorPredicate::HasModifier(modifier_id) => shape.has_modifier(modifier_id.as_str()),
        SelectorPredicate::HasModifierParameterMatching(modifier_id, parameter_name, matcher) => {
            shape.has_modifier_parameter_matching(
                modifier_id.as_str(),
                parameter_name.as_str(),
                matcher,
            )
        }
        SelectorPredicate::HasPositionalAt(index) => shape.has_positional_at(*index),
        SelectorPredicate::HasPositionalBeforeDashDashAt(index) => {
            shape.positional_args_before_dashdash.get(*index).is_some()
        }
        SelectorPredicate::HasPositionalAtMatching(index, matcher) => shape
            .positional_args
            .get(*index)
            .is_some_and(|text| argument_matches_value_matcher(text, matcher)),
        SelectorPredicate::HasPositionalAtOrAfterMatching(index, matcher) => shape
            .positional_args
            .iter()
            .skip(*index)
            .any(|text| argument_matches_value_matcher(text, matcher)),
        SelectorPredicate::HasPositionalAfterLeadingMatcher(matcher) => {
            leading_positional_prefix_len(shape, matcher) < shape.positional_args.len()
        }
        SelectorPredicate::NoPositionalAfterLeadingMatcher(matcher) => {
            leading_positional_prefix_len(shape, matcher) == shape.positional_args.len()
        }
        SelectorPredicate::LastPositionalMatches(matcher) => shape
            .positional_args
            .last()
            .is_some_and(|text| argument_matches_value_matcher(text, matcher)),
        SelectorPredicate::NoPositionalArgs => shape.positional_args.is_empty(),
        SelectorPredicate::HasDashDash => shape.has_dashdash,
        SelectorPredicate::NoDashDash => !shape.has_dashdash,
        SelectorPredicate::StdinPayloadAvailable => shape.stdin_payload_available,
        SelectorPredicate::InteractiveSession => shape.interactive_session,
        SelectorPredicate::HasSubcommandPath(path) => shape.subcommand_path == *path,
        SelectorPredicate::HasRuntimeFeature(feature) => runtime_feature_matches(*feature, shape),
    }
}

fn modifier_matches(modifier: &Modifier, shape: &InvocationShape) -> bool {
    matcher_matches(&modifier.matcher, shape)
}

fn filter_modifier_candidates_by_constraints<'a, F>(
    candidates: Vec<&'a Modifier>,
    has_flag: F,
    preselected_modifier_ids: &[crate::ModifierId],
) -> Vec<&'a Modifier>
where
    F: Fn(&str) -> bool,
{
    let preselected_ids: BTreeSet<&str> = preselected_modifier_ids
        .iter()
        .map(|modifier_id| modifier_id.as_str())
        .collect();
    let mut retained = candidates;

    loop {
        let active_ids: BTreeSet<&str> = preselected_ids
            .iter()
            .copied()
            .chain(retained.iter().map(|modifier| modifier.id.as_str()))
            .collect();
        let retained_len = retained.len();
        let next: Vec<&Modifier> = retained
            .into_iter()
            .filter(|modifier| modifier_constraints_satisfied(modifier, &active_ids, &has_flag))
            .collect();

        if next.len() == retained_len {
            return next;
        }

        retained = next;
    }
}

fn modifier_constraints_satisfied<F>(
    modifier: &Modifier,
    active_ids: &BTreeSet<&str>,
    has_flag: &F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    modifier
        .constraints
        .iter()
        .all(|constraint| match constraint {
            crate::ModifierConstraint::MutuallyExclusiveWith(other) => {
                !active_ids.contains(other.as_str())
            }
            crate::ModifierConstraint::RequiresModifier(other) => {
                active_ids.contains(other.as_str())
            }
            crate::ModifierConstraint::RequiresFlag(flag_name) => has_flag(flag_name.as_str()),
        })
}

fn modifier_matches_in_scope(
    modifier: &Modifier,
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    consumed: Option<&[bool]>,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    let flags = modifier.matcher.flag_names();
    let allow_short_attached = modifier_allows_short_attached(modifier);
    let allow_ambiguous_short_attached = modifier_uses_inline_or_short_attached(modifier);
    let allow_inline_long_operand = modifier_allows_inline_long_operand(modifier);

    !flags.is_empty()
        && match &modifier.matcher {
            ModifierMatcher::AnyFlag(_) => flags.iter().any(|flag_name| {
                modifier_flag_matches_in_scope(
                    projection,
                    scope,
                    consumed,
                    flag_name.as_str(),
                    allow_short_attached,
                    allow_ambiguous_short_attached,
                    allow_inline_long_operand,
                    declared_short_flags,
                    short_flags_allowing_attached_operands,
                )
            }),
            ModifierMatcher::AllFlags(_) => flags.iter().all(|flag_name| {
                modifier_flag_matches_in_scope(
                    projection,
                    scope,
                    consumed,
                    flag_name.as_str(),
                    allow_short_attached,
                    allow_ambiguous_short_attached,
                    allow_inline_long_operand,
                    declared_short_flags,
                    short_flags_allowing_attached_operands,
                )
            }),
        }
}

fn modifier_flag_matches_in_scope(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    consumed: Option<&[bool]>,
    flag_name: &str,
    allow_short_attached: bool,
    allow_ambiguous_short_attached: bool,
    allow_inline_long_operand: bool,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    let mut saw_positional = false;

    for (index, arg) in args_in_scope(projection, scope) {
        if consumed.is_some_and(|consumed| consumed[index]) {
            continue;
        }

        match arg.kind {
            ProjectedArgKind::Positional => {
                saw_positional = true;
            }
            ProjectedArgKind::Flag => {
                if modifier_flag_token_matches_name(
                    arg.text.as_str(),
                    flag_name,
                    allow_short_attached && !saw_positional,
                    allow_ambiguous_short_attached,
                    allow_inline_long_operand,
                    declared_short_flags,
                    short_flags_allowing_attached_operands,
                ) || short_flag_cluster_matches_flag_only_modifier(
                    arg.text.as_str(),
                    flag_name,
                    declared_short_flags,
                    short_flags_allowing_attached_operands,
                ) {
                    return true;
                }
            }
            ProjectedArgKind::DashDash => {}
        }
    }

    false
}

fn constraint_flag_matches_in_scope(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    consumed: Option<&[bool]>,
    flag_name: &str,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    for (index, arg) in args_in_scope(projection, scope) {
        if consumed.is_some_and(|consumed| consumed[index]) {
            continue;
        }

        if arg.kind != ProjectedArgKind::Flag {
            continue;
        }

        if modifier_flag_token_matches_name(
            arg.text.as_str(),
            flag_name,
            true,
            true,
            true,
            declared_short_flags,
            short_flags_allowing_attached_operands,
        ) || short_flag_cluster_matches_flag_only_modifier(
            arg.text.as_str(),
            flag_name,
            declared_short_flags,
            short_flags_allowing_attached_operands,
        ) {
            return true;
        }
    }

    false
}

fn constraint_flag_matches_in_shape(
    shape: &InvocationShape,
    flag_name: &str,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    shape.flags.iter().any(|candidate| {
        modifier_flag_token_matches_name(
            candidate.as_str(),
            flag_name,
            true,
            true,
            true,
            declared_short_flags,
            short_flags_allowing_attached_operands,
        ) || short_flag_cluster_matches_flag_only_modifier(
            candidate.as_str(),
            flag_name,
            declared_short_flags,
            short_flags_allowing_attached_operands,
        )
    })
}

fn modifier_flag_token_matches_name(
    token_text: &str,
    flag_name: &str,
    allow_short_attached: bool,
    allow_ambiguous_short_attached: bool,
    allow_inline_long_operand: bool,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    if token_text == flag_name {
        return true;
    }

    if allow_inline_long_operand && inline_long_flag_operand(token_text, flag_name).is_some() {
        return true;
    }

    allow_short_attached
        && flag_token_binding_match(
            token_text,
            flag_name,
            allow_short_attached,
            allow_ambiguous_short_attached,
            declared_short_flags,
            declared_short_flags,
            short_flags_allowing_attached_operands,
            false,
        )
        .is_some()
}

fn matcher_matches(matcher: &ModifierMatcher, shape: &InvocationShape) -> bool {
    let flags = matcher.flag_names();
    !flags.is_empty()
        && match matcher {
            ModifierMatcher::AnyFlag(_) => flags
                .iter()
                .any(|flag_name| shape.has_flag(flag_name.as_str())),
            ModifierMatcher::AllFlags(_) => flags
                .iter()
                .all(|flag_name| shape.has_flag(flag_name.as_str())),
        }
}

fn runtime_feature_matches(feature: RuntimeFeature, shape: &InvocationShape) -> bool {
    match feature {
        RuntimeFeature::InteractiveSession => shape.interactive_session,
        RuntimeFeature::StdinPayloadAvailable => shape.stdin_payload_available,
        RuntimeFeature::PipelineInputAvailable => false,
    }
}

fn leading_positional_prefix_len(shape: &InvocationShape, matcher: &ValueMatcher) -> usize {
    shape
        .positional_args
        .iter()
        .take_while(|text| argument_matches_value_matcher(text, matcher))
        .count()
}

fn argument_matches_value_matcher(text: &str, matcher: &ValueMatcher) -> bool {
    match matcher {
        ValueMatcher::StructuredValueContext(StructuredValueContext::Regex) => regex_matches(text),
        ValueMatcher::StructuredValueContext(StructuredValueContext::EnvAssignment) => {
            is_env_assignment(text)
        }
        ValueMatcher::StructuredValueContext(StructuredValueContext::NumericQuantity) => {
            is_numeric_quantity(text)
        }
        ValueMatcher::StructuredValueContext(StructuredValueContext::RemoteSpec) => {
            is_remote_spec(text)
        }
        ValueMatcher::StructuredValueContext(StructuredValueContext::OwnerGroupSpec) => {
            parse_owner_group_spec(text).is_some()
        }
        ValueMatcher::StructuredValueContext(_) => false,
        ValueMatcher::Literal(value) => text == value,
        ValueMatcher::RegexPattern(pattern) => Regex::new(pattern)
            .expect("regex patterns are validated during profile normalization")
            .is_match(text),
    }
}

fn regex_matches(text: &str) -> bool {
    Regex::new(text).is_ok()
}

fn is_env_assignment(text: &str) -> bool {
    let Some((name, _value)) = text.split_once('=') else {
        return false;
    };

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if first != '_' && !first.is_ascii_alphabetic() {
        return false;
    }

    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_numeric_quantity(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }

    let Some(first_non_digit) = text.find(|ch: char| !ch.is_ascii_digit()) else {
        return true;
    };

    if first_non_digit == 0 {
        return false;
    }

    let suffix = &text[first_non_digit..];
    matches!(
        suffix,
        "c" | "w"
            | "b"
            | "B"
            | "kB"
            | "K"
            | "KiB"
            | "MB"
            | "M"
            | "MiB"
            | "xM"
            | "GB"
            | "G"
            | "GiB"
            | "TB"
            | "T"
            | "TiB"
            | "PB"
            | "P"
            | "PiB"
            | "EB"
            | "E"
            | "EiB"
            | "ZB"
            | "Z"
            | "ZiB"
            | "YB"
            | "Y"
            | "YiB"
            | "RB"
            | "R"
            | "QB"
            | "Q"
    )
}

fn is_remote_spec(text: &str) -> bool {
    if text.starts_with("rsync://") {
        return true;
    }

    if let Some((prefix, _suffix)) = text.split_once("::") {
        return remote_spec_prefix_is_host_like(prefix);
    }

    if let Some((prefix, _suffix)) = text.split_once(':') {
        return remote_spec_prefix_is_host_like(prefix);
    }

    false
}

fn remote_spec_prefix_is_host_like(prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }

    if prefix == "." || prefix == ".." {
        return false;
    }

    if prefix.starts_with('/') || prefix.starts_with("./") || prefix.starts_with("../") {
        return false;
    }

    if prefix.contains('/') {
        return false;
    }

    if prefix.len() == 1 && prefix.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }

    true
}

fn flag_token_matches_name(token_text: &str, flag_name: &str) -> bool {
    token_text == flag_name
        || inline_long_flag_operand(token_text, flag_name).is_some()
        || short_flag_cluster_contains_name(token_text, flag_name)
}

fn short_flag_cluster_contains_name(token_text: &str, flag_name: &str) -> bool {
    let Some(flag_char) = short_flag_char(flag_name) else {
        return false;
    };

    let Some(cluster_text) = token_text.strip_prefix('-') else {
        return false;
    };

    if token_text.starts_with("--")
        || cluster_text.len() <= 1
        || !cluster_text.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        return false;
    }

    cluster_text.chars().any(|candidate| candidate == flag_char)
}

fn flag_token_binding_match<'a>(
    token_text: &'a str,
    flag_name: &str,
    allow_short_attached: bool,
    allow_ambiguous_short_attached: bool,
    declared_short_flags: &BTreeSet<String>,
    all_declared_short_flags: &BTreeSet<String>,
    all_short_flags_allowing_attached_operands: &BTreeSet<String>,
    allow_unknown_prefix_flags: bool,
) -> Option<FlagTokenMatch<'a>> {
    if token_text == flag_name {
        return Some(FlagTokenMatch::Exact);
    }

    if let Some(inline_operand) = inline_long_flag_operand(token_text, flag_name) {
        return Some(FlagTokenMatch::LongInlineOperand(inline_operand));
    }

    if !allow_short_attached {
        return None;
    }

    inline_short_flag_operand(
        token_text,
        flag_name,
        allow_ambiguous_short_attached,
        declared_short_flags,
    )
    .map(FlagTokenMatch::ShortAttachedOperand)
    .or_else(|| {
        clustered_short_flag_attached_operand(
            token_text,
            flag_name,
            all_declared_short_flags,
            all_short_flags_allowing_attached_operands,
            allow_unknown_prefix_flags,
        )
        .map(FlagTokenMatch::ShortAttachedOperand)
    })
}

fn inline_long_flag_operand<'a>(token_text: &'a str, flag_name: &str) -> Option<&'a str> {
    if !token_text.starts_with("--") || !flag_name.starts_with("--") {
        return None;
    }

    token_text.strip_prefix(flag_name)?.strip_prefix('=')
}

fn inline_short_flag_operand<'a>(
    token_text: &'a str,
    flag_name: &str,
    allow_ambiguous_short_attached: bool,
    declared_short_flags: &BTreeSet<String>,
) -> Option<&'a str> {
    if !is_single_letter_short_flag(flag_name) {
        return None;
    }

    let suffix = token_text.strip_prefix(flag_name)?;
    if suffix.is_empty() {
        return None;
    }

    if !allow_ambiguous_short_attached
        && suffix_looks_like_short_flag_cluster(suffix, declared_short_flags)
    {
        return None;
    }

    if allow_ambiguous_short_attached
        && suffix_looks_like_pure_short_flag_cluster(suffix, declared_short_flags)
    {
        return None;
    }

    Some(suffix)
}

fn clustered_short_flag_attached_operand<'a>(
    token_text: &'a str,
    flag_name: &str,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
    allow_unknown_prefix_flags: bool,
) -> Option<&'a str> {
    let flag_char = short_flag_char(flag_name)?;
    let cluster_text = token_text.strip_prefix('-')?;
    if token_text.starts_with("--") || cluster_text.len() <= 2 {
        return None;
    }

    let mut char_offsets: Vec<(usize, char)> = cluster_text.char_indices().collect();
    char_offsets.push((cluster_text.len(), '\0'));

    for window in char_offsets.windows(2) {
        let (start, candidate) = window[0];
        let (next_start, _) = window[1];
        if candidate != flag_char || start == 0 {
            continue;
        }

        let prefix = &cluster_text[..start];
        if !prefix_is_known_flag_only_short_cluster(
            prefix,
            declared_short_flags,
            short_flags_allowing_attached_operands,
            allow_unknown_prefix_flags,
        ) {
            continue;
        }

        let suffix = &cluster_text[next_start..];
        if !suffix.is_empty() {
            return Some(suffix);
        }
    }

    None
}

fn suffix_looks_like_short_flag_cluster(
    suffix: &str,
    declared_short_flags: &BTreeSet<String>,
) -> bool {
    let mut chars = suffix.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_alphabetic()
        && declared_short_flags.contains(format!("-{first}").as_str())
        && chars.all(|candidate| candidate.is_ascii_alphabetic())
}

fn suffix_looks_like_pure_short_flag_cluster(
    suffix: &str,
    declared_short_flags: &BTreeSet<String>,
) -> bool {
    suffix.len() > 1
        && suffix.chars().all(|candidate| {
            candidate.is_ascii_alphabetic()
                && declared_short_flags.contains(format!("-{candidate}").as_str())
        })
}

fn prefix_is_known_flag_only_short_cluster(
    prefix: &str,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
    allow_unknown_prefix_flags: bool,
) -> bool {
    !prefix.is_empty()
        && prefix.chars().all(|candidate| {
            if !candidate.is_ascii_alphabetic() {
                return false;
            }

            let candidate_flag = format!("-{candidate}");
            if short_flags_allowing_attached_operands.contains(&candidate_flag) {
                return false;
            }

            allow_unknown_prefix_flags || declared_short_flags.contains(&candidate_flag)
        })
}

fn modifier_allows_short_attached(modifier: &Modifier) -> bool {
    modifier.parameters.iter().any(|parameter| {
        matches!(
            parameter.binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: FlagOperandMode::NextArg | FlagOperandMode::InlineOrShortAttached,
            }
        )
    })
}

fn modifier_uses_inline_or_short_attached(modifier: &Modifier) -> bool {
    modifier.parameters.iter().any(|parameter| {
        matches!(
            parameter.binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: FlagOperandMode::InlineOrShortAttached,
            }
        )
    })
}

fn modifier_allows_inline_long_operand(modifier: &Modifier) -> bool {
    modifier.parameters.iter().any(|parameter| {
        matches!(
            parameter.binding,
            BindingSpec::FollowingMatchedFlag { operand_mode }
                | BindingSpec::FollowingFlag { operand_mode, .. }
                if !matches!(operand_mode, FlagOperandMode::SecondArg)
        )
    })
}

fn declared_short_modifier_flags(modifiers: &[Modifier]) -> BTreeSet<String> {
    modifiers
        .iter()
        .flat_map(|modifier| modifier.matcher.flag_names().iter())
        .filter(|flag_name| is_single_letter_short_flag(flag_name.as_str()))
        .map(|flag_name| flag_name.as_str().to_string())
        .collect()
}

fn short_flags_allowing_attached_operands(modifiers: &[Modifier]) -> BTreeSet<String> {
    modifiers
        .iter()
        .filter(|modifier| modifier_allows_short_attached(modifier))
        .flat_map(|modifier| modifier.matcher.flag_names().iter())
        .filter(|flag_name| is_single_letter_short_flag(flag_name.as_str()))
        .map(|flag_name| flag_name.as_str().to_string())
        .collect()
}

fn declared_short_modifier_flags_from_selected(
    modifiers: &[SelectedModifier<'_>],
) -> BTreeSet<String> {
    modifiers
        .iter()
        .flat_map(|selected| selected.modifier.matcher.flag_names().iter())
        .filter(|flag_name| is_single_letter_short_flag(flag_name.as_str()))
        .map(|flag_name| flag_name.as_str().to_string())
        .collect()
}

fn short_flags_allowing_attached_operands_from_selected(
    modifiers: &[SelectedModifier<'_>],
) -> BTreeSet<String> {
    modifiers
        .iter()
        .filter(|selected| modifier_allows_short_attached(selected.modifier))
        .flat_map(|selected| selected.modifier.matcher.flag_names().iter())
        .filter(|flag_name| is_single_letter_short_flag(flag_name.as_str()))
        .map(|flag_name| flag_name.as_str().to_string())
        .collect()
}

fn is_single_letter_short_flag(flag_name: &str) -> bool {
    flag_name.starts_with('-') && !flag_name.starts_with("--") && flag_name.chars().count() == 2
}

fn short_flag_char(flag_name: &str) -> Option<char> {
    if !is_single_letter_short_flag(flag_name) {
        return None;
    }

    flag_name.chars().nth(1)
}

fn short_flag_cluster_matches_flag_only_modifier(
    token_text: &str,
    flag_name: &str,
    declared_short_flags: &BTreeSet<String>,
    short_flags_allowing_attached_operands: &BTreeSet<String>,
) -> bool {
    let Some(flag_char) = short_flag_char(flag_name) else {
        return false;
    };

    let Some(cluster_text) = token_text.strip_prefix('-') else {
        return false;
    };

    if token_text.starts_with("--")
        || cluster_text.len() <= 1
        || !cluster_text.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        return false;
    }

    for candidate in cluster_text.chars() {
        let candidate_flag = format!("-{candidate}");
        if !declared_short_flags.contains(&candidate_flag) {
            return false;
        }
        if short_flags_allowing_attached_operands.contains(&candidate_flag) {
            return false;
        }
    }

    cluster_text.chars().any(|candidate| candidate == flag_char)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use caushell_parse::parse_command;
    use caushell_types::ShellKind;

    use super::{
        BindError, InvocationShape, bind_invocation, match_modifiers, select_form,
        select_invocation,
    };
    use crate::{
        ArgumentBindingSource, BindingSpec, BoundImplicitInput, BoundInvocation, BoundParameter,
        BoundValue, CommandProfile, CommandRefSemantic, DefaultSubcommandBehavior, DispatchKind,
        Effect, EffectKind, EffectTarget, EndpointKind, EndpointSemantic, EndpointUsage, FlagName,
        FlagOperandMode, Form, ImplicitInputSource, InvocationRuntimeContext, Modifier,
        ModifierConstraint, ModifierId, Parameter, PathPurpose, PathRole, PathSemantic,
        PayloadLanguage, PayloadSemantic, PayloadSource, PositionalBindingSource, SelectorExpr,
        SelectorPredicate, SemanticType, StructuredValueContext, SubcommandNode, SubcommandTree,
        ValueMatcher, load_command_profile_from_path, project_invocation,
    };

    fn built_in_profile(name: &str) -> CommandProfile {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join(format!("{name}.yaml"));

        load_command_profile_from_path(&profile_path).expect("expected built-in profile to load")
    }

    fn git_profile() -> CommandProfile {
        let mut profile = CommandProfile::new("git").with_modifier(
            Modifier::new("work_tree")
                .with_flag_name("-C")
                .with_parameter(Parameter::new(
                    "working_directory",
                    SemanticType::Path(PathSemantic {
                        role: PathRole::CwdAnchor,
                        purpose: Some(PathPurpose::WorkingDirectory),
                    }),
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                ))
                .with_effect(Effect::new(EffectKind::TargetPath).for_slot("working_directory")),
        );

        profile.subcommands = Some(SubcommandTree {
            roots: vec![
                SubcommandNode {
                    name: "clone".to_string(),
                    aliases: Vec::new(),
                    forms: vec![
                        Form::new("clone_repository")
                            .with_selector_predicate(SelectorPredicate::HasPositionalAt(0))
                            .with_parameter(Parameter::new(
                                "repository",
                                SemanticType::Endpoint(EndpointSemantic {
                                    kind: EndpointKind::Url,
                                    usage: EndpointUsage::FetchSource,
                                }),
                                BindingSpec::NextPositional,
                            ))
                            .with_parameter(
                                Parameter::new(
                                    "destination",
                                    SemanticType::Path(PathSemantic {
                                        role: PathRole::Write,
                                        purpose: Some(PathPurpose::WorkingDirectory),
                                    }),
                                    BindingSpec::NextPositional,
                                )
                                .optional(),
                            )
                            .with_effect(
                                Effect::new(EffectKind::NetworkEndpoint).for_slot("repository"),
                            )
                            .with_effect(
                                Effect::new(EffectKind::WritePath).for_slot("destination"),
                            ),
                    ],
                    modifiers: Vec::new(),
                    children: Vec::new(),
                    default_behavior: Some(DefaultSubcommandBehavior::RejectUnknown),
                    extensions: Default::default(),
                },
                SubcommandNode {
                    name: "remote".to_string(),
                    aliases: Vec::new(),
                    forms: Vec::new(),
                    modifiers: Vec::new(),
                    children: vec![SubcommandNode {
                        name: "add".to_string(),
                        aliases: Vec::new(),
                        forms: vec![
                            Form::new("add_remote")
                                .with_selector(SelectorExpr::All(vec![
                                    SelectorExpr::Predicate(SelectorPredicate::HasSubcommandPath(
                                        vec!["remote".to_string(), "add".to_string()],
                                    )),
                                    SelectorExpr::Predicate(SelectorPredicate::HasPositionalAt(0)),
                                ]))
                                .with_parameter(Parameter::new(
                                    "remote_name",
                                    SemanticType::PlainValue,
                                    BindingSpec::NextPositional,
                                ))
                                .with_parameter(Parameter::new(
                                    "endpoint",
                                    SemanticType::Endpoint(EndpointSemantic {
                                        kind: EndpointKind::Url,
                                        usage: EndpointUsage::ControlPlane,
                                    }),
                                    BindingSpec::NextPositional,
                                ))
                                .with_effect(
                                    Effect::new(EffectKind::NetworkEndpoint).for_slot("endpoint"),
                                ),
                        ],
                        modifiers: Vec::new(),
                        children: Vec::new(),
                        default_behavior: Some(DefaultSubcommandBehavior::RejectUnknown),
                        extensions: Default::default(),
                    }],
                    default_behavior: Some(DefaultSubcommandBehavior::RejectUnknown),
                    extensions: Default::default(),
                },
            ],
        });

        profile
    }

    fn sudo_profile() -> CommandProfile {
        CommandProfile::new("sudo").with_form(
            Form::new("wrapped_command")
                .with_selector_predicate(SelectorPredicate::HasPositionalAt(0))
                .with_parameter(Parameter::new(
                    "wrapped_command",
                    SemanticType::CommandRef(CommandRefSemantic {
                        dispatch: DispatchKind::WrapperCommand,
                    }),
                    BindingSpec::NextPositional,
                ))
                .with_parameter(
                    Parameter::new(
                        "wrapped_args",
                        SemanticType::PlainValue,
                        BindingSpec::RemainingArgs,
                    )
                    .optional()
                    .variadic(),
                ),
        )
    }

    fn copy_like_profile() -> CommandProfile {
        CommandProfile::new("copylike").with_form(
            Form::new("default")
                .with_selector_predicate(SelectorPredicate::HasPositionalAt(1))
                .with_parameter(
                    Parameter::new(
                        "source_paths",
                        SemanticType::PlainValue,
                        BindingSpec::RemainingPositionalsBeforeLast,
                    )
                    .variadic(),
                )
                .with_parameter(Parameter::new(
                    "destination_path",
                    SemanticType::PlainValue,
                    BindingSpec::LastPositional,
                )),
        )
    }

    fn positional_at_profile() -> CommandProfile {
        CommandProfile::new("retargetlike").with_form(
            Form::new("default")
                .with_selector_predicate(SelectorPredicate::HasPositionalAt(2))
                .with_parameter(Parameter::new(
                    "target",
                    SemanticType::PlainValue,
                    BindingSpec::PositionalAt(2),
                )),
        )
    }

    fn find_bound_parameter<'a>(
        invocation: &'a BoundInvocation,
        slot_name: &str,
    ) -> &'a BoundParameter {
        invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist")
    }

    fn first_argument_text(parameter: &BoundParameter) -> &str {
        match &parameter.values[0] {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn argument_texts<'a>(parameter: &'a BoundParameter) -> Vec<&'a str> {
        parameter
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect()
    }

    fn first_argument_binding_source(parameter: &BoundParameter) -> &ArgumentBindingSource {
        match &parameter.values[0] {
            BoundValue::Argument { binding_source, .. } => binding_source,
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn first_bound_implicit_input(invocation: &BoundInvocation) -> &BoundImplicitInput {
        invocation
            .bound_implicit_inputs
            .first()
            .expect("expected bound implicit input to exist")
    }

    #[test]
    fn selects_bash_command_string_form() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected command_string form");

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert!(selection.modifiers.is_empty());
    }

    #[test]
    fn selects_bash_script_file_form() {
        let profile = built_in_profile("bash");
        let shape = InvocationShape::new().with_positional_arg("./scripts/build.sh");

        let form = select_form(&profile, &shape).expect("expected script_file form");

        assert_eq!(form.id.as_str(), "script_file");
    }

    #[test]
    fn selects_bash_explicit_stdin_form() {
        let profile = built_in_profile("bash");
        let shape = InvocationShape::new().with_flag("-s");

        let form = select_form(&profile, &shape).expect("expected stdin_script_explicit form");

        assert_eq!(form.id.as_str(), "stdin_script_explicit");
    }

    #[test]
    fn selects_bash_implicit_stdin_form() {
        let profile = built_in_profile("bash");
        let shape = InvocationShape::new().with_stdin_payload_available();

        let form = select_form(&profile, &shape).expect("expected stdin_script_implicit form");

        assert_eq!(form.id.as_str(), "stdin_script_implicit");
    }

    #[test]
    fn selects_bash_interactive_form() {
        let profile = built_in_profile("bash");
        let shape = InvocationShape::new().with_interactive_session();

        let form = select_form(&profile, &shape).expect("expected interactive form");

        assert_eq!(form.id.as_str(), "interactive");
    }

    #[test]
    fn matches_bash_rcfile_modifier() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile ./team.rc -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected command_string form");

        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert_eq!(modifier_ids, vec!["rcfile"]);
    }

    #[test]
    fn select_invocation_does_not_treat_modifier_operand_as_free_script_path() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile ./team.rc"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let error =
            select_invocation(&profile, &projection).expect_err("expected no matching form");

        match error {
            BindError::NoFormMatched { command_name } => {
                assert_eq!(command_name, "bash");
            }
            other => panic!("unexpected bind error: {other:?}"),
        }
    }

    #[test]
    fn select_invocation_can_choose_interactive_form_after_modifier_consumption() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile ./team.rc"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );
        let selection =
            select_invocation(&profile, &projection).expect("expected interactive selection");

        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(selection.form.id.as_str(), "interactive");
        assert_eq!(modifier_ids, vec!["rcfile"]);
    }

    #[test]
    fn selects_sh_command_string_form() {
        let profile = built_in_profile("sh");
        let shape = InvocationShape::new()
            .with_flag("-c")
            .with_positional_arg("echo ok");

        let form = select_form(&profile, &shape).expect("expected command_string form");

        assert_eq!(form.id.as_str(), "command_string");
    }

    #[test]
    fn empty_bash_shape_returns_no_match() {
        let profile = built_in_profile("bash");

        let error =
            select_form(&profile, &InvocationShape::new()).expect_err("expected no matching form");

        match error {
            BindError::NoFormMatched { command_name } => {
                assert_eq!(command_name, "bash");
            }
            other => panic!("unexpected bind error: {other:?}"),
        }
    }

    #[test]
    fn ambiguous_profile_returns_multiple_match_error() {
        let profile = CommandProfile::new("ambiguous")
            .with_form(Form::new("first"))
            .with_form(Form::new("second"));

        let error =
            select_form(&profile, &InvocationShape::new()).expect_err("expected ambiguous match");

        match error {
            BindError::MultipleFormsMatched {
                command_name,
                form_ids,
            } => {
                assert_eq!(command_name, "ambiguous");
                assert_eq!(form_ids, vec!["first".to_string(), "second".to_string()]);
            }
            other => panic!("unexpected bind error: {other:?}"),
        }
    }

    #[test]
    fn select_invocation_matches_remaining_selector_after_preview_consumption() {
        let profile = CommandProfile::new("runner")
            .with_form(
                Form::new("command_string_with_trailer")
                    .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-c")))
                    .with_remaining_selector_predicate(SelectorPredicate::HasPositionalAt(0))
                    .with_parameter(Parameter::new(
                        "payload",
                        SemanticType::PlainValue,
                        BindingSpec::FollowingFlag {
                            flag_name: FlagName::new("-c"),
                            operand_mode: FlagOperandMode::NextPositional,
                        },
                    )),
            )
            .with_form(
                Form::new("command_string_without_trailer")
                    .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-c")))
                    .with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs)
                    .with_parameter(Parameter::new(
                        "payload",
                        SemanticType::PlainValue,
                        BindingSpec::FollowingFlag {
                            flag_name: FlagName::new("-c"),
                            operand_mode: FlagOperandMode::NextPositional,
                        },
                    )),
            );

        let artifact = parse_command("runner -c payload trailer", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        assert_eq!(selection.form.id.as_str(), "command_string_with_trailer");
    }

    #[test]
    fn select_invocation_evaluates_remaining_selector_on_post_preview_shape() {
        let profile = CommandProfile::new("runner").with_form(
            Form::new("command_string")
                .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("-c")))
                .with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs)
                .with_parameter(Parameter::new(
                    "payload",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingFlag {
                        flag_name: FlagName::new("-c"),
                        operand_mode: FlagOperandMode::NextPositional,
                    },
                )),
        );

        let artifact =
            parse_command("runner -c payload", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        assert_eq!(selection.form.id.as_str(), "command_string");
    }

    #[test]
    fn modifier_matches_any_declared_flag() {
        let profile = CommandProfile::new("bash").with_modifier(
            Modifier::new("rcfile")
                .with_flag_name("--rcfile")
                .with_flag_name("--init-file"),
        );

        let matched = match_modifiers(&profile, &InvocationShape::new().with_flag("--init-file"));

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id.as_str(), "rcfile");
    }

    #[test]
    fn select_invocation_matches_stdbuf_short_attached_modifiers() {
        let profile = built_in_profile("stdbuf");
        let artifact = parse_command("stdbuf -oL -e0 bash -c 'echo ok'", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected wrapped_command form");

        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(selection.form.id.as_str(), "wrapped_command");
        assert_eq!(modifier_ids, vec!["output", "error"]);
    }

    #[test]
    fn bind_invocation_binds_short_attached_modifier_operands() {
        let profile = built_in_profile("head");
        let artifact = parse_command("head -n5 ./input.txt", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        assert_eq!(
            first_argument_text(find_bound_parameter(&bound, "line_count")),
            "5"
        );
        assert_eq!(
            argument_texts(find_bound_parameter(&bound, "input_paths")),
            vec!["./input.txt"]
        );
    }

    #[test]
    fn bind_invocation_binds_attached_operand_after_short_flag_prefix() {
        let profile = built_in_profile("wget");
        let artifact = parse_command("wget -qO- https://example.test/payload.sh", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected wget stdout selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "fetch_to_stdout");
        assert_eq!(
            first_argument_text(find_bound_parameter(&invocation, "output_path")),
            "-"
        );
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "endpoints")),
            vec!["https://example.test/payload.sh"]
        );
    }

    #[test]
    fn select_invocation_does_not_treat_short_option_cluster_as_attached_operand() {
        let profile = CommandProfile::new("tool")
            .with_form(Form::new("default"))
            .with_modifier(
                Modifier::new("extract_with_value")
                    .with_flag_name("-x")
                    .with_parameter(Parameter::new(
                        "value",
                        SemanticType::PlainValue,
                        BindingSpec::FollowingMatchedFlag {
                            operand_mode: FlagOperandMode::NextArg,
                        },
                    )),
            )
            .with_modifier(Modifier::new("gzip").with_flag_name("-z"));

        let artifact =
            parse_command("tool -xzvf", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected default form to match");

        assert!(selection.modifiers.is_empty());
    }

    #[test]
    fn select_invocation_matches_short_attached_operand_when_suffix_is_not_pure_cluster() {
        let profile = CommandProfile::new("tool")
            .with_form(Form::new("default"))
            .with_modifier(
                Modifier::new("compatibility")
                    .with_flag_name("-c")
                    .with_parameter(Parameter::new(
                        "mode",
                        SemanticType::PlainValue,
                        BindingSpec::FollowingMatchedFlag {
                            operand_mode: FlagOperandMode::InlineOrShortAttached,
                        },
                    )),
            )
            .with_modifier(Modifier::new("noauto").with_flag_name("-n"))
            .with_modifier(Modifier::new("output").with_flag_name("-o"));

        let artifact =
            parse_command("tool -cnondos target", ShellKind::Bash).expect("expected parse");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected default form to match");
        let bound = bind_invocation(&profile, &projection, &selection);

        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(modifier_ids, vec!["compatibility"]);
        assert_eq!(
            first_argument_text(find_bound_parameter(&bound, "mode")),
            "nondos"
        );
    }

    #[test]
    fn select_invocation_matches_flag_only_short_option_cluster_members() {
        let profile = CommandProfile::new("tool")
            .with_form(Form::new("default"))
            .with_modifier(Modifier::new("recursive").with_flag_name("-r"))
            .with_modifier(Modifier::new("force").with_flag_name("-f"))
            .with_modifier(Modifier::new("verbose").with_flag_name("-v"));

        let artifact =
            parse_command("tool -rfv target", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected default form to match");
        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.modifier.id.as_str())
            .collect();

        assert_eq!(modifier_ids, vec!["recursive", "force", "verbose"]);
    }

    #[test]
    fn select_invocation_does_not_match_flag_only_bare_long_modifier_against_inline_value() {
        let profile = CommandProfile::new("tool")
            .with_form(Form::new("default"))
            .with_modifier(Modifier::new("interactive_always").with_flag_name("--interactive"))
            .with_modifier(
                Modifier::new("interactive_never").with_flag_name("--interactive=never"),
            );

        let artifact = parse_command("tool --interactive=never target", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let selection =
            select_invocation(&profile, &projection).expect("expected default form to match");
        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.modifier.id.as_str())
            .collect();

        assert_eq!(modifier_ids, vec!["interactive_never"]);
    }

    #[test]
    fn match_modifiers_filters_mutually_exclusive_candidates() {
        let profile = CommandProfile::new("tool")
            .with_modifier(
                Modifier::new("interactive_always")
                    .with_flag_name("-i")
                    .with_constraint(ModifierConstraint::MutuallyExclusiveWith(ModifierId::new(
                        "interactive_once",
                    ))),
            )
            .with_modifier(
                Modifier::new("interactive_once")
                    .with_flag_name("-I")
                    .with_constraint(ModifierConstraint::MutuallyExclusiveWith(ModifierId::new(
                        "interactive_always",
                    ))),
            );

        let matched = match_modifiers(
            &profile,
            &InvocationShape::new().with_flag("-i").with_flag("-I"),
        );

        assert!(matched.is_empty());
    }

    #[test]
    fn match_modifiers_filters_requires_modifier_candidates() {
        let profile = CommandProfile::new("tool")
            .with_modifier(
                Modifier::new("move_data")
                    .with_flag_name("--move-data")
                    .with_constraint(ModifierConstraint::RequiresModifier(ModifierId::new(
                        "partno",
                    ))),
            )
            .with_modifier(Modifier::new("partno").with_flag_name("-N").with_parameter(
                Parameter::new(
                    "partition",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                ),
            ));

        let matched_without_partno =
            match_modifiers(&profile, &InvocationShape::new().with_flag("--move-data"));
        assert!(matched_without_partno.is_empty());

        let matched_with_partno = match_modifiers(
            &profile,
            &InvocationShape::new()
                .with_flag("--move-data")
                .with_flag("-N"),
        );
        let modifier_ids: Vec<&str> = matched_with_partno
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(modifier_ids, vec!["move_data", "partno"]);
    }

    #[test]
    fn match_modifiers_filters_requires_flag_candidates() {
        let profile = CommandProfile::new("tool")
            .with_modifier(
                Modifier::new("destructive")
                    .with_flag_name("--apply")
                    .with_constraint(ModifierConstraint::RequiresFlag(FlagName::new("--yes"))),
            )
            .with_modifier(Modifier::new("confirm").with_flag_name("--yes"));

        let matched_without_yes =
            match_modifiers(&profile, &InvocationShape::new().with_flag("--apply"));
        assert_eq!(
            matched_without_yes
                .iter()
                .map(|modifier| modifier.id.as_str())
                .collect::<Vec<_>>(),
            Vec::<&str>::new()
        );

        let matched_with_yes = match_modifiers(
            &profile,
            &InvocationShape::new()
                .with_flag("--apply")
                .with_flag("--yes"),
        );
        let modifier_ids: Vec<&str> = matched_with_yes
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(modifier_ids, vec!["destructive", "confirm"]);
    }

    #[test]
    fn select_invocation_filters_modifier_with_unsatisfied_required_modifier_constraint() {
        let profile = CommandProfile::new("tool")
            .with_form(Form::new("default"))
            .with_modifier(
                Modifier::new("move_data")
                    .with_flag_name("--move-data")
                    .with_constraint(ModifierConstraint::RequiresModifier(ModifierId::new(
                        "partno",
                    ))),
            )
            .with_modifier(Modifier::new("partno").with_flag_name("-N").with_parameter(
                Parameter::new(
                    "partition",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                ),
            ));

        let artifact =
            parse_command("tool --move-data target", ShellKind::Bash).expect("expected parse");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected default form to match");

        assert!(selection.modifiers.is_empty());
    }

    #[test]
    fn invocation_shape_has_flag_sees_short_option_cluster_members() {
        let shape = InvocationShape::new().with_flag("-es");

        assert!(shape.has_flag("-e"));
        assert!(shape.has_flag("-s"));
        assert!(!shape.has_flag("-x"));
    }

    #[test]
    fn invocation_shape_has_flag_does_not_scan_short_attached_operand_text() {
        let shape = InvocationShape::new().with_flag("-f/usr/bin");

        assert!(!shape.has_flag("-u"));
        assert!(!shape.has_flag("-b"));
    }

    #[test]
    fn invocation_shape_flag_count_counts_repeated_flags() {
        let shape = InvocationShape::new()
            .with_flag("-V")
            .with_flag("-V")
            .with_flag("--help");

        assert_eq!(shape.flag_count("-V"), 2);
        assert_eq!(shape.flag_count("--help"), 1);
        assert_eq!(shape.flag_count("--version"), 0);
    }

    #[test]
    fn argument_matches_value_matcher_accepts_valid_regex() {
        assert!(super::argument_matches_value_matcher(
            "^partnum:(show|get)(:[[:xdigit:]]+)?$",
            &ValueMatcher::StructuredValueContext(StructuredValueContext::Regex),
        ));
        assert!(!super::argument_matches_value_matcher(
            "[unterminated",
            &ValueMatcher::StructuredValueContext(StructuredValueContext::Regex),
        ));
        assert!(super::argument_matches_value_matcher(
            "4:show",
            &ValueMatcher::RegexPattern("^\\d+:(show|get)(:[[:xdigit:]]+)?$".to_string()),
        ));
        assert!(!super::argument_matches_value_matcher(
            "4:set:2",
            &ValueMatcher::RegexPattern("^\\d+:(show|get)(:[[:xdigit:]]+)?$".to_string()),
        ));
    }

    #[test]
    fn bind_invocation_binds_git_clone_subcommand_scope() {
        let profile = git_profile();
        let artifact = parse_command(
            r#"git clone https://example.test/repo.git ./repo"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected clone subcommand selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let repository = find_bound_parameter(&invocation, "repository");
        let destination = find_bound_parameter(&invocation, "destination");

        assert_eq!(selection.form.id.as_str(), "clone_repository");
        assert_eq!(selection.subcommand_path, vec!["clone".to_string()]);
        assert_eq!(invocation.subcommand_path, vec!["clone".to_string()]);
        assert_eq!(
            first_argument_text(repository),
            "https://example.test/repo.git"
        );
        assert_eq!(first_argument_text(destination), "./repo");
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::NetworkEndpoint);
        assert_eq!(invocation.effects[1].kind, EffectKind::WritePath);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_git_clone_recursive_submodules_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command(
            r#"git clone --recurse-submodules https://example.test/repo.git ./repo"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected clone subcommand selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let repository = find_bound_parameter(&invocation, "repository");
        let destination = find_bound_parameter(&invocation, "destination");

        assert_eq!(
            selection.form.id.as_str(),
            "clone_repository_with_recursive_submodules"
        );
        assert_eq!(selection.subcommand_path, vec!["clone".to_string()]);
        assert_eq!(invocation.subcommand_path, vec!["clone".to_string()]);
        assert_eq!(
            first_argument_text(repository),
            "https://example.test/repo.git"
        );
        assert_eq!(first_argument_text(destination), "./repo");
        assert_eq!(invocation.effects.len(), 4);
        assert_eq!(invocation.effects[0].kind, EffectKind::NetworkEndpoint);
        assert_eq!(invocation.effects[1].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[2].kind, EffectKind::LoadConfig);
        assert_eq!(invocation.effects[3].kind, EffectKind::WritePath);
        assert!(matches!(
            &invocation.effects[3].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                root: Some(slot),
                path_set,
                ..
            }) if slot.as_str() == "destination"
                && *path_set
                    == caushell_types::RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees
        ));
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_remaining_positionals_after_dashdash() {
        let mut profile = CommandProfile::new("git");
        profile.subcommands = Some(SubcommandTree {
            roots: vec![SubcommandNode {
                name: "restore".to_string(),
                aliases: Vec::new(),
                forms: vec![
                    Form::new("dashdash_paths")
                        .with_selector_predicate(SelectorPredicate::HasPositionalAt(0))
                        .with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs)
                        .with_parameter(
                            Parameter::new(
                                "pathspecs",
                                SemanticType::PlainValue,
                                BindingSpec::RemainingPositionalsAfterDashDash,
                            )
                            .variadic(),
                        ),
                ],
                modifiers: Vec::new(),
                children: Vec::new(),
                default_behavior: Some(DefaultSubcommandBehavior::RejectUnknown),
                extensions: Default::default(),
            }],
        });

        let artifact = parse_command("git restore -- src/main.rs Cargo.toml", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "dashdash_paths");
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs", "Cargo.toml"]
        );
    }

    #[test]
    fn bind_invocation_binds_git_restore_explicit_pathspec_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git restore -- src/main.rs Cargo.toml", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected restore explicit pathspec selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "restore_dashdash_pathspecs");
        assert_eq!(selection.subcommand_path, vec!["restore".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs", "Cargo.toml"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
    }

    #[test]
    fn bind_invocation_binds_git_restore_plain_and_source_pathspecs() {
        let profile = built_in_profile("git");

        let artifact = parse_command("git restore src/main.rs Cargo.toml", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected restore explicit pathspec selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "restore_explicit_pathspecs");
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs", "Cargo.toml"]
        );

        let artifact = parse_command("git restore --source HEAD -- src/main.rs", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected restore dashdash pathspec selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "restore_dashdash_pathspecs");
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs"]
        );
        assert_eq!(
            first_argument_text(find_bound_parameter(&invocation, "treeish")),
            "HEAD"
        );
    }

    #[test]
    fn bind_invocation_keeps_git_switch_force_create_separate_from_root_work_tree() {
        let profile = built_in_profile("git");

        let artifact = parse_command("git switch -C feature/main origin/main", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git switch selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "create_and_switch_branch");
        assert_eq!(
            invocation
                .applied_modifiers
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>(),
            vec!["force_create"]
        );

        let artifact = parse_command("git -C repo switch main", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git switch selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "switch_worktree");
        assert_eq!(
            invocation
                .applied_modifiers
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>(),
            vec!["work_tree"]
        );
        assert_eq!(
            first_argument_text(find_bound_parameter(&invocation, "working_directory")),
            "repo"
        );
    }

    #[test]
    fn bind_invocation_binds_git_checkout_explicit_pathspec_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git checkout -- src/main.rs", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected checkout explicit pathspec selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "checkout_explicit_pathspecs");
        assert_eq!(selection.subcommand_path, vec!["checkout".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
    }

    #[test]
    fn bind_invocation_binds_git_checkout_treeish_and_pathspec_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command(
            "git checkout HEAD~1 -- src/main.rs Cargo.toml",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected checkout treeish pathspec selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "checkout_treeish_pathspecs");
        assert_eq!(selection.subcommand_path, vec!["checkout".to_string()]);
        assert_eq!(
            first_argument_text(find_bound_parameter(&invocation, "treeish")),
            "HEAD~1"
        );
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["src/main.rs", "Cargo.toml"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
    }

    #[test]
    fn bind_invocation_binds_git_rm_explicit_pathspec_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git rm Cargo.lock target/debug.log", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git rm selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_paths");
        assert_eq!(selection.subcommand_path, vec!["rm".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["Cargo.lock", "target/debug.log"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
    }

    #[test]
    fn bind_invocation_binds_git_rm_pathspec_from_file_read_effect() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git rm --pathspec-from-file list.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git rm selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_paths_from_file");
        assert_eq!(selection.subcommand_path, vec!["rm".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspec_file")),
            vec!["list.txt"]
        );
        assert_eq!(invocation.effects.len(), 3);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert_eq!(invocation.effects[2].kind, EffectKind::ReadPath);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
        ));
    }

    #[test]
    fn bind_invocation_binds_git_rm_pathspec_file_nul_modifier() {
        let profile = built_in_profile("git");
        let artifact = parse_command(
            "git rm --pathspec-from-file listnul.bin --pathspec-file-nul",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git rm selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_paths_from_file");
        assert_eq!(selection.subcommand_path, vec!["rm".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspec_file")),
            vec!["listnul.bin"]
        );
        assert!(
            selection
                .modifiers
                .iter()
                .any(|selected| selected.modifier.id.as_str() == "pathspec_file_nul")
        );
    }

    #[test]
    fn bind_invocation_binds_git_rm_inline_long_pathspec_from_file() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git rm --pathspec-from-file=list.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git rm selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_paths_from_file");
        assert_eq!(selection.subcommand_path, vec!["rm".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspec_file")),
            vec!["list.txt"]
        );
        assert!(
            selection
                .modifiers
                .iter()
                .any(|selected| selected.modifier.id.as_str() == "pathspec_from_file")
        );
    }

    #[test]
    fn bind_invocation_binds_git_clean_explicit_pathspec_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git clean -fdx build/ tmp/", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git clean selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(
            selection.form.id.as_str(),
            "delete_untracked_and_ignored_pathspecs"
        );
        assert_eq!(selection.subcommand_path, vec!["clean".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "pathspecs")),
            vec!["build/", "tmp/"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
    }

    #[test]
    fn bind_invocation_binds_git_clean_repo_scoped_delete() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git clean -fdx", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git clean selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(
            selection.form.id.as_str(),
            "delete_untracked_and_ignored_worktree"
        );
        assert_eq!(selection.subcommand_path, vec!["clean".to_string()]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::UntrackedAndIgnored
        ));
    }

    #[test]
    fn bind_invocation_binds_git_clean_force_scope_as_untracked_only() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git clean -f", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git clean selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_untracked_worktree");
        assert_eq!(selection.subcommand_path, vec!["clean".to_string()]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::UntrackedOnly
        ));
    }

    #[test]
    fn bind_invocation_binds_git_clean_force_x_scope_as_ignored_only() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git clean -fX", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git clean selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "delete_ignored_worktree");
        assert_eq!(selection.subcommand_path, vec!["clean".to_string()]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::DeletePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::IgnoredOnly
        ));
    }

    #[test]
    fn bind_invocation_binds_git_reset_hard_repo_scoped_write() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git reset --hard", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git reset selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "reset_hard_worktree");
        assert_eq!(selection.subcommand_path, vec!["reset".to_string()]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
        ));
    }

    #[test]
    fn bind_invocation_binds_git_reset_hard_revision() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git -C repo reset --hard origin/main", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git reset selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "reset_hard_worktree");
        assert_eq!(selection.subcommand_path, vec!["reset".to_string()]);
        assert_eq!(
            first_argument_text(find_bound_parameter(&invocation, "revision")),
            "origin/main"
        );
        assert!(matches!(
            invocation.effects.iter().find_map(|effect| match &effect.target {
                EffectTarget::MutationScope(
                    crate::MutationScopeTarget::RepositoryWorktree { path_set, .. },
                ) => Some(path_set),
                _ => None,
            }),
            Some(path_set) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
        ));
    }

    #[test]
    fn bind_invocation_binds_git_apply_patch_mutation_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git apply patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git apply selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "apply_patch_to_worktree");
        assert_eq!(selection.subcommand_path, vec!["apply".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "patch_paths")),
            vec!["patch.diff"]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(invocation.effects[1].kind, EffectKind::WritePath);
        assert!(matches!(
            &invocation.effects[1].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::PatchSelectedTracked
        ));
    }

    #[test]
    fn bind_invocation_binds_git_apply_check_as_read_only() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git apply --check patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git apply selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "inspect_patch_only");
        assert_eq!(selection.subcommand_path, vec!["apply".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "patch_paths")),
            vec!["patch.diff"]
        );
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
    }

    #[test]
    fn bind_invocation_binds_git_apply_index_as_index_and_worktree_write() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git apply --index patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git apply selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(
            selection.form.id.as_str(),
            "apply_patch_to_index_and_worktree"
        );
        assert_eq!(selection.subcommand_path, vec!["apply".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "patch_paths")),
            vec!["patch.diff"]
        );
        assert_eq!(
            invocation
                .effects
                .iter()
                .map(|effect| effect.kind)
                .collect::<Vec<_>>(),
            vec![
                EffectKind::ReadPath,
                EffectKind::WritePath,
                EffectKind::WritePath
            ]
        );
    }

    #[test]
    fn bind_invocation_binds_git_am_with_hooks() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git am patch.mbox", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git am selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "apply_mailbox_with_hooks");
        assert_eq!(selection.subcommand_path, vec!["am".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "mailbox_paths")),
            vec!["patch.mbox"]
        );
        assert_eq!(
            invocation
                .effects
                .iter()
                .map(|effect| effect.kind)
                .collect::<Vec<_>>(),
            vec![
                EffectKind::ReadPath,
                EffectKind::LoadConfig,
                EffectKind::WritePath,
                EffectKind::ExecuteHook
            ]
        );
    }

    #[test]
    fn bind_invocation_binds_git_am_no_verify_without_hook() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git am --no-verify patch.mbox", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git am selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "apply_mailbox_no_verify");
        assert_eq!(selection.subcommand_path, vec!["am".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "mailbox_paths")),
            vec!["patch.mbox"]
        );
        assert_eq!(
            invocation
                .effects
                .iter()
                .map(|effect| effect.kind)
                .collect::<Vec<_>>(),
            vec![
                EffectKind::ReadPath,
                EffectKind::LoadConfig,
                EffectKind::WritePath
            ]
        );
    }

    #[test]
    fn bind_invocation_binds_git_restore_worktree_subtree() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git restore --source=HEAD~1 --worktree .", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git restore selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "restore_worktree_subtree");
        assert_eq!(selection.subcommand_path, vec!["restore".to_string()]);
        assert_eq!(
            argument_texts(find_bound_parameter(&invocation, "subtree")),
            vec!["."]
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert_eq!(invocation.effects[1].kind, EffectKind::RepositoryOperation);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                subtree: Some(slot),
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                && slot.as_str() == "subtree"
        ));
    }

    #[test]
    fn bind_invocation_binds_git_checkout_branch_worktree() {
        let profile = built_in_profile("git");
        let artifact =
            parse_command("git checkout main", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git checkout selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "checkout_branch_worktree");
        assert_eq!(selection.subcommand_path, vec!["checkout".to_string()]);
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.effects[0].kind, EffectKind::WritePath);
        assert!(matches!(
            &invocation.effects[0].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
        ));
    }

    #[test]
    fn bind_invocation_binds_git_submodule_update_recursive_scope() {
        let profile = built_in_profile("git");
        let artifact = parse_command("git submodule update --init --recursive", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected git submodule selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        assert_eq!(selection.form.id.as_str(), "update_registered_submodules");
        assert_eq!(
            selection.subcommand_path,
            vec!["submodule".to_string(), "update".to_string()]
        );
        assert_eq!(invocation.effects.len(), 3);
        assert_eq!(invocation.effects[0].kind, EffectKind::LoadConfig);
        assert_eq!(invocation.effects[1].kind, EffectKind::LoadConfig);
        assert_eq!(invocation.effects[2].kind, EffectKind::WritePath);
        assert!(matches!(
            &invocation.effects[2].target,
            EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
                path_set,
                ..
            }) if *path_set
                == caushell_types::RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees
        ));
    }

    #[test]
    fn bind_invocation_binds_nested_git_remote_add_subcommand_scope() {
        let profile = git_profile();
        let artifact = parse_command(
            r#"git remote add origin https://example.test/repo.git"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected remote add subcommand selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let remote_name = find_bound_parameter(&invocation, "remote_name");
        let endpoint = find_bound_parameter(&invocation, "endpoint");

        assert_eq!(selection.form.id.as_str(), "add_remote");
        assert_eq!(
            selection.subcommand_path,
            vec!["remote".to_string(), "add".to_string()]
        );
        assert_eq!(
            invocation.subcommand_path,
            vec!["remote".to_string(), "add".to_string()]
        );
        assert_eq!(first_argument_text(remote_name), "origin");
        assert_eq!(
            first_argument_text(endpoint),
            "https://example.test/repo.git"
        );
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.effects[0].kind, EffectKind::NetworkEndpoint);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_keeps_root_modifier_out_of_subcommand_positionals() {
        let profile = git_profile();
        let artifact = parse_command(
            r#"git -C /tmp/repo remote add origin https://example.test/repo.git"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection)
            .expect("expected remote add subcommand selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let working_directory = find_bound_parameter(&invocation, "working_directory");
        let remote_name = find_bound_parameter(&invocation, "remote_name");
        let endpoint = find_bound_parameter(&invocation, "endpoint");
        let modifier_ids: Vec<&str> = invocation
            .applied_modifiers
            .iter()
            .map(|modifier| modifier.as_str())
            .collect();

        assert_eq!(
            invocation.subcommand_path,
            vec!["remote".to_string(), "add".to_string()]
        );
        assert_eq!(modifier_ids, vec!["work_tree"]);
        assert_eq!(first_argument_text(working_directory), "/tmp/repo");
        assert_eq!(first_argument_text(remote_name), "origin");
        assert_eq!(
            first_argument_text(endpoint),
            "https://example.test/repo.git"
        );
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_can_split_prefix_positionals_and_last_destination() {
        let profile = copy_like_profile();
        let artifact = parse_command("copylike src-a src-b dest", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected default form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let source_paths = find_bound_parameter(&invocation, "source_paths");
        let destination_path = find_bound_parameter(&invocation, "destination_path");
        let source_texts: Vec<&str> = source_paths
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();

        assert_eq!(selection.form.id.as_str(), "default");
        assert_eq!(source_texts, vec!["src-a", "src-b"]);
        assert_eq!(first_argument_text(destination_path), "dest");
        assert_eq!(
            first_argument_binding_source(destination_path),
            &ArgumentBindingSource::Positional {
                kind: PositionalBindingSource::LastPositional,
            }
        );
    }

    #[test]
    fn bind_invocation_can_bind_positional_at_without_consuming_earlier_positionals() {
        let profile = positional_at_profile();
        let artifact = parse_command("retargetlike /dev/sda select /dev/sdb", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected default form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let target = find_bound_parameter(&invocation, "target");

        assert_eq!(selection.form.id.as_str(), "default");
        assert_eq!(first_argument_text(target), "/dev/sdb");
        assert_eq!(
            first_argument_binding_source(target),
            &ArgumentBindingSource::Positional {
                kind: PositionalBindingSource::PositionalAt(2),
            }
        );
    }

    #[test]
    fn bind_invocation_binds_remaining_args_without_dropping_child_flags() {
        let profile = sudo_profile();
        let artifact = parse_command(r#"sudo rm -rf /tmp/project"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected wrapper form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let wrapped_command = find_bound_parameter(&invocation, "wrapped_command");
        let wrapped_args = find_bound_parameter(&invocation, "wrapped_args");
        let wrapped_arg_texts: Vec<&str> = wrapped_args
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();

        assert_eq!(selection.form.id.as_str(), "wrapped_command");
        assert_eq!(first_argument_text(wrapped_command), "rm");
        assert_eq!(wrapped_arg_texts, vec!["-rf", "/tmp/project"]);
        assert!(wrapped_args.values.iter().all(|value| matches!(
            value,
            BoundValue::Argument {
                binding_source: ArgumentBindingSource::RemainingArg,
                ..
            }
        )));
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_dd_prefixed_operands() {
        let profile = built_in_profile("dd");
        let artifact = parse_command("dd if=payload.img of=/dev/sda bs=4M", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected dd form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let input_target = find_bound_parameter(&invocation, "input_target");
        let output_target = find_bound_parameter(&invocation, "output_target");

        assert_eq!(selection.form.id.as_str(), "raw_copy");
        assert_eq!(first_argument_text(input_target), "payload.img");
        assert_eq!(first_argument_text(output_target), "/dev/sda");
        assert_eq!(
            first_argument_binding_source(output_target),
            &ArgumentBindingSource::ArgumentPrefix {
                prefix: "of=".to_string(),
            }
        );
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(invocation.effects[1].kind, EffectKind::WritePath);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_find_exec_command_until_terminator() {
        let profile = built_in_profile("find");
        let artifact = parse_command(
            r#"find ./src -name '*.sh' -exec bash -c 'echo "$1"' _ {} ;"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected exec form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let exec_command = find_bound_parameter(&invocation, "exec_command");
        let exec_args = find_bound_parameter(&invocation, "exec_args");
        let search_roots = find_bound_parameter(&invocation, "search_roots");
        let exec_arg_texts: Vec<&str> = exec_args
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();
        let search_root_texts: Vec<&str> = search_roots
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();

        assert_eq!(selection.form.id.as_str(), "exec_command");
        assert_eq!(first_argument_text(exec_command), "bash");
        assert_eq!(exec_arg_texts, vec!["-c", r#"echo "$1""#, "_", "{}"]);
        assert_eq!(search_root_texts, vec!["./src"]);
        assert!(
            invocation
                .effects
                .iter()
                .any(|effect| matches!(effect.kind, EffectKind::DispatchCommand))
        );
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_xargs_dispatch_template() {
        let profile = built_in_profile("xargs");
        let artifact =
            parse_command(r#"xargs -0 rm -f"#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected dispatch form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let wrapped_command = find_bound_parameter(&invocation, "wrapped_command");
        let wrapped_args = find_bound_parameter(&invocation, "wrapped_args");
        let wrapped_arg_texts: Vec<&str> = wrapped_args
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();

        assert_eq!(selection.form.id.as_str(), "dispatch_from_stdin");
        assert_eq!(first_argument_text(wrapped_command), "rm");
        assert_eq!(wrapped_arg_texts, vec!["-f"]);
        assert_eq!(invocation.bound_implicit_inputs.len(), 1);
        assert_eq!(
            invocation.bound_implicit_inputs[0].source,
            ImplicitInputSource::StdinData
        );
        assert!(
            invocation
                .effects
                .iter()
                .any(|effect| matches!(effect.kind, EffectKind::ConsumeStdin))
        );
        assert!(
            invocation
                .effects
                .iter()
                .any(|effect| matches!(effect.kind, EffectKind::DispatchCommand))
        );
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_python_script_file_as_payload_source() {
        let profile = built_in_profile("python");
        let artifact = parse_command("python ./tools/build.py --release", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected script form selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let script_path = find_bound_parameter(&invocation, "script_path");
        let script_args = find_bound_parameter(&invocation, "script_args");
        let script_arg_texts: Vec<&str> = script_args
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect();

        assert_eq!(selection.form.id.as_str(), "script_file");
        assert_eq!(first_argument_text(script_path), "./tools/build.py");
        assert_eq!(script_arg_texts, vec!["--release"]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(invocation.effects[1].kind, EffectKind::ExecutePayload);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_node_eval_payload() {
        let profile = built_in_profile("node");
        let artifact = parse_command(r#"node -e 'console.log(1)'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected command string selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let payload = find_bound_parameter(&invocation, "short_payload");

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert_eq!(first_argument_text(payload), "console.log(1)");
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.effects[0].kind, EffectKind::ExecutePayload);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_binds_perl_include_path_and_inline_payload() {
        let profile = built_in_profile("perl");
        let artifact = parse_command(r#"perl -I ./lib -e 'print 1'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected command string selection");
        let invocation = bind_invocation(&profile, &projection, &selection);

        let include_paths = find_bound_parameter(&invocation, "include_paths");
        let payload = find_bound_parameter(&invocation, "payload");

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert_eq!(first_argument_text(include_paths), "./lib");
        assert_eq!(first_argument_text(payload), "print 1");
        assert!(
            invocation
                .effects
                .iter()
                .any(|effect| matches!(effect.kind, EffectKind::ReadPath))
        );
        assert!(
            invocation
                .effects
                .iter()
                .any(|effect| matches!(effect.kind, EffectKind::ExecutePayload))
        );
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn select_invocation_rejects_unknown_git_subcommand() {
        let profile = git_profile();
        let artifact = parse_command(r#"git frobnicate now"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let error = select_invocation(&profile, &projection)
            .expect_err("expected unknown subcommand error");

        match error {
            BindError::UnknownSubcommand {
                command_name,
                attempted_path,
            } => {
                assert_eq!(command_name, "git");
                assert_eq!(attempted_path, vec!["frobnicate".to_string()]);
            }
            other => panic!("unexpected bind error: {other:?}"),
        }
    }

    #[test]
    fn bind_invocation_binds_bash_command_string_and_rcfile() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile ./team.rc -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);

        let payload = find_bound_parameter(&invocation, "payload");
        let startup_config = find_bound_parameter(&invocation, "startup_config");
        let modifier_ids: Vec<&str> = invocation
            .applied_modifiers
            .iter()
            .map(|modifier| modifier.as_str())
            .collect();

        assert_eq!(invocation.command_name.as_str(), "bash");
        assert_eq!(invocation.form_id.as_str(), "command_string");
        assert_eq!(first_argument_text(payload), "echo ok");
        assert_eq!(first_argument_text(startup_config), "./team.rc");
        assert_eq!(modifier_ids, vec!["rcfile"]);
        assert_eq!(invocation.effects.len(), 2);
        assert_eq!(invocation.effects[0].kind, EffectKind::ExecutePayload);
        assert_eq!(invocation.effects[1].kind, EffectKind::LoadConfig);
        assert!(invocation.residuals.is_empty());

        match first_argument_binding_source(payload) {
            ArgumentBindingSource::FollowingFlag { flag_name, .. } => {
                assert_eq!(flag_name.as_str(), "-c");
            }
            other => panic!("unexpected payload binding source: {other:?}"),
        }

        match first_argument_binding_source(startup_config) {
            ArgumentBindingSource::MatchedModifierFlag {
                modifier_id,
                flag_name,
                ..
            } => {
                assert_eq!(modifier_id.as_str(), "rcfile");
                assert_eq!(flag_name.as_str(), "--rcfile");
            }
            other => panic!("unexpected startup_config binding source: {other:?}"),
        }
    }

    #[test]
    fn bind_invocation_binds_bash_command_string_from_short_flag_cluster() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash -lc 'echo ok' runner"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let invocation = bind_invocation(&profile, &projection, &selection);
        let payload = find_bound_parameter(&invocation, "payload");

        assert_eq!(invocation.form_id.as_str(), "command_string");
        assert_eq!(first_argument_text(payload), "echo ok");
        assert!(invocation.residuals.is_empty());

        match first_argument_binding_source(payload) {
            ArgumentBindingSource::FollowingFlag { flag_name, .. } => {
                assert_eq!(flag_name.as_str(), "-c");
            }
            other => panic!("unexpected payload binding source: {other:?}"),
        }
    }

    #[test]
    fn bind_invocation_skips_modifier_payload_when_binding_next_positional() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(
            r#"bash --rcfile ./team.rc ./scripts/build.sh"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);

        let script_path = find_bound_parameter(&invocation, "script_path");
        let startup_config = find_bound_parameter(&invocation, "startup_config");

        assert_eq!(invocation.form_id.as_str(), "script_file");
        assert_eq!(first_argument_text(startup_config), "./team.rc");
        assert_eq!(first_argument_text(script_path), "./scripts/build.sh");
        assert_eq!(invocation.effects.len(), 3);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(invocation.effects[1].kind, EffectKind::ExecutePayload);
        assert_eq!(invocation.effects[2].kind, EffectKind::LoadConfig);
        assert!(invocation.residuals.is_empty());

        assert_eq!(
            first_argument_binding_source(script_path),
            &ArgumentBindingSource::Positional {
                kind: PositionalBindingSource::NextPositional,
            }
        );
    }

    #[test]
    fn bind_invocation_preserves_matched_modifier_alias_flag_in_binding_source() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(
            r#"bash --init-file ./team.rc -c 'echo ok'"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);
        let startup_config = find_bound_parameter(&invocation, "startup_config");

        match first_argument_binding_source(startup_config) {
            ArgumentBindingSource::MatchedModifierFlag {
                modifier_id,
                flag_name,
                ..
            } => {
                assert_eq!(modifier_id.as_str(), "rcfile");
                assert_eq!(flag_name.as_str(), "--init-file");
            }
            other => panic!("unexpected startup_config binding source: {other:?}"),
        }
    }

    #[test]
    fn select_invocation_keeps_command_string_when_c_and_s_coexist() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command(r#"bash -c -s"#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert!(selection.modifiers.is_empty());
    }

    #[test]
    fn bind_invocation_binds_command_string_after_dashdash_barrier() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command(r#"bash -c -- -s"#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);
        let payload = find_bound_parameter(&invocation, "payload");

        assert_eq!(invocation.form_id.as_str(), "command_string");
        assert_eq!(first_argument_text(payload), "-s");
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.effects[0].kind, EffectKind::ExecutePayload);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_treats_flag_like_modifier_operand_as_startup_config() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);
        let script_path = find_bound_parameter(&invocation, "script_path");
        let startup_config = find_bound_parameter(&invocation, "startup_config");
        let modifier_ids: Vec<&str> = invocation
            .applied_modifiers
            .iter()
            .map(|modifier| modifier.as_str())
            .collect();

        assert_eq!(invocation.form_id.as_str(), "script_file");
        assert_eq!(first_argument_text(script_path), "echo ok");
        assert_eq!(first_argument_text(startup_config), "-c");
        assert_eq!(modifier_ids, vec!["rcfile"]);
        assert_eq!(invocation.effects.len(), 3);
        assert_eq!(invocation.effects[0].kind, EffectKind::ReadPath);
        assert_eq!(invocation.effects[1].kind, EffectKind::ExecutePayload);
        assert_eq!(invocation.effects[2].kind, EffectKind::LoadConfig);
        assert!(invocation.residuals.is_empty());
    }

    #[test]
    fn bind_invocation_carries_stdin_implicit_input() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash -s", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);
        let implicit_input = first_bound_implicit_input(&invocation);

        assert_eq!(invocation.form_id.as_str(), "stdin_script_explicit");
        assert_eq!(invocation.bound_implicit_inputs.len(), 1);
        assert_eq!(implicit_input.source, ImplicitInputSource::StdinPayload);

        match &implicit_input.semantic {
            SemanticType::Payload(PayloadSemantic {
                language,
                source,
                recursive,
            }) => {
                assert_eq!(*language, PayloadLanguage::Bash);
                assert_eq!(*source, PayloadSource::Stdin);
                assert!(*recursive);
            }
            other => panic!("unexpected implicit input semantic: {other:?}"),
        }
    }

    #[test]
    fn bind_invocation_carries_interactive_implicit_input() {
        let profile = built_in_profile("bash");
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let invocation = bind_invocation(&profile, &projection, &selection);
        let implicit_input = first_bound_implicit_input(&invocation);

        assert_eq!(invocation.form_id.as_str(), "interactive");
        assert_eq!(invocation.bound_implicit_inputs.len(), 1);
        assert_eq!(
            implicit_input.source,
            ImplicitInputSource::InteractiveSession
        );

        match &implicit_input.semantic {
            SemanticType::Payload(PayloadSemantic {
                language,
                source,
                recursive,
            }) => {
                assert_eq!(*language, PayloadLanguage::Bash);
                assert_eq!(*source, PayloadSource::Interactive);
                assert!(*recursive);
            }
            other => panic!("unexpected implicit input semantic: {other:?}"),
        }
    }

    #[test]
    fn select_invocation_chooses_vim_interactive_editor_form() {
        let profile = built_in_profile("vim");
        let artifact =
            parse_command("vim notes.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected vim interactive form");

        assert_eq!(selection.form.id.as_str(), "interactive_editor");
    }

    #[test]
    fn select_invocation_chooses_vim_script_mode_for_short_cluster() {
        let profile = built_in_profile("vim");
        let artifact = parse_command("vim -es -S script.vim", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection = select_invocation(&profile, &projection).expect("expected vim script mode");

        assert_eq!(selection.form.id.as_str(), "script_mode");
    }

    #[test]
    fn select_invocation_keeps_vim_session_file_mode_interactive() {
        let profile = built_in_profile("vim");
        let artifact = parse_command("vim -S session.vim notes.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected vim interactive form");

        assert_eq!(selection.form.id.as_str(), "interactive_editor");
    }

    #[test]
    fn select_invocation_chooses_ed_interactive_without_stdin_payload() {
        let profile = built_in_profile("ed");
        let artifact =
            parse_command("ed file.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected ed interactive form");

        assert_eq!(selection.form.id.as_str(), "interactive_editor");
    }

    #[test]
    fn select_invocation_chooses_ed_stdin_script_mode_when_payload_available() {
        let profile = built_in_profile("ed");
        let artifact =
            parse_command("ed file.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );
        let selection =
            select_invocation(&profile, &projection).expect("expected ed stdin script form");

        assert_eq!(selection.form.id.as_str(), "stdin_script_mode");
    }
}
