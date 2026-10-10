//! Bounded coverage proof for variable-width operands in declared argv grammars.
//! No command names, filesystem lookup, shell execution, or risk policy.
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ArgumentFieldCount, ArgumentRegion, BindingSpec, EffectTarget, FlagOperandMode, Form, Modifier,
    ProjectedInvocation, ScopedOptions, SelectorExpr, SelectorPredicate, SemanticType,
    StructuredValueContext, argument_structure,
};

// None means an outer word; Some is (original flag index, remaining operands).
type Owner = Option<(usize, usize)>;
type State = (Owner, bool); // pending operand and closed positional prefix

pub(crate) struct PositionalCoverage {
    pub additional: Vec<usize>,
    pub retains_default: bool,
}

pub(crate) fn may_be_unmodeled_control(
    shape: &crate::ArgumentStructure,
    vocabulary: Option<&crate::ArgumentControlVocabulary>,
    expression_closed: bool,
) -> bool {
    // A leading option may take an attached value (e.g. BSD -fPATH). The
    // expression's exact-word vocabulary does not certify that prefix grammar.
    // Keep the legacy bound until a declared expression boundary is crossed.
    if !expression_closed {
        return shape.may_start_with("-");
    }
    match vocabulary {
        None => shape.may_start_with("-"),
        Some(v) => {
            v.unmodeled_words.iter().any(|word| shape.may_equal(word))
                || v.unmodeled_short_clusters
                    .iter()
                    .any(|letters| shape.may_be_short_cluster(letters))
        }
    }
}

fn arity(mode: Option<FlagOperandMode>) -> usize {
    match mode {
        None => 0,
        Some(FlagOperandMode::SecondArg | FlagOperandMode::FirstOfTwoArgs) => 2,
        Some(_) => 1,
    }
}

fn selector_sensitive(expr: &SelectorExpr, flag: &str, modifiers: &[Modifier]) -> bool {
    match expr {
        SelectorExpr::All(items) | SelectorExpr::Any(items) => items
            .iter()
            .any(|item| selector_sensitive(item, flag, modifiers)),
        SelectorExpr::Not(item) => selector_sensitive(item, flag, modifiers),
        SelectorExpr::Predicate(predicate) => match predicate {
            SelectorPredicate::HasFlag(name)
            | SelectorPredicate::LacksFlag(name)
            | SelectorPredicate::HasFlagAtLeast(name, _) => name.as_str() == flag,
            SelectorPredicate::HasModifier(id)
            | SelectorPredicate::HasModifierParameterMatching(id, _, _) => {
                modifiers.iter().any(|m| {
                    &m.id == id
                        && m.matcher
                            .flag_names()
                            .iter()
                            .any(|name| name.as_str() == flag)
                })
            }
            SelectorPredicate::StdinPayloadAvailable
            | SelectorPredicate::InteractiveSession
            | SelectorPredicate::HasRuntimeFeature(_) => false,
            // Positional/argv/subcommand selection cannot use a canonical
            // lexical order after width changes. Keep the existing fallback.
            _ => true,
        },
    }
}

fn inert_operand(flag: &str, modifiers: &[Modifier], forms: &[Form]) -> bool {
    let owners: Vec<_> = modifiers
        .iter()
        .filter(|m| m.matcher.flag_names().iter().any(|f| f.as_str() == flag))
        .collect();
    // Losing a harmless-looking flag can enable another effectful modifier
    // via a mutual-exclusion/requirement constraint. Do not call it inert.
    if owners
        .iter()
        .any(|m| !m.constraints.is_empty() || m.ends_option_scope)
        || modifiers
            .iter()
            .flat_map(|m| &m.constraints)
            .any(|constraint| match constraint {
                crate::ModifierConstraint::RequiresFlag(name) => name.as_str() == flag,
                crate::ModifierConstraint::MutuallyExclusiveWith(id)
                | crate::ModifierConstraint::RequiresModifier(id) => {
                    owners.iter().any(|m| &m.id == id)
                }
            })
    {
        return false;
    }
    if forms.iter().any(|f| {
        selector_sensitive(&f.selector, flag, modifiers)
            || selector_sensitive(&f.remaining_selector, flag, modifiers)
    }) {
        return false;
    }
    if forms.iter().flat_map(|f| &f.parameters).any(|p| {
        matches!(&p.binding,
        BindingSpec::FollowingFlag { flag_name, .. } if flag_name.as_str() == flag)
    }) {
        return false;
    }
    owners.iter().all(|m| {
        m.effects.is_empty()
            && m.extensions.is_empty()
            && m.parameters.iter().all(|p| {
                matches!(
                    p.semantic,
                    SemanticType::PlainValue
                        | SemanticType::StructuredValue(crate::StructuredValueSemantic {
                            context: StructuredValueContext::PathExpression,
                            ..
                        })
                ) && p.value_projection.is_none()
                    && p.structured_projection.is_none()
                    && !forms
                        .iter()
                        .flat_map(|f| &f.parameters)
                        .any(|other| other.name == p.name)
                    && !forms
                        .iter()
                        .flat_map(|f| &f.effects)
                        .chain(modifiers.iter().flat_map(|m| &m.effects))
                        .any(|e| references_slot(&e.target, &p.name))
            })
    })
}

fn references_slot(target: &EffectTarget, slot: &crate::SlotName) -> bool {
    use crate::{DerivedPathSource, DispatchCommandSource};
    match target {
        EffectTarget::Slot(name) => name == slot,
        EffectTarget::ConfiguredPath(path) => {
            path.sources.iter().any(|s| &s.slot == slot)
                || path.fallback_parent_slots.contains(slot)
                || path.relative_to.as_ref().is_some_and(|a| {
                    &a.slot == slot || a.fallback_parent_slot.as_ref() == Some(slot)
                })
        }
        EffectTarget::Dispatch(dispatch) => {
            let command = match &dispatch.command {
                DispatchCommandSource::Slot(name)
                | DispatchCommandSource::WhitespaceArgv(name)
                | DispatchCommandSource::CommandString { slot: name, .. } => name == slot,
                DispatchCommandSource::Literal(_) => false,
            };
            command
                || dispatch.argv.contains(slot)
                || dispatch.environment.contains(slot)
                || dispatch.unset_environment.contains(slot)
        }
        EffectTarget::DerivedPath(path) => {
            matches!(&path.source, DerivedPathSource::Slot(s) if s == slot)
                || matches!(&path.root, Some(DerivedPathSource::Slot(s)) if s == slot)
        }
        EffectTarget::MutationScope(crate::MutationScopeTarget::RepositoryWorktree {
            root,
            subtree,
            ..
        }) => root.as_ref() == Some(slot) || subtree.as_ref() == Some(slot),
        EffectTarget::NetworkListener(listener) => {
            &listener.host.slot == slot
                || [
                    &listener.port,
                    &listener.unix_socket,
                    &listener.inherited_fd,
                ]
                .iter()
                .any(|scalar| scalar.as_ref().is_some_and(|s| &s.slot == slot))
        }
        EffectTarget::ToolConventionPath(_)
        | EffectTarget::VariableName(_)
        | EffectTarget::ImplicitInput(_)
        | EffectTarget::None => false,
    }
}

/// Return additional possible positional sources ONLY when every reachable
/// control/operand interpretation is covered by the original binding. Missing
/// operands may cause CLI failure; they do not erase already modeled effects.
/// New controls, shifted semantic operands, or changed child boundaries fail.
pub(crate) fn covered_positionals(
    projection: &ProjectedInvocation,
    baseline: &ScopedOptions,
    declarations: &BTreeMap<String, Option<FlagOperandMode>>,
    regions: &[ArgumentRegion],
    modifiers: &[Modifier],
    forms: &[Form],
    vocabulary: Option<&crate::ArgumentControlVocabulary>,
) -> Option<PositionalCoverage> {
    let scope = baseline.scope;
    // Filter values can narrow a dispatched child's input domain elsewhere
    // in the model. This local proof does not certify those derived contracts.
    if scope.end_index - scope.start_index > 256 {
        return None;
    }
    if forms
        .iter()
        .flat_map(|f| &f.effects)
        .chain(modifiers.iter().flat_map(|m| &m.effects))
        .any(|e| {
            !e.extensions.is_empty()
                || matches!(&e.target, EffectTarget::Dispatch(d)
            if !d.clear_environment_when.is_empty() || !d.unset_environment_when.is_empty()
                || !d.unknown_environment_when.is_empty())
        })
    {
        return None;
    }
    fn stable_selector(expr: &SelectorExpr) -> bool {
        match expr {
            SelectorExpr::All(items) | SelectorExpr::Any(items) => {
                items.iter().all(stable_selector)
            }
            SelectorExpr::Not(item) => stable_selector(item),
            SelectorExpr::Predicate(predicate) => matches!(
                predicate,
                SelectorPredicate::HasFlag(_)
                    | SelectorPredicate::LacksFlag(_)
                    | SelectorPredicate::HasFlagAtLeast(_, _)
                    | SelectorPredicate::HasModifier(_)
                    | SelectorPredicate::StdinPayloadAvailable
                    | SelectorPredicate::InteractiveSession
                    | SelectorPredicate::HasRuntimeFeature(_)
            ),
        }
    }
    if forms.iter().any(|f| {
        !stable_selector(&f.selector)
            || !stable_selector(&f.remaining_selector)
            || !f.payload_projections.is_empty()
            || !f.extensions.is_empty()
    }) {
        return None;
    }
    let shapes: Vec<_> = projection.args.iter().map(argument_structure).collect();
    let flags: BTreeMap<_, _> = baseline
        .flags
        .iter()
        .map(|(i, name)| (*i, name.as_str()))
        .collect();
    if flags.len() != baseline.flags.len() {
        // Multiple cluster members share one lexical index. The one-owner
        // automaton cannot certify width shifts across their combined effects.
        return None;
    }
    let inert: BTreeMap<_, _> = flags
        .iter()
        .map(|(i, name)| (*i, inert_operand(name, modifiers, forms)))
        .collect();
    let mut canonical_owner = vec![None; projection.args.len()];
    for (index, flag) in &flags {
        if let Some(mode) = declarations.get(*flag) {
            let count = arity(*mode);
            for offset in 1..=count {
                canonical_owner[*index + offset] = Some((*index, count + 1 - offset));
            }
        }
    }
    let mut states: BTreeSet<State> = BTreeSet::from([(None, false)]);
    let invalid_outer_word = |shape: &crate::ArgumentStructure| {
        shape.exact_value().is_some_and(|word| {
            !declarations.contains_key(word)
                && !regions
                    .iter()
                    .any(|r| r.start_flags.iter().any(|f| f == word))
                && !may_be_unmodeled_control(shape, vocabulary, true)
        })
    };
    let mut additional = BTreeSet::new();
    let mut index = scope.start_index;
    while index < scope.end_index {
        if let Some(region) = baseline
            .argument_regions
            .iter()
            .find(|r| r.start_index == index)
        {
            // An opener swallowed by an inert operand leaves the fixed child
            // name in the closed outer expression. Such a bare word is an
            // error, not another child. Other shifted boundaries stay opaque.
            for (owner, closed) in &states {
                if let Some((flag, remaining)) = owner {
                    if *remaining != 1
                        || !inert[flag]
                        || !closed
                        || !invalid_outer_word(&shapes[region.command_index])
                    {
                        return None;
                    }
                }
            }
            states.retain(|(owner, _)| owner.is_none());
            index = region.end_index + 1;
            continue;
        }
        let shape = &shapes[index];
        if shape.fields == ArgumentFieldCount::Unknown {
            return None;
        }
        let variable = shape.fields == ArgumentFieldCount::ZeroOrMore;
        let mut next = BTreeSet::new();
        for state in &states {
            if variable {
                // Zero fields; then one through the maximum outstanding
                // arity plus one. Extra inert fields have an absorbing state.
                next.insert(*state);
            }
            let repetitions = if variable {
                state.0.map_or(1, |(_, count)| count + 1)
            } else {
                1
            };
            let (mut current, mut closed) = *state;
            for _ in 0..repetitions {
                if let Some((owner, remaining)) = current {
                    if !inert[&owner] && canonical_owner[index] != current {
                        return None;
                    }
                    if let Some(flag) = flags.get(&index) {
                        if !inert_operand(flag, modifiers, forms) {
                            // Prune only a branch that provably errors at its
                            // next word. Keep effectful flag operands and any
                            // possible exposed controls unresolved otherwise.
                            if closed
                                && remaining == 1
                                && inert[&owner]
                                && shapes.get(index + 1).is_some_and(&invalid_outer_word)
                            {
                                break;
                            }
                            return None;
                        }
                    }
                    current = (remaining > 1).then_some((owner, remaining.saturating_sub(1)));
                } else if let Some(word) = shape.exact_value() {
                    if let Some(mode) = declarations.get(word) {
                        // Even a previously inert quoted operand can become a
                        // control word after a preceding zero-field expansion.
                        if flags.get(&index).copied() != Some(word) {
                            return None;
                        }
                        let count = arity(*mode);
                        current = (count > 0).then_some((index, count));
                        closed |= vocabulary
                            .is_some_and(|v| v.positional_boundary_words.iter().any(|w| w == word));
                    } else {
                        if closed && invalid_outer_word(shape) {
                            break;
                        }
                        if word.starts_with('-') && word.len() > 1
                            || regions
                                .iter()
                                .any(|r| r.start_flags.iter().any(|f| f == word))
                        {
                            return None;
                        }
                        if !baseline.positionals.as_ref()?.contains(&index) {
                            additional.insert(index);
                        }
                    }
                } else {
                    // Unknown undeclared options remain unknown, even when a
                    // suffix excludes all currently declared control words.
                    if may_be_unmodeled_control(shape, vocabulary, closed)
                        || declarations.keys().any(|flag| shape.may_equal(flag))
                        || regions
                            .iter()
                            .any(|r| r.start_flags.iter().any(|f| shape.may_equal(f)))
                    {
                        return None;
                    }
                    if closed {
                        break;
                    }
                    if !baseline.positionals.as_ref()?.contains(&index) {
                        additional.insert(index);
                    }
                }
                next.insert((current, closed));
            }
        }
        // Bounds only affect this optional proof, never truncate effects or
        // silently approve unvisited argv. Exact argv uses the original scan.
        if next.len() > 128 {
            return None;
        }
        states = next;
        index += 1;
    }
    if !additional.is_empty() {
        // Ordered/fixed positional slots cannot absorb a varying-width set.
        // RemainingPositionals is explicitly variadic and preserves sources.
        if forms.iter().any(|f| {
            f.parameters
                .iter()
                .filter(|p| p.binding == BindingSpec::RemainingPositionals)
                .count()
                != 1
                || f.parameters.iter().any(|p| {
                    !matches!(
                        p.binding,
                        BindingSpec::ArgumentRegionCommand(_) | BindingSpec::ArgumentRegionArgs(_)
                    ) && !(p.binding == BindingSpec::RemainingPositionals
                        && p.cardinality.is_variadic())
                })
        }) {
            return None;
        }
        // Effectful modifiers cannot be introduced or lost by the proof
        // above. Check each possible form with its activated modifier effects;
        // a companion in another form is not evidence of target coverage.
        let active_modifiers: Vec<_> = modifiers
            .iter()
            .filter(|m| {
                let names = m.matcher.flag_names();
                let present = |name: &crate::FlagName| flags.values().any(|f| *f == name.as_str());
                !names.is_empty()
                    && match &m.matcher {
                        crate::ModifierMatcher::AnyFlag(_) => names.iter().any(present),
                        crate::ModifierMatcher::AllFlags(_) => names.iter().all(present),
                    }
            })
            .collect();
        for form in forms {
            let effects: Vec<_> = form
                .effects
                .iter()
                .chain(active_modifiers.iter().flat_map(|m| &m.effects))
                .collect();
            for parameter in form
                .parameters
                .iter()
                .filter(|p| p.binding == BindingSpec::RemainingPositionals)
            {
                if parameter.value_projection.is_some() || parameter.structured_projection.is_some()
                {
                    return None;
                }
                // Exclusions used for ordinary positional binding must not erase
                // a newly possible target after operand roles shift.
                if parameter
                    .value_constraints
                    .iter()
                    .any(|constraint| match constraint {
                        crate::ValueConstraint::ExcludeLiteral(word) => {
                            additional.iter().any(|i| shapes[*i].may_equal(word))
                        }
                    })
                {
                    return None;
                }
                for effect in &effects {
                    if !references_slot(&effect.target, &parameter.name) {
                        continue;
                    }
                    match &effect.target {
                        EffectTarget::Slot(_) => {}
                        // A last-value configured source is safe only when an
                        // identity slot effect also retains the WHOLE target set.
                        EffectTarget::ConfiguredPath(path)
                            if path.environment.is_none()
                                && path.relative_to.is_none()
                                && path.fallback_parent_slots.is_empty()
                                && !path.expand_environment
                                && !path.expand_user
                                && !path.unresolved_relative_base
                                && matches!(&parameter.semantic, SemanticType::Path(p) if p.purpose == path.purpose)
                                && path.sources.iter().all(|s| {
                                    s.slot == parameter.name
                                        && s.projection == crate::ValueProjection::Identity
                                })
                                && {
                                    let mut equivalent = (**effect).clone();
                                    equivalent.target = EffectTarget::Slot(parameter.name.clone());
                                    effects.iter().any(|other| **other == equivalent)
                                } => {}
                        _ => return None,
                    }
                }
            }
        }
    }
    // Optional roots are a union, never a replacement of a possible cwd
    // default. The binder emits the declared fallback as a separate effect.
    let retains_default = !additional.is_empty()
        && !baseline.positionals.as_ref()?.iter().any(|i| {
            shapes[*i].fields == ArgumentFieldCount::ExactlyOne
                && !shapes[*i].may_equal("")
                && forms
                    .iter()
                    .flat_map(|f| &f.parameters)
                    .filter(|p| p.binding == BindingSpec::RemainingPositionals)
                    .all(|p| {
                        p.value_constraints
                            .iter()
                            .all(|constraint| match constraint {
                                crate::ValueConstraint::ExcludeLiteral(word) => {
                                    !shapes[*i].may_equal(word)
                                }
                            })
                    })
        });
    Some(PositionalCoverage {
        additional: additional.into_iter().collect(),
        retains_default,
    })
}
