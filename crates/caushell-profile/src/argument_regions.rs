//! Opt-in argv ownership. No command names or runtime inspection are used.
use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    ArgumentFieldCount, ArgumentRegion, ArgumentScope, BindingSpec, FlagName, FlagOperandMode,
    Form, Modifier, ProjectedArg, ProjectedInvocation, ScopedOptions, argument_structure,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundArgumentRegion {
    pub id: String,
    pub start_index: usize,
    pub command_index: usize,
    /// Exclusive end of the child argv; points at its delimiter.
    pub end_index: usize,
}

pub(crate) fn argv_value(arg: &ProjectedArg) -> Option<Cow<'_, str>> {
    if arg.runtime_data {
        Some(Cow::Borrowed(&arg.text))
    } else {
        let structure = argument_structure(arg);
        structure
            .exact
            .then_some(Cow::Owned(structure.static_prefix))
    }
}

pub(crate) fn operand_declarations(
    modifiers: &[Modifier],
    forms: &[Form],
) -> Result<BTreeMap<String, Option<FlagOperandMode>>, String> {
    let mut options = BTreeMap::new();
    for modifier in modifiers {
        for flag in modifier.matcher.flag_names() {
            options.entry(flag.as_str().to_string()).or_insert(None);
        }
    }
    let mut add = |flag: &str, mode| -> Result<(), String> {
        let previous = options.entry(flag.into()).or_insert(None);
        if previous.is_some_and(|previous| previous != mode) {
            return Err(format!(
                "argument_regions: conflicting operand modes for {flag:?}"
            ));
        }
        *previous = Some(mode);
        // Region grammars use exact option words and immediate argv operands.
        if !matches!(
            mode,
            FlagOperandMode::NextArg | FlagOperandMode::SecondArg | FlagOperandMode::FirstOfTwoArgs
        ) {
            return Err(format!(
                "argument_regions: unsupported operand mode for {flag:?}"
            ));
        }
        Ok(())
    };
    for modifier in modifiers {
        for parameter in &modifier.parameters {
            match &parameter.binding {
                BindingSpec::FollowingMatchedFlag { operand_mode } => {
                    for flag in modifier.matcher.flag_names() {
                        add(flag.as_str(), *operand_mode)?;
                    }
                }
                BindingSpec::FollowingFlag {
                    flag_name,
                    operand_mode,
                } => add(flag_name.as_str(), *operand_mode)?,
                _ => {
                    return Err(
                        "argument_regions: modifier parameters must bind option operands".into(),
                    );
                }
            }
        }
    }
    for parameter in forms.iter().flat_map(|form| &form.parameters) {
        if let BindingSpec::FollowingFlag {
            flag_name,
            operand_mode,
        } = &parameter.binding
        {
            add(flag_name.as_str(), *operand_mode)?;
        }
    }
    Ok(options)
}

pub(crate) fn scan(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    regions: &[ArgumentRegion],
    modifiers: &[Modifier],
    forms: &[Form],
    vocabulary: Option<&crate::ArgumentControlVocabulary>,
) -> ScopedOptions {
    let mut result = ScopedOptions {
        exact_argv: true,
        ownership_unresolved: false,
        scope,
        flags: Vec::new(),
        terminator: None,
        positionals: Some(Vec::new()),
        additional_positionals: Vec::new(),
        retains_positional_default: false,
        argument_regions: Vec::new(),
        error: None,
    };
    let declarations = match operand_declarations(modifiers, forms) {
        Ok(declarations) => declarations,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    };
    let mut index = scope.start_index;
    let mut operand_width_unresolved = false;
    let mut expression_closed = false;
    while index < scope.end_index {
        let Some(value) = argv_value(&projection.args[index]) else {
            let structure = argument_structure(&projection.args[index]);
            // Unknown path data is not an unknown control surface. Only use
            // per-field bounds: unquoted splitting has no such prefix proof.
            let may_control = structure.fields == ArgumentFieldCount::Unknown
                || crate::argument_ownership::may_be_unmodeled_control(
                    &structure,
                    vocabulary,
                    expression_closed,
                )
                || declarations.keys().any(|flag| structure.may_equal(flag))
                || regions.iter().any(|region| {
                    region
                        .start_flags
                        .iter()
                        .any(|flag| structure.may_equal(flag))
                });
            result.ownership_unresolved |= may_control;
            result.positionals.as_mut().unwrap().push(index);
            index += 1;
            continue;
        };
        if let Some(region) = regions
            .iter()
            .find(|r| r.start_flags.iter().any(|f| f == value.as_ref()))
        {
            result.flags.push((index, FlagName::new(value.as_ref())));
            let mut end = index + 1;
            while end < scope.end_index {
                let Some(word) = argv_value(&projection.args[end]) else {
                    let structure = argument_structure(&projection.args[end]);
                    // A bounded word may exclude every parent delimiter but
                    // still disappear or widen inside the child's CLI. Until
                    // child operand ownership is independently certified, keep
                    // that uncertainty: a missing option value can swallow the
                    // next path, and a legacy child Profile may not audit it.
                    result.ownership_unresolved |= end == index + 1
                        || structure.fields != ArgumentFieldCount::ExactlyOne
                        || region
                            .terminators
                            .iter()
                            .any(|t| structure.may_equal(&t.value));
                    end += 1;
                    continue;
                };
                let mut terminates = false;
                for t in &region.terminators {
                    if t.value != word.as_ref() {
                        continue;
                    }
                    let Some(preceding) = &t.preceding else {
                        terminates = true;
                        break;
                    };
                    if end > index + 1 {
                        if let Some(previous) = argv_value(&projection.args[end - 1]) {
                            terminates |= previous.as_ref() == preceding;
                        } else {
                            let previous = argument_structure(&projection.args[end - 1]);
                            result.ownership_unresolved |= previous.fields
                                != ArgumentFieldCount::ExactlyOne
                                || previous.may_equal(preceding);
                        }
                    }
                }
                if terminates {
                    break;
                }
                end += 1;
            }
            if result.error.is_some() {
                break;
            }
            if end == scope.end_index || end == index + 1 {
                result.error = Some(format!(
                    "argument_regions: missing child or terminator for {:?} at {index}",
                    region.id
                ));
                break;
            }
            result.argument_regions.push(BoundArgumentRegion {
                id: region.id.clone(),
                start_index: index,
                command_index: index + 1,
                end_index: end,
            });
            index = end + 1;
            continue;
        }
        if let Some(mode) = declarations.get(value.as_ref()) {
            result.flags.push((index, FlagName::new(value.as_ref())));
            expression_closed |= vocabulary.is_some_and(|v| {
                v.positional_boundary_words
                    .iter()
                    .any(|word| word == value.as_ref())
            });
            let operands = match mode {
                None => 0,
                Some(FlagOperandMode::SecondArg | FlagOperandMode::FirstOfTwoArgs) => 2,
                Some(_) => 1,
            };
            if index + operands >= scope.end_index {
                result.error = Some(format!("argument_regions: missing operand for {value:?}"));
                break;
            }
            index += operands + 1;
            if projection.args[index - operands..index]
                .iter()
                .any(|operand| argument_structure(operand).fields != ArgumentFieldCount::ExactlyOne)
            {
                // Quotes alone do not prove width: "$@" may have many fields.
                // An owned single field may have ANY value, including flags.
                operand_width_unresolved = true;
            }
            continue;
        }
        if value.starts_with('-') && value.len() > 1 {
            if let Some(tail) = value.strip_prefix('-')
                && vocabulary.is_some_and(|v| {
                    v.operand_free_short_clusters.iter().any(|letters| {
                        !tail.is_empty() && tail.chars().all(|c| letters.contains(c))
                    })
                })
            {
                // Retain each member's semantics (not just the final flag).
                // Validation excludes any member with an argv operand.
                for flag in tail.chars() {
                    result
                        .flags
                        .push((index, FlagName::new(format!("-{flag}"))));
                }
                index += 1;
                continue;
            }
            result.error = Some(format!(
                "argument_regions: undeclared outer option {value:?}; operand ownership unknown"
            ));
            break;
        }
        result.positionals.as_mut().unwrap().push(index);
        index += 1;
    }
    if operand_width_unresolved {
        // Only attempt the extra proof for bounded operand-width uncertainty.
        // Existing unknown controls/children and scanner errors keep their
        // fallback; no second scanner on the common exact-argv path.
        if result.error.is_none() && !result.ownership_unresolved {
            match crate::argument_ownership::covered_positionals(
                projection,
                &result,
                &declarations,
                regions,
                modifiers,
                forms,
                vocabulary,
            ) {
                Some(coverage) => {
                    result.additional_positionals = coverage.additional;
                    result.retains_positional_default = coverage.retains_default;
                }
                None => result.ownership_unresolved = true,
            }
        } else {
            result.ownership_unresolved = true;
        }
    }
    result
}
