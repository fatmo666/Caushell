//! Opt-in argv ownership. No command names or runtime inspection are used.
use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    ArgumentRegion, ArgumentScope, BindingSpec, FlagName, FlagOperandMode, Form, Modifier,
    ProjectedArg, ProjectedInvocation, ScopedOptions,
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
        caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
            .map(Cow::Owned)
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
        if !matches!(mode, FlagOperandMode::NextArg | FlagOperandMode::SecondArg) {
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
) -> ScopedOptions {
    let mut result = ScopedOptions {
        exact_argv: true,
        ownership_unresolved: false,
        scope,
        flags: Vec::new(),
        terminator: None,
        positionals: Some(Vec::new()),
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
    while index < scope.end_index {
        let Some(value) = argv_value(&projection.args[index]) else {
            // Retain a possible root and later known child effects. This is
            // a partial model, not proof that an unknown word is plain data.
            result.ownership_unresolved = true;
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
                    // An unknown word may itself terminate the child. Keep
                    // the known prefix/candidate, explicitly marking that
                    // its full argv ownership has not been established.
                    result.ownership_unresolved = true;
                    end += 1;
                    continue;
                };
                let terminates = region.terminators.iter().any(|t| {
                    t.value == word.as_ref()
                        && t.preceding.as_ref().is_none_or(|preceding| {
                            end > index + 1
                                && argv_value(&projection.args[end - 1])
                                    .is_some_and(|v| v.as_ref() == preceding)
                        })
                });
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
            let operands = match mode {
                None => 0,
                Some(FlagOperandMode::SecondArg) => 2,
                Some(_) => 1,
            };
            if index + operands >= scope.end_index {
                result.error = Some(format!("argument_regions: missing operand for {value:?}"));
                break;
            }
            index += operands + 1;
            if projection.args[index - operands..index]
                .iter()
                .any(|operand| !operand.quoted && argv_value(operand).is_none())
            {
                // Unknown unquoted operands can expand to zero or many words.
                result.ownership_unresolved = true;
            }
            continue;
        }
        if value.starts_with('-') && value.len() > 1 {
            result.error = Some(format!(
                "argument_regions: undeclared outer option {value:?}; operand ownership unknown"
            ));
            break;
        }
        result.positionals.as_mut().unwrap().push(index);
        index += 1;
    }
    result
}
