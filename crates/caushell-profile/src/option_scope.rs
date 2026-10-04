//! Declarative option ownership, independent of any particular command.
use std::collections::BTreeMap;

use crate::{
    ArgumentScope, BindingSpec, FlagName, FlagOperandMode, Form, Modifier, OptionMatchingPolicy,
    OptionPrefixPolicy, ProjectedInvocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedOptions {
    pub scope: ArgumentScope,
    /// Actual option occurrences, excluding option operands and child argv.
    pub flags: Vec<(usize, FlagName)>,
    pub terminator: Option<usize>,
    /// Sorted non-option argv indices inside a permuted scope. None keeps the
    /// leading-prefix representation and avoids allocating for old profiles.
    pub positionals: Option<Vec<usize>>,
    /// An unknown option means its arity (and hence the boundary) is unknown.
    pub error: Option<String>,
}

type Declarations = BTreeMap<String, Option<FlagOperandMode>>;

impl ScopedOptions {
    pub(crate) fn is_positional(&self, index: usize) -> bool {
        index >= self.scope.end_index
            || self
                .positionals
                .as_ref()
                .is_some_and(|indices| indices.binary_search(&index).is_ok())
    }
}

fn declarations(
    modifiers: &[Modifier],
    forms: &[Form],
    matching: OptionMatchingPolicy,
) -> Result<Declarations, String> {
    let mut flags = BTreeMap::new();
    for modifier in modifiers {
        for flag in modifier.matcher.flag_names() {
            let name = flag.as_str();
            let short = name
                .strip_prefix(['-', '+'])
                .is_some_and(|tail| tail.len() == 1 && !tail.starts_with(['-', '+']));
            let long = name.starts_with("--") && name.len() > 2 && !name.contains('=');
            let exact_word = matching == OptionMatchingPolicy::ExactNames
                && name.starts_with(['-', '+'])
                && name.len() > 1
                && name != "--"
                && name != "++"
                && !name.contains('=')
                && !name.chars().any(char::is_whitespace);
            if !short && !long && !exact_word {
                return Err(format!(
                    "leading_options: unsupported option spelling {name:?}; declare one-character short or long options"
                ));
            }
            flags.entry(flag.as_str().to_string()).or_insert(None);
        }
    }
    let mut add = |flag: &str, mode| -> Result<(), String> {
        let Some(existing) = flags.get_mut(flag) else {
            return Err(format!(
                "leading_options: option {flag:?} must be declared by a modifier"
            ));
        };
        if existing.is_some_and(|existing| existing != mode) {
            return Err(format!(
                "leading_options: conflicting operand modes for {flag:?}"
            ));
        }
        *existing = Some(mode);
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
                    return Err(format!(
                        "leading_options: modifier parameter {:?} must bind an option operand",
                        parameter.name.as_str()
                    ));
                }
            }
        }
    }
    for form in forms {
        for parameter in &form.parameters {
            if let BindingSpec::FollowingFlag {
                flag_name,
                operand_mode,
            } = &parameter.binding
            {
                add(flag_name.as_str(), *operand_mode)?;
            }
        }
    }
    Ok(flags)
}

pub(crate) fn validate_declarations(
    modifiers: &[Modifier],
    forms: &[Form],
    matching: OptionMatchingPolicy,
) -> Result<(), String> {
    declarations(modifiers, forms, matching).map(|_| ())
}

pub(crate) fn scan_leading_options(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    modifiers: &[Modifier],
    forms: &[Form],
    matching: OptionMatchingPolicy,
    prefixes: OptionPrefixPolicy,
    permuted: bool,
) -> ScopedOptions {
    let mut result = ScopedOptions {
        scope: ArgumentScope::new(scope.start_index, scope.start_index),
        flags: Vec::new(),
        terminator: None,
        positionals: permuted.then(Vec::new),
        error: None,
    };
    let declarations = match declarations(modifiers, forms, matching) {
        Ok(flags) => flags,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    };
    let mut index = scope.start_index;
    while index < scope.end_index {
        let token = projection.args[index].text.as_str();
        if prefixes.is_terminator(token) {
            result.terminator = Some(index);
            result.scope.end_index = index + 1;
            return result;
        }
        if !prefixes.is_option(token) {
            if let Some(positionals) = &mut result.positionals {
                positionals.push(index);
                index += 1;
                result.scope.end_index = index;
                continue;
            }
            break;
        }
        let mut token_flags = Vec::new();
        let mode_and_inline = if token.starts_with("--") {
            let (name, inline) = token
                .split_once('=')
                .map_or((token, None), |(name, value)| (name, Some(value)));
            match declarations.get(name) {
                Some(mode) => {
                    token_flags.push(FlagName::new(name));
                    Ok((*mode, inline.is_some(), false))
                }
                None => Err(format!("unknown leading option {name:?}")),
            }
        } else if matching == OptionMatchingPolicy::ExactNames {
            match declarations.get(token) {
                Some(mode) => {
                    token_flags.push(FlagName::new(token));
                    Ok((*mode, false, true))
                }
                None => Err(format!("unknown leading option {token:?}")),
            }
        } else {
            let mut mode = None;
            let mut inline = false;
            let mut error = None;
            for (offset, ch) in token[1..].char_indices() {
                let name = format!("{}{ch}", &token[..1]);
                let Some(flag_mode) = declarations.get(&name) else {
                    error = Some(format!("unknown leading option {name:?} in {token:?}"));
                    break;
                };
                token_flags.push(FlagName::new(&name));
                if flag_mode.is_some() {
                    mode = *flag_mode;
                    inline = offset + ch.len_utf8() < token.len() - 1;
                    break;
                }
            }
            error.map_or(Ok((mode, inline, true)), Err)
        };
        let (mode, inline, short) = match mode_and_inline {
            Ok(parsed) => parsed,
            Err(error) => {
                // Even if the later member's arity is unknown, earlier
                // decoded members of this cluster are confirmed options.
                if !token_flags.is_empty() {
                    result
                        .flags
                        .extend(token_flags.into_iter().map(|name| (index, name)));
                    result.scope.end_index = index + 1;
                }
                result.error = Some(error);
                break;
            }
        };
        if inline
            && (mode.is_none()
                || matches!(mode, Some(FlagOperandMode::SecondArg))
                || (short
                    && !matches!(
                        mode,
                        Some(
                            FlagOperandMode::NextArg
                                | FlagOperandMode::OptionalNextArg
                                | FlagOperandMode::InlineOrShortAttached
                                | FlagOperandMode::OptionalInlineOrShortAttached
                        )
                    )))
        {
            result.error = Some(format!("unsupported inline operand in {token:?}"));
            break;
        }
        let extra = if inline {
            0
        } else {
            match mode {
                Some(FlagOperandMode::NextArg | FlagOperandMode::NextPositional) => 1,
                Some(FlagOperandMode::OptionalNextArg) => usize::from(
                    index + 1 < scope.end_index
                        && projection.args.get(index + 1).is_some_and(|arg| {
                            !prefixes.is_option(&arg.text) && !prefixes.is_terminator(&arg.text)
                        }),
                ),
                Some(FlagOperandMode::SecondArg) => 2,
                Some(FlagOperandMode::NextPositionalAfterDashDash) => {
                    if projection
                        .args
                        .get(index + 1)
                        .is_some_and(|arg| arg.text == "--")
                    {
                        2
                    } else {
                        1
                    }
                }
                _ => 0,
            }
        };
        result
            .flags
            .extend(token_flags.into_iter().map(|name| (index, name)));
        if index + extra >= scope.end_index {
            result.scope.end_index = scope.end_index;
            result.error = Some(format!("missing operand for {token:?}"));
            return result;
        }
        index += 1 + extra;
        result.scope.end_index = index;
    }
    result
}
