//! Declarative option ownership, independent of any particular command.
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ArgumentScope, BindingSpec, FlagName, FlagOperandMode, Form, Modifier, OptionMatchingPolicy,
    OptionPrefixPolicy, ProjectedInvocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedOptions {
    /// Exact decoded argv words, rather than shell-lexical flag spellings.
    pub exact_argv: bool,
    /// Keep partial known child semantics, but never approve uncertain ownership.
    pub ownership_unresolved: bool,
    pub argument_regions: Vec<crate::BoundArgumentRegion>,
    pub scope: ArgumentScope,
    /// Actual option occurrences, excluding option operands and child argv.
    pub flags: Vec<(usize, FlagName)>,
    pub terminator: Option<usize>,
    /// Sorted non-option argv indices inside a permuted scope. None keeps the
    /// leading-prefix representation and avoids allocating for old profiles.
    pub positionals: Option<Vec<usize>>,
    /// Original argv sources that may ALSO be positionals after bounded field
    /// expansion. Bind them conservatively even if a filter owns them too.
    pub additional_positionals: Vec<usize>,
    /// A bounded expansion may leave no explicit roots. Preserve configured
    /// positional defaults alongside the union of possible explicit targets.
    pub retains_positional_default: bool,
    /// An unknown option means its arity (and hence the boundary) is unknown.
    pub error: Option<String>,
}

type Declarations = BTreeMap<String, Option<FlagOperandMode>>;

/// A native replacement can preserve an entire long-option name and equals
/// sign while leaving the value unknown. Diff's anchor operand grammar
/// interprets the suffix as one file or stdin operand.
pub fn native_diff_anchor(argument: &crate::ProjectedArg) -> Option<&'static str> {
    use caushell_types::{ImplicitInputSource, RuntimeArgumentDomain};

    if argument.implicit_input_source != Some(ImplicitInputSource::StdinData)
        || argument.node_kind != "runtime_scalar"
    {
        return None;
    }
    match argument.runtime_argument_domain.as_ref()? {
        RuntimeArgumentDomain::TextTemplate { prefix, .. }
        | RuntimeArgumentDomain::PathTemplate { prefix, .. } => {
            match prefix.split_once('=')?.0 {
                "--from-file" => Some("--from-file"),
                "--to-file" => Some("--to-file"),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn declared_options(
    profile: &crate::CommandProfile,
) -> Result<BTreeMap<String, Option<FlagOperandMode>>, String> {
    declarations(
        &profile.modifiers,
        &profile.forms,
        profile.option_matching,
        &profile.exact_option_words,
    )
}

impl ScopedOptions {
    pub(crate) fn ownership_is_leading(&self) -> bool {
        let first_positional = self
            .positionals
            .as_ref()
            .and_then(|indices| indices.first())
            .into_iter()
            .chain(&self.additional_positionals)
            .copied()
            .min()
            .unwrap_or(self.scope.end_index);
        self.flags.iter().all(|(index, _)| *index < first_positional)
            && self.terminator.is_none_or(|index| index < first_positional)
    }

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
    exact_option_words: &[FlagName],
) -> Result<Declarations, String> {
    let mut flags = BTreeMap::new();
    for modifier in modifiers {
        for flag in modifier.matcher.flag_names() {
            let name = flag.as_str();
            let short = name
                .strip_prefix(['-', '+'])
                .is_some_and(|tail| tail.len() == 1 && !tail.starts_with(['-', '+']));
            let long = name.starts_with("--") && name.len() > 2 && !name.contains('=');
            let exact_word = (matching == OptionMatchingPolicy::ExactNames
                || exact_option_words.contains(flag))
                && name.starts_with(['-', '+'])
                && name.len() > 1
                && name != "--"
                && name != "++"
                && !name.contains('=')
                && !name.chars().any(|c| c.is_whitespace() || c == '\0');
            let declared_word = matching == OptionMatchingPolicy::DeclaredShortWords
                && name.starts_with('-')
                && !name.starts_with("--")
                && (1..=2).contains(&(name.len() - 1))
                && name[1..]
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"@!$".contains(&c));
            if !short && !long && !exact_word && !declared_word {
                return Err(format!(
                    "leading_options: unsupported option spelling {name:?}; declare one-character short or long options"
                ));
            }
            flags.entry(flag.as_str().to_string()).or_insert(None);
        }
    }
    let mut seen = BTreeSet::new();
    for word in exact_option_words {
        let name = word.as_str();
        if !name.starts_with(['-', '+'])
            || name.starts_with("--")
            || name.starts_with("++")
            || name.len() <= 2
            || name.contains('=')
            || name.chars().any(|c| c.is_whitespace() || c == '\0')
            || !flags.contains_key(name)
            || !seen.insert(name)
        {
            return Err(format!(
                "exact_option_words must contain unique declared single-prefix option words: {name:?}"
            ));
        }
    }
    let mut add = |flag: &str, mode| -> Result<(), String> {
        if matches!(
            mode,
            FlagOperandMode::WordAttached
                | FlagOperandMode::OptionalWordAttached
                | FlagOperandMode::WordAttachedOrNextArg
        ) && (matching != OptionMatchingPolicy::ExactNames || flag.starts_with("--"))
        {
            return Err(
                "word_attached requires scoped exact_names single-prefix option words".into(),
            );
        }
        if mode == FlagOperandMode::OptionalShortOctalPrefix
            && (matching != OptionMatchingPolicy::ShortClusters
                || flag.len() != 2
                || !flag.starts_with('-'))
        {
            return Err("optional_short_octal_prefix requires a one-character short option and short_clusters matching".into());
        }
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
    exact_option_words: &[FlagName],
) -> Result<(), String> {
    declarations(modifiers, forms, matching, exact_option_words).map(|_| ())
}

fn trailing_option_candidate(token: &str, words: &[FlagName], declarations: &Declarations) -> bool {
    words.iter().any(|word| {
        let name = word.as_str();
        if token == name {
            return true;
        }
        let Some(suffix) = token.strip_prefix(name).filter(|suffix| !suffix.is_empty()) else {
            return false;
        };
        let Some(Some(mode)) = declarations.get(name) else {
            return false;
        };
        if name.starts_with("--") {
            return suffix.starts_with('=');
        }
        matches!(
            mode,
            FlagOperandMode::NextArg
                | FlagOperandMode::WordAttached
                | FlagOperandMode::OptionalWordAttached
                | FlagOperandMode::WordAttachedOrNextArg
                | FlagOperandMode::OptionalNextArg
                | FlagOperandMode::InlineOrShortAttached
                | FlagOperandMode::OptionalInlineOrShortAttached
        )
    })
}

/// Does this original word already prove the control bytes and one argv
/// field? Keep value-dependent operations and possible empty short operands
/// on the ordinary conservative path.
fn fixed_temporal_attachment(
    token: &str,
    structure: &crate::ArgumentStructure,
    declarations: &Declarations,
    modifiers: &[Modifier],
    forms: &[Form],
    matching: OptionMatchingPolicy,
    exact_option_words: &[FlagName],
) -> bool {
    if structure.fields != crate::ArgumentFieldCount::ExactlyOne {
        return false;
    }
    let flag = if token.starts_with("--") {
        let Some((flag, _)) = token.split_once('=') else {
            return false;
        };
        if !structure
            .static_prefix
            .strip_prefix(flag)
            .is_some_and(|tail| tail.starts_with('='))
        {
            return false;
        }
        flag
    } else {
        if matching != OptionMatchingPolicy::ShortClusters || !exact_option_words.is_empty() {
            return false;
        }
        let Some(flag) = token
            .get(..2)
            .filter(|flag| flag.starts_with('-') && flag.as_bytes()[1].is_ascii_alphabetic())
        else {
            return false;
        };
        if token.len() == 2
            || !structure.static_prefix.starts_with(flag)
            || structure.may_equal(flag)
        {
            return false;
        }
        flag
    };
    declarations.get(flag) == Some(&Some(FlagOperandMode::NextArg))
        && temporal_option_is_value_only(flag, modifiers, forms)
}

pub(crate) fn temporal_option_is_value_only(
    flag: &str,
    modifiers: &[Modifier],
    forms: &[Form],
) -> bool {
    use crate::{SelectorExpr, SelectorPredicate, SemanticType, StructuredValueContext};

    // A time expression is data in one already-owned slot. Keep the proof
    // limited to declarations with no effects or constraints based on that
    // slot's runtime value. Other option data needs a separate value proof.
    let mut owners = modifiers.iter().filter(|m| {
        m.matcher
            .flag_names()
            .iter()
            .any(|name| name.as_str() == flag)
    });
    let Some(owner) = owners.next() else {
        return false;
    };
    if owners.next().is_some()
        || owner.ends_option_scope
        || !owner.constraints.is_empty()
        || !owner.effects.is_empty()
    {
        return false;
    }
    let [parameter] = owner.parameters.as_slice() else {
        return false;
    };
    if !matches!(
        parameter.semantic,
        SemanticType::StructuredValue(value)
            if value.context == StructuredValueContext::DateExpression
    ) || !matches!(
        parameter.binding,
        BindingSpec::FollowingMatchedFlag {
            operand_mode: FlagOperandMode::NextArg
        }
    ) || !parameter.value_constraints.is_empty()
        || parameter.value_projection.is_some()
        || parameter.structured_projection.is_some()
    {
        return false;
    }
    fn tests_modifier_value(selector: &SelectorExpr) -> bool {
        match selector {
            SelectorExpr::All(items) | SelectorExpr::Any(items) => {
                items.iter().any(tests_modifier_value)
            }
            SelectorExpr::Not(item) => tests_modifier_value(item),
            SelectorExpr::Predicate(SelectorPredicate::HasModifierParameterMatching(..)) => true,
            SelectorExpr::Predicate(_) => false,
        }
    }
    !modifiers.iter().any(|m| {
        m.effects_when.as_ref().is_some_and(|c| {
            c.last_option_not_matching.is_some() || c.last_parameter_not_matching.is_some()
        })
    }) && !forms.iter().any(|form| {
        tests_modifier_value(&form.selector)
            || tests_modifier_value(&form.remaining_selector)
            || form.parameters.iter().any(|p| {
                matches!(&p.binding,
                    BindingSpec::FollowingFlag { flag_name, .. } if flag_name.as_str() == flag
                )
            })
    })
}

pub(crate) fn scan_leading_options(
    projection: &ProjectedInvocation,
    scope: ArgumentScope,
    modifiers: &[Modifier],
    forms: &[Form],
    matching: OptionMatchingPolicy,
    prefixes: OptionPrefixPolicy,
    permuted: bool,
    positional_prefix: Option<usize>,
    operand_matcher: Option<&crate::OptionOperandMatcher>,
    exact_option_words: &[FlagName],
    trailing_option_words: &[FlagName],
) -> ScopedOptions {
    let mut result = ScopedOptions {
        exact_argv: false,
        ownership_unresolved: false,
        argument_regions: Vec::new(),
        scope: ArgumentScope::new(scope.start_index, scope.start_index),
        flags: Vec::new(),
        terminator: None,
        positionals: (permuted || !trailing_option_words.is_empty()).then(Vec::new),
        additional_positionals: Vec::new(),
        retains_positional_default: false,
        error: None,
    };
    let declarations = match declarations(modifiers, forms, matching, exact_option_words) {
        Ok(flags) => flags,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    };
    let mut index = scope.start_index;
    let mut trailing = false;
    let ends_scope: BTreeSet<_> = modifiers
        .iter()
        .filter(|m| m.ends_option_scope)
        .flat_map(|m| m.matcher.flag_names())
        .map(|flag| flag.as_str())
        .collect();
    while index < scope.end_index {
        if permuted
            && !trailing
            && positional_prefix.is_none()
            && operand_matcher.is_none()
            && projection.command_name.as_deref() == Some("diff")
            && let Some(flag) = native_diff_anchor(&projection.args[index])
            && declarations.get(flag) == Some(&Some(FlagOperandMode::NextArg))
            && !ends_scope.contains(flag)
        {
            result.flags.push((index, FlagName::new(flag)));
            index += 1;
            result.scope.end_index = index;
            continue;
        }
        let structure = crate::argument_structure(&projection.args[index]);
        if !structure.exact {
            // Quotes certify at most field width, not native option ownership.
            // Keep known effects, but do not bless a tail that may introduce
            // another option or a terminator. A proven data prefix is distinct
            // from an unbounded runtime list.
            let may_be_an_option = structure.may_start_with("-")
                || prefixes == OptionPrefixPolicy::DashAndPlus && structure.may_start_with("+");
            if may_be_an_option
                && !(permuted
                    && !trailing
                    && positional_prefix.is_none()
                    && operand_matcher.is_none()
                    && fixed_temporal_attachment(
                        &projection.args[index].text,
                        &structure,
                        &declarations,
                        modifiers,
                        forms,
                        matching,
                        exact_option_words,
                    ))
            {
                result.ownership_unresolved = true;
            }
            // A non-option batch can end the leading option phase without
            // knowing its length. Its disappearance matters only if later
            // words could then become options/terminators instead of data.
            result.ownership_unresolved |= !permuted
                && structure.fields != crate::ArgumentFieldCount::ExactlyOne
                && projection.args[index + 1..scope.end_index]
                    .iter()
                    .any(|arg| {
                        let later = crate::argument_structure(arg);
                        later.may_start_with("-")
                            || prefixes == OptionPrefixPolicy::DashAndPlus
                                && later.may_start_with("+")
                    });
        }
        if positional_prefix.is_some() {
            // This grammar's boundary is counted in actual argv fields, not
            // source words. Dynamic option words/field width cannot certify it.
            result.ownership_unresolved |= !structure.exact;
        }
        let token = projection.args[index].text.as_str();
        if prefixes.is_terminator(token) {
            if permuted && result.error.is_some() {
                // A preceding unknown arity may consume this word as data.
                // Retain hazards in either possible tail; do not certify a
                // terminator or treat the following words as proven operands.
                index += 1;
                result.scope.end_index = index;
                continue;
            }
            result.terminator = Some(index);
            result.scope.end_index = index + 1;
            return result;
        }
        if !prefixes.is_option(token)
            || (trailing && !trailing_option_candidate(token, trailing_option_words, &declarations))
            || operand_matcher.is_some_and(|grammar| match &grammar.regex {
                Some(regex) => regex
                    .regex()
                    .find(token)
                    .is_some_and(|m| m.start() == 0 && m.end() == token.len()),
                None => crate::bind::argument_matches_value_matcher(token, &grammar.matcher),
            })
        {
            if let Some(positionals) = &mut result.positionals {
                if positional_prefix.is_some_and(|limit| positionals.len() >= limit) {
                    break;
                }
                positionals.push(index);
                // Later words use only the declared trailing vocabulary.
                // They never restart the leading operation-mode grammar.
                trailing |= !trailing_option_words.is_empty();
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
        } else if matching == OptionMatchingPolicy::ExactNames
            || exact_option_words.iter().any(|name| name.as_str() == token)
        {
            match declarations.get(token) {
                Some(mode) => {
                    token_flags.push(FlagName::new(token));
                    Ok((*mode, false, true))
                }
                None => {
                    // Exact single-prefix option words may own an explicitly
                    // declared =VALUE operand, just like long options. Do not
                    // reinterpret their suffix as short-option clusters.
                    if let Some((name, _)) = token.split_once('=')
                        && let Some(mode) = declarations.get(name)
                        && matches!(
                            mode,
                            Some(
                                FlagOperandMode::InlineOnly
                                    | FlagOperandMode::OptionalInlineOnly
                                    | FlagOperandMode::InlineOrShortAttached
                                    | FlagOperandMode::OptionalInlineOrShortAttached
                            )
                        )
                    {
                        token_flags.push(FlagName::new(name));
                        Ok((*mode, true, false))
                    } else {
                        // An explicit attached grammar may extend only its own
                        // declared word. Exact flag-only names win above; among
                        // attached words the longest declaration owns the suffix.
                        let matched = declarations
                            .iter()
                            .filter(|(name, mode)| {
                                matches!(
                                    mode,
                                    Some(
                                        FlagOperandMode::WordAttached
                                            | FlagOperandMode::OptionalWordAttached
                                            | FlagOperandMode::WordAttachedOrNextArg
                                    )
                                ) && token.starts_with(name.as_str())
                                    && token.len() > name.len()
                            })
                            .max_by_key(|(name, _)| name.len());
                        match matched {
                            Some((name, mode)) => {
                                token_flags.push(FlagName::new(name));
                                Ok((*mode, true, true))
                            }
                            None => Err(format!("unknown leading option {token:?}")),
                        }
                    }
                }
            }
        } else {
            let mut mode = None;
            let mut inline = false;
            let mut error = None;
            let mut offset = 1;
            while offset < token.len() {
                let ch = token[offset..]
                    .chars()
                    .next()
                    .expect("nonempty short option suffix");
                let name = if matching == OptionMatchingPolicy::DeclaredShortWords {
                    declarations
                        .keys()
                        .filter(|name| {
                            !name.starts_with("--")
                                && name.starts_with(&token[..1])
                                && token[offset..].starts_with(&name[1..])
                        })
                        .max_by_key(|name| name.len())
                        .cloned()
                        .unwrap_or_else(|| format!("{}{ch}", &token[..1]))
                } else {
                    format!("{}{ch}", &token[..1])
                };
                let Some(flag_mode) = declarations.get(&name) else {
                    error = Some(format!("unknown leading option {name:?} in {token:?}"));
                    break;
                };
                if *flag_mode == Some(FlagOperandMode::OptionalShortOctalPrefix)
                    && token_flags.contains(&FlagName::new(&name))
                {
                    error = Some(format!(
                        "repeated numeric-prefix option {name:?} in one short token is unresolved"
                    ));
                    break;
                }
                token_flags.push(FlagName::new(&name));
                offset += name.len() - 1;
                if ends_scope.contains(name.as_str()) && flag_mode.is_none() {
                    break;
                }
                if flag_mode.is_some() {
                    if *flag_mode == Some(FlagOperandMode::OptionalShortOctalPrefix) {
                        offset += octal_prefix_len(&token[offset..]);
                        continue;
                    }
                    mode = *flag_mode;
                    inline = offset < token.len();
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
                result.error.get_or_insert(error);
                if permuted {
                    // Recover only possible modifier effects in a permuted
                    // argv grammar. An unknown option's arity cannot certify
                    // ownership, but must not erase later declared hazards.
                    // The original error still prevents complete analysis
                    // and all namespace/operand ownership certificates.
                    result.ownership_unresolved = true;
                    index += 1;
                    result.scope.end_index = index;
                    continue;
                }
                break;
            }
        };
        // Exact-word precedence still applies. A longer declared word may
        // resemble an allowed short option plus an attached value, but must
        // not escape the trailing vocabulary after canonical decoding.
        if trailing
            && token_flags
                .iter()
                .any(|flag| !trailing_option_words.contains(flag))
        {
            result
                .positionals
                .as_mut()
                .expect("trailing positional map")
                .push(index);
            index += 1;
            result.scope.end_index = index;
            continue;
        }
        if inline
            && (mode.is_none()
                || matches!(mode, Some(FlagOperandMode::SecondArg))
                || (short
                    && !matches!(
                        mode,
                        Some(
                            FlagOperandMode::NextArg
                                | FlagOperandMode::WordAttached
                                | FlagOperandMode::OptionalWordAttached
                                | FlagOperandMode::WordAttachedOrNextArg
                                | FlagOperandMode::OptionalNextArg
                                | FlagOperandMode::InlineOrShortAttached
                                | FlagOperandMode::OptionalInlineOrShortAttached
                        )
                    )))
        {
            result
                .error
                .get_or_insert_with(|| format!("unsupported inline operand in {token:?}"));
            if permuted {
                result.ownership_unresolved = true;
                index += 1;
                result.scope.end_index = index;
                continue;
            }
            break;
        }
        let extra = if inline {
            0
        } else {
            match mode {
                Some(
                    FlagOperandMode::NextArg
                    | FlagOperandMode::NextPositional
                    | FlagOperandMode::WordAttachedOrNextArg,
                ) => 1,
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
        let ends = token_flags
            .iter()
            .any(|flag| ends_scope.contains(flag.as_str()));
        result
            .flags
            .extend(token_flags.into_iter().map(|name| (index, name)));
        if index + extra >= scope.end_index {
            result.scope.end_index = scope.end_index;
            result.error = Some(format!("missing operand for {token:?}"));
            return result;
        }
        // Consuming one source token does not prove consuming one argv word.
        // A disappearing/multi-field operand can expose following words as
        // controls, even for grammars without a positional-prefix boundary.
        result.ownership_unresolved |=
            projection.args[index + 1..index + 1 + extra]
                .iter()
                .any(|arg| {
                    crate::argument_structure(arg).fields != crate::ArgumentFieldCount::ExactlyOne
                });
        if mode == Some(FlagOperandMode::OptionalNextArg) && extra == 1 {
            let operand = crate::argument_structure(&projection.args[index + 1]);
            result.ownership_unresolved |= !operand.exact
                && (operand.may_start_with("-")
                    || prefixes == OptionPrefixPolicy::DashAndPlus && operand.may_start_with("+"));
        }
        // After a gap, a preceding option may consume the apparent owner of
        // the next value. Scan those argv words as possible controls too. A
        // known operand/terminator before the gap keeps its exact boundary.
        index += if result.error.is_some() { 1 } else { 1 + extra };
        result.scope.end_index = index;
        if ends {
            return result;
        }
    }
    result
}

pub(crate) fn octal_prefix_len(value: &str) -> usize {
    value
        .bytes()
        .take_while(|ch| matches!(ch, b'0'..=b'7'))
        .count()
}
