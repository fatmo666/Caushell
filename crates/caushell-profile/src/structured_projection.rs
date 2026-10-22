use std::collections::BTreeMap;

use crate::{
    BoundInvocation, BoundParameter, BoundValue, Parameter, ProjectedSemanticValue,
    ProjectionUnknownReason, SemanticValueResolution, StructuredProjection,
    StructuredProjectionMatcher, StructuredProjectionTarget, ValueProjection, project_value,
};

/// Decode only parameters with a declared tool grammar. No global scan or shell reparse.
pub(crate) fn project_parameters<'a>(
    invocation: &mut BoundInvocation,
    parameters: impl Iterator<Item = (&'a Parameter, bool)>,
) {
    for (parameter, flag_present) in parameters {
        let Some(grammar) = &parameter.structured_projection else {
            continue;
        };
        if let Some(source) = invocation
            .bound_parameters
            .iter_mut()
            .find(|p| p.name == parameter.name)
        {
            source.structured_projection = Some(grammar.clone());
        } else {
            let missing_flag_operand = flag_present
                && matches!(
                    parameter.binding,
                    crate::BindingSpec::FollowingMatchedFlag { operand_mode }
                        | crate::BindingSpec::FollowingFlag { operand_mode, .. }
                        if !matches!(operand_mode,
                            crate::FlagOperandMode::OptionalWordAttached
                                | crate::FlagOperandMode::OptionalNextArg
                                | crate::FlagOperandMode::OptionalInlineOnly
                                | crate::FlagOperandMode::OptionalInlineOrShortAttached
                                | crate::FlagOperandMode::OptionalShortOctalPrefix)
                );
            if parameter.cardinality.is_optional() && !missing_flag_operand {
                continue;
            }
            let mut source =
                BoundParameter::new(parameter.name.clone(), parameter.semantic.clone());
            source.structured_projection = Some(grammar.clone());
            invocation.bound_parameters.push(source);
        }
    }
    refresh_structured_parameters(invocation);
}

pub(crate) fn refresh_structured_parameters(invocation: &mut BoundInvocation) {
    invocation
        .bound_parameters
        .retain(|p| p.structured_source.is_none());
    let mut generated = BTreeMap::new();
    let mut native_unresolved = false;
    for parameter in &invocation.bound_parameters {
        let Some(grammar) = &parameter.structured_projection else {
            continue;
        };
        let source = parameter;
        // A declared branch that does not select a target makes that target
        // inapplicable, not unbound. Unknown/missing sources still populate
        // every possible active target below; never clear earlier values.
        for target in grammar
            .branches
            .iter()
            .filter_map(|branch| branch.target.as_ref())
            .chain(grammar.fallback.iter())
        {
            generated.entry(target.name.clone()).or_insert_with(|| {
                let mut projected =
                    BoundParameter::new(target.name.clone(), target.semantic.clone());
                projected.projected_values = Some(Vec::new());
                projected.structured_source = Some(parameter.name.clone());
                projected
            });
        }
        if source.values.is_empty() {
            // The owning modifier was selected, but no operand was bound.
            // A missing operand is not proof of a missing write or child.
            let missing = BoundValue::argument_with_node_kind(
                "",
                true,
                "structured_missing",
                caushell_parse::SourceSpan {
                    start_byte: 0,
                    end_byte: 0,
                    start_row: 0,
                    end_row: 0,
                    start_column: 0,
                    end_column: 0,
                },
                crate::ArgumentBindingSource::RemainingArg,
            );
            emit_unknown(invocation, grammar, &missing, &mut generated);
            native_unresolved |= grammar.native_syntax.is_some();
            for target in grammar
                .branches
                .iter()
                .filter_map(|b| b.target.as_ref())
                .chain(grammar.fallback.iter())
            {
                if let Some(projected) = generated.get_mut(&target.name) {
                    projected.structured_source = Some(parameter.name.clone());
                }
            }
            continue;
        }
        let values = if grammar.last_value_only {
            &source.values[source.values.len() - 1..]
        } else {
            &source.values[..]
        };
        'operands: for value in values {
            let matched = match project_value(&ValueProjection::Identity, value) {
                Some(SemanticValueResolution::Known(text)) => {
                    if let Some(syntax) = grammar.native_syntax {
                        let inputs = match syntax {
                            crate::NativeOperandSyntax::CurlMultipart => {
                                crate::native_operand::multipart_inputs(&text)
                            }
                            crate::NativeOperandSyntax::PassphraseSource => {
                                crate::native_operand::passphrase_inputs(&text)
                            }
                            crate::NativeOperandSyntax::CurlWriteOut => {
                                crate::native_operand::write_out_paths(&text)
                            }
                        };
                        match inputs {
                            Some(items) => {
                                for item in items {
                                    project_item(invocation, grammar, value, &item, &mut generated);
                                }
                            }
                            None => {
                                emit_unknown(invocation, grammar, value, &mut generated);
                                native_unresolved = true;
                            }
                        }
                        false
                    } else if let Some(separator) = &grammar.separator {
                        for item in text.split(separator.as_str()) {
                            let matched =
                                project_item(invocation, grammar, value, item, &mut generated);
                            if matched && grammar.first_match_only {
                                break 'operands;
                            }
                        }
                        false
                    } else {
                        project_item(invocation, grammar, value, &text, &mut generated)
                    }
                }
                Some(SemanticValueResolution::Unknown(
                    crate::ProjectionUnknownReason::EmptyValue,
                )) if grammar.native_syntax.is_none() && grammar.separator.is_none() => {
                    // Identity reports EmptyValue only for a complete decoded
                    // scalar. An explicit no-effect branch may recognize it;
                    // missing operands and dynamic prefixes never enter here.
                    project_item(invocation, grammar, value, "", &mut generated)
                }
                _ => {
                    let guaranteed_match = emit_unknown(invocation, grammar, value, &mut generated);
                    native_unresolved |= grammar.native_syntax.is_some();
                    // A possible match is not a guaranteed first match.
                    // Retain later operands until a concrete match is found.
                    guaranteed_match
                }
            };
            if matched && grammar.first_match_only {
                break;
            }
        }
        for target in grammar
            .branches
            .iter()
            .filter_map(|b| b.target.as_ref())
            .chain(grammar.fallback.iter())
        {
            if let Some(projected) = generated.get_mut(&target.name) {
                projected.structured_source = Some(parameter.name.clone());
            }
        }
    }
    invocation.bound_parameters.extend(generated.into_values());
    invocation.operation_semantics_unresolved |= native_unresolved;
}

fn project_item(
    invocation: &BoundInvocation,
    grammar: &StructuredProjection,
    source: &BoundValue,
    item: &str,
    generated: &mut BTreeMap<crate::SlotName, BoundParameter>,
) -> bool {
    if item.is_empty() {
        if let Some(branch) = grammar.branches.iter().find(|branch| {
            !branch_disabled(invocation, branch)
                && matches!(&branch.matcher,
                StructuredProjectionMatcher::RegexCapture {regex, ..} if regex.regex().is_match(""))
        }) {
            if branch.target.is_none() {
                return true;
            }
        }
        emit_unknown(invocation, grammar, source, generated);
        return true;
    }
    let mut selected = grammar.fallback.as_ref();
    let mut selected_text = item;
    let mut selected_unknown = false;
    let mut matched_item = grammar.fallback.is_some();
    for branch in &grammar.branches {
        if branch_disabled(invocation, branch) {
            continue;
        }
        let matched = match &branch.matcher {
            StructuredProjectionMatcher::RegexCapture { regex, group } => {
                let Some(captures) = regex.regex().captures(item) else {
                    continue;
                };
                let entire = captures.get(0).expect("regex match has group zero");
                if entire.start() != 0 || entire.end() != item.len() {
                    continue;
                }
                match captures.get(*group) {
                    Some(value) => Some(value.as_str()),
                    None => {
                        // A matched optional capture missing its value is unknown,
                        // not permission to fall back to a different operand kind.
                        selected_unknown = true;
                        Some(item)
                    }
                }
            }
            StructuredProjectionMatcher::Literal(literal) => (item == literal).then_some(item),
            StructuredProjectionMatcher::Prefix(prefix) => item.strip_prefix(prefix),
            StructuredProjectionMatcher::KeywordValue {
                keyword,
                case_insensitive,
                allow_quoted_keyword,
                disabled_values,
                unresolved_markers,
            } => {
                let Some(text) =
                    keyword_value(item, keyword, *case_insensitive, *allow_quoted_keyword)
                else {
                    continue;
                };
                if disabled_values.iter().any(|value| {
                    if *case_insensitive {
                        text.eq_ignore_ascii_case(value)
                    } else {
                        text == value
                    }
                }) {
                    // Disabled is still the first value selected by the tool.
                    return true;
                }
                selected_unknown = unresolved_markers
                    .iter()
                    .any(|marker| text.contains(marker));
                Some(text)
            }
        };
        if let Some(text) = matched {
            selected = branch.target.as_ref();
            selected_text = text;
            matched_item = true;
            break;
        }
    }
    let Some(target) = selected else {
        return matched_item;
    };
    if selected_unknown || target.unresolved {
        emit(target, source, unknown(), generated);
        return true;
    }
    if target.sources.is_empty() {
        let resolution = if selected_text.is_empty() {
            SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue)
        } else {
            SemanticValueResolution::Known(selected_text.to_string())
        };
        emit(target, source, resolution, generated);
        return true;
    }
    // Never replace an explicit unknown source with a later default.
    if let Some(parameter) = target
        .sources
        .iter()
        .find_map(|slot| invocation.bound_parameters.iter().find(|p| p.name == *slot))
    {
        let mut values = parameter.semantic_values().peekable();
        if values.peek().is_none() {
            emit(target, source, unknown(), generated);
        }
        for value in values {
            let (source, resolution, preserves_source) = match value {
                crate::SemanticValueRef::Original(source) => (
                    source,
                    project_value(&ValueProjection::Identity, source).unwrap_or_else(unknown),
                    true,
                ),
                crate::SemanticValueRef::Projected { source, value } => {
                    (source, value.resolution.clone(), value.preserves_source)
                }
            };
            emit_value(target, source, resolution, preserves_source, generated);
        }
    } else {
        emit(target, source, unknown(), generated);
    }
    true
}

/// Consume only the tool's keyword separator, never quotes or shell syntax in its value.
fn keyword_value<'a>(
    item: &'a str,
    keyword: &str,
    insensitive: bool,
    quoted: bool,
) -> Option<&'a str> {
    let whitespace = |c| matches!(c, ' ' | '\t' | '\r' | '\n');
    let item = item.trim_start_matches(whitespace);
    let equal = |left: &str, right: &str| {
        if insensitive {
            left.eq_ignore_ascii_case(right)
        } else {
            left == right
        }
    };
    if quoted {
        // Tool configuration token quoting, NOT shell quoting. A quoted segment
        // terminates the keyword; the command remainder is kept byte-for-byte.
        let delimiter = item.find(|c| whitespace(c) || c == '=' || c == '"');
        if let Some(start) = delimiter.filter(|&i| item.as_bytes()[i] == b'"') {
            let tail = &item[start + 1..];
            let end = tail.find('"')?;
            if !equal(item.get(..start)?, keyword.get(..start)?)
                || !equal(&tail[..end], keyword.get(start..)?)
            {
                return None;
            }
            return Some(tail[end + 1..].trim_start_matches(|c| whitespace(c) || c == '='));
        }
    }
    let head = item.get(..keyword.len())?;
    if !equal(head, keyword) {
        return None;
    }
    let rest = &item[keyword.len()..];
    if !rest.is_empty() && !rest.starts_with(|c| whitespace(c) || c == '=') {
        return None;
    }
    Some(rest.trim_start_matches(|c| whitespace(c) || c == '='))
}

fn unknown() -> SemanticValueResolution {
    SemanticValueResolution::Unknown(ProjectionUnknownReason::DynamicArgument)
}

fn branch_disabled(
    invocation: &BoundInvocation,
    branch: &crate::types::StructuredProjectionBranch,
) -> bool {
    if branch
        .requires_modifiers
        .iter()
        .any(|id| !invocation.applied_modifiers.contains(id))
        || branch
            .unless_modifiers
            .iter()
            .any(|id| invocation.applied_modifiers.contains(id))
    {
        return true;
    }
    if branch
        .unless_modifier
        .as_ref()
        .is_some_and(|id| invocation.applied_modifiers.contains(id))
    {
        return true;
    }
    let Some(condition) = &branch.unless_parameter_matches else {
        return false;
    };
    let last = invocation
        .bound_parameters
        .iter()
        .filter(|p| p.name == condition.name)
        .flat_map(|p| p.semantic_values())
        .filter_map(|v| crate::project_semantic_value(&ValueProjection::Identity, v))
        .last();
    matches!(last, Some(SemanticValueResolution::Known(text)) if crate::bind::argument_matches_value_matcher(&text, &condition.matcher))
}

fn emit_unknown(
    invocation: &BoundInvocation,
    grammar: &StructuredProjection,
    source: &BoundValue,
    generated: &mut BTreeMap<crate::SlotName, BoundParameter>,
) -> bool {
    let whole_operand = grammar.separator.is_none() && grammar.native_syntax.is_none();
    let structure = (whole_operand || grammar.first_match_only && grammar.fallback.is_some())
        .then(|| source_structure(source))
        .flatten();
    let mut targets = BTreeMap::new();
    for (target, identity) in grammar
        .branches
        .iter()
        .filter(|b| !branch_disabled(invocation, b))
        .filter(|b| {
            !whole_operand
                || structure
                    .as_ref()
                    .is_none_or(|s| branch_may_match(s, &b.matcher))
        })
        .filter_map(|b| {
            b.target.as_ref().map(|t| {
                (
                    t,
                    matches!(
                        b.matcher,
                        StructuredProjectionMatcher::Literal(_)
                            | StructuredProjectionMatcher::RegexCapture { group: 0, .. }
                    ),
                )
            })
        })
        .chain(grammar.fallback.iter().map(|t| (t, true)))
    {
        let identity = whole_operand && identity && !target.unresolved && target.sources.is_empty();
        targets
            .entry(&target.name)
            .and_modify(
                |(_, all_identity): &mut (&StructuredProjectionTarget, bool)| {
                    *all_identity &= identity
                },
            )
            .or_insert((target, identity));
    }
    for (_, (target, identity)) in targets {
        emit_value(target, source, unknown(), identity, generated);
    }
    // A fallback guarantees a match only if an operand actually exists.
    // Nullglob, unquoted splitting and vectors may produce zero operands.
    grammar.fallback.is_some()
        && grammar.native_syntax.is_none()
        && structure.is_some_and(|s| s.fields == crate::ArgumentFieldCount::ExactlyOne)
}

fn source_structure(source: &BoundValue) -> Option<crate::ArgumentStructure> {
    match source {
        BoundValue::Argument {
            text,
            quoted,
            node_kind,
            materialization: crate::BoundArgumentMaterialization::Literal,
            ..
        } => Some(crate::shell_word_structure(text, *quoted, node_kind)),
        BoundValue::ImplicitInput {
            source,
            domain,
            origin: Some(origin),
        } if origin.single_field => Some(crate::argument_structure(&crate::ProjectedArg {
            word_context: crate::WordContext::ShellArgument,
            text: String::new(),
            implicit_input_source: Some(source.to_caushell_types_implicit_input_source()),
            runtime_argument_domain: domain.clone(),
            runtime_data: false,
            substitution_shape: None,
            lexical_field_prefix: None,
            kind: crate::ProjectedArgKind::Positional,
            quoted: true,
            node_kind: "runtime_scalar".into(),
            span: origin.span.clone(),
        })),
        _ => None,
    }
}

fn branch_may_match(
    structure: &crate::ArgumentStructure,
    matcher: &StructuredProjectionMatcher,
) -> bool {
    match matcher {
        StructuredProjectionMatcher::Literal(value) => structure.may_equal(value),
        StructuredProjectionMatcher::Prefix(prefix) => structure.may_start_with(prefix),
        StructuredProjectionMatcher::RegexCapture { regex, .. } => {
            crate::runtime_matcher::matches(
                structure,
                &crate::ValueMatcher::RegexPattern(regex.regex().as_str().into()),
            ) != Some(false)
        }
        // Tool-specific whitespace/quoting is not shell-word prefix syntax.
        StructuredProjectionMatcher::KeywordValue { .. } => true,
    }
}

fn emit(
    target: &StructuredProjectionTarget,
    source: &BoundValue,
    resolution: SemanticValueResolution,
    generated: &mut BTreeMap<crate::SlotName, BoundParameter>,
) {
    emit_value(target, source, resolution, false, generated);
}

fn emit_value(
    target: &StructuredProjectionTarget,
    source: &BoundValue,
    resolution: SemanticValueResolution,
    preserves_source: bool,
    generated: &mut BTreeMap<crate::SlotName, BoundParameter>,
) {
    let parameter = generated.entry(target.name.clone()).or_insert_with(|| {
        let mut parameter = BoundParameter::new(target.name.clone(), target.semantic.clone());
        parameter.projected_values = Some(Vec::new());
        parameter.structured_source = Some(target.name.clone());
        parameter
    });
    let source_index = parameter.values.len();
    parameter.values.push(source.clone());
    parameter
        .projected_values
        .as_mut()
        .unwrap()
        .push(ProjectedSemanticValue {
            source_index,
            preserves_source,
            resolution,
        });
}

#[cfg(test)]
mod source_preservation_tests {
    use super::*;
    use crate::*;

    #[test]
    fn runtime_affixes_require_a_single_field_origin_before_excluding_branches() {
        let parsed =
            caushell_parse::parse_command("echo item", caushell_types::ShellKind::Bash).unwrap();
        let span = parsed.commands[0].span.clone();
        let mut source = BoundValue::ImplicitInput {
            source: ImplicitInputSource::DispatchOutput,
            domain: Some(caushell_types::RuntimeArgumentDomain::TextTemplate {
                prefix: "https://example.test/".into(),
                suffix: String::new(),
            }),
            origin: Some(BoundImplicitArgumentOrigin {
                span,
                single_field: true,
            }),
        };
        let matcher = StructuredProjectionMatcher::RegexCapture {
            regex: CompiledOperandRegex::compile("(?i)^gophers?://.+$").unwrap(),
            group: 0,
        };
        let structure = source_structure(&source).unwrap();
        assert!(!branch_may_match(&structure, &matcher));
        assert!(!structure.exact);
        let BoundValue::ImplicitInput { origin, .. } = &mut source else {
            unreachable!()
        };
        origin.as_mut().unwrap().single_field = false;
        assert!(source_structure(&source).is_none());
        let BoundValue::ImplicitInput { origin, .. } = &mut source else {
            unreachable!()
        };
        *origin = None;
        assert!(source_structure(&source).is_none());
    }

    #[test]
    fn only_whole_unsplit_unmodified_values_retain_source_bounds() {
        for (grammar, expected) in [
            (
                "{branches: [{matcher: {kind: regex_capture, pattern: '^.+$', group: 0}, target: {name: paths, semantic: {kind: path, role: write}}}]}",
                true,
            ),
            (
                "{branches: [{matcher: {kind: literal, value: ':memory:'}}], fallback: {name: paths, semantic: {kind: path, role: write}}}",
                true,
            ),
            (
                "{branches: [{matcher: {kind: regex_capture, pattern: '^(.*)$', group: 1}, target: {name: paths, semantic: {kind: path, role: write}}}]}",
                false,
            ),
            (
                "{branches: [{matcher: {kind: prefix, value: 'path:'}, target: {name: paths, semantic: {kind: path, role: write}}}]}",
                false,
            ),
            (
                "{separator: ';', branches: [], fallback: {name: paths, semantic: {kind: path, role: write}}}",
                false,
            ),
            (
                "{branches: [{matcher: {kind: prefix, value: 'path:'}, target: {name: paths, semantic: {kind: path, role: write}}}], fallback: {name: paths, semantic: {kind: path, role: write}}}",
                false,
            ),
            (
                "{branches: [], fallback: {name: paths, semantic: {kind: path, role: write}, unresolved: true}}",
                false,
            ),
        ] {
            let yaml = format!(
                "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: bounds-fixture}}\nforms:\n  - id: write\n    selector: {{kind: has_positional_at, index: 0}}\n    parameters:\n      - name: raw\n        semantic: {{kind: plain_value}}\n        binding: {{kind: next_positional}}\n        cardinality: required_one\n        structured_projection: {grammar}\n    effects: [{{kind: write_path, target: {{kind: slot, name: paths}}}}]\n"
            );
            let registry =
                ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&yaml).unwrap()])
                    .unwrap();
            let parsed = caushell_parse::parse_command(
                "bounds-fixture file",
                caushell_types::ShellKind::Bash,
            )
            .unwrap();
            let ResolveInvocationResult::Resolved(resolved) = resolve_invocation_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            ) else {
                panic!("fixture failed")
            };
            let mut bound = resolved.bound;
            let source = BoundValue::ImplicitInput {
                source: ImplicitInputSource::DispatchOutput,
                domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
                    roots: vec!["/workspace".into()],
                    may_escape: false,
                }),
                origin: None,
            };
            bound
                .bound_parameters
                .iter_mut()
                .find(|p| p.name.as_str() == "raw")
                .unwrap()
                .values = vec![source.clone()];
            refresh_structured_parameters(&mut bound);
            let paths = bound
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == "paths")
                .unwrap();
            let SemanticValueRef::Projected {
                source: actual,
                value,
            } = paths.semantic_values().next().unwrap()
            else {
                panic!("missing projected view")
            };
            assert_eq!(actual, &source);
            assert_eq!(value.preserves_source, expected, "{grammar}");
            assert!(matches!(
                value.resolution,
                SemanticValueResolution::Unknown(_)
            ));
        }
    }
}
