//! Positive stdout shape proofs for selected Profiles, without shell execution
//! or filesystem observation.
use std::collections::BTreeMap;

use caushell_parse::{
    CommandFact, CommandSubstitutionFact, CommandToken, ParseStatus, ParsedCommandArtifact,
    PipelinePosition, ScalarArgumentPart, SourceSpan, parse_command, scalar_word_parts,
};
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    StdoutScalarShape, SubstitutionOutputProof, observed_ifs_value,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::{ARITHMETIC_STDOUT_CHARS, SessionAliasBinding, ShellKind};

/// A direct literal echo pipeline captures only the recognized encoder's stdout.
pub(super) fn encoded_stdout_shape(
    registry: &ProfileRegistry,
    shell_kind: ShellKind,
    body: &str,
    bindings: &SessionBindings,
) -> Option<StdoutScalarShape> {
    if shell_kind != ShellKind::Bash || body.len() > 8192 {
        return None;
    }
    let parsed = parse_command(body, shell_kind).ok()?;
    let [source, encoder] = parsed.commands.as_slice() else {
        return None;
    };
    let encoder_name = encoder.command_name.as_deref()?;
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || !parsed.redirections.is_empty()
        || source.pipeline_span.is_none()
        || source.pipeline_span != encoder.pipeline_span
        || source.command_name.as_deref() != Some("echo")
        || !matches!(encoder_name, "xxd" | "b64encode")
        || !body
            .get(..source.span.start_byte)
            .is_some_and(|s| s.trim().is_empty())
        || !body
            .get(source.span.end_byte..encoder.span.start_byte)
            .is_some_and(|s| s.trim() == "|")
        || !body
            .get(encoder.span.end_byte..)
            .is_some_and(|s| s.trim().is_empty())
        || [source, encoder].iter().any(|command| {
            command.guarded
                || command.conditional_execution
                || !command.prefix_assignments.is_empty()
        })
        || ["echo", encoder_name].iter().any(|name| {
            bindings.function_binding(name).is_some()
                || bindings.profile_has_alias_shadow(name)
                || !registry
                    .lookup(name)
                    .profile
                    .is_some_and(|p| p.trust.source == caushell_profile::ProfileSourceKind::BuiltIn)
        })
    {
        return None;
    }
    let [input] = source.tokens.as_slice() else {
        return None;
    };
    if input.node_kind != "raw_string" || !input.command_substitutions.is_empty() {
        return None;
    }
    let options = encoder
        .tokens
        .iter()
        .map(|token| {
            caushell_parse::decode_static_shell_argument(
                &token.text,
                token.quoted,
                &token.node_kind,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    let (shape, form_id) = match (encoder_name, options.as_slice()) {
        ("xxd", [format, rest @ ..])
            if matches!(format.as_str(), "-p" | "-ps" | "-plain" | "-postscript")
                && plain_hex_width(rest) =>
        {
            (StdoutScalarShape::PlainHexText, "hexdump_stream")
        }
        // The raw mode requires one header-name operand, then ignores it.
        ("b64encode", [flag, name])
            if flag == "-r" && (name == "-" || (!name.is_empty() && !name.starts_with('-'))) =>
        {
            (StdoutScalarShape::RawBase64Text, "encode_raw_stdin")
        }
        _ => return None,
    };
    matches!(
        resolve_invocation_artifact_with_bindings(
            registry, encoder, InvocationRuntimeContext::default().with_shell_kind(shell_kind), bindings
        ),
        ResolveInvocationArtifactResult::Resolved(r) if r.bound.form_id.as_str() == form_id
            && !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty()
    )
    .then_some(shape)
}

fn plain_hex_width(options: &[String]) -> bool {
    match options {
        [] => true,
        [flag, columns] => {
            flag == "-c"
                && columns.bytes().all(|b| b.is_ascii_digit())
                && columns
                    .parse::<u16>()
                    .is_ok_and(|value| (1..=256).contains(&value))
        }
        _ => false,
    }
}

pub(crate) fn arithmetic_stdout(
    registry: &ProfileRegistry,
    shell_kind: ShellKind,
    body: &str,
    bindings: &SessionBindings,
) -> bool {
    if body.len() > 8192 {
        return false;
    }
    let Ok(parsed) = parse_command(body, shell_kind) else {
        return false;
    };
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.declaration_commands.is_empty()
        || !parsed.unset_commands.is_empty()
        || !parsed.function_definitions.is_empty()
        || parsed
            .redirections
            .iter()
            .any(|r| !matches!(r.operator.as_deref(), Some("<" | "<<" | "<<-" | "<<<")))
    {
        return false;
    }
    let command = match parsed.commands.as_slice() {
        [command] if !command.in_pipeline => command,
        [source, tail]
            if shell_kind == ShellKind::Bash
                && plain_stdout_pipeline(body, &parsed, source, tail, registry, bindings) =>
        {
            tail
        }
        _ => return false,
    };
    if command.guarded
        || command.conditional_execution
        || command.terminator.is_some()
        || !command.prefix_assignments.is_empty()
    {
        return false;
    }
    let Some(name) = command
        .command_name
        .as_deref()
        .and_then(|name| caushell_profile::materialize_command_name(name, bindings))
    else {
        return false;
    };
    if bindings.function_binding(&name).is_some() || bindings.profile_has_alias_shadow(&name) {
        return false;
    }
    matches!(resolve_invocation_artifact_with_bindings(registry, command,
        InvocationRuntimeContext::default().with_shell_kind(shell_kind), bindings),
        ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout())
}

/// Only the tail owns stdout in this simple pipe. Upstream effect analysis
/// still checks the original source and its arguments independently.
fn plain_stdout_pipeline(
    body: &str,
    parsed: &ParsedCommandArtifact,
    source: &CommandFact,
    tail: &CommandFact,
    registry: &ProfileRegistry,
    bindings: &SessionBindings,
) -> bool {
    let Some(name) = source.command_name.as_deref() else {
        return false;
    };
    parsed.redirections.is_empty()
        && source.pipeline_position == Some(PipelinePosition::First)
        && tail.pipeline_position == Some(PipelinePosition::Last)
        && source.pipeline_span.is_some()
        && source.pipeline_span == tail.pipeline_span
        && !source.command_name_runtime_data
        && caushell_profile::materialize_command_name(name, bindings).as_deref() == Some(name)
        && !bindings.profile_has_alias_shadow(name)
        && bindings.function_binding(name).is_none()
        && registry.lookup(name).profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
        && !source.guarded
        && !source.conditional_execution
        && source.terminator.is_none()
        && source.prefix_assignments.is_empty()
        && body.get(..source.span.start_byte).is_some_and(|head| head.trim().is_empty())
        && body.get(source.span.end_byte..tail.span.start_byte).is_some_and(|pipe| pipe.trim() == "|")
        && body.get(tail.span.end_byte..).is_some_and(|rest| rest.trim().is_empty())
}

/// The entire captured stream must satisfy the declaration. A recognized
/// producer among other commands/branches is not proof of the stream's shape.
pub(crate) fn substitution_shapes(
    registry: &ProfileRegistry,
    command: &CommandFact,
    shell_kind: ShellKind,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    remaining_depth: u8,
) -> Vec<(SourceSpan, SubstitutionOutputProof)> {
    if remaining_depth == 0 || !matches!(shell_kind, ShellKind::Bash | ShellKind::Sh) {
        return Vec::new();
    }
    command
        .tokens
        .iter()
        .filter_map(|token| {
            if token.runtime_data || token.implicit_input_source.is_some() {
                return None;
            }
            if shell_kind == ShellKind::Bash && command.command_name.as_deref() == Some("sed")
                && let Some(proof) = quoted_sed_day_template(registry, token, bindings, aliases)
            {
                return Some((token.span.clone(), proof));
            }
            let [substitution] = token.command_substitutions.as_slice() else {
                return None;
            };
            let quoted = token.quoted && token.node_kind == "string";
            if shell_kind == ShellKind::Bash
                && !token.quoted
                && command.command_name.as_deref() == Some("sed")
                && token.text.strip_suffix('q') == Some(substitution.text.as_str())
                && proves_redirected_line_count(registry, substitution, bindings, aliases)
            {
                return Some((token.span.clone(), SubstitutionOutputProof::LineCountQuit));
            }
            // A producer proof applies only within the original word. A
            // more general arithmetic field may include literal affixes.
            let field = (shell_kind == ShellKind::Bash)
                .then(|| arithmetic_field(token, substitution, bindings))
                .flatten();
            let legacy_shape = if quoted {
                token
                    .text
                    .strip_prefix(&substitution.text)
                    .and_then(|suffix| {
                        caushell_parse::decode_static_shell_argument(suffix, true, "string")
                    })
                    .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            } else {
                !token.quoted
                    && shell_kind == ShellKind::Bash
                    && only_numeric_affixes(token, substitution)
            };
            if field.is_none() && !legacy_shape {
                return None;
            }
            let parsed = parse_command(&substitution.body_text, shell_kind).ok()?;
            let producer = plain_single_producer(&parsed)?;
            let name = producer.command_name.as_deref()?;
            let executable = if producer.command_name_runtime_data {
                name.to_string()
            } else {
                caushell_profile::materialize_command_name(name, bindings)?
            };
            // A function/alias can replace the registered executable. Do not
            // borrow the executable's contract for a shadowing definition, even
            // if that definition would itself be statically analyzable.
            if aliases.contains_key(name)
                || bindings.function_binding(&executable).is_some()
                || bindings.profile_has_alias_shadow(&executable)
            {
                return None;
            }
            let ResolveInvocationArtifactResult::Resolved(resolved) =
                resolve_invocation_artifact_with_bindings(
                    registry,
                    producer,
                    InvocationRuntimeContext::default().with_shell_kind(shell_kind),
                    bindings,
                )
            else {
                return None;
            };
            let shape = resolved.proven_stdout_scalar()?;
            let proof = match (shape, field) {
                (StdoutScalarShape::ArithmeticText, Some(field)) => field,
                // The legacy absolute-path proof allows empty stdout only
                // where the original quoted suffix remains absolute or empty.
                (shape, _)
                    if legacy_shape && (quoted || shape == StdoutScalarShape::ArithmeticText) =>
                {
                    SubstitutionOutputProof::ScalarShape(shape)
                }
                _ => return None,
            };
            Some((token.span.clone(), proof))
        })
        .collect()
}

fn quoted_sed_day_template(
    registry: &ProfileRegistry,
    token: &CommandToken,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<SubstitutionOutputProof> {
    if token.text.len() > 256
        || !(1..=2).contains(&token.command_substitutions.len())
        || aliases.contains_key("date")
        || bindings.function_binding("date").is_some()
        || bindings.profile_has_alias_shadow("date")
        || !registry.lookup("date").profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
    {
        return None;
    }
    let mut captures = token.command_substitutions.iter();
    let mut literal_parts = Vec::new();
    let mut literal = String::new();
    for part in scalar_word_parts(&token.text, token.quoted, &token.node_kind, false)? {
        match part {
            ScalarArgumentPart::Literal(text) => literal.push_str(&text),
            ScalarArgumentPart::CommandSubstitution(text) => {
                let capture = captures.next()?;
                if text != capture.text
                    || capture.body_text.trim() != "date +%d"
                    || !arithmetic_stdout(registry, ShellKind::Bash, &capture.body_text, bindings)
                {
                    return None;
                }
                literal_parts.push(std::mem::take(&mut literal));
            }
            _ => return None,
        }
    }
    if captures.next().is_some() || literal_parts.len() != token.command_substitutions.len() {
        return None;
    }
    literal_parts.push(literal);
    Some(SubstitutionOutputProof::SedDayTemplate { literal_parts })
}

/// Certify the one-counter stdout case. The sole redirection must only
/// supply data to wc; named operands could appear in the captured output.
fn proves_redirected_line_count(
    registry: &ProfileRegistry,
    substitution: &CommandSubstitutionFact,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> bool {
    let body = &substitution.body_text;
    if body.len() > 8192
        || aliases.contains_key("wc")
        || bindings.function_binding("wc").is_some()
        || bindings.profile_has_alias_shadow("wc")
        || !registry.lookup("wc").profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
    {
        return false;
    }
    let Ok(parsed) = parse_command(body, ShellKind::Bash) else {
        return false;
    };
    let [input] = parsed.redirections.as_slice() else {
        return false;
    };
    let Some(prefix) = body.get(..input.span.start_byte) else {
        return false;
    };
    input.operator.as_deref() == Some("<")
        && matches!(input.file_descriptor.as_deref(), None | Some("0"))
        && body.get(input.span.end_byte..).is_some_and(|tail| tail.trim().is_empty())
        && input.target.as_ref().is_some_and(|target| {
            !target.expansion_unresolved && target.command_substitutions.is_empty()
                && caushell_parse::decode_static_shell_argument(
                    &target.text, target.quoted, &target.node_kind,
                ).is_some()
        })
        && {
            let mut words = prefix.split_ascii_whitespace();
            words.next() == Some("wc") && matches!(words.next(), Some("-l" | "--lines"))
                && words.next().is_none()
        }
        && arithmetic_stdout(registry, ShellKind::Bash, body, bindings)
}

/// Compose the producer's alphabet with the decoded literal parts of one
/// original word. Quoting or an observed disjoint IFS must preserve one field.
fn arithmetic_field(
    token: &CommandToken,
    substitution: &CommandSubstitutionFact,
    bindings: &SessionBindings,
) -> Option<SubstitutionOutputProof> {
    if token.text.len() > 8192 {
        return None;
    }
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut captured = false;
    let mut quoted = false;
    let (parts, capture) = substitution_word_parts(token, substitution)?;
    for part in parts {
        match part {
            ScalarArgumentPart::Literal(literal) => {
                if literal.contains(['\0', '*', '?', '[', '~', '{', '}']) {
                    return None;
                }
                let affix = if captured { &mut suffix } else { &mut prefix };
                affix.push_str(&literal);
            }
            ScalarArgumentPart::CommandSubstitution(text) if !captured && text == capture => {
                captured = true;
                quoted = true;
            }
            ScalarArgumentPart::UnquotedCommandSubstitution(text)
                if !captured && text == capture =>
            {
                captured = true;
            }
            _ => return None,
        }
    }
    // A fixed leading non-option literal preserves the field even when the
    // producer fails with empty stdout. Other words retain their old analysis.
    if !captured || prefix.is_empty() || prefix.starts_with(['-', '+']) {
        return None;
    }
    if !quoted
        && !observed_ifs_value(bindings).is_some_and(|ifs| {
            ifs.is_ascii()
                && !ifs.contains('\0')
                && !ifs.chars().any(|ch| ARITHMETIC_STDOUT_CHARS.contains(ch))
        })
    {
        return None;
    }
    Some(SubstitutionOutputProof::ArithmeticField { prefix, suffix })
}

/// Reparse one word using the parser's existing quote-removal rules. The
/// backquote recovery can identify an exact capture even when the raw word
/// grammar consumes its suffix. In that case mask only that verified span;
/// the producer is always checked separately from its original body.
fn substitution_word_parts<'a>(
    token: &CommandToken,
    substitution: &'a CommandSubstitutionFact,
) -> Option<(Vec<ScalarArgumentPart>, &'a str)> {
    if let Some(parts) = scalar_word_parts(&token.text, token.quoted, &token.node_kind, true) {
        return Some((parts, &substitution.text));
    }
    if token.quoted
        || !substitution.text.starts_with('`')
        || token.span.end_byte.checked_sub(token.span.start_byte)? != token.text.len()
    {
        return None;
    }
    let start = substitution
        .span
        .start_byte
        .checked_sub(token.span.start_byte)?;
    let end = substitution
        .span
        .end_byte
        .checked_sub(token.span.start_byte)?;
    if token.text.get(start..end)? != substitution.text {
        return None;
    }
    let marker = "$(__caushell_capture__)";
    let mut word = token.text.clone();
    word.replace_range(start..end, marker);
    let parts = scalar_word_parts(&word, false, &token.node_kind, true)?;
    Some((parts, marker))
}

/// Check literal bytes in the original token around the one expansion.
fn only_numeric_affixes(
    token: &caushell_parse::CommandToken,
    substitution: &caushell_parse::CommandSubstitutionFact,
) -> bool {
    let base = token.span.start_byte;
    let Some(start) = substitution.span.start_byte.checked_sub(base) else {
        return false;
    };
    let Some(end) = substitution.span.end_byte.checked_sub(base) else {
        return false;
    };
    token.span.end_byte.checked_sub(base) == Some(token.text.len())
        && token.text.get(start..end) == Some(substitution.text.as_str())
        && token.text.as_bytes()[..start]
            .iter()
            .chain(&token.text.as_bytes()[end..])
            .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-'))
}

pub(super) fn plain_single_producer(parsed: &ParsedCommandArtifact) -> Option<&CommandFact> {
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || parsed.commands.len() != 1
        || !parsed.redirections.is_empty()
        || !parsed.declaration_commands.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.unset_commands.is_empty()
        || !parsed.function_definitions.is_empty()
    {
        return None;
    }
    let command = &parsed.commands[0];
    if command.in_pipeline
        || command.guarded
        || command.conditional_execution
        || command.terminator.is_some()
        || !command.prefix_assignments.is_empty()
        || command.text.trim() != parsed.raw_command.trim()
    {
        return None;
    }
    Some(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_profile::load_command_profile_from_str;
    const SOURCE: &str = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_absolute_producer}\noption_scope: all_arguments\nopaque_on_unresolved: true\nforms:\n  - id: path\n    stdout_scalar: absolute_path\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n";

    #[test]
    fn unquoted_affixes_require_the_observed_field_separator() {
        for command in [
            "touch filename_$(date +%s).txt",
            "touch filename_`date +%s`.txt",
        ] {
            let parsed = parse_command(command, ShellKind::Bash).unwrap();
            let token = &parsed.commands[0].tokens[0];
            let [substitution] = token.command_substitutions.as_slice() else {
                panic!("{token:#?}");
            };
            assert_eq!(
                arithmetic_field(
                    token,
                    substitution,
                    &SessionBindings::new().with_exact_scalar("IFS", "")
                ),
                Some(SubstitutionOutputProof::ArithmeticField {
                    prefix: "filename_".into(),
                    suffix: ".txt".into(),
                }),
                "{token:#?}, parts: {:?}",
                scalar_word_parts(&token.text, token.quoted, &token.node_kind, true)
            );
            for bindings in [
                SessionBindings::new(),
                SessionBindings::new().with_exact_scalar("IFS", "0"),
            ] {
                assert_eq!(arithmetic_field(token, substitution, &bindings), None);
            }
        }
    }

    #[test]
    fn declarations_work_for_arbitrary_producer_names() {
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(SOURCE).unwrap()])
                .unwrap();
        for (text, expected) in [
            ("consumer \"$(arbitrary_absolute_producer)\"", 1),
            ("consumer \"`arbitrary_absolute_producer`\"", 1),
            ("consumer \"$(arbitrary_absolute_producer)/child\"", 1),
            ("consumer $(arbitrary_absolute_producer)", 0),
            ("consumer \"$(arbitrary_absolute_producer)-delete\"", 0),
            ("consumer \"$(arbitrary_absolute_producer)/$unknown\"", 0),
            ("consumer \"$(arbitrary_absolute_producer; other)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer & )\"", 0),
            ("consumer \"$(arbitrary_absolute_producer --unknown)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer 2>&1)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer >out)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer | other)\"", 0),
        ] {
            let parsed = parse_command(text, ShellKind::Bash).unwrap();
            assert_eq!(
                substitution_shapes(
                    &registry,
                    &parsed.commands[0],
                    ShellKind::Bash,
                    &SessionBindings::new(),
                    &BTreeMap::new(),
                    8
                )
                .len(),
                expected,
                "{text}: {parsed:#?}"
            );
        }
        let parsed = parse_command(
            "consumer \"$(arbitrary_absolute_producer)\"",
            ShellKind::Bash,
        )
        .unwrap();
        let aliases = BTreeMap::from([(
            "arbitrary_absolute_producer".into(),
            SessionAliasBinding::new(
                "arbitrary_absolute_producer",
                "other",
                caushell_types::CommandSequenceNo::new(1),
            ),
        )]);
        assert!(
            substitution_shapes(
                &registry,
                &parsed.commands[0],
                ShellKind::Bash,
                &SessionBindings::new(),
                &aliases,
                8
            )
            .is_empty()
        );
        assert!(
            substitution_shapes(
                &registry,
                &parsed.commands[0],
                ShellKind::Bash,
                &SessionBindings::new(),
                &BTreeMap::new(),
                0
            )
            .is_empty()
        );
    }
}
