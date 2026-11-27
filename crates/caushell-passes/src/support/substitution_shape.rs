//! Positive stdout shape proofs for selected Profiles, without shell execution
//! or filesystem observation.
use std::collections::BTreeMap;

use caushell_parse::{
    CommandFact, CommandSubstitutionFact, CommandToken, ParseStatus, ParsedCommandArtifact,
    PipelinePosition, ScalarArgumentPart, SourceSpan, parse_command, scalar_word_parts,
};
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    StdoutScalarShape, SubstitutionOutputProof, TextRecordFields, TextRecordStream, observed_ifs_value,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::{ARITHMETIC_STDOUT_CHARS, RuntimeArgumentDomain, SessionAliasBinding, ShellKind};

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
            if shell_kind == ShellKind::Bash
                && !token.quoted
                && token.text == substitution.text
                && command.tokens.first() == Some(token)
                && attested_pipeline_tool(registry, command, bindings, aliases, "mv", "gnu_coreutils_9_1")
                && let Ok(body) = parse_command(&substitution.body_text, shell_kind)
                && let Some(last) = body.commands.len().checked_sub(1)
                && let Some(stdout) = grep_stdin_label_stdout(registry, &body, last, bindings, aliases)
            {
                use caushell_profile::{ShellFieldFragment, materialize_bash_field_fragments};
                let [empty, record] = stdout;
                let split = |stream: &str| {
                    materialize_bash_field_fragments(
                        &[ShellFieldFragment::UnquotedExpansion(stream.trim_end_matches('\n').into())],
                        bindings,
                    )
                };
                if split(empty).is_some_and(|fields| fields.is_empty())
                    && let Some(fields) = split(record)
                    && !fields.is_empty()
                {
                    return Some((token.span.clone(), SubstitutionOutputProof::OptionalMoveSourceFields(fields)));
                }
            }
            if shell_kind == ShellKind::Bash && command.command_name.as_deref() == Some("sed")
                && let Some(proof) = sed_decimal_addresses(registry, token, substitution, bindings, aliases)
            {
                return Some((token.span.clone(), proof));
            }
            if shell_kind == ShellKind::Bash
                && command.tokens.len() == 1
                && !token.quoted
                && token.text == substitution.text
                && attested_pipeline_tool(registry, command, bindings, aliases, "mkdir", "gnu_coreutils_9_1")
                && observed_ifs_value(bindings).is_some_and(|ifs| {
                    ifs.bytes().all(|byte| matches!(byte, b' ' | b'\t' | b'\n'))
                })
                && let Ok(body) = parse_command(&substitution.body_text, shell_kind)
                && let Some(last) = body.commands.len().checked_sub(1)
                && filtered_filename_stdout(registry, &body, last, bindings, aliases)
            {
                return Some((token.span.clone(), SubstitutionOutputProof::LocalFilenameFields));
            }
            if let Some(domain) =
                quoted_dirname_path(registry, token, substitution, shell_kind, bindings, aliases)
            {
                return Some((token.span.clone(), SubstitutionOutputProof::PathWord(domain)));
            }
            if shell_kind == ShellKind::Bash
                && command.command_name.as_deref() == Some("touch")
                && matches!(command.tokens.as_slice(), [flag, timestamp, _]
                    if flag.text == "-t" && timestamp.span == token.span)
                && !token.quoted
                && token.text == substitution.text
                && calendar_date_format(registry, substitution, bindings, aliases, false)
                    .is_some_and(|format| decimal_clock_format(&format))
            {
                return Some((token.span.clone(), SubstitutionOutputProof::DecimalCalendarFields));
            }
            if shell_kind == ShellKind::Bash
                && command.command_name.as_deref() == Some("touch")
                && command.tokens.len() == 1
                && command.prefix_assignments.is_empty()
                && !command.in_pipeline
                && !command.guarded
                && calendar_filename_fields(registry, token, substitution, bindings, aliases, false)
            {
                return Some((token.span.clone(), SubstitutionOutputProof::LocalFilenameFields));
            }
            let quoted = token.quoted && token.node_kind == "string";
            if quoted
                && substitution_word_parts(token, substitution).is_some_and(|(parts, marker)| {
                    matches!(parts.as_slice(),
                        [ScalarArgumentPart::CommandSubstitution(word)] if word == &marker)
                })
                && calendar_date_format(registry, substitution, bindings, aliases, false)
                    .is_some_and(|format| calendar_filename_format(&format, true))
            {
                return Some((token.span.clone(), SubstitutionOutputProof::CalendarFilename {
                    prefix: String::new(),
                    suffix: String::new(),
                }));
            }
            if shell_kind == ShellKind::Bash
                && quoted
                && let Some((prefix, suffix)) = calendar_filename_affixes(token, substitution, true, false)
                && calendar_date_format(registry, substitution, bindings, aliases, false)
                    .is_some_and(|format| calendar_filename_format(&format, true))
            {
                return Some((token.span.clone(), SubstitutionOutputProof::CalendarFilename { prefix, suffix }));
            }
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
            if field.is_none()
                && shell_kind == ShellKind::Bash
                && command.command_name.as_deref() == Some("mv")
                && command.tokens.len() == 2
                && !command.in_pipeline
                && !command.guarded
                && calendar_filename_fields(registry, token, substitution, bindings, aliases, true)
            {
                return Some((token.span.clone(), SubstitutionOutputProof::LocalMovePathFields));
            }
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
            if shell_kind == ShellKind::Bash
                && command.command_name.as_deref() == Some("top")
                && !token.quoted
                && token.text == substitution.text
                && name == "pidof"
                && !producer.command_name_runtime_data
                && resolved.normalized_command_name == "pidof"
                && resolved.bound.form_id.as_str() == "discover_processes"
                && shape == StdoutScalarShape::ArithmeticText
                && registry.lookup(name).profile.is_some_and(|profile| {
                    profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
                })
            {
                return Some((token.span.clone(), SubstitutionOutputProof::DecimalPidFields));
            }
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

pub(crate) fn attested_pipeline_tool(
    registry: &ProfileRegistry,
    command: &CommandFact,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    name: &str,
    variant: &str,
) -> bool {
    command.command_name.as_deref() == Some(name)
        && !command.command_name_runtime_data
        && command.prefix_assignments.is_empty()
        && !aliases.contains_key(name)
        && !bindings.profile_has_alias_shadow(name)
        && bindings.function_binding(name).is_none()
        && bindings.native_variant(name) == Some(variant)
        && registry.lookup(name).profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
}

/// GNU grep's filename for standard input is independent of its input bytes.
/// The stream may be empty, including on a read or regex error. Preserve that
/// alternative through the supported first-field projection.
pub(crate) fn grep_stdin_label_stdout(
    registry: &ProfileRegistry,
    parsed: &ParsedCommandArtifact,
    output: usize,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<[&'static str; 2]> {
    let [grep, projection @ ..] = parsed.commands.get(..=output)? else {
        return None;
    };
    if !plain_stream_chain(parsed)
        || !attested_pipeline_tool(registry, grep, bindings, aliases, "grep", "gnu_grep_3_8_c_locales")
        || !ascii_locale_bound(bindings)
        || !environment_allows(bindings, "LANGUAGE", &["", "C", "POSIX"])
        || !environment_allows(bindings, "NLSPATH", &[""])
    {
        return None;
    }
    let words = literal_arguments(grep)?;
    if !matches!(words.as_slice(), [option, pattern] if
        matches!(option.as_str(), "-l" | "--files-with-matches") && !pattern.starts_with('-'))
    {
        return None;
    }
    let alternatives = ["", "(standard input)\n"];
    match projection {
        [] => Some(alternatives),
        [awk]
            if attested_pipeline_tool(registry, awk, bindings, aliases, "awk", "mawk_1_3_4")
                && matches!(literal_arguments(awk)?.as_slice(), [flag, separator, program]
                    if flag == "-F" && separator == ":" && program == "{print $1}")
                && alternatives.iter().all(|stdout| !stdout.contains(':')) =>
        {
            Some(alternatives)
        }
        _ => None,
    }
}

fn literal_arguments(command: &CommandFact) -> Option<Vec<String>> {
    command.tokens.iter().map(|arg| {
        if arg.runtime_data || arg.implicit_input_source.is_some() {
            return None;
        }
        caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
    }).collect()
}

fn environment_allows(bindings: &SessionBindings, name: &str, permitted: &[&str]) -> bool {
    use caushell_profile::{EnvironmentValueRef, SessionValue};
    match bindings.environment_value(name) {
        // The tool's attestation covers the owning environment when the
        // request supplies no override. A supplied opaque value is separate.
        EnvironmentValueRef::Unknown | EnvironmentValueRef::Absent => true,
        EnvironmentValueRef::Present(SessionValue::ExactScalar(value)) => {
            permitted.contains(&value.as_str())
        }
        _ => false,
    }
}

fn ascii_locale_bound(bindings: &SessionBindings) -> bool {
    environment_allows(bindings, "LOCPATH", &[""])
        && ["LC_ALL", "LC_MESSAGES", "LC_COLLATE", "LC_CTYPE", "LANG"].into_iter().all(|name| {
            environment_allows(bindings, name, &["", "C", "C.UTF-8", "C.utf8", "POSIX"])
        })
}

fn plain_stream_chain(parsed: &ParsedCommandArtifact) -> bool {
    let (Some(first), Some(last)) = (parsed.commands.first(), parsed.commands.last()) else {
        return false;
    };
    parsed.status == ParseStatus::Complete
        && parsed.diagnostics.is_empty()
        && parsed.redirections.is_empty()
        && (parsed.commands.len() == 1 || first.pipeline_span.is_some())
        && parsed.raw_command.get(..first.span.start_byte).is_some_and(|s| s.trim().is_empty())
        && parsed.raw_command.get(last.span.end_byte..).is_some_and(|s| s.trim().is_empty())
        && parsed.commands.iter().all(|stage| {
            stage.pipeline_span == first.pipeline_span && !stage.guarded && !stage.conditional_execution
        })
        && parsed.commands.windows(2).all(|pair| {
            parsed.raw_command.get(pair[0].span.end_byte..pair[1].span.start_byte)
                .is_some_and(|separator| separator.trim() == "|")
        })
}

/// Proves zero or one nonempty ASCII-alphanumeric filename from an
/// attested byte filter, fixed-width fold and first-line selection. The
/// input may be arbitrary bytes. The caller owns the final stdout route.
pub(crate) fn filtered_filename_stdout(
    registry: &ProfileRegistry,
    parsed: &ParsedCommandArtifact,
    output: usize,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> bool {
    let Some(start) = output.checked_sub(2) else {
        return false;
    };
    let Some([filter, fold, head]) = parsed.commands.get(start..=output) else {
        return false;
    };
    if !plain_stream_chain(parsed) {
        return false;
    }
    // The filter attestation includes the fixed environment's locale set.
    // A supplied locale outside that set, or an alternate locale directory,
    // cannot inherit that proof.
    if !environment_allows(bindings, "LOCPATH", &[""])
        || ["LC_ALL", "LC_COLLATE", "LC_CTYPE", "LANG"]
            .iter()
            .any(|name| !environment_allows(bindings, name, &["", "C", "C.UTF-8", "C.utf8", "POSIX"]))
        || ![
            (filter, "tr", "gnu_tr_9_1_ascii_locales"),
            (fold, "fold", "gnu_coreutils_9_1"),
            (head, "head", "gnu_coreutils_9_1"),
        ]
        .into_iter()
        .all(|(command, name, variant)| {
            attested_pipeline_tool(registry, command, bindings, aliases, name, variant)
        })
    {
        return false;
    }

    let (Some(filter), Some(fold), Some(head)) =
        (literal_arguments(filter), literal_arguments(fold), literal_arguments(head))
    else {
        return false;
    };
    let set = match filter.as_slice() {
        [mode, set] if matches!(mode.as_str(), "-dc" | "-cd") => set,
        _ => return false,
    };
    alphanumeric_filter_set(set.as_bytes())
        && matches!(fold.as_slice(), [mode, width] if mode == "-w" &&
            width.bytes().all(|b| b.is_ascii_digit()) && width.parse::<u8>().is_ok_and(|n| n > 0))
        && matches!(head.as_slice(), [mode, count] if mode == "-n" && count == "1")
}

fn alphanumeric_filter_set(mut set: &[u8]) -> bool {
    if set.is_empty() {
        return false;
    }
    while let [first, rest @ ..] = set {
        if let [b'-', last, tail @ ..] = rest {
            if first > last || !(*first..=*last).all(|byte| byte.is_ascii_alphanumeric()) {
                return false;
            }
            set = tail;
        } else if first.is_ascii_alphanumeric() {
            set = rest;
        } else {
            return false;
        }
    }
    true
}

fn sed_decimal_addresses(
    registry: &ProfileRegistry,
    token: &CommandToken,
    substitution: &CommandSubstitutionFact,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<SubstitutionOutputProof> {
    if !token.quoted || token.node_kind != "string" {
        return None;
    }
    let suffix = token.text.strip_prefix(&substitution.text)?;
    let suffix = caushell_parse::decode_static_shell_argument(suffix, true, "string")?;
    // Only pass a script composed of a single capture and literal text.
    if !suffix.starts_with(',') {
        return None;
    }
    let records = pipeline_text_records(registry, &substitution.body_text, bindings, aliases)?;
    (records.fields == TextRecordFields::Decimal).then_some(
        SubstitutionOutputProof::SedDecimalAddresses { suffix, max_records: records.max_records },
    )
}

fn pipeline_text_records(
    registry: &ProfileRegistry,
    body: &str,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<TextRecordStream> {
    if body.len() > 8192 {
        return None;
    }
    let parsed = parse_command(body, ShellKind::Bash).ok()?;
    let first = parsed.commands.first()?;
    let last = parsed.commands.last()?;
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || !parsed.redirections.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.declaration_commands.is_empty()
        || !parsed.unset_commands.is_empty()
        || !parsed.function_definitions.is_empty()
        || first.pipeline_span.is_none()
        || first.pipeline_position != Some(PipelinePosition::First)
        || last.pipeline_position != Some(PipelinePosition::Last)
        || !body.get(..first.span.start_byte)?.trim().is_empty()
        || !body.get(last.span.end_byte..)?.trim().is_empty()
        || parsed.commands.windows(2).any(|pair| {
            body.get(pair[0].span.end_byte..pair[1].span.start_byte)
                .is_none_or(|separator| separator.trim() != "|")
        })
    {
        return None;
    }
    let mut records = None;
    for command in &parsed.commands {
        let name = command.command_name.as_deref()?;
        if command.pipeline_span != first.pipeline_span
            || command.guarded
            || command.conditional_execution
            || command.terminator.is_some()
            || !command.prefix_assignments.is_empty()
            || command.command_name_runtime_data
            || aliases.contains_key(name)
            || bindings.profile_has_alias_shadow(name)
            || bindings.function_binding(name).is_some()
            || !registry.lookup(name).profile.is_some_and(|profile| {
                profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
            })
        {
            return None;
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                registry, command,
                InvocationRuntimeContext::default().with_shell_kind(ShellKind::Bash), bindings,
            )
        else {
            return None;
        };
        if resolved.normalized_command_name != name {
            return None;
        }
        records = Some(resolved.proven_stdout_text_records(records, bindings)?);
    }
    records
}

fn quoted_dirname_path(
    registry: &ProfileRegistry,
    token: &CommandToken,
    capture: &CommandSubstitutionFact,
    shell_kind: ShellKind,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<RuntimeArgumentDomain> {
    if !token.quoted
        || token.node_kind != "string"
        || token.text.len() > 8192
        || capture.body_text.len() > 8192
        || !capture.body_text.trim_start().starts_with("dirname")
    {
        return None;
    }
    let (parts, marker) = substitution_word_parts(token, capture)?;
    let prefix = match parts.as_slice() {
        [ScalarArgumentPart::CommandSubstitution(word)] if word == &marker => None,
        [ScalarArgumentPart::Literal(prefix), ScalarArgumentPart::CommandSubstitution(word)]
            if word == &marker && prefix.strip_suffix('/').is_some_and(ordinary_relative_anchor) =>
        {
            Some(prefix.clone())
        }
        _ => return None,
    };
    let parsed = parse_command(&capture.body_text, shell_kind).ok()?;
    let producer = plain_single_producer(&parsed)?;
    let name = producer.command_name.as_deref()?;
    if name != "dirname"
        || producer.command_name_runtime_data
        || aliases.contains_key(name)
        || bindings.function_binding(name).is_some()
        || bindings.profile_has_alias_shadow(name)
        || !registry.lookup(name).profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
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
    let [arg] = resolved.materialized_projection.invocation.args.as_slice() else {
        return None;
    };
    let Some(RuntimeArgumentDomain::PathSet { roots, may_escape: false, .. }) =
        &arg.runtime_argument_domain
    else {
        return None;
    };
    if resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
        || caushell_profile::argument_structure(arg).fields
            != caushell_profile::ArgumentFieldCount::ExactlyOne
        || roots.is_empty()
        || !roots.iter().all(|root| ordinary_relative_anchor(root))
    {
        return None;
    }
    // dirname can return ".", or the capture can be empty. Trimming trailing
    // newlines can make the last component ".."; keep its parent in the
    // envelope. The fixed ordinary first input component cannot disappear.
    let roots = if let Some(prefix) = prefix {
        vec![prefix]
    } else {
        let mut candidates = vec![String::new(), ".".into()];
        candidates.extend(roots.iter().filter_map(|root| {
            root.split('/').next().filter(|component| !component.is_empty()).map(str::to_owned)
        }));
        candidates.sort();
        candidates.dedup();
        candidates
    };
    Some(RuntimeArgumentDomain::PathSet {
        roots,
        may_escape: false,
        basename_suffix: None,
        no_adjacent_slashes: false,
        dot_relative_components: false,
        execdir_leaf: false,
    })
}

fn ordinary_relative_anchor(path: &str) -> bool {
    let path = path.strip_prefix("./").unwrap_or(path);
    !path.starts_with(['-', '+', '~'])
        && !path.contains(['\0', '\n'])
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

/// In the default calendar format, the only possible sign is before the
/// first year digit. The literal prefix keeps it in the initial filename or
/// IFS consumes it. Other fields contain digits, the literal extension, or
/// no bytes. Neither pathname generation nor option parsing can take over.
fn calendar_filename_fields(
    registry: &ProfileRegistry,
    token: &CommandToken,
    capture: &CommandSubstitutionFact,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    directory_prefix: bool,
) -> bool {
    calendar_filename_affixes(token, capture, false, directory_prefix).is_some()
        && calendar_date_format(registry, capture, bindings, aliases, directory_prefix)
            .is_some_and(|format| calendar_filename_format(&format, false))
}

fn calendar_filename_affixes(
    token: &CommandToken,
    capture: &CommandSubstitutionFact,
    quoted: bool,
    directory_prefix: bool,
) -> Option<(String, String)> {
    if token.text.len() > 8192 || capture.body_text.len() > 8192 {
        return None;
    }
    let (parts, marker) = substitution_word_parts(token, capture)?;
    let [ScalarArgumentPart::Literal(prefix), capture, ScalarArgumentPart::Literal(suffix)] =
        parts.as_slice()
    else {
        return None;
    };
    match capture {
        ScalarArgumentPart::CommandSubstitution(word) if quoted && word == marker => {}
        ScalarArgumentPart::UnquotedCommandSubstitution(word) if !quoted && word == marker => {}
        _ => return None,
    };
    let prefix_name = if directory_prefix {
        prefix.strip_suffix('/')?
    } else {
        prefix.as_str()
    };
    let name_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (prefix_name.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && prefix_name.bytes().all(|b| name_byte(b) || quoted && matches!(b, b'-' | b'.'))
        && suffix.strip_prefix('.').is_some_and(|s| !s.is_empty() && s.bytes().all(name_byte)))
        .then(|| (prefix.clone(), suffix.clone()))
}

fn calendar_filename_format(format: &str, allow_separator: bool) -> bool {
    let Some(rest) = format.strip_prefix("+%Y") else {
        return false;
    };
    !rest.is_empty()
        && (allow_separator || !rest.contains(['_', '-']))
        && rest.strip_prefix(['_', '-']).unwrap_or(rest).split(['_', '-']).all(|run| {
            let chunks = run.as_bytes().chunks_exact(2);
            !run.is_empty()
                && chunks.remainder().is_empty()
                && chunks.into_iter().all(|part| matches!(part, b"%m" | b"%d" | b"%H" | b"%M" | b"%S"))
        })
}

fn calendar_date_format(
    registry: &ProfileRegistry,
    capture: &CommandSubstitutionFact,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    allow_date_operand: bool,
) -> Option<String> {
    if capture.body_text.len() > 8192 {
        return None;
    }
    let parsed = parse_command(&capture.body_text, ShellKind::Bash).ok()?;
    let producer = plain_single_producer(&parsed)?;
    let name @ ("date" | "/bin/date" | "/usr/bin/date") = producer.command_name.as_deref()? else {
        return None;
    };
    if producer.command_name_runtime_data || aliases.contains_key(name)
        || bindings.function_binding(name).is_some() || bindings.profile_has_alias_shadow(name)
        || !registry.lookup(name).profile.is_some_and(|p| {
            p.primary_name() == "date" && p.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
    {
        return None;
    }
    let decode = |argument: &CommandToken| {
        caushell_parse::decode_static_shell_argument(
            &argument.text, argument.quoted, &argument.node_kind,
        )
    };
    let format = match producer.tokens.as_slice() {
        [format] => decode(format),
        [flag, expression, format] if allow_date_operand
            && decode(flag).as_deref() == Some("-d")
            && decode(expression).is_some() => decode(format),
        _ => None,
    }?;
    matches!(
        resolve_invocation_artifact_with_bindings(
            registry, producer, InvocationRuntimeContext::default(), bindings,
        ),
        ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout()
            || (!allow_date_operand
                && format.contains('_')
                && calendar_filename_format(&format, true)
                && r.bound.form_id.as_str() == "print_or_parse_date"
                && r.proven_stream_contract().is_some())
    ).then_some(format)
}

fn decimal_clock_format(format: &str) -> bool {
    let Some(rest) = format.strip_prefix('+') else {
        return false;
    };
    let mut found_conversion = false;
    let mut bytes = rest.bytes();
    while let Some(byte) = bytes.next() {
        if byte.is_ascii_digit() {
            continue;
        }
        if byte != b'%' || !matches!(bytes.next(), Some(b'm' | b'd' | b'H' | b'M' | b'S')) {
            return false;
        }
        found_conversion = true;
    }
    found_conversion
}

/// A whole quoted capture of a portable find path listing keeps the
/// starting-point spelling at the start of any nonempty stdout. Newlines
/// inside or between emitted names do not become additional shell fields.
/// This provides no proof of which paths exist or what the capture contains.
pub(crate) fn quoted_find_positional_capture(
    registry: &ProfileRegistry,
    token: &CommandToken,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
) -> Option<SourceSpan> {
    let [capture] = token.command_substitutions.as_slice() else {
        return None;
    };
    if token.runtime_data
        || token.implicit_input_source.is_some()
        || capture.body_text.len() > 8192
        || !matches!(
            caushell_parse::scalar_argument_parts(&token.text, token.quoted, &token.node_kind)
                .as_deref(),
            Some([ScalarArgumentPart::CommandSubstitution(text)]) if text == &capture.text
        )
        || aliases.contains_key("find")
        || bindings.function_binding("find").is_some()
        || bindings.profile_has_alias_shadow("find")
        || !registry.lookup("find").profile.is_some_and(|profile| {
            profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
        })
    {
        return None;
    }
    let parsed = parse_command(&capture.body_text, ShellKind::Bash).ok()?;
    let producer = plain_single_producer(&parsed)?;
    if producer.command_name.as_deref() != Some("find") || producer.command_name_runtime_data {
        return None;
    }
    let argv = producer.tokens.iter().map(|arg| {
        caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
    }).collect::<Option<Vec<_>>>()?;
    let [root, predicate, _, rest @ ..] = argv.as_slice() else {
        return None;
    };
    // Limit this proof to the shared GNU and BSD grammar for file-name tests
    // with implicit or explicit -print.
    if !root.as_bytes().first().is_some_and(|b| {
        b.is_ascii_alphanumeric() || matches!(*b, b'/' | b'.' | b'_')
    }) || predicate != "-name"
        || !(rest.is_empty() || matches!(rest, [print] if print == "-print"))
    {
        return None;
    }
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            registry, producer, InvocationRuntimeContext::default(), bindings,
        )
    else {
        return None;
    };
    let plan = resolved.native_stdout_record_plan()?.ok()?;
    (plan.roots == [root.clone()]
        && plan.record_encoding() == caushell_types::StreamRecordEncoding::Lines)
        .then(|| capture.span.clone())
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

pub(crate) fn plain_single_producer(parsed: &ParsedCommandArtifact) -> Option<&CommandFact> {
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
    fn numbered_match_field_flows_through_record_prefixes() {
        let registry = ProfileRegistry::built_in().unwrap();
        let mut bindings = SessionBindings::new();
        bindings.reset_child_environment(true);
        let aliases = BTreeMap::new();
        for (body, limit) in [
            ("grep -a -n marker input | head -1 | cut -d: -f1", Some(1)),
            ("grep --text --line-number marker input | head -n 3 | cut -f 1 -d :", Some(3)),
            ("grep -a -n marker input | cut -d: -f1", None),
        ] {
            assert_eq!(
                pipeline_text_records(&registry, body, &bindings, &aliases),
                Some(TextRecordStream { fields: TextRecordFields::Decimal, max_records: limit }),
                "{body}",
            );
        }
        for body in [
            "grep -n marker input | cut -d: -f1",
            "grep -a -n -H marker input | cut -d: -f1",
            "grep -a -n marker input another | cut -d: -f1",
            "grep -a -n marker input | cut -d: -f2",
            "grep -a -n marker input | cut -d/ -f1",
            "grep -a -n marker input | cut -d: -f1 other",
            "grep -a -n marker input | head -c1 | cut -d: -f1",
            "grep -a -n marker input | head -v | cut -d: -f1",
            "grep -a -n marker input | head -1 | /tmp/cut -d: -f1",
            "grep -a -n marker input | head -1 other | cut -d: -f1",
            "grep -a -n marker input |& cut -d: -f1",
        ] {
            assert_eq!(pipeline_text_records(&registry, body, &bindings, &aliases), None, "{body}");
        }
    }

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
