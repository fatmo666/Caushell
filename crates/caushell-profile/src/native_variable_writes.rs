//! Native argument grammars that write owning-shell variables. No argument
//! bytes are reparsed as shell source, and external argv never owns shell state.
use crate::*;
use caushell_types::ShellKind;

pub(crate) fn attach(
    profile: &CommandProfile,
    source: &ProjectedInvocation,
    argv: &MaterializedProjectedInvocation,
    domain: &CommandLookupDomain,
    shell: ShellKind,
    bindings: &SessionBindings,
    bound: &mut BoundInvocation,
) -> Option<caushell_parse::SourceSpan> {
    let Some(NativeVariableWrites::Printf) = profile.native_variable_writes else {
        return None;
    };
    if !matches!(
        domain,
        CommandLookupDomain::Shell | CommandLookupDomain::Builtin
    ) {
        return None;
    }
    let mut targets = Vec::new();
    let mut args = argv.invocation.args.iter();
    let exact = |arg: &ProjectedArg| argument_structure(arg).exact_value().map(str::to_owned);
    let mut destination = None;
    let mut separated = false;
    let mut write_free_format_span = None;
    let format = loop {
        let Some(arg) = args.next() else { break None };
        let Some(word) = exact(arg) else {
            let shape = argument_structure(arg);
            // A single, definitely non-option FORMAT with no following argv
            // cannot supply a %n destination. Its bytes/output remain unknown;
            // this is only a proof about the absence of variable writes.
            let target_free = shape.fields == ArgumentFieldCount::ExactlyOne
                && (separated || !shape.may_start_with("-"))
                && args.len() == 0;
            // Hexadecimal and standard Base64 contain no option prefix, format
            // directive, escape, or glob characters, even after word splitting.
            let encoded_format = shell == ShellKind::Bash
                && profile.trust.source == ProfileSourceKind::BuiltIn
                && argv.invocation.args.len() == 1
                && !arg.runtime_data
                && arg.implicit_input_source.is_none()
                && !matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string")
                && matches!(exact_shell_parameter_reference(&arg.text),
                    Some(ShellParameterReference::Variable(name))
                        if matches!(bindings.variable_facts(&name).scalar_shape,
                            Some(StdoutScalarShape::PlainHexText | StdoutScalarShape::RawBase64Text)));
            let inert_format_suffix = shell == ShellKind::Bash
                && profile.trust.source == ProfileSourceKind::BuiltIn
                && shape.fields == ArgumentFieldCount::ExactlyOne
                && {
                    let mut matching = source.args.iter().filter(|word| word.span == arg.span);
                    matches!((matching.next(), matching.next()), (Some(word), None)
                        if quoted_format_with_inert_suffix(word, bindings, separated))
                };
            // A bounded bare numeric range can produce only signed decimal
            // arguments, or its literal brace spelling with expansion off.
            // Neither can name a Bash variable or array member for %n.
            let numeric_range_operands = shell == ShellKind::Bash
                && profile.trust.source == ProfileSourceKind::BuiltIn
                && shape.fields == ArgumentFieldCount::ExactlyOne
                && (separated || !shape.may_start_with("-"))
                && args.len() > 0
                && args.clone().all(|word| {
                    argv.shell_expansion_gaps.iter().any(|gap| {
                        gap.span == word.span
                            && gap.kind == ShellExpansionGapKind::BraceBudgetExhausted
                            && gap.bounded_literal_bytes.is_some()
                    }) && word
                        .text
                        .strip_prefix('{')
                        .and_then(|text| text.strip_suffix('}'))
                        .is_some_and(|text| {
                            text.bytes()
                                .all(|byte| byte.is_ascii_digit() || b"+-.".contains(&byte))
                        })
                });
            if inert_format_suffix || numeric_range_operands {
                write_free_format_span = Some(arg.span.clone());
            }
            if !target_free && !encoded_format && !inert_format_suffix && !numeric_range_operands {
                targets.push(None);
            }
            break None;
        };
        if !separated && word == "--" {
            separated = true;
            continue;
        }
        if !separated && word == "-v" {
            destination = Some(args.next().and_then(exact));
            continue;
        }
        if !separated && word.starts_with("-v") {
            destination = Some(Some(word[2..].to_owned()));
            continue;
        }
        if !separated && word.starts_with('-') && word != "-" {
            // Invalid/unsupported controls cannot certify a variable-free call.
            targets.push(None);
            break None;
        }
        break Some(word);
    };
    if let Some(target) = destination {
        targets.push(target);
        // Assignment output is independent of input bytes. Do not certify a
        // formatted scalar, record framing or exact value from the old form.
        if let Some(contract) = bound.stream_contract.as_mut() {
            contract.stdout_dependency = caushell_types::StreamDataDependency::Independent;
        }
        bound.stdout_scalar = None;
        bound.stdout_scalar_inputs.clear();
        bound.stdout_scalar_complete = false;
        bound.stdout_records = None;
        bound.stdout_growth = None;
        bound.stdout_growth_complete = false;
    }
    if let Some(format) = format {
        match printf_arguments(&format) {
            None => targets.push(None),
            Some(roles) if roles.contains(&true) => {
                let arguments: Vec<_> = args.collect();
                if arguments
                    .iter()
                    .any(|a| argument_structure(a).fields != ArgumentFieldCount::ExactlyOne)
                {
                    targets.push(None);
                } else {
                    // Bash reuses FORMAT until all supplied arguments have
                    // been consumed. Missing conversion arguments get defaults;
                    // missing %n destinations must never become invented names.
                    let mut offset = 0;
                    loop {
                        for (i, target) in roles.iter().enumerate() {
                            if *target && let Some(argument) = arguments.get(offset + i) {
                                targets.push(exact(argument));
                            }
                        }
                        offset += roles.len();
                        if offset >= arguments.len() {
                            break;
                        }
                    }
                }
            }
            Some(_) => {}
        }
    }
    if shell != ShellKind::Bash && !targets.is_empty() {
        // Other shells do not establish the Bash extension's target grammar.
        targets.push(None);
    }
    for target in targets {
        let mut effect = Effect::new(EffectKind::BindVariableFromRuntimeInput);
        effect.target = target.map_or(EffectTarget::None, EffectTarget::VariableName);
        if !bound.effects.contains(&effect) {
            bound.effects.push(effect);
        }
    }
    write_free_format_span
}

// A complete format prefix can only be followed by literal data when the
// owning shell proves both the quoted field and the suffix's alphabet.
// Keep the actual output unknown and never substitute representative bytes.
fn quoted_format_with_inert_suffix(
    arg: &ProjectedArg,
    bindings: &SessionBindings,
    separated: bool,
) -> bool {
    if arg.word_context != WordContext::ShellArgument || !arg.quoted
        || arg.node_kind != "string" || arg.runtime_data || arg.implicit_input_source.is_some()
        || arg.text.contains(['"', '\\', '`'])
    {
        return false;
    }
    let Some((prefix, suffix)) = arg.text.split_once('$') else {
        return false;
    };
    if prefix.is_empty() || (!separated && prefix.starts_with('-'))
        || !printf_arguments(prefix).is_some_and(|roles| roles.into_iter().all(|writes| !writes))
    {
        return false;
    }
    if let Some(name) = suffix.strip_prefix('{').and_then(|s| s.strip_suffix(",,}")) {
        let reference = exact_shell_parameter_reference(&format!("${{{name}}}"));
        let Some(reference @ ShellParameterReference::Variable(_)) = reference else {
            return false;
        };
        return exact_scalar_shell_parameter_value(bindings, &reference)
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_alphabetic()));
    }
    let reference = format!("${suffix}");
    matches!(exact_shell_parameter_reference(&reference),
        Some(ShellParameterReference::Variable(name))
            if bindings.variable_facts(&name).integer_scalar
                || bindings.variable_facts(&name).scalar_shape == Some(StdoutScalarShape::ArithmeticText))
}

/// Ordered argument consumption, including star width/precision. `true` is
/// %n's variable destination; %% and strftime's embedded %n consume no target.
/// A malformed or unreviewed directive retains uncertainty, never a proof.
fn printf_arguments(format: &str) -> Option<Vec<bool>> {
    let b = format.as_bytes();
    let mut i = 0;
    let mut roles = Vec::new();
    while i < b.len() {
        match b[i] {
            // Only an escaped backslash shields the next backslash. Bash
            // retains unknown escapes (e.g. \%) and still interprets %n.
            b'\\' => {
                i += if b.get(i + 1) == Some(&b'\\') { 2 } else { 1 };
                continue;
            }
            b'%' => {}
            _ => {
                i += 1;
                continue;
            }
        }
        i += 1;
        if b.get(i) == Some(&b'%') {
            i += 1;
            continue;
        }
        while b.get(i).is_some_and(|c| b"#0- +'".contains(c)) {
            i += 1;
        }
        if b.get(i) == Some(&b'*') {
            roles.push(false);
            i += 1;
        } else {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        if b.get(i) == Some(&b'.') {
            i += 1;
            if b.get(i) == Some(&b'*') {
                roles.push(false);
                i += 1;
            } else {
                while b.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
            }
        }
        if b.get(i) == Some(&b'(') {
            i += 1;
            while b.get(i).is_some_and(|c| *c != b')') {
                i += 1;
            }
            if b.get(i) != Some(&b')') || b.get(i + 1) != Some(&b'T') {
                return None;
            }
            i += 2;
            roles.push(false);
            continue;
        }
        while b.get(i).is_some_and(|c| b"hlLjzt".contains(c)) {
            i += 1;
        }
        let conversion = *b.get(i)?;
        if !b"diouxXfFeEgGaAcsSCbqQn".contains(&conversion) {
            return None;
        }
        roles.push(conversion == b'n');
        i += 1;
    }
    Some(roles)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_consumption_is_not_a_substring_search() {
        for (format, expected) in [
            ("%%n%s", vec![false]),
            ("%(%n)T", vec![false]),
            ("%*.*s%n", vec![false, false, false, true]),
            ("%s%n%s%n", vec![false, true, false, true]),
            ("%03d %q %b %ln", vec![false, false, false, true]),
            ("literal", vec![]),
            ("\\%n", vec![true]),
        ] {
            assert_eq!(printf_arguments(format), Some(expected), "{format}");
        }
        for format in ["%", "%Y%n", "%2$n", "%(%n)X"] {
            assert!(printf_arguments(format).is_none());
        }
    }
}
