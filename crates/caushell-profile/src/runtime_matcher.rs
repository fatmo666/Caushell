//! Certainty of declared value matchers over native argv spelling bounds.
use crate::{ArgumentStructure, ValueMatcher};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub(crate) fn matches(structure: &ArgumentStructure, matcher: &ValueMatcher) -> Option<bool> {
    if let Some(value) = structure.exact_value() {
        return Some(crate::bind::argument_matches_value_matcher(value, matcher));
    }
    match matcher {
        ValueMatcher::Literal(value) => (!structure.may_equal(value)).then_some(false),
        ValueMatcher::AsciiCaseInsensitiveLiterals(values) => {
            let mut folded = structure.clone();
            folded.static_prefix.make_ascii_lowercase();
            folded.static_suffix.make_ascii_lowercase();
            values
                .iter()
                .all(|value| !folded.may_equal(&value.to_ascii_lowercase()))
                .then_some(false)
        }
        ValueMatcher::RegexPattern(pattern) if pattern.len() <= 4096 => {
            // Certify only a start anchor followed by one literal/class atom.
            // Such a completed prefix match cannot be undone by unknown data.
            // Other regex syntax remains unknown, not a sampled-value guess.
            let hir = regex_syntax::ParserBuilder::new()
                .nest_limit(32)
                .build()
                .parse(pattern)
                .ok()?;
            let HirKind::Concat(parts) = hir.kind() else {
                return None;
            };
            let [start, atom] = parts.as_slice() else {
                return None;
            };
            if !matches!(start.kind(), HirKind::Look(Look::Start)) {
                return None;
            }
            prefix_atom(atom, &structure.static_prefix)
        }
        _ => None,
    }
}

fn prefix_atom(atom: &Hir, prefix: &str) -> Option<bool> {
    match atom.kind() {
        HirKind::Capture(capture) => prefix_atom(&capture.sub, prefix),
        HirKind::Literal(literal) => {
            let literal = literal.0.as_ref();
            let common = prefix.len().min(literal.len());
            if prefix.as_bytes()[..common] != literal[..common] {
                return Some(false);
            }
            (prefix.len() >= literal.len()).then_some(true)
        }
        HirKind::Class(Class::Unicode(class)) => {
            let first = prefix.chars().next()?;
            Some(
                class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= first && first <= range.end()),
            )
        }
        HirKind::Class(Class::Bytes(class)) => {
            let first = *prefix.as_bytes().first()?;
            Some(
                class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= first && first <= range.end()),
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InvocationRuntimeContext, argument_structure, project_invocation};
    use caushell_types::{ImplicitInputSource, RuntimeArgumentDomain, ShellKind};
    fn shape(prefix: &str, suffix: &str) -> ArgumentStructure {
        let parsed = caushell_parse::parse_command("echo placeholder", ShellKind::Bash).unwrap();
        let mut p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let arg = &mut p.args[0];
        arg.text.clear();
        arg.node_kind = "runtime_scalar".into();
        arg.implicit_input_source = Some(ImplicitInputSource::StdinData);
        arg.runtime_argument_domain = Some(RuntimeArgumentDomain::TextTemplate {
            prefix: prefix.into(),
            suffix: suffix.into(),
        });
        argument_structure(arg)
    }
    #[test]
    fn prefix_proofs_never_treat_an_unknown_middle_as_an_exact_value() {
        for (pattern, prefix, suffix, expected) in [
            ("^[^+]", "+%c: ", "", Some(false)),
            ("^[^+]", "202", "", Some(true)),
            ("^query:", "query: ", "", Some(true)),
            ("^query:", "qu", "", None),
            ("^query:", "other", "", Some(false)),
            ("^query:$", "query:", "", None),
            ("(?m)^query:", "other\n", "", None),
            ("^[0-9]", "", "1", None),
            ("^猫", "猫", "", Some(true)),
        ] {
            assert_eq!(
                matches(
                    &shape(prefix, suffix),
                    &ValueMatcher::RegexPattern(pattern.into())
                ),
                expected,
                "{pattern} {prefix} {suffix}"
            );
        }
        assert_eq!(
            matches(
                &shape("query:", ""),
                &ValueMatcher::Literal("query:".into())
            ),
            None
        );
        assert_eq!(
            matches(
                &shape("query:", ""),
                &ValueMatcher::Literal("mutate".into())
            ),
            Some(false)
        );
    }

    #[test]
    fn certified_results_agree_with_complete_strings() {
        for pattern in [
            "^[^+]",
            "^[0-9]",
            "^read:",
            "^猫",
            "^[A-Z]",
            "^read:$",
            "(?m)^read:",
        ] {
            let regex = regex::Regex::new(pattern).unwrap();
            for prefix in ["", "+", "202", "r", "read:", "read:\n", "猫", "Z"] {
                for suffix in ["", "\n", "read:", " END"] {
                    let Some(expected) = matches(
                        &shape(prefix, suffix),
                        &ValueMatcher::RegexPattern(pattern.into()),
                    ) else {
                        continue;
                    };
                    for middle in ["", "x", "--set=tomorrow", "\nread:", "猫", "202"] {
                        assert_eq!(
                            regex.is_match(&format!("{prefix}{middle}{suffix}")),
                            expected,
                            "{pattern} {prefix:?} {middle:?} {suffix:?}"
                        );
                    }
                }
            }
        }
    }
}
