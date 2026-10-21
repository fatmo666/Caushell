//! Certainty of declared value matchers over native argv spelling bounds.
use crate::{ArgumentStructure, ValueMatcher};
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, StartKind, dense},
    nfa::thompson,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock, RwLock},
};

const MAX_PATTERNS: usize = 32;
const MAX_PREFIX_BYTES: usize = 1024;
const MAX_DFA_BYTES: usize = 64 * 1024;
const MAX_BUILD_BYTES: usize = 256 * 1024;

enum PrefixPlan {
    Atom(Hir),
    RejectOnly(dense::DFA<Vec<u32>>),
    Unknown,
}

impl PrefixPlan {
    fn compile(pattern: &str) -> Self {
        let Ok(hir) = regex_syntax::ParserBuilder::new()
            .nest_limit(32)
            .build()
            .parse(pattern)
        else {
            return Self::Unknown;
        };
        let HirKind::Concat(parts) = hir.kind() else {
            return Self::Unknown;
        };
        // Only an absolute start anchor permits rejecting every possible
        // completion from a prefix. Multiline or unanchored searches may start later.
        if !parts
            .first()
            .is_some_and(|p| matches!(p.kind(), HirKind::Look(Look::Start)))
        {
            return Self::Unknown;
        }
        fn simple(atom: &Hir) -> bool {
            match atom.kind() {
                HirKind::Literal(_) | HirKind::Class(_) => true,
                HirKind::Capture(c) => simple(&c.sub),
                _ => false,
            }
        }
        if let [_, atom] = parts.as_slice()
            && simple(atom)
        {
            return Self::Atom(atom.clone());
        }
        let result = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .start_kind(StartKind::Anchored)
                    .dfa_size_limit(Some(MAX_DFA_BYTES))
                    .determinize_size_limit(Some(MAX_BUILD_BYTES)),
            )
            .syntax(regex_automata::util::syntax::Config::new().nest_limit(32))
            .thompson(thompson::Config::new().nfa_size_limit(Some(MAX_DFA_BYTES)))
            .build(pattern);
        match result {
            Ok(dfa) => Self::RejectOnly(dfa),
            Err(_) => Self::Unknown,
        }
    }

    fn matches(&self, prefix: &str) -> Option<bool> {
        match self {
            Self::Atom(atom) => prefix_atom(atom, prefix),
            Self::Unknown => None,
            Self::RejectOnly(dfa) => {
                if prefix.is_empty() || prefix.len() > MAX_PREFIX_BYTES {
                    return None;
                }
                let mut state = dfa
                    .start_state_forward(&Input::new(prefix).anchored(Anchored::Yes))
                    .ok()?;
                for &byte in prefix.as_bytes() {
                    state = dfa.next_state(state, byte);
                    if dfa.is_quit_state(state) || dfa.is_match_state(state) {
                        return None;
                    }
                    if dfa.is_dead_state(state) {
                        return Some(false);
                    }
                }
                // No EOI transition: the unknown middle and suffix have not
                // been consumed. Reaching the prefix end is not a full match.
                None
            }
        }
    }
}

fn prefix_plan(pattern: &str) -> Option<Arc<PrefixPlan>> {
    static CACHE: OnceLock<RwLock<BTreeMap<String, Arc<PrefixPlan>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    if let Some(plan) = cache.read().ok()?.get(pattern).cloned() {
        return Some(plan);
    }
    let mut plans = cache.write().ok()?;
    if let Some(plan) = plans.get(pattern) {
        return Some(Arc::clone(plan));
    }
    let plan = Arc::new(PrefixPlan::compile(pattern));
    if plans.len() >= MAX_PATTERNS {
        plans.pop_first();
    }
    plans.insert(pattern.into(), Arc::clone(&plan));
    Some(plan)
}

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
            prefix_plan(pattern)?.matches(&structure.static_prefix)
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
    fn compound_regex_rejection_uses_only_the_known_prefix() {
        for (pattern, prefix, expected) in [
            (r"^\+(%[sYmdHMS]|[0-9+ -])+$", "+%c: ", Some(false)),
            (r"^\+(%[sYmdHMS]|[0-9+ -])+$", "+%+: ", Some(false)),
            (r"^\+(%[sYmdHMS]|[0-9+ -])+$", "+%s", None),
            (r"^read:(ab|cd)+$", "read:ax", Some(false)),
            (r"^read:(ab|cd)+$", "read:ab", None),
            (r"^read:(ab|cd)+", "read:abx", None),
            (r"^(safe|read):[0-9]{2}$", "safe:x", Some(false)),
            (r"^(safe|read):[0-9]{2}$", "safe:123", Some(false)),
            (r"^(safe|read):[0-9]{2}$", "safe:12", None),
            (r"^(safe|read):[0-9]{2}$", "sa", None),
            (r"^猫[0-9]+$", "猫x", Some(false)),
            (r"^猫[0-9]+$", "猫1", None),
            (r"\A(foo|bar)[0-9]+$", "baz", Some(false)),
            (r"^foo|bar", "baz", None),
            (r"(?m)^foo$", "bar\n", None),
            (r"foo$", "bar", None),
        ] {
            assert_eq!(
                matches(
                    &shape(prefix, ""),
                    &ValueMatcher::RegexPattern(pattern.into())
                ),
                expected,
                "{pattern} {prefix}"
            );
        }
    }

    #[test]
    fn proof_limits_and_cached_failure_remain_unknown() {
        let pattern = r"^(ab|cd)+$";
        assert!(Arc::ptr_eq(
            &prefix_plan(pattern).unwrap(),
            &prefix_plan(pattern).unwrap()
        ));
        for (pattern, prefix) in [
            ("^a{1000000}$".to_owned(), "x".to_owned()),
            (
                format!("^{}a{}$", "(".repeat(40), ")".repeat(40)),
                "x".to_owned(),
            ),
            (format!("^{}$", "a".repeat(4096)), "x".to_owned()),
            (pattern.into(), "x".repeat(MAX_PREFIX_BYTES + 1)),
        ] {
            let matcher = ValueMatcher::RegexPattern(pattern);
            assert_eq!(matches(&shape(&prefix, ""), &matcher), None);
            assert_eq!(matches(&shape(&prefix, ""), &matcher), None);
        }
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
            r"^\+(%[sYmdHMS]|[0-9+ -])+$",
            r"^(safe|read):[0-9]{1,3}$",
            r"^read:(ab|cd)+",
            r"^read:(ab|cd)+$",
            r"^猫[0-9]+$",
            r"\A(foo|bar)+$",
            r"^(?:a?|b*)c$",
            r"^a?$",
            r"^a*",
            r"^a\b$",
            r"(?m)\Afoo$",
        ] {
            let regex = regex::Regex::new(pattern).unwrap();
            for prefix in [
                "", "+", "+%c: ", "+%s", "202", "r", "read:", "read:\n", "read:abx", "safe:12",
                "猫", "猫x", "Z", "a", "abc", "foo\n",
            ] {
                for suffix in ["", "\n", "read:", " END"] {
                    let Some(expected) = matches(
                        &shape(prefix, suffix),
                        &ValueMatcher::RegexPattern(pattern.into()),
                    ) else {
                        continue;
                    };
                    for middle in [
                        "",
                        "x",
                        "--set=tomorrow",
                        "\nread:",
                        "猫",
                        "202",
                        "ab",
                        "cd",
                        "c",
                        "bar",
                        "\n",
                    ] {
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
