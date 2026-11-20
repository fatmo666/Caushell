//! Bounded post-expansion field formation. Bytes are data, never shell source.
//! Only expansion-origin characters may be split; quoted nulls remain fields.
use crate::{SessionBindings, SessionValue, VariablePresence};

#[derive(Debug, Clone)]
pub enum ShellFieldFragment {
    /// Quote-removed literal data; the caller has excluded active glob syntax.
    Literal(String),
    QuotedExpansion(String),
    UnquotedExpansion(String),
}

/// Materialize expansion bytes without discarding their source quoting.
pub fn materialize_shell_field_fragments(
    parts: Vec<caushell_parse::ScalarArgumentPart>,
    bindings: &SessionBindings,
    mut substitution: impl FnMut(&str) -> Option<String>,
) -> Option<Vec<ShellFieldFragment>> {
    use caushell_parse::ScalarArgumentPart as Part;
    use ShellFieldFragment::{Literal, QuotedExpansion, UnquotedExpansion};
    let parameter = |s: &str| crate::materialize_shell_assignment_value(s, true, "string", bindings);
    parts.into_iter().map(|part| Some(match part {
        Part::Literal(value) => Literal(value),
        Part::Parameter(source) => QuotedExpansion(parameter(&source)?),
        Part::UnquotedParameter(source) => UnquotedExpansion(parameter(&source)?),
        Part::CommandSubstitution(source) => QuotedExpansion(substitution(&source)?),
        Part::UnquotedCommandSubstitution(source) => UnquotedExpansion(substitution(&source)?),
    })).collect()
}

/// Unknown owning-shell state is not an observation of Bash's default IFS.
pub fn observed_ifs_value(bindings: &SessionBindings) -> Option<String> {
    match bindings.variable_presence("IFS") {
        VariablePresence::Absent => Some(" \t\n".into()),
        VariablePresence::Present => match &bindings.get("IFS")?.value {
            SessionValue::ExactScalar(s) | SessionValue::RuntimeProduced { value: s, .. } => {
                Some(s.clone())
            }
            _ => None,
        },
        VariablePresence::Unknown => None,
    }
}

/// Enumerate IFS layouts for one known, nonnegative decimal expansion. Only
/// the digits present in the value can affect splitting. This is a union of
/// possible layouts, with no claim about the actual IFS or argv.
pub(crate) fn decimal_field_layouts(value: u32) -> Option<std::collections::BTreeSet<Vec<String>>> {
    let value = value.to_string();
    let mut digits = value.as_bytes().to_vec();
    digits.sort_unstable();
    digits.dedup();
    let fragments = [ShellFieldFragment::UnquotedExpansion(value)];
    let mut layouts = std::collections::BTreeSet::new();
    let mut bindings = SessionBindings::new();
    for mask in 0..(1u16 << digits.len()) {
        let ifs: String = digits.iter().enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, byte)| char::from(*byte))
            .collect();
        bindings.insert_exact_scalar("IFS", ifs);
        layouts.insert(materialize_bash_field_fragments(&fragments, &bindings)?);
    }
    Some(layouts)
}

/// For a whole, unquoted expansion whose proven output is one ASCII byte
/// without glob syntax, splitting can only preserve, empty or remove the
/// field. Keeping all three covers IFS whitespace and dialect variation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalBashField(u8);

impl OptionalBashField {
    pub fn from_fragments(fragments: &[ShellFieldFragment]) -> Option<Self> {
        let [ShellFieldFragment::UnquotedExpansion(text)] = fragments else {
            return None;
        };
        let [byte] = *text.as_bytes() else {
            return None;
        };
        (byte != 0 && byte.is_ascii() && !matches!(byte, b'*' | b'?' | b'['))
            .then_some(Self(byte))
    }

    pub fn variants(self) -> [Option<String>; 3] {
        [Some(char::from(self.0).to_string()), Some(String::new()), None]
    }

    pub(crate) fn may_equal(self, value: &str) -> bool {
        value.is_empty() || value.as_bytes() == [self.0]
    }
}

enum Atom {
    Character(char, bool), // expansion-origin: splitting and globbing may apply
    QuotedNull,
}

/// Exact fields only. Pathname generation and unsupported IFS locales retain
/// uncertainty; this function supplies no filesystem or command-success facts.
pub fn materialize_bash_field_fragments(
    fragments: &[ShellFieldFragment],
    bindings: &SessionBindings,
) -> Option<Vec<String>> {
    if fragments.len() > 256 {
        return None;
    }
    let needs_ifs = fragments.iter().any(|f| {
        matches!(f, ShellFieldFragment::UnquotedExpansion(s) if !s.is_empty())
    });
    let ifs = if needs_ifs { observed_ifs_value(bindings)? } else { String::new() };
    // Multibyte IFS is locale-dependent. Never guess its byte/character rules.
    if !ifs.is_ascii() || ifs.contains(['\0', '\r', '\u{b}', '\u{c}']) {
        return None;
    }
    // Bash 3.2 and 5.2 differ in retaining a quoted null beside a split
    // expansion. Do not invent an exact trailing field without dialect proof.
    if !ifs.is_empty() && needs_ifs && fragments.iter().any(|f|
        matches!(f, ShellFieldFragment::QuotedExpansion(s) | ShellFieldFragment::Literal(s) if s.is_empty())) {
        return None;
    }
    let mut atoms = Vec::new();
    let mut bytes = 0usize;
    for fragment in fragments {
        let (s, expansion) = match fragment {
            ShellFieldFragment::UnquotedExpansion(s) => (s, true),
            ShellFieldFragment::QuotedExpansion(s) | ShellFieldFragment::Literal(s) => {
                if s.is_empty() { atoms.push(Atom::QuotedNull); }
                (s, false)
            }
        };
        bytes = bytes.checked_add(s.len())?;
        if bytes > 262_144 || s.contains('\0') {
            return None;
        }
        atoms.extend(s.chars().map(|c| Atom::Character(c, expansion)));
    }
    let separator = |a: &Atom| matches!(a, Atom::Character(c, true) if ifs.contains(*c));
    // CR/VT/FF in IFS have different whitespace behavior in our native Bash
    // 3.2 and 5.2 controls. Without a trusted dialect fact they stay unsupported.
    let white = |a: &Atom| matches!(a, Atom::Character(' ' | '\t' | '\n', true)) && separator(a);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut present = false;
    let mut at = 0;
    while at < atoms.len() {
        if separator(&atoms[at]) {
            let mut nonwhite = !white(&atoms[at]);
            if !nonwhite {
                while at < atoms.len() && white(&atoms[at]) { at += 1; }
                if at < atoms.len() && separator(&atoms[at]) && !white(&atoms[at]) {
                    nonwhite = true;
                    at += 1;
                }
            } else {
                at += 1;
            }
            if nonwhite {
                while at < atoms.len() && white(&atoms[at]) { at += 1; }
            }
            if present || nonwhite {
                out.push(std::mem::take(&mut current));
                if out.len() > 4096 { return None; }
            }
            present = false;
            continue;
        }
        match atoms[at] {
            Atom::QuotedNull => present = true,
            Atom::Character(c, expansion) => {
                // Expansion-produced backslashes are data, not quoting syntax.
                if expansion && matches!(c, '*' | '?' | '[') { return None; }
                current.push(c);
                present = true;
            }
        }
        at += 1;
    }
    if present { out.push(current); }
    (out.len() <= 4096).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ShellFieldFragment::{Literal as L, QuotedExpansion as Q, UnquotedExpansion as U};
    fn with_ifs(ifs: &str) -> SessionBindings {
        let mut b = SessionBindings::new(); b.insert_exact_scalar("IFS", ifs); b
    }
    fn strings(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }
    #[test]
    fn field_splitting_requires_current_ifs_and_respects_unknown_invalidation() {
        assert!(materialize_bash_field_fragments(&[U("a b".into())], &SessionBindings::new()).is_none());
        let mut b = with_ifs(" "); b.mark_variable_presence_unknown("IFS");
        assert!(materialize_bash_field_fragments(&[U("a b".into())], &b).is_none());
        assert_eq!(materialize_bash_field_fragments(&[Q("a b".into())], &b), Some(strings(&["a b"])));
    }
    #[test]
    fn field_splitting_default_is_only_the_three_bash_ifs_whitespace_bytes() {
        let mut b = SessionBindings::new(); b.reset_child_environment(true);
        assert_eq!(materialize_bash_field_fragments(&[U(" \ta\rb\u{b}c\u{a0}d\n".into())], &b),
            Some(strings(&["a\rb\u{b}c\u{a0}d"])));
    }
    #[test]
    fn field_splitting_empty_ifs_and_unquoted_nulls_are_distinct() {
        let b = with_ifs("");
        assert_eq!(materialize_bash_field_fragments(&[U("a b".into())], &b), Some(strings(&["a b"])));
        assert_eq!(materialize_bash_field_fragments(&[U("".into())], &b), Some(vec![]));
        assert_eq!(materialize_bash_field_fragments(&[Q("".into())], &b), Some(strings(&[""])));
    }
    #[test]
    fn field_splitting_keeps_nonwhite_null_fields_and_discards_the_last_delimiter() {
        let b = with_ifs(",");
        assert_eq!(materialize_bash_field_fragments(&[U(",a,,b,".into())], &b), Some(strings(&["","a","","b"])));
        assert!(materialize_bash_field_fragments(&[U(",a,,b,".into()),Q("".into())], &b).is_none());
    }
    #[test]
    fn field_splitting_white_adjacent_to_a_nonwhite_delimiter_is_one_separator() {
        assert_eq!(materialize_bash_field_fragments(&[U(" , a , , b, ".into())], &with_ifs(" ,")),
            Some(strings(&["","a","","b"])));
    }
    #[test]
    fn field_splitting_dialect_sensitive_control_delimiters_remain_unknown() {
        for c in ['\r', '\u{b}', '\u{c}'] {
            let s = format!("a{c}{c}b{c}");
            assert!(materialize_bash_field_fragments(&[U(s.clone())], &with_ifs(&c.to_string())).is_none());
            assert_eq!(materialize_bash_field_fragments(&[U(s.clone())], &with_ifs(" ")),
                Some(vec![s]));
        }
    }
    #[test]
    fn field_splitting_does_not_split_literal_characters_or_reparse_output() {
        assert_eq!(materialize_bash_field_fragments(&[L("printf".into()),U("f".into()),L("X".into())], &with_ifs("f")),
            Some(strings(&["printf","X"])));
        assert_eq!(materialize_bash_field_fragments(&[Q("$(touch x);$HOME\\*".into())], &SessionBindings::new()),
            Some(strings(&["$(touch x);$HOME\\*"])));
    }
    #[test]
    fn field_splitting_literal_affixes_join_the_first_and_last_fields() {
        assert_eq!(materialize_bash_field_fragments(&[L("pre".into()),U(" a b ".into()),L("post".into())], &with_ifs(" ")),
            Some(strings(&["pre","a","b","post"])));
    }
    #[test]
    fn field_splitting_does_not_invent_globs_or_multibyte_locale_rules() {
        assert!(materialize_bash_field_fragments(&[U("*".into())], &with_ifs(" ")).is_none());
        assert_eq!(materialize_bash_field_fragments(&[Q("*".into())], &with_ifs(" ")),Some(strings(&["*"])));
        assert!(materialize_bash_field_fragments(&[U("aéb".into())], &with_ifs("é")).is_none());
    }
    #[test]
    fn field_splitting_budgets_fail_without_a_partial_prefix() {
        assert!(materialize_bash_field_fragments(&[U("x ".repeat(4097))], &with_ifs(" ")).is_none());
        assert!(materialize_bash_field_fragments(&[Q("x".repeat(262145))], &SessionBindings::new()).is_none());
        assert!(materialize_bash_field_fragments(&[Q("\0".into())], &SessionBindings::new()).is_none());
    }
}
