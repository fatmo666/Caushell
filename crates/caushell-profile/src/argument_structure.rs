//! Pure shell-field facts for argv ownership, not evaluation of shell words.
//! Prefixes describe EVERY possible field, never just the first split field.
use crate::{
    ProjectedArg, ShellAllPositionalsKind, ShellParameterReference,
    parse_shell_parameter_reference_after_dollar,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentFieldCount {
    ExactlyOne,
    /// Bounded variable-width generation/splitting; zero covers nullglob/IFS.
    ZeroOrMore,
    /// Field splitting, arrays, or syntax outside this query's proof domain.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentStructure {
    pub fields: ArgumentFieldCount,
    /// A literal prefix shared by every produced field; empty means no bound.
    pub static_prefix: String,
    /// Literal tail shared by each field (not by arbitrary split fields).
    pub static_suffix: String,
    pub exact: bool,
    spelling: Option<Vec<SpellingPart>>,
    pathname_generation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SpellingPart {
    EmptyOrAbsolutePath,
    Literal(char),
    Any,
    One,
    Class(String),
    CharacterRun(String),
}

impl ArgumentStructure {
    pub fn exact_value(&self) -> Option<&str> {
        self.exact.then_some(self.static_prefix.as_str())
    }

    pub fn may_equal(&self, value: &str) -> bool {
        if self.exact {
            self.static_prefix == value
        } else {
            // Cheap literal rejection before the bounded pattern proof. Only
            // compare ASCII here; unknown Unicode collation must stay widened.
            if self.static_prefix.is_ascii() && self.static_suffix.is_ascii() && value.is_ascii() {
                let equal = |a: &str, b: &str| {
                    if self.pathname_generation {
                        a.eq_ignore_ascii_case(b)
                    } else {
                        a == b
                    }
                };
                if value
                    .get(..self.static_prefix.len())
                    .is_none_or(|head| !equal(head, &self.static_prefix))
                    || value
                        .len()
                        .checked_sub(self.static_suffix.len())
                        .and_then(|i| value.get(i..))
                        .is_none_or(|tail| !equal(tail, &self.static_suffix))
                {
                    return false;
                }
            }
            self.spelling.as_ref().map_or_else(
                || value.starts_with(&self.static_prefix) && value.ends_with(&self.static_suffix),
                |parts| spelling_matches(parts, value, false, self.pathname_generation),
            )
        }
    }

    pub fn may_start_with(&self, prefix: &str) -> bool {
        if self.exact {
            self.static_prefix.starts_with(prefix)
        } else {
            if self.static_prefix.is_ascii() && prefix.is_ascii() {
                let count = self.static_prefix.len().min(prefix.len());
                let a = &self.static_prefix[..count];
                let b = &prefix[..count];
                if if self.pathname_generation {
                    !a.eq_ignore_ascii_case(b)
                } else {
                    a != b
                } {
                    return false;
                }
            }
            self.spelling.as_ref().map_or_else(
                || {
                    self.static_prefix.starts_with(prefix)
                        || prefix.starts_with(&self.static_prefix)
                },
                |parts| spelling_matches(parts, prefix, true, self.pathname_generation),
            )
        }
    }

    fn unknown() -> Self {
        Self {
            fields: ArgumentFieldCount::Unknown,
            static_prefix: String::new(),
            static_suffix: String::new(),
            exact: false,
            spelling: None,
            pathname_generation: false,
        }
    }

    /// Intersection with `-[letters]+`, used only by explicitly declared
    /// unmodeled short-option grammars. Three bounded automaton states; no
    /// enumeration of filenames, option combinations, or shell values.
    pub(crate) fn may_be_short_cluster(&self, letters: &str) -> bool {
        if self.spelling.as_deref() == Some(&[SpellingPart::EmptyOrAbsolutePath]) {
            return false;
        }
        if self.fields == ArgumentFieldCount::Unknown || letters.is_empty() {
            return true;
        }
        if self.exact {
            return self
                .static_prefix
                .strip_prefix('-')
                .is_some_and(|tail| !tail.is_empty() && tail.chars().all(|c| letters.contains(c)));
        }
        let fallback;
        let parts = if let Some(parts) = &self.spelling {
            parts
        } else {
            fallback = self
                .static_prefix
                .chars()
                .map(SpellingPart::Literal)
                .chain([SpellingPart::Any])
                .chain(self.static_suffix.chars().map(SpellingPart::Literal))
                .collect();
            &fallback
        };
        if parts.len() > 256 {
            return true;
        }
        let mut states = [true, false, false]; // empty, '-', at least one flag
        for part in parts {
            let matches = |c: char| match part {
                SpellingPart::Literal(v) => {
                    *v == c
                        || self.pathname_generation && (v.eq_ignore_ascii_case(&c) || !v.is_ascii())
                }
                SpellingPart::Any | SpellingPart::One => true,
                SpellingPart::Class(body) => class_may_match(body, c),
                SpellingPart::CharacterRun(chars) => chars.contains(c),
                SpellingPart::EmptyOrAbsolutePath => true,
            };
            let dash = matches('-');
            let flag = letters.chars().any(matches);
            let mut next = [false; 3];
            if matches!(part, SpellingPart::Any | SpellingPart::CharacterRun(_)) {
                // Epsilon plus closure of a single character transition.
                next = states;
                next[1] |= next[0] && dash;
                next[2] |= (next[1] || next[2]) && flag;
            } else {
                next[1] = states[0] && dash;
                next[2] = (states[1] || states[2]) && flag;
            }
            states = next;
        }
        states[2]
    }
}

// Match only short declared control words, never filenames. A bounded DP,
// not regex compilation or pathname enumeration. Unsupported/large proofs
// return "possible". ASCII case folding covers Bash's nocaseglob option.
fn spelling_matches(parts: &[SpellingPart], value: &str, prefix: bool, fold_case: bool) -> bool {
    if parts == [SpellingPart::EmptyOrAbsolutePath] {
        return value.is_empty() || value.starts_with('/');
    }
    if parts.len() > 256 || value.len() > 256 {
        return true;
    }
    let chars: Vec<_> = value.chars().collect();
    let mut reachable = vec![false; chars.len() + 1];
    reachable[0] = true;
    let equals = |a: char, b: char| {
        a == b || (fold_case && (a.eq_ignore_ascii_case(&b) || !a.is_ascii() || !b.is_ascii()))
    };
    for part in parts {
        if prefix && reachable[chars.len()] {
            return true;
        }
        let mut next = vec![false; chars.len() + 1];
        match part {
            SpellingPart::Any => {
                let mut seen = false;
                for index in 0..=chars.len() {
                    seen |= reachable[index];
                    next[index] = seen;
                }
            }
            SpellingPart::CharacterRun(allowed) => {
                next[0] = reachable[0];
                for index in 0..chars.len() {
                    next[index + 1] =
                        reachable[index + 1] || (next[index] && allowed.contains(chars[index]));
                }
            }
            _ => {
                for index in 0..chars.len() {
                    next[index + 1] |= reachable[index]
                        && match part {
                            SpellingPart::Literal(ch) => equals(*ch, chars[index]),
                            SpellingPart::One => true,
                            SpellingPart::Class(body) => class_may_match(body, chars[index]),
                            SpellingPart::Any | SpellingPart::CharacterRun(_) => unreachable!(),
                            SpellingPart::EmptyOrAbsolutePath => true,
                        };
                    if reachable[index]
                        && let SpellingPart::Class(body) = part
                    {
                        // noglob or an unmatched glob preserves the literal
                        // bracket spelling, which is longer than one field char.
                        let retained: Vec<_> = format!("[{body}]").chars().collect();
                        let available = chars.len() - index;
                        let compared = available.min(retained.len());
                        if retained[..compared]
                            .iter()
                            .zip(&chars[index..index + compared])
                            .all(|(a, b)| equals(*a, *b))
                        {
                            if prefix && available < retained.len() {
                                return true;
                            }
                            if available >= retained.len() {
                                next[index + retained.len()] = true;
                            }
                        }
                    }
                }
            }
        }
        reachable = next;
    }
    reachable[chars.len()]
}

fn class_may_match(body: &str, value: char) -> bool {
    // Locale-dependent classes/collation and non-ASCII ranges have no local
    // proof. Widen them; never infer safety from a guessed locale.
    if !body.is_ascii() || !value.is_ascii() || body.contains(['[', ':', '=', '\\']) {
        return true;
    }
    let (negated, body) = body
        .strip_prefix(['!', '^'])
        .map_or((false, body), |b| (true, b));
    let bytes = body.as_bytes();
    let mut index = 0;
    let mut matched = false;
    while index < bytes.len() {
        if index + 2 < bytes.len() && bytes[index + 1] == b'-' {
            // Range order and membership can depend on LC_COLLATE.
            return true;
        }
        matched |= bytes[index].eq_ignore_ascii_case(&(value as u8));
        index += 1;
    }
    // nocaseglob only enlarges positive classes. For negated classes, retain
    // both case-sensitive and case-insensitive interpretations.
    if negated {
        !body.contains(value)
    } else {
        matched
    }
}

fn exact_word(value: String) -> ArgumentStructure {
    ArgumentStructure {
        fields: ArgumentFieldCount::ExactlyOne,
        static_suffix: String::new(), // exact_value already owns the full word
        static_prefix: value,
        exact: true,
        spelling: None,
        pathname_generation: false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

// Absence is a proof, not an assumption about a variable's value. In a whole
// Bash/sh double-quoted word, multiple fields require $@, a vector subscript,
// or an indirect/vector parameter form. Inspect syntax conservatively even
// inside nested substitutions; false positives keep the Unknown fallback.
fn may_expand_quoted_vector(text: &str) -> bool {
    let mut previous = 0;
    let mut parameter = false;
    for byte in text.bytes() {
        if previous == b'$' && byte == b'@' {
            return true;
        }
        if previous == b'$' && byte == b'{' {
            parameter = true;
        }
        if parameter && matches!(byte, b'@' | b'!' | b'[') {
            return true;
        }
        if byte == b'}' {
            parameter = false;
        }
        previous = byte;
    }
    parameter
}

fn incomplete_word(prefix: String, whole_quoted_scalar: bool) -> ArgumentStructure {
    if whole_quoted_scalar {
        ArgumentStructure {
            fields: ArgumentFieldCount::ExactlyOne,
            static_prefix: prefix,
            static_suffix: String::new(),
            exact: false,
            spelling: None,
            pathname_generation: false,
        }
    } else {
        ArgumentStructure::unknown()
    }
}

fn literal(
    ch: char,
    exact: bool,
    prefix: &mut String,
    suffix: &mut String,
    parts: &mut Vec<SpellingPart>,
) {
    if exact {
        prefix.push(ch);
    }
    suffix.push(ch);
    parts.push(SpellingPart::Literal(ch));
}

fn pid_field_bounds(arg: &ProjectedArg) -> Option<ArgumentStructure> {
    if arg.quoted {
        return None;
    }
    let (prefix, suffix) = arg.text.split_once("$$")?;
    // Only literal affixes and the shell's numeric PID. No value evaluation,
    // assumed IFS, inherited prefix, glob, brace, or concatenated substitution.
    if prefix.chars().chain(suffix.chars()).any(|c| {
        matches!(
            c,
            '$' | '`' | '*' | '?' | '[' | '{' | '}' | '~' | '\'' | '"' | '\\'
        )
    }) {
        return None;
    }
    // Every split field uses this alphabet, but only the first may retain the
    // prefix. This deliberately does NOT claim that /tmp/stamp$$ is one path.
    let allowed = format!("0123456789{prefix}{suffix}");
    Some(ArgumentStructure {
        fields: ArgumentFieldCount::ZeroOrMore,
        static_prefix: String::new(),
        static_suffix: String::new(),
        exact: false,
        spelling: Some(vec![SpellingPart::CharacterRun(allowed)]),
        pathname_generation: false,
    })
}

fn opaque_glob(arg: &ProjectedArg, prefix: String) -> ArgumentStructure {
    // Unsupported bracket/collation syntax does not erase a proven prefix
    // of a pure pathname word. But expansions/quotes outside that bracket
    // could split fields, so those retain the fully unknown fallback.
    if arg.text.contains(['$', '`', '"', '\'', '\\', '~']) {
        return ArgumentStructure::unknown();
    }
    let mut spelling: Vec<_> = prefix.chars().map(SpellingPart::Literal).collect();
    spelling.push(SpellingPart::Any);
    ArgumentStructure {
        fields: ArgumentFieldCount::ZeroOrMore,
        static_prefix: prefix,
        static_suffix: String::new(),
        exact: false,
        spelling: Some(spelling),
        pathname_generation: true,
    }
}

fn arithmetic_field_bounds(arg: &ProjectedArg) -> Option<ArgumentStructure> {
    if arg.quoted {
        return None;
    }
    let start = arg.text.find("$((")?;
    // Prove the boundary of ONE supported arithmetic construct. A last-`))`
    // search would wrongly swallow a second substitution or ordinary text.
    let mut depth = 1usize;
    let mut end = None;
    let body = &arg.text[start + 3..];
    if body.contains(['\'', '"', '`', '[', ']', '\\']) || body.contains("$(") {
        return None;
    }
    for (offset, ch) in body.char_indices() {
        match ch {
            '(' => depth = depth.checked_add(1)?,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let closing = start + 3 + offset;
                    if arg.text.as_bytes().get(closing + 1) != Some(&b')') {
                        return None;
                    }
                    end = Some(closing + 2);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    let prefix = &arg.text[..start];
    let suffix = &arg.text[end..];
    // Only literal affixes surrounding one arithmetic expansion. Integer
    // output may be split by any IFS, but cannot manufacture letter controls.
    // This is an output alphabet proof, not arithmetic evaluation; embedded
    // command substitutions and variable effects remain independently audited.
    if end <= start + 4
        || prefix.chars().chain(suffix.chars()).any(|c| {
            matches!(
                c,
                '$' | '`' | '*' | '?' | '[' | '{' | '}' | '~' | '\'' | '"' | '\\'
            )
        })
    {
        return None;
    }
    Some(ArgumentStructure {
        fields: ArgumentFieldCount::ZeroOrMore,
        static_prefix: String::new(),
        static_suffix: String::new(),
        exact: false,
        spelling: Some(vec![SpellingPart::CharacterRun(format!(
            "0123456789+-{prefix}{suffix}"
        ))]),
        pathname_generation: false,
    })
}

/// Query existing lexical metadata without parsing another AST, running a
/// command, or looking up files. Unsupported constructs return Unknown.
pub fn argument_structure(arg: &ProjectedArg) -> ArgumentStructure {
    if arg.implicit_input_source.is_some() && arg.node_kind == "runtime_scalar" {
        // A tool-substituted single argv item is not re-split by a shell.
        // Its bytes may still be ANY control word or an unknown path.
        let mut structure = incomplete_word(String::new(), true);
        match &arg.runtime_argument_domain {
            Some(caushell_types::RuntimeArgumentDomain::PathTemplate {
                prefix, suffix, ..
            }) => {
                // Decoded tool-argv affixes, not shell source. The tool substitutes
                // one data field without removing/expanding these bytes again.
                structure.static_prefix = prefix.clone();
                structure.static_suffix = suffix.clone();
            }
            Some(caushell_types::RuntimeArgumentDomain::PathSet {
                roots,
                may_escape: false,
            }) if !roots.is_empty()
                && roots
                    .iter()
                    .all(|root| !root.is_empty() && !root.contains('\0')) =>
            {
                // The domain carries producer argv-spelling anchors, not just
                // normalized containment. Use only a prefix shared by EVERY
                // root and descendant; no representative path or filename.
                let mut prefix = roots[0].trim_end_matches('/').to_string();
                if prefix.is_empty() {
                    prefix.push('/');
                }
                for root in &roots[1..] {
                    let length = prefix
                        .chars()
                        .zip(root.chars())
                        .take_while(|(a, b)| a == b)
                        .map(|(a, _)| a.len_utf8())
                        .sum();
                    prefix.truncate(length);
                    if prefix.is_empty() {
                        break;
                    }
                }
                structure.static_prefix = prefix;
            }
            _ => {}
        }
        return structure;
    }
    if arg.implicit_input_source.is_some() {
        // A runtime tail marker represents unknown argv width, not a single
        // empty field. Only an explicit scalar contract above proves arity.
        return ArgumentStructure::unknown();
    }
    if arg.substitution_shape == Some(crate::StdoutScalarShape::AbsolutePath) {
        return ArgumentStructure {
            fields: ArgumentFieldCount::ExactlyOne,
            static_prefix: String::new(),
            static_suffix: String::new(),
            exact: false,
            spelling: Some(vec![SpellingPart::EmptyOrAbsolutePath]),
            pathname_generation: false,
        };
    }
    if arg.runtime_data || matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string") {
        return exact_word(arg.text.clone());
    }
    if arg.node_kind == "process_substitution" {
        // The shell supplies one generated FIFO/fd pathname. Its contents and
        // producer effects are still modeled by the existing substitution path.
        return ArgumentStructure {
            fields: ArgumentFieldCount::ExactlyOne,
            // FIFO locations are platform/environment dependent. Do not
            // assume /dev/fd or a particular TMPDIR for path classification.
            static_prefix: String::new(),
            static_suffix: String::new(),
            exact: false,
            // A generated fd/FIFO pathname has a directory separator, even
            // when a platform uses a relative TMPDIR. Do not infer its root.
            spelling: Some(vec![
                SpellingPart::Any,
                SpellingPart::Literal('/'),
                SpellingPart::Any,
            ]),
            pathname_generation: false,
        };
    }
    if let Some(bounds) = pid_field_bounds(arg) {
        return bounds;
    }
    if let Some(bounds) = arithmetic_field_bounds(arg) {
        return bounds;
    }
    if !matches!(
        arg.node_kind.as_str(),
        "word" | "number" | "string" | "concatenation" | "simple_expansion" | "expansion"
    ) {
        return ArgumentStructure::unknown();
    }
    let initial = if arg.quoted && arg.node_kind == "string" {
        Quote::Double
    } else {
        Quote::None
    };
    let whole_quoted_scalar = initial == Quote::Double && !may_expand_quoted_vector(&arg.text);
    // Keep the legacy literal fast path, except concatenation needs its actual
    // quote transitions and unquoted braces may generate multiple fields.
    if arg.node_kind != "concatenation"
        && (initial != Quote::None || !arg.text.contains('{'))
        && let Some(value) =
            caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
    {
        return exact_word(value);
    }
    let mut quote = initial;
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut spelling = Vec::new();
    let mut exact = true;
    let mut pathname_generation = false;
    let mut fields = ArgumentFieldCount::ExactlyOne;
    let mut chars = arg.text.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else {
                    literal(ch, exact, &mut prefix, &mut suffix, &mut spelling);
                }
            }
            Quote::Double => match ch {
                '"' if initial == Quote::None => quote = Quote::None,
                '"' => return ArgumentStructure::unknown(),
                '\\' => match chars.next() {
                    Some(escaped @ ('$' | '`' | '"' | '\\')) => {
                        literal(escaped, exact, &mut prefix, &mut suffix, &mut spelling)
                    }
                    Some('\n') => {}
                    Some(other) => {
                        literal('\\', exact, &mut prefix, &mut suffix, &mut spelling);
                        literal(other, exact, &mut prefix, &mut suffix, &mut spelling);
                    }
                    None => return ArgumentStructure::unknown(),
                },
                '$' => {
                    // A trailing '$' (e.g. a regex anchor) is literal shell
                    // data, as is '$' before a non-expansion character.
                    if chars.peek().is_none_or(|c| {
                        !c.is_ascii_alphanumeric()
                            && !matches!(
                                c,
                                '_' | '$' | '?' | '!' | '#' | '-' | '@' | '*' | '{' | '('
                            )
                    }) {
                        literal('$', exact, &mut prefix, &mut suffix, &mut spelling);
                        continue;
                    }
                    if chars
                        .peek()
                        .is_some_and(|c| matches!(c, '$' | '?' | '!' | '#' | '-'))
                    {
                        chars.next();
                    } else {
                        match parse_shell_parameter_reference_after_dollar(&mut chars) {
                            Some(
                                ShellParameterReference::Variable(_)
                                | ShellParameterReference::Positional(_)
                                | ShellParameterReference::AllPositionals(
                                    ShellAllPositionalsKind::Star,
                                ),
                            ) => {}
                            // Fall back to the whole-quoted scalar proof for
                            // opaque syntax; vectors/indirection stay Unknown.
                            _ => return incomplete_word(prefix, whole_quoted_scalar),
                        }
                    }
                    exact = false;
                    suffix.clear();
                    spelling.push(SpellingPart::Any);
                }
                '`' => return incomplete_word(prefix, whole_quoted_scalar),
                other => literal(other, exact, &mut prefix, &mut suffix, &mut spelling),
            },
            Quote::None => match ch {
                '@' | '!' | '+' | '*' | '?' if chars.peek() == Some(&'(') => {
                    // Only unquoted extglob syntax is an expansion; a quoted
                    // regex in a concatenated word is ordinary argv data.
                    return ArgumentStructure::unknown();
                }
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => match chars.next() {
                    Some('\n') => {}
                    Some(other) => literal(other, exact, &mut prefix, &mut suffix, &mut spelling),
                    None => return ArgumentStructure::unknown(),
                },
                // No prefix survives an unquoted expansion: later split fields
                // do not inherit it. ./ $value must not become a safety proof.
                '$' | '`' | '~' => return ArgumentStructure::unknown(),
                '{' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal('{', exact, &mut prefix, &mut suffix, &mut spelling);
                    literal('}', exact, &mut prefix, &mut suffix, &mut spelling);
                }
                '{' => {
                    // Simple lists/ranges preserve the prefix of EVERY
                    // alternative, but do not prove single-field width. Never
                    // enumerate alternatives or infer their complete values.
                    // Nested/quoted/expanding bodies remain outside this proof.
                    let mut body = String::new();
                    let mut closed = false;
                    for c in chars.by_ref() {
                        if c == '}' {
                            closed = true;
                            break;
                        }
                        if !c.is_ascii_alphanumeric()
                            && !matches!(c, '.' | '_' | '-' | ',' | '*' | '?' | '[' | ']' | '/')
                        {
                            return ArgumentStructure::unknown();
                        }
                        body.push(c);
                    }
                    if !closed {
                        return ArgumentStructure::unknown();
                    }
                    if body.contains(',') || body.contains("..") {
                        fields = ArgumentFieldCount::ZeroOrMore;
                        exact = false;
                        suffix.clear();
                        spelling.push(SpellingPart::Any);
                        pathname_generation |= body.contains(['*', '?', '[']);
                    } else {
                        // A non-expanding brace spelling can still contain a
                        // glob. Leave those unusual combinations unresolved.
                        if body.contains(['*', '?', '[']) {
                            return ArgumentStructure::unknown();
                        }
                        for c in format!("{{{body}}}").chars() {
                            literal(c, exact, &mut prefix, &mut suffix, &mut spelling);
                        }
                    }
                }
                '*' | '?' => {
                    fields = ArgumentFieldCount::ZeroOrMore;
                    exact = false;
                    pathname_generation = true;
                    suffix.clear();
                    spelling.push(if ch == '*' {
                        SpellingPart::Any
                    } else {
                        SpellingPart::One
                    });
                }
                '[' => {
                    // [] and unmatched [ are literals. Bash requires a
                    // nonempty, closed bracket expression (a first ] is data).
                    let mut lookahead = chars.clone();
                    let mut body = String::new();
                    let mut closed = false;
                    while let Some(c) = lookahead.next() {
                        if c == ']' && !body.is_empty() && body != "!" && body != "^" {
                            closed = true;
                            break;
                        }
                        if matches!(c, '$' | '`' | '\\' | '\'' | '"' | '[') {
                            // POSIX classes and quoting need a wider proof.
                            return opaque_glob(arg, prefix);
                        }
                        body.push(c);
                    }
                    if closed {
                        chars = lookahead;
                        fields = ArgumentFieldCount::ZeroOrMore;
                        exact = false;
                        pathname_generation = true;
                        suffix.clear();
                        // An unmatched pattern is retained literally when
                        // nullglob is off. The glob atom also has to include
                        // that spelling when checking equality (below).
                        spelling.push(SpellingPart::Class(body));
                    } else {
                        literal('[', exact, &mut prefix, &mut suffix, &mut spelling);
                    }
                }
                other => literal(other, exact, &mut prefix, &mut suffix, &mut spelling),
            },
        }
    }
    if quote != initial {
        return ArgumentStructure::unknown();
    }
    if exact {
        return exact_word(prefix);
    }
    ArgumentStructure {
        fields,
        static_prefix: prefix,
        static_suffix: suffix,
        exact,
        spelling: Some(spelling),
        pathname_generation,
    }
}

/// Lexical-only form of the argv query, for shell path/redirection facts.
/// No runtime value, output proof, or source identity is manufactured here.
pub fn shell_word_structure(text: &str, quoted: bool, node_kind: &str) -> ArgumentStructure {
    argument_structure(&ProjectedArg {
        text: text.into(),
        implicit_input_source: None,
        runtime_argument_domain: None,
        runtime_data: false,
        substitution_shape: None,
        kind: crate::ProjectedArgKind::Positional,
        quoted,
        node_kind: node_kind.into(),
        span: caushell_parse::SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            start_column: 0,
            end_row: 0,
            end_column: 0,
        },
    })
}
