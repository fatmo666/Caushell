//! Pure shell-field facts for argv ownership, not evaluation of shell words.
//! Prefixes describe EVERY possible field, never just the first split field.
use crate::{
    ProjectedArg, ShellAllPositionalsKind, ShellParameterReference,
    parse_shell_parameter_reference_after_dollar,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentFieldCount {
    ExactlyOne,
    /// Pathname/brace generation has variable width; zero covers nullglob.
    ZeroOrMore,
    /// Field splitting, arrays, or syntax outside this query's proof domain.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentStructure {
    pub fields: ArgumentFieldCount,
    /// A literal prefix shared by every produced field; empty means no bound.
    pub static_prefix: String,
    pub exact: bool,
}

impl ArgumentStructure {
    pub fn exact_value(&self) -> Option<&str> {
        self.exact.then_some(self.static_prefix.as_str())
    }

    pub fn may_equal(&self, value: &str) -> bool {
        if self.exact {
            self.static_prefix == value
        } else {
            value.starts_with(&self.static_prefix)
        }
    }

    pub fn may_start_with(&self, prefix: &str) -> bool {
        self.static_prefix.starts_with(prefix)
            || (!self.exact && prefix.starts_with(&self.static_prefix))
    }

    fn unknown() -> Self {
        Self {
            fields: ArgumentFieldCount::Unknown,
            static_prefix: String::new(),
            exact: false,
        }
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
            exact: false,
        }
    } else {
        ArgumentStructure::unknown()
    }
}

/// Query existing lexical metadata without parsing another AST, running a
/// command, or looking up files. Unsupported constructs return Unknown.
pub fn argument_structure(arg: &ProjectedArg) -> ArgumentStructure {
    if arg.runtime_data || matches!(arg.node_kind.as_str(), "raw_string" | "ansi_c_string") {
        return ArgumentStructure {
            fields: ArgumentFieldCount::ExactlyOne,
            static_prefix: arg.text.clone(),
            exact: true,
        };
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
        return ArgumentStructure {
            fields: ArgumentFieldCount::ExactlyOne,
            static_prefix: value,
            exact: true,
        };
    }
    let mut quote = initial;
    let mut prefix = String::new();
    let mut exact = true;
    let mut fields = ArgumentFieldCount::ExactlyOne;
    let mut chars = arg.text.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else if exact {
                    prefix.push(ch);
                }
            }
            Quote::Double => match ch {
                '"' if initial == Quote::None => quote = Quote::None,
                '"' => return ArgumentStructure::unknown(),
                '\\' => match chars.next() {
                    Some(escaped @ ('$' | '`' | '"' | '\\')) if exact => prefix.push(escaped),
                    Some('$' | '`' | '"' | '\\' | '\n') => {}
                    Some(other) if exact => {
                        prefix.push('\\');
                        prefix.push(other);
                    }
                    Some(_) => {}
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
                        if exact {
                            prefix.push('$');
                        }
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
                }
                '`' => return incomplete_word(prefix, whole_quoted_scalar),
                other if exact => prefix.push(other),
                _ => {}
            },
            Quote::None => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => match chars.next() {
                    Some('\n') => {}
                    Some(other) if exact => prefix.push(other),
                    Some(_) => {}
                    None => return ArgumentStructure::unknown(),
                },
                // No prefix survives an unquoted expansion: later split fields
                // do not inherit it. ./ $value must not become a safety proof.
                '$' | '`' => return ArgumentStructure::unknown(),
                '~' if prefix.is_empty() && exact => return ArgumentStructure::unknown(),
                '{' if chars.peek() == Some(&'}') => {
                    chars.next();
                    if exact {
                        prefix.push_str("{}");
                    }
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
                        if !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-' | ',') {
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
                    } else if exact {
                        prefix.push('{');
                        prefix.push_str(&body);
                        prefix.push('}');
                    }
                }
                '*' | '?' | '[' => {
                    fields = ArgumentFieldCount::ZeroOrMore;
                    exact = false;
                }
                other if exact => prefix.push(other),
                _ => {}
            },
        }
    }
    if quote != initial {
        return ArgumentStructure::unknown();
    }
    ArgumentStructure {
        fields,
        static_prefix: prefix,
        exact,
    }
}
