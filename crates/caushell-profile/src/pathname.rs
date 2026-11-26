use crate::{ProjectedArg, WordContext};
use caushell_types::ShellKind;

/// The complete argument shape for which a trusted Profile can use the
/// independent Bash entry defaults. Normal argv and effect checks still run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StaticBashPathnameDefaults {
    FlagsAndStarPath { flags: Vec<String> },
    FlagsAndLiteralSuffixGlob { flags: Vec<String> },
    SubstitutionAndSuffixGlob,
}

impl StaticBashPathnameDefaults {
    pub fn matches(
        &self,
        leading: &caushell_parse::CommandToken,
        glob: &caushell_parse::CommandToken,
    ) -> bool {
        if leading.runtime_data || glob.runtime_data || glob.quoted {
            return false;
        }
        match self {
            Self::FlagsAndStarPath { flags } => {
                !leading.quoted
                    && flags.contains(&leading.text)
                    && glob.text.contains('/')
                    && glob.text.split('/').all(|component| component == "*")
            }
            Self::FlagsAndLiteralSuffixGlob { flags } => {
                !leading.quoted
                    && flags.contains(&leading.text)
                    && glob.text.strip_prefix('*').is_some_and(|suffix| {
                        !suffix.is_empty()
                            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
                    })
            }
            Self::SubstitutionAndSuffixGlob => {
                leading.node_kind == "raw_string"
                    && glob.text.strip_prefix("*.").is_some_and(|suffix| {
                        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
                    && crate::rename_payload::is_static_substitution(&leading.text)
            }
        }
    }
}

pub(crate) fn snapshot(
    state: &caushell_types::ShellStateSnapshot,
) -> Option<caushell_types::ShellPathnameSnapshot> {
    use caushell_types::{ShellEnvironmentValue as V, ShellStateKnowledge, ShellValueSnapshot};
    let value = state
        .execution_frame
        .as_ref()
        .and_then(|frame| frame.pathname.as_ref())
        .or(state.pathname.as_ref())?;
    for (name, observation) in [
        ("GLOBIGNORE", &value.globignore),
        ("LC_ALL", &value.lc_all),
        ("LC_COLLATE", &value.lc_collate),
        ("LC_CTYPE", &value.lc_ctype),
        ("LANG", &value.lang),
    ] {
        if matches!(observation, V::Present { value } if value.contains('\0')) {
            return None;
        }
        let variables = state
            .variables
            .iter()
            .filter(|v| v.name == name)
            .collect::<Vec<_>>();
        if matches!(observation, V::Unknown) {
            continue;
        }
        if variables.iter().any(|v| match (&v.value, observation) {
            (
                ShellValueSnapshot::ExactScalar { value: a }
                | ShellValueSnapshot::RuntimeProduced { value: a, .. },
                V::Present { value: b },
            ) => a != b,
            _ => true,
        }) || variables.is_empty()
            && state.observability.variables == ShellStateKnowledge::Complete
            && matches!(observation, V::Present { .. })
        {
            return None;
        }
    }
    Some(value.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Unit {
    Literal(char),
    Any,
    One,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathnameComponent(Vec<Unit>);

impl PathnameComponent {
    pub fn literal(&self) -> Option<String> {
        self.0
            .iter()
            .map(|u| match u {
                Unit::Literal(c) => Some(*c),
                _ => None,
            })
            .collect()
    }

    pub fn matches(&self, name: &str, dotglob: bool, nocase: bool) -> bool {
        self.matches_in_locale(name, dotglob, nocase, true)
    }

    pub fn matches_in_locale(
        &self,
        name: &str,
        dotglob: bool,
        nocase: bool,
        unicode: bool,
    ) -> bool {
        if name.starts_with('.') && !dotglob && self.0.first() != Some(&Unit::Literal('.')) {
            return false;
        }
        let chars: Vec<_> = if unicode {
            name.chars().collect()
        } else {
            name.bytes().map(char::from).collect()
        };
        let units: Vec<_> = self
            .0
            .iter()
            .flat_map(|u| match u {
                Unit::Literal(c) if !unicode => c
                    .to_string()
                    .bytes()
                    .map(|b| Unit::Literal(char::from(b)))
                    .collect(),
                _ => vec![u.clone()],
            })
            .collect();
        let mut states = vec![false; chars.len() + 1];
        states[0] = true;
        for unit in &units {
            let mut next = vec![false; states.len()];
            match unit {
                Unit::Any => {
                    let mut seen = false;
                    for i in 0..states.len() {
                        seen |= states[i];
                        next[i] = seen;
                    }
                }
                Unit::One | Unit::Literal(_) | Unit::Class { .. } => {
                    for i in 0..chars.len() {
                        next[i + 1] = states[i]
                            && match unit {
                                Unit::One => true,
                                Unit::Literal(c) => {
                                    *c == chars[i] || nocase && c.eq_ignore_ascii_case(&chars[i])
                                }
                                Unit::Class { negated, ranges } => {
                                    let c = chars[i];
                                    let contains = |c| {
                                        ranges.iter().any(|(low, high)| *low <= c && c <= *high)
                                    };
                                    (contains(c)
                                        || nocase
                                            && (contains(c.to_ascii_lowercase())
                                                || contains(c.to_ascii_uppercase())))
                                        != *negated
                                }
                                _ => unreachable!(),
                            };
                    }
                }
            }
            states = next;
        }
        states[chars.len()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathnamePattern {
    pub literal: String,
    pub components: Vec<PathnameComponent>,
    pub absolute: bool,
    pub recursive_star: bool,
}

impl PathnamePattern {
    /// A subset for which case folding and dotfile eligibility can be widened
    /// without interpreting locale-sensitive pattern syntax or recursive stars.
    pub fn supports_option_independent_match_bound(&self) -> bool {
        !self.recursive_star
            && self.components.iter().all(|component| {
                component.0.iter().all(|unit| match unit {
                    Unit::Literal(c) => c.is_ascii(),
                    Unit::Any => true,
                    _ => false,
                })
            })
    }

    /// Quote removal and wildcard activity only; variables and substitutions
    /// remain with the ordinary materializer until their field shape is proved.
    pub fn from_argument(arg: &ProjectedArg, shell: ShellKind) -> Result<Option<Self>, String> {
        if arg.runtime_data
            || arg.implicit_input_source.is_some()
            || arg.word_context != WordContext::ShellArgument
            || arg.quoted
                && matches!(
                    arg.node_kind.as_str(),
                    "raw_string" | "ansi_c_string" | "string"
                )
        {
            return Ok(None);
        }
        if shell == ShellKind::Bash {
            // Whole arithmetic and exit-status expansions own their lexical
            // metacharacters and cannot produce glob syntax. Keep the normal
            // checks for evaluation, word splitting, and adjacent glob text.
            let integer_expansion = match arg.node_kind.as_str() {
                "arithmetic_expansion" => {
                    arg.text.starts_with("$[") && arg.text.ends_with(']')
                        || arg.text.starts_with("$((") && arg.text.ends_with("))")
                }
                "simple_expansion" => arg.text == "$?",
                "expansion" => arg.text == "${?}",
                _ => false,
            };
            if integer_expansion {
                return Ok(None);
            }
        }
        let mut quote = None;
        let mut units = Vec::new();
        let mut chars = arg.text.chars().peekable();
        let mut active = false;
        let mut unsupported = false;
        let mut literal = String::new();
        while let Some(c) = chars.next() {
            if quote == Some('\'') {
                if c == '\'' {
                    quote = None;
                } else {
                    units.push(Unit::Literal(c));
                    literal.push(c);
                }
                continue;
            }
            match c {
                '\'' | '"' if quote.is_none() => quote = Some(c),
                '"' if quote == Some('"') => quote = None,
                '\\' => {
                    let Some(next) = chars.peek().copied() else {
                        unsupported = true;
                        break;
                    };
                    if quote.is_none() || matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                        chars.next();
                        if next != '\n' {
                            units.push(Unit::Literal(next));
                            literal.push(next);
                        }
                    } else {
                        units.push(Unit::Literal(c));
                        literal.push(c);
                    }
                }
                '[' if quote.is_none() => {
                    active = true;
                    literal.push(c);
                    let mut body = Vec::new();
                    let mut closed = false;
                    while let Some(next) = chars.next() {
                        literal.push(next);
                        if next == ']'
                            && !body.is_empty()
                            && !(body.len() == 1 && matches!(body[0], '!' | '^'))
                        {
                            closed = true;
                            break;
                        }
                        body.push(next);
                    }
                    if !closed
                        || body.iter().any(|c| {
                            !c.is_ascii() || matches!(c, '[' | '\\' | '\'' | '"' | '$' | '`')
                        })
                    {
                        unsupported = true;
                        continue;
                    }
                    let negated = body.first().is_some_and(|c| matches!(c, '!' | '^'));
                    let body = &body[usize::from(negated)..];
                    let mut ranges = Vec::new();
                    let mut index = 0;
                    while index < body.len() {
                        if index + 2 < body.len() && body[index + 1] == '-' {
                            unsupported |= body[index] > body[index + 2];
                            ranges.push((body[index], body[index + 2]));
                            index += 3;
                        } else {
                            ranges.push((body[index], body[index]));
                            index += 1;
                        }
                    }
                    units.push(Unit::Class { negated, ranges });
                }
                '*' | '?' if quote.is_none() => {
                    active = true;
                    literal.push(c);
                    units.push(if c == '*' { Unit::Any } else { Unit::One });
                }
                _ => {
                    unsupported |= c == '$'
                        || c == '`'
                        || quote.is_none() && matches!(c, '{' | '}' | '(' | ')' | '~');
                    units.push(Unit::Literal(c));
                    literal.push(c);
                }
            }
        }
        if !active {
            return Ok(None);
        }
        if unsupported
            || quote.is_some()
            || units.len() > 256
            || literal.len() > 4096
            || literal.contains('\0')
        {
            return Err("pathname word syntax is unsupported or exceeds its budget".into());
        }
        let recursive_star = units.windows(2).any(|w| w == [Unit::Any, Unit::Any]);
        let components: Vec<_> = units
            .split(|u| *u == Unit::Literal('/'))
            .map(|u| PathnameComponent(u.to_vec()))
            .collect();
        if components.len() > 32 {
            return Err("pathname depth budget exceeded".into());
        }
        Ok(Some(Self {
            absolute: literal.starts_with('/'),
            literal,
            components,
            recursive_star,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_keeps_literal_and_active_metacharacters_distinct() {
        let parse = |text: &str| {
            let p = caushell_parse::parse_command(
                &format!("cat {text}"),
                caushell_types::ShellKind::Bash,
            )
            .unwrap();
            let projected = crate::project_invocation(&p.commands[0], Default::default());
            PathnamePattern::from_argument(&projected.args[0], projected.shell_kind)
        };
        for word in ["'*'", "\\*", "\"*\""] {
            assert_eq!(parse(word).unwrap(), None);
        }
        let p = parse("a'*'?*").unwrap().unwrap();
        assert!(p.components[0].matches("a*b", false, false));
        assert!(!p.components[0].matches("axb", false, false));
        assert!(parse("$path/*").is_err());
        assert!(parse("[[:alpha:]]*").is_err());
        let p = parse(".[^.]*").unwrap().unwrap();
        assert!(p.components[0].matches(".hidden", false, false));
        assert!(!p.components[0].matches("..meta", false, false));
        let p = parse("*").unwrap().unwrap();
        assert!(!p.components[0].matches(".dot", false, false));
        assert!(p.components[0].matches(".dot", true, false));
    }
}
