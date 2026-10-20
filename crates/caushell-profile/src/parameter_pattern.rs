//! Bounded shell parameter-pattern matching, independent of commands and paths.
//! One dynamic-programming scan finds every matching prefix, including empty.
const MAX_UNITS: usize = 4096;
const MAX_STEPS: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellPatternRemovalKind {
    ShortestPrefix,
    LongestPrefix,
    ShortestSuffix,
    LongestSuffix,
}

impl ShellPatternRemovalKind {
    pub(crate) fn prefix(self) -> bool {
        matches!(self, Self::ShortestPrefix | Self::LongestPrefix)
    }
    fn longest(self) -> bool {
        matches!(self, Self::LongestPrefix | Self::LongestSuffix)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PatternUnit {
    pub ch: char,
    pub literal: bool,
}

#[derive(Clone, Debug)]
enum Token {
    Literal(char),
    Any,
    Star,
    Set { members: Vec<char>, negative: bool },
}

pub(crate) struct ParameterPattern {
    tokens: Vec<Token>,
}

impl ParameterPattern {
    pub fn compile(units: &[PatternUnit]) -> Option<Self> {
        if units.len() > MAX_UNITS {
            return None;
        }
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < units.len() {
            let u = units[i];
            if !u.literal
                && matches!(u.ch, '*' | '?' | '+' | '@' | '!')
                && units.get(i + 1).is_some_and(|u| !u.literal && u.ch == '(')
            {
                // Extended patterns depend on shell options, not guessed here.
                return None;
            }
            match u.ch {
                '\\' if !u.literal => {
                    i += 1;
                    tokens.push(Token::Literal(units.get(i)?.ch));
                }
                '*' if !u.literal => {
                    if !matches!(tokens.last(), Some(Token::Star)) {
                        tokens.push(Token::Star);
                    }
                }
                '?' if !u.literal => tokens.push(Token::Any),
                '[' if !u.literal => {
                    if let Some((token, end)) = bracket(units, i)? {
                        tokens.push(token);
                        i = end;
                    } else {
                        tokens.push(Token::Literal('['));
                    }
                }
                ch => tokens.push(Token::Literal(ch)),
            }
            i += 1;
        }
        Some(Self { tokens })
    }

    pub fn literal(&self) -> Option<String> {
        self.tokens
            .iter()
            .map(|t| match t {
                Token::Literal(ch) => Some(*ch),
                _ => None,
            })
            .collect()
    }

    pub fn remove(&self, value: &str, kind: ShellPatternRemovalKind) -> Option<String> {
        if value.len() > MAX_UNITS
            || !value.is_ascii()
                && self
                    .tokens
                    .iter()
                    .any(|t| matches!(t, Token::Any | Token::Set { .. }))
        {
            // Character width and bracket collation require a locale fact.
            return None;
        }
        let mut chars: Vec<char> = value.chars().collect();
        let mut tokens = self.tokens.clone();
        if (chars.len() + 1).checked_mul(tokens.len() + 1)? > MAX_STEPS {
            return None;
        }
        if !kind.prefix() {
            chars.reverse();
            tokens.reverse();
        }
        let mut state = vec![false; chars.len() + 1];
        state[0] = true;
        for token in &tokens {
            let mut next = vec![false; state.len()];
            for i in 0..state.len() {
                match token {
                    Token::Star => next[i] = state[i] || i > 0 && next[i - 1],
                    _ if i > 0 => {
                        let matches = match token {
                            Token::Literal(ch) => *ch == chars[i - 1],
                            Token::Any => true,
                            Token::Set { members, negative } => {
                                members.binary_search(&chars[i - 1]).is_ok() != *negative
                            }
                            Token::Star => unreachable!(),
                        };
                        next[i] = state[i - 1] && matches;
                    }
                    _ => (),
                }
            }
            state = next;
        }
        let length = if kind.longest() {
            state.iter().rposition(|m| *m)
        } else {
            state.iter().position(|m| *m)
        };
        let Some(length) = length else {
            return Some(value.into());
        };
        let boundaries: Vec<usize> = value
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(value.len()))
            .collect();
        Some(if kind.prefix() {
            value[boundaries[length]..].into()
        } else {
            value[..boundaries[chars.len() - length]].into()
        })
    }

    pub fn cannot_match_slash(&self) -> bool {
        self.tokens.iter().all(|t| match t {
            Token::Literal(ch) => *ch != '/',
            Token::Set { members, negative } => members.binary_search(&'/').is_ok() == *negative,
            Token::Any | Token::Star => false,
        })
    }

    pub fn transfer_domain(
        &self,
        domain: &caushell_types::RuntimeArgumentDomain,
        kind: ShellPatternRemovalKind,
        template: &str,
        marker: &str,
    ) -> Option<caushell_types::RuntimeArgumentDomain> {
        use caushell_types::RuntimeArgumentDomain as D;
        let (before, after) = template.split_once(marker)?;
        if after.contains(marker) {
            return None;
        }
        let literal = self.literal()?;
        if literal.is_empty() {
            return Some(domain.substitute_into(template, marker));
        }
        // Removing within a fixed affix leaves the abstract core unchanged.
        let trim = |prefix: &str, suffix: &str| -> Option<(String, String)> {
            if kind.prefix() {
                if let Some(rest) = prefix.strip_prefix(&literal) {
                    return Some((rest.into(), suffix.into()));
                }
                if !literal.starts_with(prefix) {
                    return Some((prefix.into(), suffix.into()));
                }
            } else {
                if let Some(rest) = suffix.strip_suffix(&literal) {
                    return Some((prefix.into(), rest.into()));
                }
                if !literal.ends_with(suffix) {
                    return Some((prefix.into(), suffix.into()));
                }
            }
            None
        };
        match domain {
            D::GeneratedFileName { prefix, suffix } => {
                let (prefix, suffix) = trim(prefix, suffix)?;
                Some(D::GeneratedFileName { prefix, suffix }.substitute_into(template, marker))
            }
            D::TextTemplate { prefix, suffix } => {
                let (prefix, suffix) = trim(prefix, suffix)?;
                Some(D::TextTemplate { prefix, suffix }.substitute_into(template, marker))
            }
            D::PathTemplate {
                roots,
                may_escape,
                prefix,
                suffix,
            } => {
                let (prefix, suffix) = trim(prefix, suffix)?;
                Some(
                    D::PathTemplate {
                        roots: roots.clone(),
                        may_escape: *may_escape,
                        prefix,
                        suffix,
                    }
                    .substitute_into(template, marker),
                )
            }
            D::PathSet {
                roots,
                may_escape: false,
            } if !roots.is_empty() && roots.len() <= 128 => {
                if kind.prefix() {
                    let roots = roots
                        .iter()
                        .map(|r| {
                            r.strip_prefix(&literal)
                                .filter(|r| !r.is_empty())
                                .map(String::from)
                        })
                        .collect::<Option<Vec<_>>>()?;
                    return Some(
                        D::PathSet {
                            roots,
                            may_escape: false,
                        }
                        .substitute_into(template, marker),
                    );
                }
                // No slash may disappear. A known final basename suffix also
                // prevents a trimmed member from becoming '.' or '..'. Keep
                // the root case separately: changing ROOT.txt changes ROOT.
                if !self.cannot_match_slash()
                    || after.contains('/')
                    || after.contains('\0')
                    || !protected_basename(after)
                {
                    return None;
                }
                let mut outputs = Vec::new();
                for root in roots {
                    outputs.push(format!("{before}{root}"));
                    outputs.push(format!("{before}{}{after}", self.remove(root, kind)?));
                }
                outputs.sort();
                outputs.dedup();
                Some(D::PathSet {
                    roots: outputs,
                    may_escape: false,
                })
            }
            _ => None,
        }
    }
}

fn protected_basename(suffix: &str) -> bool {
    suffix.len() >= 3 || suffix.chars().any(|ch| ch != '.')
}

fn bracket(units: &[PatternUnit], start: usize) -> Option<Option<(Token, usize)>> {
    let mut i = start + 1;
    let negative = units
        .get(i)
        .is_some_and(|u| !u.literal && matches!(u.ch, '!' | '^'));
    if negative {
        i += 1;
    }
    let mut members = Vec::new();
    while let Some(unit) = units.get(i) {
        if !unit.literal && unit.ch == ']' && !members.is_empty() {
            members.sort_unstable();
            members.dedup();
            return Some(Some((Token::Set { members, negative }, i)));
        }
        if !unit.literal
            && unit.ch == '['
            && units
                .get(i + 1)
                .is_some_and(|u| matches!(u.ch, ':' | '.' | '='))
        {
            return None;
        }
        if !unit.literal
            && unit.ch == '-'
            && !members.is_empty()
            && units.get(i + 1).is_some_and(|u| u.literal || u.ch != ']')
        {
            // Ranges and character/collation classes are locale-sensitive.
            return None;
        }
        if !unit.literal && unit.ch == '\\' {
            i += 1;
            members.push(units.get(i)?.ch);
        } else {
            members.push(unit.ch);
        }
        i += 1;
    }
    Some(None)
}
