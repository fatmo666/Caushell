//! Bounded, lexical Bash brace expansion, before parameter/tilde expansion.
//! Results remain shell words: quoting, escaping and source provenance are not
//! discarded, and substituted/native argv data never enters this decoder.

#[derive(Debug)]
pub(crate) struct BraceBudget {
    words: usize,
    bytes: usize,
}

impl Default for BraceBudget {
    fn default() -> Self {
        Self {
            words: 256,
            bytes: 65_536,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

struct Group {
    start: usize,
    end: usize,
    commas: Vec<usize>,
}

/// None leaves the original word on the existing materialization path. Err
/// retains an explicit unresolved-shell-expansion fact; never return a prefix
/// of an expansion that exceeded its budget.
pub(crate) fn expand(text: &str, budget: &mut BraceBudget) -> Result<Option<Vec<String>>, ()> {
    if !text.contains('{') {
        return Ok(None);
    }
    let Some(group) = first_group(text)? else {
        return Ok(None);
    };
    let mut output = Vec::new();
    expand_group(text, group, budget, 0, &mut output)?;
    Ok(Some(output))
}

fn expand_group(
    text: &str,
    group: Group,
    budget: &mut BraceBudget,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), ()> {
    if depth >= 32 {
        return Err(());
    }
    let alternatives = alternatives(text, &group)?.ok_or(())?;
    for alternative in alternatives {
        let size = group
            .start
            .checked_add(alternative.len())
            .and_then(|n| n.checked_add(text.len() - group.end))
            .ok_or(())?;
        budget.words = budget.words.checked_sub(1).ok_or(())?;
        budget.bytes = budget.bytes.checked_sub(size).ok_or(())?;
        let word = format!(
            "{}{}{}",
            &text[..group.start],
            alternative,
            &text[group.end..]
        );
        if let Some(next) = first_group(&word)? {
            expand_group(&word, next, budget, depth + 1, output)?;
        } else if !word.is_empty() {
            // An unquoted empty field disappears; explicit ''/"" stays a word.
            output.push(word);
        }
    }
    Ok(())
}

fn first_group(text: &str) -> Result<Option<Group>, ()> {
    if text.len() > 8192 {
        return Err(());
    }
    let mut quote = Quote::None;
    let mut chars = text.char_indices();
    let mut stack: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut groups = Vec::new();
    while let Some((index, ch)) = chars.next() {
        match (quote, ch) {
            (Quote::Single, '\'') => quote = Quote::None,
            (Quote::Single, _) => {}
            (Quote::Double, '"') => quote = Quote::None,
            (Quote::None, '\'') => quote = Quote::Single,
            (Quote::None, '"') => quote = Quote::Double,
            (_, '\\') => {
                chars.next();
            }
            // No partial expansion across substitutions: neither their braces
            // nor values are lexical brace candidates in the outer argv.
            (_, '$' | '`') => return Ok(None),
            (Quote::None, '{') => {
                if stack.len() >= 32 {
                    return Err(());
                }
                stack.push((index, Vec::new()));
            }
            (Quote::None, ',') => {
                if let Some((_, commas)) = stack.last_mut() {
                    commas.push(index);
                }
            }
            (Quote::None, '}') => {
                if let Some((start, commas)) = stack.pop() {
                    groups.push(Group {
                        start,
                        end: index + 1,
                        commas,
                    });
                }
            }
            _ => {}
        }
    }
    if quote != Quote::None {
        return Ok(None);
    }
    groups.sort_by_key(|group| group.start);
    for group in groups {
        if alternatives(text, &group)?.is_some() {
            return Ok(Some(group));
        }
    }
    Ok(None)
}

fn alternatives(text: &str, group: &Group) -> Result<Option<Vec<String>>, ()> {
    if !group.commas.is_empty() {
        if group.commas.len() >= 256 {
            return Err(());
        }
        let mut start = group.start + 1;
        let mut result = Vec::with_capacity(group.commas.len() + 1);
        for end in group
            .commas
            .iter()
            .copied()
            .chain(std::iter::once(group.end - 1))
        {
            result.push(text[start..end].to_owned());
            start = end + 1;
        }
        return Ok(Some(result));
    }
    let body = &text[group.start + 1..group.end - 1];
    let parts: Vec<_> = body.split("..").collect();
    if !(2..=3).contains(&parts.len()) {
        return Ok(None);
    }
    let number = |s: &str| {
        let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    };
    if parts.len() == 3 && !number(parts[2]) {
        return Ok(None);
    }
    let step = if parts.len() == 3 {
        i128::from(parts[2].parse::<i64>().map_err(|_| ())?)
            .abs()
            .max(1)
    } else {
        1
    };
    let numeric = number(parts[0]) && number(parts[1]);
    let (start, end) = if numeric {
        (
            i128::from(parts[0].parse::<i64>().map_err(|_| ())?),
            i128::from(parts[1].parse::<i64>().map_err(|_| ())?),
        )
    } else if parts[0].len() == 1
        && parts[1].len() == 1
        && parts[0].as_bytes()[0].is_ascii_alphabetic()
        && parts[1].as_bytes()[0].is_ascii_alphabetic()
    {
        let a = parts[0].as_bytes()[0];
        let b = parts[1].as_bytes()[0];
        // Cross-case ranges contain shell metacharacters. Retain uncertainty
        // rather than reparsing generated quoting/globbing as source syntax.
        if a.is_ascii_lowercase() != b.is_ascii_lowercase() {
            return Err(());
        }
        (i128::from(a), i128::from(b))
    } else {
        return Ok(None);
    };
    let count = (end - start).abs() / step + 1;
    if count > 256 {
        return Err(());
    }
    let padded = numeric
        && parts[..2].iter().any(|s| {
            s.strip_prefix('-').unwrap_or(s).starts_with('0')
                && s.strip_prefix('-').unwrap_or(s).len() > 1
        });
    let width = parts[..2].iter().map(|s| s.len()).max().unwrap_or(0);
    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count {
        let value = start + index * if start <= end { step } else { -step };
        result.push(if !numeric {
            char::from(value as u8).to_string()
        } else if padded {
            format!("{value:0width$}")
        } else {
            value.to_string()
        });
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn words(s: &str) -> Vec<String> {
        expand(s, &mut BraceBudget::default()).unwrap().unwrap()
    }
    #[test]
    fn lists_products_nested_and_empty_alternatives_keep_order() {
        assert_eq!(
            words("p/{a,b{1,2},}/z"),
            ["p/a/z", "p/b1/z", "p/b2/z", "p//z"]
        );
        assert_eq!(words("{1..2}{a,b}"), ["1a", "1b", "2a", "2b"]);
        assert_eq!(words("{,new.}name"), ["name", "new.name"]);
        assert!(words("{,}").is_empty());
        assert_eq!(words("''{,}"), ["''", "''"]);
        assert_eq!(words("{x{a,b}}"), ["{xa}", "{xb}"]);
    }
    #[test]
    fn sequences_preserve_padding_direction_and_stride() {
        assert_eq!(words("{-01..2}"), ["-01", "000", "001", "002"]);
        assert_eq!(words("{+1..3}"), ["1", "2", "3"]);
        assert_eq!(words("{3..1..0}"), ["3", "2", "1"]);
        assert_eq!(words("{a..f..2}"), ["a", "c", "e"]);
        assert_eq!(words("{Z..U..-2}"), ["Z", "X", "V"]);
        assert_eq!(words("{1..1}"), ["1"]);
    }
    #[test]
    fn quoting_escaping_and_substitution_are_not_reinterpreted() {
        for s in [
            "'{a,b}'",
            "\"{a,b}\"",
            r"\{a,b\}",
            "{x}",
            "${x:-{a,b}}",
            "{a,b}$X",
            "{a,b}$(echo x)",
            "{a,b}`echo x`",
        ] {
            assert!(
                expand(s, &mut BraceBudget::default()).unwrap().is_none(),
                "{s}"
            );
        }
        assert_eq!(
            words(r#"x'{literal}'{a,"b,c"}"#),
            ["x'{literal}'a", "x'{literal}'\"b,c\""]
        );
        assert_eq!(words(r"{a\,b,c}"), [r"a\,b", "c"]);
    }
    #[test]
    fn budgets_are_shared_and_never_return_partial_results() {
        for s in [
            "{1..10000}",
            "{1..20}{1..20}",
            "{a..Z}",
            "{9223372036854775807..-9223372036854775808}",
        ] {
            assert!(expand(s, &mut BraceBudget::default()).is_err(), "{s}");
        }
        let mut budget = BraceBudget {
            words: 3,
            bytes: 100,
        };
        assert!(expand("{a,b}", &mut budget).unwrap().is_some());
        assert!(expand("{c,d}", &mut budget).is_err());
    }
}
