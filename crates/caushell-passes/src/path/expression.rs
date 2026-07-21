use super::normalize::{join_shell_path, normalize_shell_path, resolve_path_operand};

const MAX_BRACE_EXPANSIONS: usize = 128;
const MAX_BRACE_EXPANSION_PASSES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathExpression {
    Exact(String),
    OneOf(Vec<PathExpression>),
    Pattern(PathPattern),
    Dynamic,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathPattern {
    pattern: String,
}

impl PathPattern {
    pub(crate) fn as_str(&self) -> &str {
        self.pattern.as_str()
    }
}

pub(crate) fn classify_path_operand_expression(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> PathExpression {
    let text = text.trim();
    if text.is_empty() {
        return PathExpression::Unsupported;
    }

    if is_dynamic_path_node_kind(node_kind) {
        return PathExpression::Dynamic;
    }

    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return resolve_exact_path_operand_optional(text, quoted, node_kind, cwd, home)
            .map(PathExpression::Exact)
            .unwrap_or(PathExpression::Unsupported);
    }

    if contains_unescaped_chars(text, &['$', '`']) {
        return PathExpression::Dynamic;
    }

    if !quoted && is_static_shell_word_node_kind(node_kind) {
        return static_shell_word_text(text)
            .map(|word| classify_static_shell_word_expression(&word, cwd, home))
            .unwrap_or(PathExpression::Unsupported);
    }

    classify_path_operand_expression_without_brace_expansion(text, quoted, node_kind, cwd, home)
}

pub(crate) fn shell_pattern_matches_path(pattern: &str, path: &str) -> bool {
    let normalized_pattern = normalize_shell_path(pattern);
    let normalized_path = normalize_shell_path(path);

    if normalized_path == "/" {
        return normalized_pattern == "/";
    }

    glob_match(normalized_pattern.as_bytes(), normalized_path.as_bytes())
}

pub(crate) fn shell_pattern_is_bare_star_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some('*')) && chars.next().is_none()
}

fn classify_path_operand_expression_without_brace_expansion(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> PathExpression {
    if !quoted && contains_unescaped_glob_syntax(text) {
        return resolve_pattern_path_operand(text, quoted, node_kind, cwd, home)
            .map(|pattern| PathExpression::Pattern(PathPattern { pattern }))
            .unwrap_or(PathExpression::Unsupported);
    }

    resolve_exact_path_operand_optional(text, quoted, node_kind, cwd, home)
        .map(PathExpression::Exact)
        .unwrap_or(PathExpression::Unsupported)
}

fn classify_static_shell_word_expression(
    word: &StaticShellWordText,
    cwd: Option<&str>,
    home: Option<&str>,
) -> PathExpression {
    if word.has_dynamic {
        return PathExpression::Dynamic;
    }

    if let Some(expanded) = brace_expanded_texts(&word.text) {
        let mut expressions = Vec::new();
        for expanded_text in expanded {
            expressions.push(classify_static_shell_word_without_brace_expansion(
                expanded_text.as_str(),
                cwd,
                home,
                word.allow_tilde_expansion,
            ));
        }
        return one_of(expressions);
    }

    classify_static_shell_word_without_brace_expansion(
        &word.text,
        cwd,
        home,
        word.allow_tilde_expansion,
    )
}

fn classify_static_shell_word_without_brace_expansion(
    text: &str,
    cwd: Option<&str>,
    home: Option<&str>,
    allow_tilde_expansion: bool,
) -> PathExpression {
    if contains_unescaped_glob_syntax(text) {
        return resolve_static_pattern_path_operand(text, cwd, home, allow_tilde_expansion)
            .map(|pattern| PathExpression::Pattern(PathPattern { pattern }))
            .unwrap_or(PathExpression::Unsupported);
    }

    resolve_static_exact_path_operand(text, cwd, home, allow_tilde_expansion)
        .map(PathExpression::Exact)
        .unwrap_or(PathExpression::Unsupported)
}

fn one_of(expressions: Vec<PathExpression>) -> PathExpression {
    let mut flattened = Vec::new();
    for expression in expressions {
        match expression {
            PathExpression::OneOf(children) => flattened.extend(children),
            other => flattened.push(other),
        }
    }

    flattened.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
    flattened.dedup();

    match flattened.len() {
        0 => PathExpression::Unsupported,
        1 => flattened.remove(0),
        _ => PathExpression::OneOf(flattened),
    }
}

fn resolve_exact_path_operand_optional(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    if is_static_shell_word_node_kind(node_kind) && !quoted && contains_backslash_path_escape(text)
    {
        return resolve_escaped_unquoted_word_path(text, cwd, home);
    }

    match cwd {
        Some(cwd) => resolve_path_operand(text, quoted, node_kind, cwd, home),
        None => resolve_cwd_independent_path_operand(text, quoted, node_kind, home),
    }
}

fn resolve_pattern_path_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    if quoted || !is_static_shell_word_node_kind(node_kind) {
        return None;
    }

    let pattern_text = shell_pattern_path_text(text)?;

    if pattern_text == "~" {
        return home.map(normalize_shell_path);
    }

    if let Some(rest) = pattern_text.strip_prefix("~/") {
        return home.map(|home| join_shell_path(home, rest));
    }

    if pattern_text.starts_with('~') {
        return None;
    }

    if pattern_text.starts_with('/') {
        return Some(normalize_shell_path(&pattern_text));
    }

    cwd.map(|cwd| join_shell_path(cwd, &pattern_text))
}

fn resolve_static_exact_path_operand(
    text: &str,
    cwd: Option<&str>,
    home: Option<&str>,
    allow_tilde_expansion: bool,
) -> Option<String> {
    let unescaped = unescape_shell_word_path(text)?;
    resolve_static_path_text(&unescaped, cwd, home, allow_tilde_expansion)
}

fn resolve_static_pattern_path_operand(
    text: &str,
    cwd: Option<&str>,
    home: Option<&str>,
    allow_tilde_expansion: bool,
) -> Option<String> {
    let pattern_text = shell_pattern_path_text(text)?;
    resolve_static_path_text(&pattern_text, cwd, home, allow_tilde_expansion)
}

fn resolve_static_path_text(
    text: &str,
    cwd: Option<&str>,
    home: Option<&str>,
    allow_tilde_expansion: bool,
) -> Option<String> {
    if allow_tilde_expansion {
        if text == "~" {
            return home.map(normalize_shell_path);
        }

        if let Some(rest) = text.strip_prefix("~/") {
            return home.map(|home| join_shell_path(home, rest));
        }

        if text.starts_with('~') {
            return None;
        }
    }

    if text.starts_with('/') {
        Some(normalize_shell_path(text))
    } else {
        cwd.map(|cwd| join_shell_path(cwd, text))
    }
}

fn resolve_escaped_unquoted_word_path(
    text: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    let unescaped = unescape_shell_word_path(text)?;

    if unescaped == "~" {
        return home.map(normalize_shell_path);
    }

    if let Some(rest) = unescaped.strip_prefix("~/") {
        return home.map(|home| join_shell_path(home, rest));
    }

    if unescaped.starts_with('~') {
        return None;
    }

    if unescaped.starts_with('/') {
        Some(normalize_shell_path(&unescaped))
    } else {
        cwd.map(|cwd| join_shell_path(cwd, &unescaped))
    }
}

fn resolve_cwd_independent_path_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    home: Option<&str>,
) -> Option<String> {
    let cwd_independent =
        text.starts_with('/') || (!quoted && (text == "~" || text.starts_with("~/")));
    if !cwd_independent {
        return None;
    }

    resolve_path_operand(text, quoted, node_kind, "/", home)
}

fn shell_pattern_path_text(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let escaped = chars.next()?;
        if escaped == '\n' {
            return None;
        }

        if matches!(escaped, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(escaped);
    }

    Some(out)
}

fn unescape_shell_word_path(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let escaped = chars.next()?;
        if escaped == '\n' {
            return None;
        }
        out.push(escaped);
    }

    Some(out)
}

fn contains_backslash_path_escape(text: &str) -> bool {
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            continue;
        }
        let Some(next) = chars.next() else {
            return true;
        };
        if next != '\n' {
            return true;
        }
    }
    false
}

fn contains_unescaped_glob_syntax(text: &str) -> bool {
    contains_unescaped_chars(text, &['*', '?']) || has_unescaped_bracket_glob(text)
}

fn contains_unescaped_chars(text: &str, targets: &[char]) -> bool {
    let mut escaped = false;

    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if targets.contains(&ch) {
            return true;
        }
    }

    false
}

fn has_unescaped_bracket_glob(text: &str) -> bool {
    let mut escaped = false;
    let mut seen_open = false;

    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == '[' {
            seen_open = true;
            continue;
        }

        if ch == ']' && seen_open {
            return true;
        }
    }

    false
}

fn is_dynamic_path_node_kind(node_kind: &str) -> bool {
    matches!(
        node_kind,
        "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
    )
}

fn is_static_shell_word_node_kind(node_kind: &str) -> bool {
    matches!(node_kind, "word" | "concatenation")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticShellWordText {
    text: String,
    has_dynamic: bool,
    allow_tilde_expansion: bool,
}

fn static_shell_word_text(text: &str) -> Option<StaticShellWordText> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote = ShellQuote::None;
    let mut has_dynamic = false;
    let mut allow_tilde_expansion = true;

    while let Some(ch) = chars.next() {
        match quote {
            ShellQuote::None => match ch {
                '\\' => {
                    let escaped = chars.next()?;
                    if escaped == '\n' {
                        return None;
                    }
                    if out.is_empty() && escaped == '~' {
                        allow_tilde_expansion = false;
                    }
                    out.push('\\');
                    out.push(escaped);
                }
                '\'' => quote = ShellQuote::Single,
                '"' => quote = ShellQuote::Double,
                '$' | '`' => {
                    has_dynamic = true;
                    out.push(ch);
                }
                _ => out.push(ch),
            },
            ShellQuote::Single => {
                if ch == '\'' {
                    quote = ShellQuote::None;
                } else {
                    push_quoted_literal_char(ch, &mut out, &mut allow_tilde_expansion);
                }
            }
            ShellQuote::Double => match ch {
                '"' => quote = ShellQuote::None,
                '\\' => {
                    let escaped = chars.next()?;
                    match escaped {
                        '$' | '`' | '"' | '\\' => {
                            push_quoted_literal_char(escaped, &mut out, &mut allow_tilde_expansion)
                        }
                        '\n' => return None,
                        _ => {
                            push_quoted_literal_char('\\', &mut out, &mut allow_tilde_expansion);
                            push_quoted_literal_char(escaped, &mut out, &mut allow_tilde_expansion);
                        }
                    }
                }
                '$' | '`' => {
                    has_dynamic = true;
                    out.push(ch);
                }
                _ => push_quoted_literal_char(ch, &mut out, &mut allow_tilde_expansion),
            },
        }
    }

    if quote != ShellQuote::None {
        return None;
    }

    Some(StaticShellWordText {
        text: out,
        has_dynamic,
        allow_tilde_expansion,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellQuote {
    None,
    Single,
    Double,
}

fn push_quoted_literal_char(ch: char, out: &mut String, allow_tilde_expansion: &mut bool) {
    if out.is_empty() && ch == '~' {
        *allow_tilde_expansion = false;
    }

    if matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | ',' | '\\') {
        out.push('\\');
    }
    out.push(ch);
}

fn brace_expanded_texts(text: &str) -> Option<Vec<String>> {
    let mut current = vec![text.to_string()];
    let mut changed_any = false;

    for _ in 0..MAX_BRACE_EXPANSION_PASSES {
        let mut next = Vec::new();
        let mut changed_this_pass = false;

        for item in current {
            if let Some((start, end, alternatives)) = first_expandable_brace(&item) {
                changed_any = true;
                changed_this_pass = true;
                let prefix = &item[..start];
                let suffix = &item[end..];
                for alternative in alternatives {
                    next.push(format!("{prefix}{alternative}{suffix}"));
                    if next.len() > MAX_BRACE_EXPANSIONS {
                        return None;
                    }
                }
            } else {
                next.push(item);
            }
        }

        current = next;
        if !changed_this_pass {
            return changed_any.then_some(current);
        }
    }

    None
}

fn first_expandable_brace(text: &str) -> Option<(usize, usize, Vec<String>)> {
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch != '{' {
            continue;
        }

        let Some(end_index) = matching_brace_end(text, index) else {
            continue;
        };
        let body = &text[index + 1..end_index];
        let alternatives = split_brace_alternatives(body);
        if alternatives.len() > 1 {
            return Some((index, end_index + 1, alternatives));
        }
    }

    None
}

fn matching_brace_end(text: &str, start: usize) -> Option<usize> {
    let mut escaped = false;
    let mut depth = 0usize;

    for (index, ch) in text[start..].char_indices() {
        let absolute_index = start + index;
        if absolute_index == start {
            depth = 1;
            continue;
        }

        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(absolute_index);
                }
            }
            _ => {}
        }
    }

    None
}

fn split_brace_alternatives(body: &str) -> Vec<String> {
    let mut alternatives = Vec::new();
    let mut start = 0usize;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut saw_comma = false;

    for (index, ch) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                saw_comma = true;
                alternatives.push(body[start..index].to_string());
                start = index + 1;
            }
            _ => {}
        }
    }

    if !saw_comma {
        return Vec::new();
    }

    alternatives.push(body[start..].to_string());
    alternatives
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut memo = std::collections::BTreeMap::new();
    glob_match_from(pattern, text, 0, 0, &mut memo)
}

fn glob_match_from(
    pattern: &[u8],
    text: &[u8],
    pattern_index: usize,
    text_index: usize,
    memo: &mut std::collections::BTreeMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pattern_index, text_index)) {
        return *result;
    }

    let result = if pattern_index == pattern.len() {
        text_index == text.len()
    } else if pattern[pattern_index] == b'\\' {
        match pattern.get(pattern_index + 1).copied() {
            Some(literal) => {
                text.get(text_index).copied() == Some(literal)
                    && glob_match_from(pattern, text, pattern_index + 2, text_index + 1, memo)
            }
            None => {
                text.get(text_index).copied() == Some(b'\\')
                    && glob_match_from(pattern, text, pattern_index + 1, text_index + 1, memo)
            }
        }
    } else if pattern[pattern_index] == b'*' {
        glob_match_from(pattern, text, pattern_index + 1, text_index, memo)
            || (text.get(text_index).is_some_and(|ch| *ch != b'/')
                && glob_match_from(pattern, text, pattern_index, text_index + 1, memo))
    } else if pattern[pattern_index] == b'?' {
        text.get(text_index).is_some_and(|ch| *ch != b'/')
            && glob_match_from(pattern, text, pattern_index + 1, text_index + 1, memo)
    } else if pattern[pattern_index] == b'[' {
        match parse_bracket_class(pattern, pattern_index) {
            Some((class, next_index)) => {
                text.get(text_index)
                    .is_some_and(|ch| *ch != b'/' && class.matches(*ch))
                    && glob_match_from(pattern, text, next_index, text_index + 1, memo)
            }
            None => {
                text.get(text_index).copied() == Some(b'[')
                    && glob_match_from(pattern, text, pattern_index + 1, text_index + 1, memo)
            }
        }
    } else {
        text.get(text_index).copied() == Some(pattern[pattern_index])
            && glob_match_from(pattern, text, pattern_index + 1, text_index + 1, memo)
    };

    memo.insert((pattern_index, text_index), result);
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BracketClass {
    negated: bool,
    members: Vec<BracketMember>,
}

impl BracketClass {
    fn matches(&self, ch: u8) -> bool {
        let matched = self.members.iter().any(|member| member.matches(ch));
        if self.negated { !matched } else { matched }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BracketMember {
    Literal(u8),
    Range(u8, u8),
}

impl BracketMember {
    fn matches(&self, ch: u8) -> bool {
        match self {
            BracketMember::Literal(literal) => ch == *literal,
            BracketMember::Range(start, end) => *start <= ch && ch <= *end,
        }
    }
}

fn parse_bracket_class(pattern: &[u8], start: usize) -> Option<(BracketClass, usize)> {
    let mut index = start + 1;
    let mut negated = false;
    let mut members = Vec::new();

    if matches!(pattern.get(index), Some(b'!' | b'^')) {
        negated = true;
        index += 1;
    }

    while index < pattern.len() {
        if pattern[index] == b']' && !members.is_empty() {
            return Some((BracketClass { negated, members }, index + 1));
        }

        let (first, after_first) = bracket_literal(pattern, index)?;
        if pattern.get(after_first) == Some(&b'-') {
            if let Some((second, after_second)) = bracket_literal(pattern, after_first + 1) {
                if pattern.get(after_first + 1) != Some(&b']') {
                    members.push(BracketMember::Range(first.min(second), first.max(second)));
                    index = after_second;
                    continue;
                }
            }
        }

        members.push(BracketMember::Literal(first));
        index = after_first;
    }

    None
}

fn bracket_literal(pattern: &[u8], index: usize) -> Option<(u8, usize)> {
    match pattern.get(index).copied()? {
        b'\\' => pattern
            .get(index + 1)
            .copied()
            .map(|literal| (literal, index + 2)),
        b']' => None,
        literal => Some((literal, index + 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PathExpression, classify_path_operand_expression, shell_pattern_is_bare_star_segment,
        shell_pattern_matches_path,
    };

    #[test]
    fn path_expression_resolves_literal_parent_segments() {
        assert_eq!(
            classify_path_operand_expression("/usr/../etc", false, "word", Some("/tmp"), None),
            PathExpression::Exact("/etc".to_string())
        );
    }

    #[test]
    fn path_expression_classifies_root_name_globs_as_patterns() {
        assert!(matches!(
            classify_path_operand_expression("/u*", false, "word", Some("/tmp"), None),
            PathExpression::Pattern(_)
        ));
        assert!(matches!(
            classify_path_operand_expression("/[e]tc", false, "concatenation", Some("/tmp"), None),
            PathExpression::Pattern(_)
        ));
        assert!(shell_pattern_matches_path("/u*", "/usr"));
        assert!(shell_pattern_matches_path("/et?", "/etc"));
        assert!(shell_pattern_matches_path("/[e]tc", "/etc"));
    }

    #[test]
    fn path_expression_respects_quoted_and_escaped_globs() {
        assert_eq!(
            classify_path_operand_expression("/u*", true, "word", Some("/tmp"), None),
            PathExpression::Exact("/u*".to_string())
        );
        assert_eq!(
            classify_path_operand_expression(r#"/u\*"#, false, "word", Some("/tmp"), None),
            PathExpression::Exact("/u*".to_string())
        );
        assert!(!shell_pattern_matches_path(r#"/u\*"#, "/usr"));
    }

    #[test]
    fn path_expression_expands_simple_braces() {
        assert_eq!(
            classify_path_operand_expression(
                "/{etc,usr}",
                false,
                "concatenation",
                Some("/tmp"),
                None
            ),
            PathExpression::OneOf(vec![
                PathExpression::Exact("/etc".to_string()),
                PathExpression::Exact("/usr".to_string()),
            ])
        );
    }

    #[test]
    fn path_expression_removes_embedded_static_quotes_without_unquoting_globs() {
        assert!(matches!(
            classify_path_operand_expression(
                r#"/"etc"/*"#,
                false,
                "concatenation",
                Some("/tmp"),
                None
            ),
            PathExpression::Pattern(_)
        ));
        assert_eq!(
            classify_path_operand_expression(
                r#"/etc/"*""#,
                false,
                "concatenation",
                Some("/tmp"),
                None
            ),
            PathExpression::Exact("/etc/*".to_string())
        );
        assert_eq!(
            classify_path_operand_expression(
                r#""/{etc,usr}""#,
                false,
                "concatenation",
                Some("/tmp"),
                None
            ),
            PathExpression::Exact("/{etc,usr}".to_string())
        );
    }

    #[test]
    fn path_expression_matches_bare_star_child_segment() {
        assert!(shell_pattern_is_bare_star_segment("*"));
        assert!(!shell_pattern_is_bare_star_segment("a*"));
        assert!(!shell_pattern_is_bare_star_segment(r#"\*"#));
    }
}
