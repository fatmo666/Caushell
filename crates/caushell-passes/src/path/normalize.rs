pub(crate) fn resolve_path_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    if text.is_empty() {
        return None;
    }

    // These forms are runtime-dependent or not ordinary filesystem paths, so this stage must not guess.
    if matches!(
        node_kind,
        "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
    ) {
        return None;
    }

    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return Some(resolve_literal_path(text, cwd));
    }

    if contains_unescaped_chars(text, &['$', '`']) {
        return None;
    }

    if !quoted && contains_unescaped_glob_syntax(text) {
        return None;
    }

    if !quoted {
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

    Some(resolve_literal_path(text, cwd))
}

fn resolve_literal_path(text: &str, cwd: &str) -> String {
    if text.starts_with('/') {
        return normalize_shell_path(text);
    }

    join_shell_path(cwd, text)
}

pub(crate) fn join_shell_path(base: &str, child: &str) -> String {
    let mut joined = base.to_string();

    if !joined.ends_with('/') {
        joined.push('/');
    }

    joined.push_str(child);
    normalize_shell_path(&joined)
}

pub(crate) fn normalize_shell_path(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = parts.last() {
                    if *last != ".." {
                        parts.pop();
                        continue;
                    }
                }

                if !is_absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }

    if is_absolute {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

pub(crate) fn path_is_within_root(path: &str, root: &str) -> bool {
    let normalized_path = normalize_shell_path(path);
    let normalized_root = normalize_shell_path(root);

    if normalized_root == "/" {
        return normalized_path.starts_with('/');
    }

    normalized_path == normalized_root
        || normalized_path
            .strip_prefix(&normalized_root)
            .is_some_and(|suffix| suffix.starts_with('/'))
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

fn contains_unescaped_glob_syntax(text: &str) -> bool {
    contains_unescaped_chars(text, &['*', '?']) || has_unescaped_bracket_glob(text)
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
