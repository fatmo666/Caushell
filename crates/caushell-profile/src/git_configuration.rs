//! Bounded, non-executing Git configuration syntax and last-value precedence.
//! Includes are ordered events for the caller's execution-namespace reader.
use std::collections::BTreeMap;

/// Native configuration/search and executable-source dependencies. These are
/// child exports, not shell locals and never the guard process's environment.
pub const GIT_CONFIGURATION_ENVIRONMENT: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_TEST_FSMONITOR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EXTERNAL_DIFF",
    "GIT_ATTR_NOSYSTEM",
    "GIT_EXEC_PATH",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitConfigEvent {
    Value { key: String, value: Option<String> },
    Include { path: String, conditional: bool },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitConfigValue {
    Absent,
    Known {
        value: Option<String>,
        source: String,
    },
    Unknown {
        reason: String,
    },
}
#[derive(Debug, Clone, Default)]
pub struct GitConfiguration {
    values: BTreeMap<String, GitConfigValue>,
    unknown: Vec<String>,
}
impl GitConfiguration {
    /// A later known key can override an uncertain lower source without
    /// proving that the entire configuration was observed.
    pub fn is_complete(&self) -> bool {
        self.unknown.is_empty()
    }
    pub fn get(&self, key: &str) -> GitConfigValue {
        self.values
            .get(&key.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| {
                if self.unknown.is_empty() {
                    GitConfigValue::Absent
                } else {
                    GitConfigValue::Unknown {
                        reason: self.unknown.join("; "),
                    }
                }
            })
    }
    pub fn configured_driver_keys(&self) -> Vec<String> {
        self.values
            .keys()
            .filter(|k| {
                k.starts_with("diff.") && (k.ends_with(".command") || k.ends_with(".textconv"))
            })
            .cloned()
            .collect()
    }
    pub fn conversion_filter_keys(&self) -> Vec<String> {
        self.values
            .keys()
            .filter(|k| {
                k.starts_with("filter.") && (k.ends_with(".clean") || k.ends_with(".process"))
            })
            .cloned()
            .collect()
    }
    pub fn unresolved_reasons(&self) -> &[String] {
        &self.unknown
    }
    pub fn set(&mut self, key: &str, value: Option<String>, source: &str) {
        self.values.insert(
            key.to_ascii_lowercase(),
            GitConfigValue::Known {
                value,
                source: source.into(),
            },
        );
    }
    pub fn unresolved(&mut self, reason: impl Into<String>) {
        self.values.clear();
        let reason = reason.into();
        if !self.unknown.contains(&reason) {
            self.unknown.push(reason);
        }
    }
}

/// Git booleans, not arbitrary executable names. A missing '=value' is true.
pub fn git_boolean(value: Option<&str>) -> Option<bool> {
    match value {
        None => Some(true),
        Some(s)
            if s.is_empty()
                || ["false", "no", "off", "0"]
                    .iter()
                    .any(|v| s.eq_ignore_ascii_case(v)) =>
        {
            Some(false)
        }
        Some(s)
            if ["true", "yes", "on", "1"]
                .iter()
                .any(|v| s.eq_ignore_ascii_case(v)) =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn decode_value(raw: &str) -> Result<String, String> {
    let mut value = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut trailing = 0;
    for ch in raw.trim_start_matches([' ', '\t']).chars() {
        if escaped {
            value.push(match ch {
                'n' => '\n',
                't' => '\t',
                'b' => '\u{8}',
                '\\' => '\\',
                '"' => '"',
                _ => return Err("invalid Git value escape".into()),
            });
            escaped = false;
            trailing = 0;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
            trailing = 0;
        } else if !quoted && matches!(ch, '#' | ';') {
            break;
        } else {
            value.push(ch);
            if !quoted && matches!(ch, ' ' | '\t') {
                trailing += ch.len_utf8();
            } else {
                trailing = 0;
            }
        }
    }
    if quoted || escaped {
        return Err("incomplete Git value quote/escape".into());
    }
    value.truncate(value.len() - trailing);
    Ok(value)
}

pub fn parse_git_configuration(text: &str) -> Result<Vec<GitConfigEvent>, String> {
    if text.len() > 65536 || text.contains('\0') {
        return Err("Git config input exceeds byte grammar/budget".into());
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut logical = Vec::new();
    let mut line = String::new();
    for raw in text.split_inclusive('\n') {
        let raw = raw
            .strip_suffix('\n')
            .unwrap_or(raw)
            .strip_suffix('\r')
            .unwrap_or(raw.strip_suffix('\n').unwrap_or(raw));
        let n = raw.bytes().rev().take_while(|b| *b == b'\\').count();
        if n % 2 == 1 {
            line.push_str(&raw[..raw.len() - 1]);
            continue;
        }
        line.push_str(raw);
        logical.push(std::mem::take(&mut line));
        if logical.len() > 4096 {
            return Err("Git config line budget exceeded".into());
        }
    }
    if !line.is_empty() {
        return Err("unfinished Git config continuation".into());
    }
    let mut section = String::new();
    let mut subsection = None;
    let mut out = Vec::new();
    for raw in logical {
        let line = raw.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            // Section brackets inside a quoted subsection are not delimiters.
            let mut quote = false;
            let mut escape = false;
            let mut close = None;
            for (i, ch) in rest.char_indices() {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' && quote {
                    escape = true;
                } else if ch == '"' {
                    quote = !quote;
                } else if ch == ']' && !quote {
                    close = Some(i);
                    break;
                }
            }
            let close = close.ok_or("unterminated Git section")?;
            let tail = rest[close + 1..].trim_start();
            if !tail.is_empty() && !tail.starts_with(['#', ';']) {
                return Err("invalid Git section tail".into());
            }
            let header = rest[..close].trim();
            let end = header.find([' ', '\t']).unwrap_or(header.len());
            section = header[..end].to_ascii_lowercase();
            subsection = None;
            if section.is_empty()
                || !section
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
            {
                return Err("invalid Git section".into());
            }
            let sub = header[end..].trim();
            if !sub.is_empty() {
                if !sub.starts_with('"') {
                    return Err("invalid Git subsection".into());
                }
                subsection = Some(decode_value(sub)?);
            }
            continue;
        }
        if section.is_empty() {
            return Err("Git value outside section".into());
        }
        let end = line.find(['=', ' ', '\t']).unwrap_or(line.len());
        let name = &line[..end];
        if name.is_empty()
            || !name.as_bytes()[0].is_ascii_alphabetic()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err("invalid Git variable".into());
        }
        let rest = line[end..].trim_start_matches([' ', '\t']);
        let value = if let Some(raw) = rest.strip_prefix('=') {
            Some(decode_value(raw)?)
        } else if rest.is_empty() || rest.starts_with(['#', ';']) {
            None
        } else {
            return Err("invalid Git variable tail".into());
        };
        let name = name.to_ascii_lowercase();
        if (section == "include" && subsection.is_none() || section == "includeif")
            && name == "path"
        {
            out.push(GitConfigEvent::Include {
                path: value.ok_or("include without path")?,
                conditional: section == "includeif",
            });
        } else {
            // Subsections have their own namespace; they cannot set core.*.
            let key = match &subsection {
                Some(sub) => format!("{section}.\"{sub}\".{name}"),
                None => format!("{section}.{name}"),
            };
            out.push(GitConfigEvent::Value { key, value });
        }
    }
    Ok(out)
}

/// Git's environment parameter serialization is single-quote data syntax,
/// including old 'key=value' and new 'key'='value' forms. Never shell-evaluate.
pub fn parse_git_config_parameters(text: &str) -> Result<Vec<(String, Option<String>)>, String> {
    if text.len() > 65536 || text.contains('\0') {
        return Err("Git environment config budget exceeded".into());
    }
    let b = text.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n') {
            i += 1;
        }
        if i == b.len() {
            break;
        }
        let mut token = String::new();
        let mut saw = false;
        while i < b.len() && !matches!(b[i], b' ' | b'\t' | b'\n') {
            if b[i] == b'\'' {
                saw = true;
                i += 1;
                let start = i;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                if i == b.len() {
                    return Err("unclosed Git environment quote".into());
                }
                token.push_str(&text[start..i]);
                i += 1;
            } else if b[i] == b'=' {
                token.push('=');
                i += 1;
            } else if b[i] == b'\\' && i + 1 < b.len() && matches!(b[i + 1], b'\'' | b'\\') {
                token.push(b[i + 1] as char);
                i += 2;
            } else {
                return Err("unquoted Git environment parameter".into());
            }
        }
        if !saw {
            return Err("invalid Git environment parameter".into());
        }
        let (key, value) = token
            .split_once('=')
            .map_or((token.as_str(), None), |(k, v)| (k, Some(v.to_owned())));
        if !key.contains('.') || key.is_empty() {
            return Err("invalid Git environment key".into());
        }
        out.push((key.into(), value));
        if out.len() > 256 {
            return Err("Git environment item budget exceeded".into());
        }
    }
    Ok(out)
}
