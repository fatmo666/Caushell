//! A bounded subset of pip 25.3 RawConfigParser data, never Python or Shell.
use std::collections::{BTreeMap, BTreeSet};

pub const PIP_CONFIGURATION_ENVIRONMENT: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_CACHE_HOME",
    "PIP_CONFIG_FILE",
    "PIP_LOG",
    "PIP_CACHE_DIR",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_NO_CACHE_DIR",
    "PIP_USER",
    "PIP_GLOBAL",
    "PIP_SITE",
    "PIP_PYTHON",
    "PIP_EDITOR",
    "PIP_DEBUG",
    "PIP_VERBOSE",
    "PIP_QUIET",
    "PIP_REQUIREMENT",
    "PIP_ISOLATED",
    "PIP_CERT",
    "PIP_CLIENT_CERT",
    "PIP_PROXY",
    "PIP_KEYRING_PROVIDER",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONPYCACHEPREFIX",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONEXECUTABLE",
    "__PYVENV_LAUNCHER__",
    "PYTHONBREAKPOINT",
    "PYTHONWARNINGS",
    "PYTHONPLATLIBDIR",
    "PYTHONNOUSERSITE",
    "PYTHONSAFEPATH",
    "PIP_AUTO_COMPLETE",
];

#[derive(Clone, Debug, Default)]
pub struct PipConfiguration {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
    pub errors: Vec<String>,
}

impl PipConfiguration {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut out = Self::default();
        if bytes.len() > 65536 || !bytes.is_ascii() || bytes.contains(&0) {
            out.errors
                .push("Pip INI requires bounded ASCII data without NUL".into());
            return out;
        }
        let text = std::str::from_utf8(bytes).unwrap();
        let mut section = None;
        let mut seen_sections = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        let mut count = 0;
        for (i, raw) in text.lines().enumerate() {
            let fail = |detail: &str| format!("line {}: {detail}", i + 1);
            if i >= 4096 || count >= 1024 {
                out.errors.push(fail("Pip INI budget exceeded"));
                break;
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if raw.starts_with([' ', '\t']) {
                out.errors
                    .push(fail("indented/multiline Pip INI values are unsupported"));
                continue;
            }
            if line.starts_with('[') {
                let Some(end) = line.find(']') else {
                    out.errors.push(fail("unterminated Pip INI section"));
                    continue;
                };
                let name = &line[1..end];
                if end + 1 != line.len()
                    || name.is_empty()
                    || name.len() > 128
                    || name.contains(['[', ']', ':'])
                    || name.trim() != name
                    || !seen_sections.insert(name.to_owned())
                {
                    out.errors
                        .push(fail("unsupported or duplicate Pip INI section"));
                }
                section = Some(name.to_owned());
                continue;
            }
            let Some(name) = section.as_ref() else {
                out.errors.push(fail("Pip INI option has no section"));
                continue;
            };
            let Some((key, value)) = line.split_once(['=', ':']) else {
                out.errors
                    .push(fail("Pip INI option has no value delimiter"));
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let normalized = key.replace('_', "-");
            let normalized = normalized
                .strip_prefix("--")
                .unwrap_or(&normalized)
                .to_owned();
            if key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !seen_keys.insert((name.clone(), normalized.clone()))
                || value.trim().len() > 8192
            {
                out.errors
                    .push(fail("invalid, duplicate or oversized Pip INI option"));
                continue;
            }
            if name == "DEFAULT" {
                out.errors
                    .push(fail("Pip INI DEFAULT inheritance is unsupported"));
                continue;
            }
            count += 1;
            out.sections
                .entry(name.clone())
                .or_default()
                .insert(normalized, value.trim().into());
        }
        out
    }
    /// Last file wins for a section/key, including an explicitly empty value.
    pub fn merge(&mut self, other: Self) {
        self.errors.extend(other.errors);
        for (section, values) in other.sections {
            self.sections.entry(section).or_default().extend(values);
        }
    }
    /// Pip applies global defaults, then command defaults. Empty defaults do not
    /// override an already selected value; no quote removal or interpolation.
    pub fn effective(&self, command: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for section in ["global", command] {
            for (key, value) in self.sections.get(section).into_iter().flatten() {
                if !value.is_empty() {
                    out.insert(key.clone(), value.clone());
                }
            }
        }
        out
    }
}

pub fn pip_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "y" | "yes" | "t" | "true" | "on" | "1" => Some(true),
        "n" | "no" | "f" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_is_never_shell_interpolated_or_unquoted() {
        let p = PipConfiguration::parse(
            b"[global]\nlog = $(touch marker)\ncache_dir = \"literal\" # data\n",
        );
        assert!(p.errors.is_empty());
        assert_eq!(p.effective("list")["log"], "$(touch marker)");
        assert_eq!(p.effective("list")["cache-dir"], "\"literal\" # data");
    }
    #[test]
    fn file_order_section_order_and_empty_values_are_distinct() {
        let mut p = PipConfiguration::parse(
            b"[global]\nlog = early\ncache-dir = first\n[list]\nlog = scoped\n",
        );
        p.merge(PipConfiguration::parse(
            b"[global]\nlog = later\ncache-dir =\n[list]\nlog =\n",
        ));
        assert!(p.errors.is_empty());
        assert_eq!(p.effective("list")["log"], "later");
        assert!(!p.effective("list").contains_key("cache-dir"));
    }
    #[test]
    fn incomplete_grammar_never_proves_a_safe_prefix() {
        for bytes in [
            b"log=x".as_slice(),
            b"[global]\nlog=x\n log=y",
            b"[global]\nlog=x\nlog=y",
            b"[global]\nlog=x\n[global]\nquiet=true",
            b"[DEFAULT]\nlog=x\n[list]\nquiet=true",
            b"[global]\nlog=x\nmalformed",
            b"[global]\nlog=\xff",
            b"[global]\nlog=x\0",
        ] {
            assert!(
                !PipConfiguration::parse(bytes).errors.is_empty(),
                "{bytes:?}"
            );
        }
    }
}
