//! Bounded APT configuration data. No Shell evaluation, process probes or authority.
use crate::{ConfigurationOption, ConfigurationParse, ConfigurationParseError};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Value(String),
    Open,
    Close,
    End,
}

pub fn parse_apt_configuration(bytes: &[u8]) -> ConfigurationParse {
    let mut out = ConfigurationParse::default();
    let parsed = (|| -> Result<(), String> {
        if bytes.len() > 65536 || bytes.contains(&0) {
            return Err("APT configuration byte budget or NUL".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "APT configuration is not UTF-8")?;
        let mut tokens = Vec::new();
        let mut chars = text.chars().peekable();
        let mut line = 1;
        while let Some(c) = chars.next() {
            if c == '\n' {
                line += 1;
                continue;
            }
            if c.is_whitespace() {
                continue;
            }
            if c == '#' {
                let tail: String = chars.by_ref().take_while(|c| *c != '\n').collect();
                let directive = tail.trim_start().to_ascii_lowercase();
                if directive.starts_with("include") || directive.starts_with("clear") {
                    return Err("APT #include/#clear is not modeled".into());
                }
                line += 1;
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                chars.next();
                for c in chars.by_ref() {
                    if c == '\n' {
                        line += 1;
                        break;
                    }
                }
                continue;
            }
            if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    if c == '\n' {
                        line += 1
                    }
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err("unterminated APT comment".into());
                }
                continue;
            }
            let token = match c {
                '{' => Token::Open,
                '}' => Token::Close,
                ';' => Token::End,
                '"' => {
                    let mut value = String::new();
                    let mut closed = false;
                    for c in chars.by_ref() {
                        if c == '"' {
                            closed = true;
                            break;
                        }
                        if matches!(c, '\\' | '\n' | '\r') {
                            return Err("APT escaped or multiline value is unsupported".into());
                        }
                        value.push(c);
                        if value.len() > 16384 {
                            return Err("APT value budget exceeded".into());
                        }
                    }
                    if !closed {
                        return Err("unterminated APT string".into());
                    }
                    Token::Value(value)
                }
                _ => {
                    let valid = |c: char| c.is_ascii_alphanumeric() || "/-:._+".contains(c);
                    if !valid(c) {
                        return Err(format!("unsupported APT syntax: {c}"));
                    }
                    let mut word = String::from(c);
                    while chars.peek().is_some_and(|c| valid(*c)) {
                        word.push(chars.next().unwrap())
                    }
                    if word.len() > 256 {
                        return Err("APT key budget exceeded".into());
                    }
                    Token::Word(word.to_ascii_lowercase())
                }
            };
            tokens.push((token, line));
            if tokens.len() > 8192 {
                return Err("APT token budget exceeded".into());
            }
        }
        fn block(
            tokens: &[(Token, usize)],
            i: &mut usize,
            prefix: &str,
            depth: usize,
            out: &mut ConfigurationParse,
        ) -> Result<(), String> {
            if depth > 8 {
                return Err("APT scope depth exceeded".into());
            }
            while *i < tokens.len() {
                let (token, line) = &tokens[*i];
                let line = *line;
                *i += 1;
                if *token == Token::Close {
                    if depth == 0 {
                        return Err("unexpected APT closing scope".into());
                    }
                    return Ok(());
                }
                let key = match token {
                    Token::Word(word) => {
                        if prefix.is_empty() {
                            word.clone()
                        } else {
                            format!("{prefix}::{word}")
                        }
                    }
                    Token::Value(value) if !prefix.is_empty() => {
                        if tokens.get(*i).map(|t| &t.0) != Some(&Token::End) {
                            return Err("APT list item lacks semicolon".into());
                        }
                        *i += 1;
                        out.options.push(ConfigurationOption {
                            option: "-o".into(),
                            argument: Some(format!("{prefix}::={value}")),
                            line,
                        });
                        if out.options.len() > 2048 {
                            return Err("APT option budget exceeded".into());
                        }
                        continue;
                    }
                    _ => return Err("APT configuration requires a key or scoped list value".into()),
                };
                match tokens.get(*i).map(|t| &t.0) {
                    Some(Token::Value(value)) => {
                        let value = value.clone();
                        *i += 1;
                        if tokens.get(*i).map(|t| &t.0) != Some(&Token::End) {
                            return Err("APT assignment lacks semicolon".into());
                        }
                        *i += 1;
                        out.options.push(ConfigurationOption {
                            option: "-o".into(),
                            argument: Some(format!("{key}={value}")),
                            line,
                        });
                    }
                    Some(Token::Open) => {
                        *i += 1;
                        block(tokens, i, &key, depth + 1, out)?;
                        if tokens.get(*i).map(|t| &t.0) != Some(&Token::End) {
                            return Err("APT scope lacks semicolon".into());
                        }
                        *i += 1;
                    }
                    _ => return Err("APT assignment requires quoted value or scope".into()),
                }
                if out.options.len() > 2048 {
                    return Err("APT option budget exceeded".into());
                }
            }
            if depth != 0 {
                return Err("unterminated APT scope".into());
            }
            Ok(())
        }
        block(&tokens, &mut 0, "", 0, &mut out)
    })();
    if let Err(detail) = parsed {
        out.errors.push(ConfigurationParseError { line: 0, detail })
    }
    out
}

/// Ordered data merge. Unknown keys are retained as gaps, never treated as safe.
#[derive(Debug, Clone)]
pub struct AptConfiguration {
    pub values: BTreeMap<String, String>,
    pub errors: Vec<String>,
}
impl Default for AptConfiguration {
    fn default() -> Self {
        Self {
            values: [
                ("dir", "/"),
                ("dir::etc", "etc/apt"),
                ("dir::etc::parts", "apt.conf.d"),
                ("dir::etc::main", "apt.conf"),
                ("dir::state", "var/lib/apt"),
                ("dir::state::lists", "lists"),
                ("dir::state::status", "/var/lib/dpkg/status"),
                ("dir::cache", "var/cache/apt"),
                ("dir::cache::archives", "archives"),
                ("dir::log", "var/log/apt"),
                ("apt::get::download-only", "false"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
            errors: Vec::new(),
        }
    }
}
impl AptConfiguration {
    pub fn apply(&mut self, option: &str) {
        let Some((key, value)) = option.split_once('=') else {
            self.error("APT option is not key=value");
            return;
        };
        let key = key.to_ascii_lowercase();
        let hooks = [
            "apt::update::pre-invoke",
            "apt::update::post-invoke",
            "apt::update::post-invoke-success",
            "dpkg::pre-invoke",
            "dpkg::post-invoke",
            "dpkg::pre-install-pkgs",
        ];
        if hooks
            .iter()
            .any(|h| key == *h || key.starts_with(&format!("{h}::")))
        {
            self.error("APT execution hook requires separate approval");
            return;
        }
        let path = matches!(
            key.as_str(),
            "dir"
                | "dir::etc"
                | "dir::etc::parts"
                | "dir::etc::main"
                | "dir::state"
                | "dir::state::lists"
                | "dir::state::status"
                | "dir::state::extended_states"
                | "dir::cache"
                | "dir::cache::archives"
                | "dir::cache::pkgcache"
                | "dir::cache::srcpkgcache"
                | "dir::log"
                | "dir::log::history"
                | "dir::log::terminal"
        );
        let boolean = matches!(
            key.as_str(),
            "apt::get::download-only"
                | "apt::get::assume-yes"
                | "apt::install-recommends"
                | "apt::install-suggests"
                | "debug::nolocking"
                | "apt::color"
                | "acquire::changelogs::alwaysonline"
                | "acquire::gzipindexes"
                | "apt::autoremove::suggestsimportant"
                | "apt::protect-kernels"
        );
        let numeric = matches!(
            key.as_str(),
            "acquire::retries" | "apt::periodic::enable" | "apt::neverautoremove::kernelcount"
        );
        // Native data selectors cannot erase independent import/deletion effects.
        let data_list = matches!(
            key.trim_end_matches("::"),
            "apt::neverautoremove"
                | "apt::versionedkernelpackages"
                | "apt::never-markauto-sections"
                | "apt::move-autobit-sections"
                | "acquire::languages"
        );
        let compression_order = key.trim_end_matches("::") == "acquire::compressiontypes::order"
            && matches!(
                value,
                "gz" | "bz2" | "xz" | "lzma" | "lz4" | "zst" | "uncompressed"
            );
        let disabled_cache = value.is_empty()
            && matches!(
                key.as_str(),
                "dir::cache::pkgcache" | "dir::cache::srcpkgcache"
            );
        if (!path && !boolean && !numeric && !data_list && !compression_order)
            || (boolean && bool_value(value).is_none())
            || (numeric && value.parse::<u32>().ok().filter(|v| *v <= 1000).is_none())
            || (path && value.is_empty() && !disabled_cache)
            || ((data_list || compression_order)
                && (value.len() > 4096 || value.contains(['\n', '\r'])))
            || value.contains('\0')
            || value.len() > 16384
        {
            self.error(&format!(
                "APT configuration key or value is unmodeled: {key}"
            ));
            return;
        }
        self.values.insert(key, value.into());
    }
    pub fn download_only(&self) -> Option<bool> {
        bool_value(self.values.get("apt::get::download-only")?)
    }
    pub fn error(&mut self, s: &str) {
        if self.errors.len() < 64 {
            self.errors.push(s.into())
        }
    }
    pub fn path(&self, key: &str, cwd: &str) -> Option<String> {
        fn join(base: &str, path: &str) -> String {
            if path.starts_with('/') {
                path.into()
            } else {
                format!("{}/{path}", base.trim_end_matches('/'))
            }
        }
        let value = self.values.get(key)?;
        let parent = key.rsplit_once("::").map(|p| p.0);
        let base = if let Some(parent) = parent {
            self.path(parent, cwd)?
        } else {
            cwd.into()
        };
        if value.is_empty() {
            Some(String::new())
        } else {
            Some(join(&base, value))
        }
    }
    pub fn package_outputs(&self, operation: &str, cwd: &str) -> Option<Vec<String>> {
        let keys: &[&str] = match operation {
            "download" => return Some(vec![cwd.into()]),
            "update" => &["dir::state", "dir::cache"],
            "install" if self.download_only() == Some(true) => {
                &["dir::state", "dir::cache", "dir::log"]
            }
            "install" => return None,
            _ => return Some(Vec::new()),
        };
        let mut paths = keys
            .iter()
            .map(|k| self.path(k, cwd))
            .collect::<Option<Vec<_>>>()?;
        if operation == "install" {
            let status = self.path("dir::state::status", cwd)?;
            paths.push(status.rsplit_once('/')?.0.into()); // Includes dpkg lock/transaction paths.
        }
        // Absolute child overrides are independent roots, not confined by parents.
        for (key, _) in self.values.iter().filter(|(k, _)| {
            k.starts_with("dir::state::")
                || k.starts_with("dir::cache::")
                || (operation == "install" && k.starts_with("dir::log::"))
        }) {
            if key == "dir::state::status" && operation != "install" {
                continue;
            }
            let path = self.path(key, cwd)?;
            if !path.is_empty() {
                let directory =
                    matches!(key.as_str(), "dir::state::lists" | "dir::cache::archives");
                let root = if directory {
                    path
                } else {
                    path.rsplit_once('/').map(|p| p.0.to_owned())?
                };
                paths.push(root)
            }
        }
        if paths.iter().any(|p| p.is_empty()) {
            return None;
        }
        paths.sort();
        paths.dedup();
        // One closed parent family subsumes its child output roots. Do not
        // normalize parent components or replace namespace proof with strings.
        let minimal = paths
            .iter()
            .filter(|path| {
                !paths.iter().any(|root| {
                    root != *path
                        && !root.split('/').any(|c| matches!(c, "." | ".."))
                        && path
                            .strip_prefix(root.trim_end_matches('/'))
                            .is_some_and(|p| p.starts_with('/'))
                })
            })
            .cloned()
            .collect();
        Some(minimal)
    }
}
fn bool_value(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
