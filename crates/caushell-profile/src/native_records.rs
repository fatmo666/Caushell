use crate::{ResolvedInvocationArtifact, StdoutRecordSyntax, argument_structure};
use caushell_types::{DirectoryEntryKind, MAX_DIRECTORY_DEPTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePathPredicate {
    Name { pattern: String, insensitive: bool },
    Path { pattern: String, insensitive: bool },
    Kind(DirectoryEntryKind),
    Constant(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRecordFormat {
    Line,
    Nul,
    Format(Vec<NativeFormatPart>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFormatPart {
    Literal(Vec<u8>),
    Path,
    RelativePath,
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePathOutputPlan {
    pub roots: Vec<String>,
    pub min_depth: usize,
    pub max_depth: Option<usize>,
    pub predicates: Vec<NativePathPredicate>,
    pub output: Vec<NativeRecordFormat>,
}

impl ResolvedInvocationArtifact {
    /// The adapter validates its full native argv; symbolic record conditions
    /// are a separate proof and cannot certify concrete output bytes.
    pub fn native_stdout_record_plan(&self) -> Option<Result<NativePathOutputPlan, String>> {
        let syntax = self.bound.stdout_records.as_ref()?.native?;
        Some((|| {
            self.proven_stream_contract()
                .ok_or("producer invocation is incomplete")?;
            let argv = self
                .materialized_projection
                .invocation
                .args
                .iter()
                .map(|a| argument_structure(a).exact_value().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or("producer argv is incomplete")?;
            match syntax {
                StdoutRecordSyntax::Find => NativePathOutputPlan::find(&argv),
            }
            .map_err(String::from)
        })())
    }
}

impl NativePathOutputPlan {
    pub fn find(argv: &[String]) -> Result<Self, &'static str> {
        if argv.len() > 256 || argv.iter().any(|a| a.len() > 4096 || a.contains('\0')) {
            return Err("producer argv budget exceeded");
        }
        let mut args = argv.iter().map(String::as_str).peekable();
        while args.peek() == Some(&"-P") {
            args.next();
        }
        if args.peek() == Some(&"--") {
            args.next();
        }
        let mut roots = Vec::new();
        while args
            .peek()
            .is_some_and(|a| !a.starts_with('-') && !matches!(*a, "!" | "(" | ")" | ","))
        {
            let root = args.next().unwrap();
            if root.is_empty() {
                return Err("empty search root");
            }
            roots.push(root.into());
        }
        if roots.is_empty() {
            roots.push(".".into());
        }
        let mut plan = Self {
            roots,
            min_depth: 0,
            max_depth: None,
            predicates: Vec::new(),
            output: Vec::new(),
        };
        let mut needs_test = false;
        while let Some(word) = args.next() {
            let mut predicate = None;
            match word {
                "-a" | "-and"
                    if !plan.predicates.is_empty() && !needs_test && plan.output.is_empty() =>
                {
                    needs_test = true;
                    continue;
                }
                "-name" | "-iname" | "-path" | "-ipath" => {
                    let pattern = args.next().ok_or("missing name pattern")?;
                    // No locale-sensitive classes, ranges, '?' or escapes.
                    if !pattern.is_ascii() || pattern.contains(['[', ']', '?', '\\']) {
                        return Err("unsupported native name pattern");
                    }
                    let insensitive = matches!(word, "-iname" | "-ipath");
                    predicate = Some(if matches!(word, "-name" | "-iname") {
                        NativePathPredicate::Name {
                            pattern: pattern.into(),
                            insensitive,
                        }
                    } else {
                        NativePathPredicate::Path {
                            pattern: pattern.into(),
                            insensitive,
                        }
                    });
                }
                "-type" => {
                    predicate = Some(NativePathPredicate::Kind(match args.next() {
                        Some("f") => DirectoryEntryKind::File,
                        Some("d") => DirectoryEntryKind::Directory,
                        Some("l") => DirectoryEntryKind::Symlink,
                        _ => return Err("unsupported native type test"),
                    }))
                }
                "-true" | "-false" => {
                    predicate = Some(NativePathPredicate::Constant(word == "-true"))
                }
                "-mindepth" | "-maxdepth" if plan.output.is_empty() => {
                    let value = args
                        .next()
                        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                        .and_then(|v| v.parse::<usize>().ok())
                        .filter(|v| *v <= MAX_DIRECTORY_DEPTH)
                        .ok_or("unsupported traversal depth")?;
                    if word == "-mindepth" {
                        plan.min_depth = value;
                    } else {
                        plan.max_depth = Some(value);
                    }
                }
                "-print" => plan.output.push(NativeRecordFormat::Line),
                "-print0" => plan.output.push(NativeRecordFormat::Nul),
                "-printf" => plan.output.push(NativeRecordFormat::Format(format_parts(
                    args.next().ok_or("missing output format")?,
                )?)),
                _ => return Err("unsupported native output expression"),
            }
            if let Some(predicate) = predicate {
                if !plan.output.is_empty() {
                    return Err("predicate follows output action");
                }
                plan.predicates.push(predicate);
                needs_test = false;
            } else if needs_test {
                return Err("incomplete conjunction");
            }
        }
        if needs_test {
            return Err("incomplete conjunction");
        }
        if plan.output.is_empty() {
            plan.output.push(NativeRecordFormat::Line);
        }
        Ok(plan)
    }

    pub fn accepts(
        &self,
        path: &str,
        name: &str,
        kind: DirectoryEntryKind,
        depth: usize,
    ) -> Result<bool, &'static str> {
        if depth < self.min_depth {
            return Ok(false);
        }
        for test in &self.predicates {
            let matched = match test {
                NativePathPredicate::Constant(v) => *v,
                NativePathPredicate::Kind(v) => *v == kind,
                NativePathPredicate::Name {
                    pattern,
                    insensitive,
                } => glob(pattern, name, *insensitive)?,
                NativePathPredicate::Path {
                    pattern,
                    insensitive,
                } => glob(pattern, path, *insensitive)?,
            };
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn encode(&self, path: &str, relative: &str, name: &str) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
            if out.len().saturating_add(bytes.len()) > caushell_types::MAX_OBSERVED_STREAM_BYTES {
                return Err("producer byte budget exceeded");
            }
            out.extend_from_slice(bytes);
            Ok(())
        }
        for format in &self.output {
            match format {
                NativeRecordFormat::Line => {
                    append(&mut out, path.as_bytes())?;
                    append(&mut out, b"\n")?;
                }
                NativeRecordFormat::Nul => {
                    append(&mut out, path.as_bytes())?;
                    append(&mut out, b"\0")?;
                }
                NativeRecordFormat::Format(parts) => {
                    for part in parts {
                        append(
                            &mut out,
                            match part {
                                NativeFormatPart::Literal(bytes) => bytes,
                                NativeFormatPart::Path => path.as_bytes(),
                                NativeFormatPart::RelativePath => relative.as_bytes(),
                                NativeFormatPart::Name => name.as_bytes(),
                            },
                        )?;
                    }
                }
            }
        }
        Ok(out)
    }
}

fn glob(pattern: &str, value: &str, insensitive: bool) -> Result<bool, &'static str> {
    if insensitive && !value.is_ascii() {
        return Err("case folding locale is unobserved");
    }
    let (pattern, value) = if insensitive {
        (pattern.to_ascii_lowercase(), value.to_ascii_lowercase())
    } else {
        (pattern.into(), value.into())
    };
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return Ok(pattern == value);
    }
    let Some(mut remaining) = value.strip_prefix(parts[0]) else {
        return Ok(false);
    };
    let Some(without_suffix) = remaining.strip_suffix(parts[parts.len() - 1]) else {
        return Ok(false);
    };
    remaining = without_suffix;
    for part in &parts[1..parts.len() - 1] {
        let Some(position) = remaining.find(part) else {
            return Ok(false);
        };
        remaining = &remaining[position + part.len()..];
    }
    Ok(true)
}

fn format_parts(format: &str) -> Result<Vec<NativeFormatPart>, &'static str> {
    let mut parts = Vec::new();
    let mut literal = Vec::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let part = match chars.next() {
                    Some('%') => {
                        literal.push(b'%');
                        continue;
                    }
                    Some('p') => NativeFormatPart::Path,
                    Some('P') => NativeFormatPart::RelativePath,
                    Some('f') => NativeFormatPart::Name,
                    _ => return Err("unsupported native output directive"),
                };
                if !literal.is_empty() {
                    parts.push(NativeFormatPart::Literal(std::mem::take(&mut literal)));
                }
                parts.push(part);
            }
            '\\' => literal.push(match chars.next() {
                Some('\\') => b'\\',
                Some('a') => 7,
                Some('b') => 8,
                Some('f') => 12,
                Some('n') => b'\n',
                Some('r') => b'\r',
                Some('t') => b'\t',
                Some('v') => 11,
                Some(d @ '0'..='7') => {
                    let mut n = d.to_digit(8).unwrap();
                    for _ in 0..2 {
                        if let Some(d) = chars.peek().and_then(|c| c.to_digit(8)) {
                            n = n * 8 + d;
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if n > 255 {
                        return Err("output escape exceeds a byte");
                    }
                    n as u8
                }
                _ => return Err("unsupported native output escape"),
            }),
            c => {
                let mut bytes = [0; 4];
                literal.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
    if !literal.is_empty() {
        parts.push(NativeFormatPart::Literal(literal));
    }
    Ok(parts)
}
