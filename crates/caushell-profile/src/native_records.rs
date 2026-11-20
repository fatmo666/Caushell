use crate::native_find_expression::{self, Expression, NativeFindEvaluation};
use crate::{ResolvedInvocationArtifact, StdoutRecordSyntax, argument_structure};
use caushell_types::DirectoryEntryKind;

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
    expression: Expression,
}

impl ResolvedInvocationArtifact {
    /// The adapter validates its full native argv; symbolic record conditions
    /// are a separate proof and cannot certify concrete output bytes.
    pub fn native_stdout_record_plan(&self) -> Option<Result<NativePathOutputPlan, String>> {
        self.native_stdout_record_plan_with_variant(None)
    }

    /// Variant evidence must describe this invocation's executable.
    pub fn native_stdout_record_plan_with_variant(
        &self,
        native_variant: Option<&str>,
    ) -> Option<Result<NativePathOutputPlan, String>> {
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
                StdoutRecordSyntax::Find => {
                    NativePathOutputPlan::find_with_variant(&argv, native_variant)
                }
            }
            .map_err(String::from)
        })())
    }
}

impl NativePathOutputPlan {
    pub fn find(argv: &[String]) -> Result<Self, &'static str> {
        Self::find_with_variant(argv, None)
    }

    fn find_with_variant(argv: &[String], native_variant: Option<&str>) -> Result<Self, &'static str> {
        let parsed = native_find_expression::parse(argv, native_variant == Some("apple_find"))?;
        Ok(Self {
            roots: parsed.roots,
            min_depth: parsed.min_depth,
            max_depth: parsed.max_depth,
            expression: parsed.expression,
        })
    }

    pub fn record_encoding(&self) -> caushell_types::StreamRecordEncoding {
        self.expression.record_encoding()
    }

    /// Prove absence of output without assuming any directory contents.
    pub fn output_is_unreachable(&self) -> bool {
        !self.expression.output_reachability().1
    }

    pub fn stays_on_device(&self) -> bool {
        self.expression.stays_on_device()
    }

    pub fn needs_case_locale(&self) -> bool {
        self.expression.needs_case_locale()
    }

    /// A completed observation only short-circuited these metadata tests.
    /// It did not establish the metadata needed for the producer's full domain.
    pub fn contains_metadata_test(&self) -> bool {
        self.expression.contains_metadata_test(None)
    }

    /// One evaluation owns both predicate control flow and the bytes/actions it
    /// actually executes. Callers must not combine a flattened filter with an
    /// unconditional encoder.
    pub fn evaluate(
        &self,
        path: &str,
        relative: &str,
        name: &str,
        kind: DirectoryEntryKind,
        depth: usize,
    ) -> Result<NativeFindEvaluation, &'static str> {
        self.evaluate_with_case_fold(path, relative, name, kind, depth, true)
    }

    /// A caller without a locale proof may still evaluate paths that never
    /// reach a case-insensitive predicate.
    pub fn evaluate_with_case_fold(
        &self,
        path: &str,
        relative: &str,
        name: &str,
        kind: DirectoryEntryKind,
        depth: usize,
        case_fold_proven: bool,
    ) -> Result<NativeFindEvaluation, &'static str> {
        if kind == DirectoryEntryKind::Symlink && self.expression.follows_symlinks() {
            // The directory evidence describes the link entry, not its
            // referent, its type, or the subtree that find could traverse.
            return Err("followed symlink target is not observed");
        }
        let mut result = NativeFindEvaluation::default();
        if depth >= self.min_depth {
            self.expression
                .evaluate(path, relative, name, kind, case_fold_proven, &mut result)?;
        }
        // find parses reference dates before traversal, even on a branch
        // that the expression evaluator never reaches.
        if result.emitted && self.expression.contains_metadata_test(Some("-newermt")) {
            return Err("native reference date parsing is unproved");
        }
        Ok(result)
    }
}

pub(super) fn encode_format(
    format: &NativeRecordFormat,
    path: &str,
    relative: &str,
    name: &str,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
        if out.len().saturating_add(bytes.len()) > caushell_types::MAX_OBSERVED_STREAM_BYTES {
            return Err("producer byte budget exceeded");
        }
        out.extend_from_slice(bytes);
        Ok(())
    }
    match format {
        NativeRecordFormat::Line => {
            append(out, path.as_bytes())?;
            append(out, b"\n")?;
        }
        NativeRecordFormat::Nul => {
            append(out, path.as_bytes())?;
            append(out, b"\0")?;
        }
        NativeRecordFormat::Format(parts) => {
            for part in parts {
                append(
                    out,
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
    Ok(())
}

pub(super) fn glob(pattern: &str, value: &str, insensitive: bool) -> Result<bool, &'static str> {
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

pub(super) fn format_parts(format: &str) -> Result<Vec<NativeFormatPart>, &'static str> {
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
