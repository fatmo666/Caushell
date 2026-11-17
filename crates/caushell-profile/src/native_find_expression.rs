//! A bounded find expression, preserving short-circuit actions and traversal.
use crate::native_records::{NativePathPredicate, NativeRecordFormat, format_parts, glob};
use caushell_types::{DirectoryEntryKind, MAX_DIRECTORY_DEPTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expression {
    Test(NativePathPredicate),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Output(NativeRecordFormat),
    Prune,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NativeFindEvaluation {
    pub bytes: Vec<u8>,
    pub emitted: bool,
    pub prune: bool,
}

pub(crate) struct ParsedFind {
    pub roots: Vec<String>,
    pub min_depth: usize,
    pub max_depth: Option<usize>,
    pub expression: Expression,
}

impl Expression {
    pub(crate) fn record_encoding(&self) -> caushell_types::StreamRecordEncoding {
        fn visit(expression: &Expression, nul: &mut bool, line: &mut bool) {
            match expression {
                Expression::Output(format) => {
                    *nul &= matches!(format, NativeRecordFormat::Nul);
                    *line &= matches!(format, NativeRecordFormat::Line);
                }
                Expression::And(a, b) | Expression::Or(a, b) => {
                    visit(a, nul, line);
                    visit(b, nul, line);
                }
                Expression::Not(a) => visit(a, nul, line),
                _ => {}
            }
        }
        let (mut nul, mut line) = (true, true);
        visit(self, &mut nul, &mut line);
        if nul {
            caushell_types::StreamRecordEncoding::Nul
        } else if line {
            caushell_types::StreamRecordEncoding::Lines
        } else {
            caushell_types::StreamRecordEncoding::NativeFormat
        }
    }

    pub(crate) fn needs_case_locale(&self) -> bool {
        match self {
            Self::Test(
                NativePathPredicate::Name {
                    insensitive: true, ..
                }
                | NativePathPredicate::Path {
                    insensitive: true, ..
                },
            ) => true,
            Self::And(a, b) | Self::Or(a, b) => a.needs_case_locale() || b.needs_case_locale(),
            Self::Not(a) => a.needs_case_locale(),
            _ => false,
        }
    }

    pub(crate) fn evaluate(
        &self,
        path: &str,
        relative: &str,
        name: &str,
        kind: DirectoryEntryKind,
        result: &mut NativeFindEvaluation,
    ) -> Result<bool, &'static str> {
        Ok(match self {
            Self::Test(test) => match test {
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
            },
            Self::And(a, b) => {
                a.evaluate(path, relative, name, kind, result)?
                    && b.evaluate(path, relative, name, kind, result)?
            }
            Self::Or(a, b) => {
                a.evaluate(path, relative, name, kind, result)?
                    || b.evaluate(path, relative, name, kind, result)?
            }
            Self::Not(a) => !a.evaluate(path, relative, name, kind, result)?,
            Self::Prune => {
                result.prune = true;
                true
            }
            Self::Output(format) => {
                crate::native_records::encode_format(
                    format,
                    path,
                    relative,
                    name,
                    &mut result.bytes,
                )?;
                result.emitted = true;
                true
            }
        })
    }
}

struct Parser<'a> {
    argv: &'a [String],
    at: usize,
    min_depth: usize,
    max_depth: Option<usize>,
    has_output: bool,
}
impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.argv.get(self.at).map(String::as_str)
    }
    fn take(&mut self) -> Result<&str, &'static str> {
        let word = self.argv.get(self.at).ok_or("missing expression operand")?;
        self.at += 1;
        Ok(word)
    }
    fn or(&mut self) -> Result<Expression, &'static str> {
        let mut lhs = self.and()?;
        while matches!(self.peek(), Some("-o" | "-or")) {
            self.at += 1;
            lhs = Expression::Or(Box::new(lhs), Box::new(self.and()?));
        }
        Ok(lhs)
    }
    fn and(&mut self) -> Result<Expression, &'static str> {
        let mut lhs = self.primary()?;
        loop {
            match self.peek() {
                None | Some(")" | "," | "-o" | "-or") => break,
                Some("-a" | "-and") => self.at += 1,
                _ => {} // Adjacency has the same precedence as explicit AND.
            }
            lhs = Expression::And(Box::new(lhs), Box::new(self.primary()?));
        }
        Ok(lhs)
    }
    fn primary(&mut self) -> Result<Expression, &'static str> {
        let word = self.take()?.to_owned();
        Ok(match word.as_str() {
            "!" | "-not" => Expression::Not(Box::new(self.primary()?)),
            "(" => {
                let inner = self.or()?;
                if self.take()? != ")" {
                    return Err("unclosed native expression group");
                }
                inner
            }
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                let pattern = self.take()?.to_owned();
                if !pattern.is_ascii() || pattern.contains(['[', ']', '?', '\\']) {
                    return Err("unsupported native name pattern");
                }
                let insensitive = matches!(word.as_str(), "-iname" | "-ipath" | "-iwholename");
                Expression::Test(if matches!(word.as_str(), "-name" | "-iname") {
                    NativePathPredicate::Name {
                        pattern,
                        insensitive,
                    }
                } else {
                    NativePathPredicate::Path {
                        pattern,
                        insensitive,
                    }
                })
            }
            "-type" => Expression::Test(NativePathPredicate::Kind(match self.take()? {
                "f" => DirectoryEntryKind::File,
                "d" => DirectoryEntryKind::Directory,
                "l" => DirectoryEntryKind::Symlink,
                _ => return Err("unsupported native type test"),
            })),
            "-true" | "-false" => Expression::Test(NativePathPredicate::Constant(word == "-true")),
            "-mindepth" | "-maxdepth" => {
                let token = self.take()?;
                let value = (!token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| token.parse::<usize>().ok())
                    .flatten()
                    .filter(|v| *v <= MAX_DIRECTORY_DEPTH)
                    .ok_or("unsupported traversal depth")?;
                if word == "-mindepth" {
                    self.min_depth = value;
                } else {
                    self.max_depth = Some(value);
                }
                // Traversal options apply globally, even on an unevaluated branch.
                Expression::Test(NativePathPredicate::Constant(true))
            }
            "-prune" => Expression::Prune,
            "-print" | "-print0" | "-printf" => {
                let format = match word.as_str() {
                    "-print" => NativeRecordFormat::Line,
                    "-print0" => NativeRecordFormat::Nul,
                    _ => NativeRecordFormat::Format(format_parts(self.take()?)?),
                };
                self.has_output = true;
                Expression::Output(format)
            }
            _ => return Err("unsupported native output expression"),
        })
    }
}

pub(crate) fn parse(argv: &[String]) -> Result<ParsedFind, &'static str> {
    if argv.len() > 256 || argv.iter().any(|a| a.len() > 4096 || a.contains('\0')) {
        return Err("producer argv budget exceeded");
    }
    let mut parser = Parser {
        argv,
        at: 0,
        min_depth: 0,
        max_depth: None,
        has_output: false,
    };
    while parser.peek() == Some("-P") {
        parser.at += 1;
    }
    if parser.peek() == Some("--") {
        parser.at += 1;
    }
    let mut roots = Vec::new();
    while parser
        .peek()
        .is_some_and(|a| !a.starts_with('-') && !matches!(a, "!" | "(" | ")" | ","))
    {
        let root = parser.take()?;
        if root.is_empty() {
            return Err("empty search root");
        }
        roots.push(root.to_owned());
    }
    if roots.is_empty() {
        roots.push(".".into());
    }
    let mut expression = if parser.peek().is_none() {
        Expression::Test(NativePathPredicate::Constant(true))
    } else {
        parser.or()?
    };
    if parser.peek().is_some() {
        return Err("trailing native expression token");
    }
    // A prune action alone does not suppress find's implicit print. Any explicit
    // output suppresses it globally, including output on an unvisited branch.
    if !parser.has_output {
        expression = Expression::And(
            Box::new(expression),
            Box::new(Expression::Output(NativeRecordFormat::Line)),
        );
    }
    Ok(ParsedFind {
        roots,
        min_depth: parser.min_depth,
        max_depth: parser.max_depth,
        expression,
    })
}
