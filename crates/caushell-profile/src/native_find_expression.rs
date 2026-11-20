//! A bounded find expression, preserving short-circuit actions and traversal.
use crate::native_records::{NativePathPredicate, NativeRecordFormat, format_parts, glob};
use caushell_types::{DirectoryEntryKind, MAX_DIRECTORY_DEPTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expression {
    Test(NativePathPredicate),
    MetadataTest { test: String, operand: String },
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Output(NativeRecordFormat),
    Prune,
    FollowLinks,
    StayOnDevice,
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
    /// A missing truth value stands for either result. Output remains visible
    /// even when a later predicate makes the whole expression false.
    pub(crate) fn output_reachability(&self) -> (Option<bool>, bool) {
        match self {
            Self::Test(NativePathPredicate::Constant(value)) => (Some(*value), false),
            Self::Test(_) | Self::MetadataTest { .. } => (None, false),
            Self::Output(_) => (Some(true), true),
            Self::Prune | Self::FollowLinks | Self::StayOnDevice => (Some(true), false),
            Self::Not(inner) => {
                let (truth, emits) = inner.output_reachability();
                (truth.map(|value| !value), emits)
            }
            Self::And(left, right) | Self::Or(left, right) => {
                let short_circuit = matches!(self, Self::Or(..));
                let (left_truth, left_emits) = left.output_reachability();
                if left_truth == Some(short_circuit) {
                    return (left_truth, left_emits);
                }
                let (right_truth, right_emits) = right.output_reachability();
                let truth = if left_truth.is_some() || right_truth == Some(short_circuit) {
                    right_truth
                } else {
                    None
                };
                (truth, left_emits || right_emits)
            }
        }
    }

    /// This traversal setting takes effect while parsing the whole expression,
    /// even if the evaluator later short-circuits the branch containing it.
    pub(crate) fn follows_symlinks(&self) -> bool {
        match self {
            Self::FollowLinks => true,
            Self::And(a, b) | Self::Or(a, b) => a.follows_symlinks() || b.follows_symlinks(),
            Self::Not(inner) => inner.follows_symlinks(),
            _ => false,
        }
    }

    /// This primary controls descent even when its Boolean branch is skipped.
    pub(crate) fn stays_on_device(&self) -> bool {
        match self {
            Self::StayOnDevice => true,
            Self::And(left, right) | Self::Or(left, right) => {
                left.stays_on_device() || right.stays_on_device()
            }
            Self::Not(inner) => inner.stays_on_device(),
            _ => false,
        }
    }

    fn disable_pruning(&mut self) {
        match self {
            Self::Prune => *self = Self::Test(NativePathPredicate::Constant(true)),
            Self::And(left, right) | Self::Or(left, right) => {
                left.disable_pruning();
                right.disable_pruning();
            }
            Self::Not(inner) => inner.disable_pruning(),
            _ => {}
        }
    }

    pub(crate) fn contains_metadata_test(&self, name: Option<&str>) -> bool {
        match self {
            Self::MetadataTest { test, .. } => name.is_none_or(|name| test == name),
            Self::And(a, b) | Self::Or(a, b) => {
                a.contains_metadata_test(name) || b.contains_metadata_test(name)
            }
            Self::Not(inner) => inner.contains_metadata_test(name),
            _ => false,
        }
    }

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
        case_fold_proven: bool,
        result: &mut NativeFindEvaluation,
    ) -> Result<bool, &'static str> {
        Ok(match self {
            Self::Test(test) => match test {
                NativePathPredicate::Constant(v) => *v,
                NativePathPredicate::Kind(v) => *v == kind,
                NativePathPredicate::Name {
                    pattern,
                    insensitive,
                }
                | NativePathPredicate::Path {
                    pattern,
                    insensitive,
                } => {
                    if *insensitive && !case_fold_proven {
                        return Err("native case folding locale is unobserved or unsupported");
                    }
                    let operand = if matches!(test, NativePathPredicate::Name { .. }) {
                        name
                    } else {
                        path
                    };
                    glob(pattern, operand, *insensitive)?
                }
            },
            // The syntax is closed, but the observer does not have an
            // authoritative value for this test. Only a branch that reaches
            // it loses exact output; the existing short circuit owns that.
            Self::MetadataTest { test, .. } if test == "-perm" => {
                return Err("native permission bits are unobserved");
            }
            Self::MetadataTest { test, .. } if test == "-newermt" => {
                return Err("native modification time and reference timezone are unobserved");
            }
            Self::MetadataTest { .. } => {
                return Err("native numeric metadata predicate is unobserved");
            }
            Self::And(a, b) => {
                a.evaluate(path, relative, name, kind, case_fold_proven, result)?
                    && b.evaluate(path, relative, name, kind, case_fold_proven, result)?
            }
            Self::Or(a, b) => {
                a.evaluate(path, relative, name, kind, case_fold_proven, result)?
                    || b.evaluate(path, relative, name, kind, case_fold_proven, result)?
            }
            Self::Not(a) => !a.evaluate(path, relative, name, kind, case_fold_proven, result)?,
            Self::Prune => {
                result.prune = true;
                true
            }
            Self::FollowLinks | Self::StayOnDevice => true,
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

fn numeric_metadata_operand(test: &str, operand: &str) -> bool {
    let number = operand.strip_prefix(['+', '-']).unwrap_or(operand);
    let digits = if test == "-size" {
        // This profile also serves BSD find, which rejects GNU's b/w suffixes.
        number.strip_suffix(['c', 'k', 'M', 'G']).unwrap_or(number)
    } else {
        number
    };
    // Limit the admitted syntax to bounded decimal integers. Even the
    // largest supported size multiplier stays within signed 64-bit range.
    digits.bytes().all(|b| b.is_ascii_digit()) && digits.parse::<u32>().is_ok()
}

/// Recognize the shared numeric date spelling, leaving calendar and timezone
/// interpretation to the native tool.
fn civil_time_spelling(operand: &str) -> bool {
    let shape = b"dddd-dd-dd dd:dd:dd";
    operand.len() == shape.len()
        && operand.bytes().zip(shape).all(|(actual, expected)| {
            if *expected == b'd' {
                actual.is_ascii_digit()
            } else {
                actual == *expected
            }
        })
}

/// Keep the shared octal and explicit-class symbolic subset. The slash prefix
/// is a GNU extension and cannot establish an output plan across dialects.
fn validate_permission_operand(operand: &str) -> Result<(), &'static str> {
    let mode = operand.strip_prefix(['-', '/']).unwrap_or(operand);
    let octal =
        (1..=4).contains(&mode.len()) && mode.bytes().all(|digit| matches!(digit, b'0'..=b'7'));
    let symbolic = mode.split(',').all(|clause| {
        clause
            .split_once(['=', '+', '-'])
            .is_some_and(|(who, bits)| {
                !who.is_empty()
                    && who
                        .bytes()
                        .all(|byte| matches!(byte, b'u' | b'g' | b'o' | b'a'))
                    && !bits.is_empty()
                    && bits.bytes().all(|byte| matches!(byte, b'r' | b'w' | b'x'))
            })
    });
    if !octal && !symbolic {
        return Err("unsupported native permission mode");
    }
    if operand.starts_with('/') {
        return Err("native permission mode requires a GNU find dialect proof");
    }
    Ok(())
}

struct Parser<'a> {
    argv: &'a [String],
    at: usize,
    min_depth: usize,
    max_depth: Option<usize>,
    has_output: bool,
    depth_first: bool,
    apple_leading_x: bool,
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
            "-amin" | "-atime" | "-cmin" | "-ctime" | "-mmin" | "-mtime" | "-size" => {
                let operand = self.take()?;
                if !numeric_metadata_operand(&word, operand) {
                    return Err("unsupported native numeric metadata operand");
                }
                Expression::MetadataTest {
                    test: word,
                    operand: operand.to_owned(),
                }
            }
            "-newermt" => {
                let operand = self.take()?.to_owned();
                if !civil_time_spelling(&operand) {
                    return Err("unsupported native modification-time date spelling");
                }
                Expression::MetadataTest {
                    test: word,
                    operand,
                }
            }
            "-perm" => {
                let operand = self.take()?;
                validate_permission_operand(operand)?;
                Expression::MetadataTest {
                    test: word,
                    operand: operand.to_owned(),
                }
            }
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
            "-depth" => {
                self.depth_first = true;
                Expression::Test(NativePathPredicate::Constant(true))
            }
            "-prune" => Expression::Prune,
            "-follow" => Expression::FollowLinks,
            "-xdev" | "-mount" => Expression::StayOnDevice,
            "-printf" if self.apple_leading_x => {
                return Err("Apple find does not support -printf");
            }
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

pub(crate) fn parse(argv: &[String], apple_find: bool) -> Result<ParsedFind, &'static str> {
    if argv.len() > 256 || argv.iter().any(|a| a.len() > 4096 || a.contains('\0')) {
        return Err("producer argv budget exceeded");
    }
    let mut parser = Parser {
        argv,
        at: 0,
        min_depth: 0,
        max_depth: None,
        has_output: false,
        depth_first: false,
        apple_leading_x: false,
    };
    let mut follow_descendants = false;
    let mut requires_explicit_root = false;
    while let Some(mode @ ("-H" | "-L" | "-P" | "-x")) = parser.peek() {
        if mode == "-x" {
            if !apple_find {
                return Err("leading -x requires an Apple find dialect proof");
            }
            parser.apple_leading_x = true;
        } else {
            // The last link setting wins. With -H, the observer must see a
            // real directory at the root, so descendant traversal is physical.
            follow_descendants = mode == "-L";
            requires_explicit_root |= mode != "-P";
        }
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
    let implicit_root = roots.is_empty();
    if implicit_root {
        if parser.apple_leading_x {
            return Err("native device traversal requires an explicit starting point");
        }
        if requires_explicit_root {
            return Err("native link mode requires an explicit search root");
        }
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
    if parser.depth_first {
        if implicit_root {
            // BSD find has no implicit starting point.
            return Err("native depth traversal requires an explicit starting point");
        }
        // The observer proves a record set and does not promise traversal order.
        // In depth-first find, -prune still tests true after visiting children.
        expression.disable_pruning();
    }
    if implicit_root && expression.stays_on_device() {
        return Err("native device traversal requires an explicit starting point");
    }
    if parser.apple_leading_x {
        expression = Expression::And(Box::new(Expression::StayOnDevice), Box::new(expression));
    }
    if follow_descendants {
        expression = Expression::And(Box::new(Expression::FollowLinks), Box::new(expression));
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

#[cfg(test)]
mod depth_tests {
    use super::*;

    fn evaluation(arguments: &[&str], path: &str) -> NativeFindEvaluation {
        let mut argv = vec![".".to_owned()];
        argv.extend(arguments.iter().map(|word| (*word).to_owned()));
        let name = path.rsplit('/').next().unwrap();
        let mut result = NativeFindEvaluation::default();
        parse(&argv, false)
            .expect("recognize the traversal expression")
            .expression
            .evaluate(
                path,
                path,
                name,
                DirectoryEntryKind::Directory,
                true,
                &mut result,
            )
            .unwrap();
        result
    }

    #[test]
    fn depth_disables_pruning_but_preserves_its_true_result() {
        let ordinary = evaluation(&["-name", "skip", "-prune", "-o", "-print0"], "./skip");
        assert!(ordinary.prune);
        assert!(!ordinary.emitted);

        let depth = ["-depth", "-name", "skip", "-prune", "-o", "-print0"];
        let directory = evaluation(&depth, "./skip");
        assert!(!directory.prune);
        assert!(!directory.emitted);
        let child = evaluation(&depth, "./skip/nested");
        assert!(child.emitted);
        assert_eq!(child.bytes, b"./skip/nested\0");
    }

    #[test]
    fn depth_is_global_even_inside_a_skipped_branch() {
        let result = evaluation(
            &[
                "(",
                "-name",
                "unmatched",
                "-a",
                "-depth",
                ")",
                "-o",
                "-name",
                "skip",
                "-prune",
                "-o",
                "-print0",
            ],
            "./skip",
        );
        assert!(!result.prune);
        assert!(!result.emitted);

        let operand = evaluation(&["-name", "-depth", "-prune", "-o", "-print0"], "./-depth");
        assert!(operand.prune);
        assert!(!operand.emitted);
    }

    #[test]
    fn depth_requires_an_explicit_starting_point() {
        for argv in [vec!["-depth", "-print0"], vec!["--", "-depth", "-print0"]] {
            let argv = argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse(&argv, false).err(),
                Some("native depth traversal requires an explicit starting point")
            );
        }
    }
}
