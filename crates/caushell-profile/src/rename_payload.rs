//! Native rename argv and bounded filename transforms. No Perl or tool execution.
//! Implementation alternatives are joined, not selected by argument count.
use crate::*;
use regex::{Regex, RegexBuilder};

type Result<T> = std::result::Result<T, ProjectionUnknownReason>;
fn invalid<T>() -> Result<T> {
    Err(ProjectionUnknownReason::InvalidPayload)
}
fn charge(work: &mut usize, cost: usize) -> Result<()> {
    *work = work
        .checked_sub(cost)
        .ok_or(ProjectionUnknownReason::PayloadBudgetExceeded)?;
    Ok(())
}

#[derive(Clone)]
struct Arg {
    source: BoundValue,
    text: Option<String>,
    single: bool,
}
impl Arg {
    fn new(source: BoundValue) -> Self {
        let text = match project_value(&ValueProjection::Identity, &source) {
            Some(SemanticValueResolution::Known(s)) => Some(s),
            Some(SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue)) => {
                Some(String::new())
            }
            _ => None,
        };
        let single = text.is_some()
            || matches!(&source, BoundValue::ImplicitInput { origin: Some(o), .. } if o.single_field);
        Self {
            source,
            text,
            single,
        }
    }
    fn non_option(&self) -> bool {
        match &self.text {
            Some(s) => !s.starts_with('-') || s == "-",
            None => {
                matches!(&self.source, BoundValue::ImplicitInput { domain: Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, may_escape: false }), .. }
                if !roots.is_empty() && roots.iter().all(|r| !r.is_empty() && !r.starts_with('-')))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Util,
    Perl,
}
struct Call {
    operands: Vec<Arg>,
    programs: Vec<String>,
    dry: bool,
    filename: bool,
    null: bool,
    all: bool,
    last: bool,
}
enum Parsed {
    Info,
    Inapplicable,
    Call(Call),
}

fn parse_cli(args: &[Arg], dialect: Dialect) -> Result<Parsed> {
    let mut call = Call {
        operands: Vec::new(),
        programs: Vec::new(),
        dry: false,
        filename: false,
        null: false,
        all: false,
        last: false,
    };
    let mut options = true;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        index += 1;
        if !options || arg.non_option() {
            if dialect == Dialect::Perl {
                options = false;
            }
            call.operands.push(arg.clone());
            continue;
        }
        let text = arg
            .text
            .as_deref()
            .ok_or(ProjectionUnknownReason::DynamicArgument)?;
        if text == "--" {
            options = false;
            continue;
        }
        let mut program = |value: Option<&str>, terminate: bool| -> Result<()> {
            let value = match value {
                Some(v) => v.to_string(),
                None => {
                    let a = args
                        .get(index)
                        .ok_or(ProjectionUnknownReason::InvalidPayload)?;
                    index += 1;
                    a.text
                        .clone()
                        .ok_or(ProjectionUnknownReason::DynamicArgument)?
                }
            };
            call.programs.push(if terminate {
                format!("{value};")
            } else {
                value
            });
            Ok(())
        };
        if text.starts_with("--") {
            match (dialect, text) {
                (_, "--help" | "--version") | (Dialect::Perl, "--man") => return Ok(Parsed::Info),
                (Dialect::Util, "--no-act") | (Dialect::Perl, "--nono") => call.dry = true,
                (_, "--verbose") => {}
                (Dialect::Util, "--all") => call.all = true,
                (Dialect::Util, "--last") => call.last = true,
                (Dialect::Util, "--no-overwrite") | (Dialect::Perl, "--force") => {}
                (Dialect::Perl, "--null") => call.null = true,
                (Dialect::Perl, "--filename" | "--nofullpath" | "--nopath") => call.filename = true,
                (Dialect::Perl, "--fullpath" | "--path") => call.filename = false,
                // These are implementation-specific, not alternate arities.
                (
                    Dialect::Util,
                    "--force" | "--null" | "--filename" | "--nofullpath" | "--nopath"
                    | "--fullpath" | "--path" | "--nono" | "--man",
                ) => return Ok(Parsed::Inapplicable),
                (Dialect::Perl, "--e") => program(None, false)?,
                (Dialect::Perl, "--E") => program(None, true)?,
                (Dialect::Util, "--e" | "--E") => return Ok(Parsed::Inapplicable),
                _ if text.starts_with("--e=") || text.starts_with("--E=") => {
                    if dialect == Dialect::Util {
                        return Ok(Parsed::Inapplicable);
                    }
                    program(Some(&text[4..]), text.starts_with("--E="))?;
                }
                _ => return invalid(),
            }
            continue;
        }
        // A native short-option cluster is parsed here, including -e's tail.
        // The generic binder intentionally retains the original argv intact.
        let mut chars = text[1..].char_indices().peekable();
        while let Some((offset, flag)) = chars.next() {
            match (dialect, flag) {
                (_, 'h' | 'V') | (Dialect::Perl, 'm' | '?') => return Ok(Parsed::Info),
                (_, 'v') => {}
                (_, 'n') => call.dry = true,
                (Dialect::Util, 'a') => call.all = true,
                (Dialect::Util, 'l') => call.last = true,
                (Dialect::Util, 'o') | (Dialect::Perl, 'f') => {}
                (Dialect::Perl, 'd') => call.filename = true,
                (Dialect::Perl, '0') => call.null = true,
                (Dialect::Perl, 'e' | 'E') => {
                    let tail = &text[offset + 2..];
                    program((!tail.is_empty()).then_some(tail), flag == 'E')?;
                    break;
                }
                (Dialect::Util, 'd' | '0' | 'e' | 'E' | 'f' | 'm' | '?') => {
                    return Ok(Parsed::Inapplicable);
                }
                _ => return invalid(),
            }
        }
    }
    Ok(Parsed::Call(call))
}

enum Piece {
    Literal(String),
    Capture(usize),
}
enum Operation {
    Substitute {
        regex: Regex,
        replacement: Vec<Piece>,
        global: bool,
        bounded: bool,
    },
    Transliterate {
        pairs: Vec<(char, char)>,
        bounded: bool,
    },
}
struct Program(Vec<Operation>);

fn delimited(text: &str, pos: &mut usize, delimiter: u8) -> Result<String> {
    let start = *pos;
    let bytes = text.as_bytes();
    while *pos < bytes.len() {
        if bytes[*pos] == b'\\' {
            *pos += 2;
        } else if bytes[*pos] == delimiter {
            let part = text[start..*pos].to_string();
            *pos += 1;
            return Ok(part);
        } else {
            *pos += 1;
        }
    }
    invalid()
}

/// Validate a common, interpolation-free Perl/Rust regex subset. A separate
/// component-local proof is required before deriving unknown filename bounds.
fn pattern(text: &str, insensitive: bool) -> Result<(Regex, bool)> {
    if !text.is_ascii() || text.is_empty() {
        return invalid();
    } // empty Perl pattern reuses a prior regex
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut local = true;
    while i < bytes.len() {
        match bytes[i] {
            b'@' => return invalid(),
            b'$' if i + 1 != bytes.len() => return invalid(),
            b'(' if bytes.get(i + 1) == Some(&b'?') => return invalid(),
            b'.' | b'/' | b'|' => local = false,
            b'[' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b']' {
                    if matches!(bytes[i], b'$' | b'@') {
                        return invalid();
                    }
                    if bytes[i] == b'\\' {
                        i += 1;
                        validate_escape(
                            *bytes
                                .get(i)
                                .ok_or(ProjectionUnknownReason::InvalidPayload)?,
                        )?;
                    }
                    if bytes[i] == b'[' {
                        return invalid();
                    } // POSIX/classes/intersections need separate semantics
                    i += 1;
                }
                let class = text
                    .get(start..=i)
                    .ok_or(ProjectionUnknownReason::InvalidPayload)?;
                if class.contains("&&") || class.contains("--") || class.contains("~~") {
                    return invalid();
                }
                local &= !Regex::new(&format!("^(?:{class})$"))
                    .map_err(|_| ProjectionUnknownReason::InvalidPayload)?
                    .is_match("/");
            }
            b'\\' => {
                i += 1;
                let escaped = *bytes
                    .get(i)
                    .ok_or(ProjectionUnknownReason::InvalidPayload)?;
                validate_escape(escaped)?;
                if matches!(escaped, b'/' | b'D' | b'W' | b'S') {
                    local = false;
                }
            }
            b'{' => {
                let end = text[i..]
                    .find('}')
                    .ok_or(ProjectionUnknownReason::InvalidPayload)?
                    + i;
                let spec = &text[i + 1..end];
                if spec.is_empty()
                    || !spec.bytes().all(|b| b.is_ascii_digit() || b == b',')
                    || spec
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .any(|s| s.parse::<usize>().map_or(true, |n| n > 128))
                {
                    return invalid();
                }
                i = end;
            }
            b'*' | b'+' | b'?' if i > 0 && b"*+?}".contains(&bytes[i - 1]) => return invalid(),
            _ => {}
        }
        i += 1;
    }
    let regex = RegexBuilder::new(text)
        .case_insensitive(insensitive)
        .size_limit(131072)
        .dfa_size_limit(131072)
        .build()
        .map_err(|_| ProjectionUnknownReason::InvalidPayload)?;
    if regex.captures_len() > 17 {
        return invalid();
    }
    Ok((regex, local))
}

fn validate_escape(byte: u8) -> Result<()> {
    if byte.is_ascii_alphanumeric() && !b"dDwWsStnrf".contains(&byte) {
        invalid()
    } else {
        Ok(())
    }
}

fn replacement(text: &str, delimiter: u8, captures: usize) -> Result<(Vec<Piece>, bool)> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut chars = text.chars().peekable();
    let mut non_dot = false;
    while let Some(c) = chars.next() {
        match c {
            '@' => return invalid(),
            '$' => {
                if !literal.is_empty() {
                    parts.push(Piece::Literal(std::mem::take(&mut literal)));
                }
                let braced = chars.peek() == Some(&'{');
                if braced {
                    chars.next();
                }
                let mut digits = String::new();
                while chars.peek().is_some_and(char::is_ascii_digit) {
                    digits.push(chars.next().unwrap());
                }
                if digits.is_empty() || (braced && chars.next() != Some('}')) {
                    return invalid();
                }
                let n = digits
                    .parse::<usize>()
                    .map_err(|_| ProjectionUnknownReason::InvalidPayload)?;
                if n == 0 || n >= captures {
                    return invalid();
                }
                let mut suffix = chars.clone();
                let dereference = matches!(chars.peek(), Some('[' | '{'))
                    || (suffix.next() == Some('-') && suffix.next() == Some('>'));
                if dereference {
                    return invalid();
                }
                parts.push(Piece::Capture(n));
            }
            '\\' => {
                let next = chars
                    .next()
                    .ok_or(ProjectionUnknownReason::InvalidPayload)?;
                let decoded = match next {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'f' => '\x0c',
                    c if !c.is_ascii_alphanumeric() || c == delimiter as char => c,
                    _ => return invalid(),
                };
                non_dot |= decoded != '.' && decoded != '/';
                literal.push(decoded);
            }
            c => {
                non_dot |= c != '.' && c != '/';
                literal.push(c);
            }
        }
    }
    if !literal.is_empty() {
        parts.push(Piece::Literal(literal));
    }
    let slash_free = parts
        .iter()
        .all(|p| !matches!(p, Piece::Literal(s) if s.contains('/')));
    // A non-dot literal prevents a rewritten component from becoming '..'.
    Ok((parts, slash_free && non_dot))
}

fn transliteration(text: &str, delimiter: u8) -> Result<Vec<char>> {
    if !text.is_ascii() || text.contains(['$', '@']) {
        return invalid();
    }
    let mut atoms = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        atoms.push(if c == '\\' {
            let c = chars
                .next()
                .ok_or(ProjectionUnknownReason::InvalidPayload)?;
            if c.is_ascii_alphanumeric() && c != delimiter as char {
                return invalid();
            }
            (c, true)
        } else {
            (c, false)
        });
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < atoms.len() {
        if i + 2 < atoms.len() && atoms[i + 1] == ('-', false) {
            if atoms[i].0 > atoms[i + 2].0 {
                return invalid();
            }
            out.extend((atoms[i].0 as u8..=atoms[i + 2].0 as u8).map(char::from));
            i += 3;
        } else {
            out.push(atoms[i].0);
            i += 1;
        }
    }
    Ok(out)
}

impl Program {
    fn parse(text: &str, budget: usize) -> Result<Self> {
        if text.contains('\0') {
            return invalid();
        }
        let mut ops = Vec::new();
        let mut pos = 0;
        let bytes = text.as_bytes();
        loop {
            while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
                pos += 1;
            }
            if pos == bytes.len() {
                break;
            }
            if ops.len() >= budget {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
            let kind = if bytes[pos..].starts_with(b"tr") {
                pos += 2;
                b'y'
            } else {
                let b = bytes[pos];
                pos += 1;
                b
            };
            if !matches!(kind, b's' | b'y') {
                return invalid();
            }
            let delimiter = *bytes
                .get(pos)
                .ok_or(ProjectionUnknownReason::InvalidPayload)?;
            if !delimiter.is_ascii_punctuation() || b"\\'\"`()[]{}<>".contains(&delimiter) {
                return invalid();
            }
            pos += 1;
            let left = delimited(text, &mut pos, delimiter)?;
            let right = delimited(text, &mut pos, delimiter)?;
            let start = pos;
            while bytes.get(pos).is_some_and(u8::is_ascii_alphabetic) {
                pos += 1;
            }
            let flags = &text[start..pos];
            if kind == b's' {
                if !flags.bytes().all(|b| b == b'g' || b == b'i') {
                    return invalid();
                }
                let (regex, local) = pattern(&left, flags.contains('i'))?;
                let (replacement, bounded) = replacement(&right, delimiter, regex.captures_len())?;
                ops.push(Operation::Substitute {
                    regex,
                    replacement,
                    global: flags.contains('g'),
                    bounded: local && bounded,
                });
            } else {
                if !flags.is_empty() {
                    return invalid();
                }
                let from = transliteration(&left, delimiter)?;
                let mut to = transliteration(&right, delimiter)?;
                if from.is_empty() {
                    return invalid();
                }
                if to.is_empty() {
                    to = from.clone();
                }
                let pairs: Vec<_> = from
                    .iter()
                    .enumerate()
                    .map(|(i, a)| (*a, to[i.min(to.len() - 1)]))
                    .collect();
                let bounded = pairs
                    .iter()
                    .all(|(a, b)| (*a == '/' || *b != '/') && (*a == '.' || *b != '.'))
                    && pairs.iter().all(|(a, b)| *a != '/' || *b == '/');
                ops.push(Operation::Transliterate { pairs, bounded });
            }
            while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
                pos += 1;
            }
            if pos < bytes.len() {
                if bytes[pos] != b';' {
                    return invalid();
                }
                pos += 1;
            }
        }
        if ops.is_empty() {
            return invalid();
        }
        Ok(Self(ops))
    }

    #[cfg(test)]
    fn apply(&self, input: &str, limit: usize) -> Result<String> {
        self.apply_budget(input, limit, &mut limit.saturating_mul(16))
    }
    fn apply_budget(&self, input: &str, limit: usize, work: &mut usize) -> Result<String> {
        Self::apply_ops(&self.0, input, limit, work)
    }
    fn apply_ops(
        operations: &[Operation],
        input: &str,
        limit: usize,
        work: &mut usize,
    ) -> Result<String> {
        if input.contains(['\0', '\n']) || input.len() > limit {
            return invalid();
        }
        let mut value = input.to_string();
        for op in operations {
            value = match op {
                Operation::Substitute {
                    regex,
                    replacement,
                    global,
                    ..
                } => {
                    if !value.is_ascii() || value.contains('\n') {
                        return invalid();
                    }
                    charge(
                        work,
                        value
                            .len()
                            .max(1)
                            .saturating_mul(regex.as_str().len().max(1)),
                    )?;
                    let mut output = String::new();
                    let mut end = 0;
                    for captures in regex.captures_iter(&value) {
                        let matched = captures.get(0).unwrap();
                        output.push_str(&value[end..matched.start()]);
                        for piece in replacement {
                            match piece {
                                Piece::Literal(s) => {
                                    charge(work, s.len())?;
                                    output.push_str(s);
                                }
                                Piece::Capture(n) => {
                                    if let Some(c) = captures.get(*n) {
                                        charge(work, c.len())?;
                                        output.push_str(c.as_str());
                                    }
                                }
                            }
                            if output.len() > limit {
                                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
                            }
                        }
                        end = matched.end();
                        if !global {
                            break;
                        }
                    }
                    output.push_str(&value[end..]);
                    output
                }
                Operation::Transliterate { pairs, .. } => {
                    charge(work, value.len().max(1).saturating_mul(pairs.len().max(1)))?;
                    value
                        .chars()
                        .map(|c| pairs.iter().find(|(a, _)| *a == c).map_or(c, |(_, b)| *b))
                        .collect()
                }
            };
            if value.len() > limit {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
        }
        Ok(value)
    }
    fn bounded(&self) -> bool {
        self.0.iter().all(|op| match op {
            Operation::Substitute { bounded, .. } | Operation::Transliterate { bounded, .. } => {
                *bounded
            }
        })
    }
}

fn filename_apply(
    input: &str,
    filename: bool,
    mut apply: impl FnMut(&str) -> Result<String>,
) -> Result<String> {
    if input.is_empty() || input.ends_with('/') || input.contains('\0') {
        return invalid();
    }
    if filename {
        if let Some((parent, base)) = input.rsplit_once('/') {
            return Ok(format!("{parent}/{}", apply(base)?));
        }
    }
    apply(input)
}

fn utility_apply(
    input: &str,
    from: &str,
    to: &str,
    all: bool,
    last: bool,
    limit: usize,
) -> Result<String> {
    let filename = !from.contains('/') && !to.contains('/');
    let result = filename_apply(input, filename, |input| {
        if from.is_empty() && all && !input.is_ascii() {
            return invalid();
        }
        let count = if all {
            input.matches(from).count()
        } else {
            usize::from(input.contains(from))
        };
        if input
            .len()
            .checked_add(
                count
                    .checked_mul(to.len())
                    .ok_or(ProjectionUnknownReason::PayloadBudgetExceeded)?,
            )
            .is_none_or(|n| n > limit)
        {
            return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
        }
        Ok(if all {
            input.replace(from, to)
        } else if last {
            match input.rfind(from) {
                Some(i) => format!("{}{to}{}", &input[..i], &input[i + from.len()..]),
                None => input.into(),
            }
        } else {
            input.replacen(from, to, 1)
        })
    })?;
    if result.len() > limit {
        return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
    }
    Ok(result)
}

fn path_parameter(name: &SlotName, role: PathRole) -> BoundParameter {
    let mut p = BoundParameter::new(
        name.clone(),
        SemanticType::Path(PathSemantic {
            role,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    p.payload_generated = true;
    p.projected_values = Some(Vec::new());
    p
}
fn add_path(p: &mut BoundParameter, source: BoundValue, known: Option<String>) {
    let index = p.values.len();
    p.values.push(source);
    p.projected_values
        .as_mut()
        .unwrap()
        .push(ProjectedSemanticValue {
            source_index: index,
            preserves_source: known.is_none(),
            resolution: known.map(SemanticValueResolution::Known).unwrap_or(
                SemanticValueResolution::Unknown(ProjectionUnknownReason::DynamicArgument),
            ),
        });
}
fn unknown() -> BoundValue {
    BoundValue::implicit_input(ImplicitInputSource::StdinData)
}
fn unknown_path(p: &mut BoundParameter) {
    add_path(p, unknown(), None);
}
fn decoded_value(text: String, evidence: &BoundValue) -> BoundValue {
    let span = match evidence {
        BoundValue::Argument { span, .. } => span.clone(),
        _ => caushell_parse::SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            end_row: 0,
            start_column: 0,
            end_column: 0,
        },
    };
    BoundValue::argument_with_node_kind(
        text,
        true,
        "native_data",
        span,
        ArgumentBindingSource::RemainingArg,
    )
    .with_materialization(BoundArgumentMaterialization::RuntimeData)
}

/// Derive a new domain rather than claiming a transformed value is identical
/// to its source. Include the unmodified root for end-anchor boundary changes.
fn transformed_domain(
    source: &BoundValue,
    program: &Program,
    filename: bool,
    limit: usize,
    work: &mut usize,
) -> Option<BoundValue> {
    if !program.bounded() {
        return None;
    }
    let BoundValue::ImplicitInput {
        source,
        domain:
            Some(caushell_types::RuntimeArgumentDomain::PathSet {
                roots,
                may_escape: false,
            }),
        origin,
    } = source
    else {
        return None;
    };
    if roots.is_empty() || roots.len() > 128 {
        return None;
    }
    let mut projected = roots.clone();
    // End anchors may match an inclusive root but not its descendant prefix.
    // Retain both branches at EACH operation, not only the final result: a
    // later rewrite can undo a root change without undoing descendant changes.
    for operation in &program.0 {
        let mut next = projected.clone();
        for root in &projected {
            let transformed = filename_apply(root, filename, |s| {
                Program::apply_ops(std::slice::from_ref(operation), s, limit, work)
            })
            .ok()?;
            if !next.contains(&transformed) {
                next.push(transformed);
            }
            if next.len() > 128 {
                return None;
            }
        }
        projected = next;
    }
    Some(BoundValue::ImplicitInput {
        source: *source,
        domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
            roots: projected,
            may_escape: false,
        }),
        origin: origin.clone(),
    })
}

fn stdin_files(
    text: Option<&str>,
    null: bool,
    evidence: &BoundValue,
    limit: usize,
) -> Result<Vec<Arg>> {
    let text = text.ok_or(ProjectionUnknownReason::PayloadUnavailable)?;
    let separator = if null { '\0' } else { '\n' };
    let mut files = Vec::new();
    let mut records = text.split(separator).peekable();
    while let Some(part) = records.next() {
        let final_record = records.peek().is_none();
        if final_record && part.is_empty() {
            break;
        }
        let span = match evidence {
            BoundValue::Argument { span, .. } => span.clone(),
            _ => caushell_parse::SourceSpan {
                start_byte: 0,
                end_byte: 0,
                start_row: 0,
                end_row: 0,
                start_column: 0,
                end_column: 0,
            },
        };
        let mut values = vec![part.to_string()];
        // File::Rename uses chop; older implementations use chomp. Preserve
        // both possible final records when the separator is missing.
        if final_record && !part.is_empty() {
            if !part.is_ascii() {
                return invalid();
            }
            values.push(part[..part.len() - 1].into());
        }
        for value in values {
            if files.len() >= limit {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
            let source = BoundValue::argument_with_node_kind(
                value,
                true,
                "native_filename",
                span.clone(),
                ArgumentBindingSource::RemainingArg,
            )
            .with_materialization(BoundArgumentMaterialization::RuntimeData);
            files.push(Arg::new(source));
        }
    }
    Ok(files)
}

pub(crate) fn project(
    bound: &BoundInvocation,
    projection: &PayloadProjection,
    stdin: Option<&str>,
) -> Vec<BoundParameter> {
    let reads = path_parameter(&projection.reads, PathRole::Read);
    let mut writes = path_parameter(&projection.writes, PathRole::Write);
    let deletes = path_parameter(&projection.deletes, PathRole::Target);
    let mut moves = path_parameter(projection.moves.as_ref().unwrap(), PathRole::Target);
    let mut executions = BoundParameter::new(
        projection.executions.as_ref().unwrap().clone(),
        SemanticType::Payload(PayloadSemantic {
            language: PayloadLanguage::Opaque,
            source: PayloadSource::InlineString,
            recursive: true,
        }),
    );
    executions.payload_generated = true;
    let values = match &projection.source {
        PayloadInputSource::Slot(s) => bound
            .bound_parameters
            .iter()
            .find(|p| p.name == *s)
            .map(|p| p.values.as_slice())
            .unwrap_or(&[]),
        _ => &[],
    };
    let args: Vec<_> = values.iter().cloned().map(Arg::new).collect();
    let dialects: &[Dialect] = match projection.format {
        PayloadFormat::RenameUtilLinuxArguments => &[Dialect::Util],
        PayloadFormat::RenamePerlArguments => &[Dialect::Perl],
        _ => &[Dialect::Util, Dialect::Perl],
    };
    let within_budget = args.len() <= projection.max_operations
        && args
            .iter()
            .all(|a| a.text.as_ref().is_none_or(|s| !s.contains('\0')))
        && values
            .iter()
            .try_fold(0usize, |n, v| {
                n.checked_add(match v {
                    BoundValue::Argument { text, .. } => text.len(),
                    _ => 0,
                })
            })
            .is_some_and(|n| n <= projection.max_bytes);
    let evidence = args
        .first()
        .map(|a| a.source.clone())
        .unwrap_or_else(unknown);
    let mut work = projection.max_bytes.saturating_mul(8).min(1_048_576);
    for dialect in dialects {
        let parsed = if within_budget {
            parse_cli(&args, *dialect)
        } else {
            Err(ProjectionUnknownReason::PayloadBudgetExceeded)
        };
        let call = match parsed {
            Ok(Parsed::Info | Parsed::Inapplicable) => continue,
            Ok(Parsed::Call(c)) => c,
            Err(_) => {
                unknown_path(&mut moves);
                unknown_path(&mut writes);
                if *dialect == Dialect::Perl {
                    executions.values.push(unknown());
                }
                continue;
            }
        };
        if *dialect == Dialect::Util {
            if call.operands.len() < 3 {
                if call.operands.iter().all(|a| a.single) {
                    continue;
                }
                unknown_path(&mut moves);
                unknown_path(&mut writes);
                continue;
            }
            if call.dry {
                continue;
            }
            let (Some(from), Some(to)) = (&call.operands[0].text, &call.operands[1].text) else {
                unknown_path(&mut moves);
                unknown_path(&mut writes);
                continue;
            };
            if !call.operands[0].single || !call.operands[1].single {
                unknown_path(&mut moves);
                unknown_path(&mut writes);
                continue;
            }
            for file in &call.operands[2..] {
                let destination = file.text.as_ref().and_then(|s| {
                    charge(&mut work, s.len().max(1).saturating_mul(from.len().max(1))).ok()?;
                    utility_apply(s, from, to, call.all, call.last, projection.max_bytes).ok()
                });
                if destination
                    .as_ref()
                    .is_some_and(|d| file.text.as_ref() == Some(d))
                {
                    continue;
                }
                add_path(&mut moves, file.source.clone(), file.text.clone());
                match destination {
                    Some(s) => add_path(&mut writes, file.source.clone(), Some(s)),
                    None => unknown_path(&mut writes),
                }
            }
        } else {
            let mut operands = call.operands.clone();
            let programs = if call.programs.is_empty() {
                if operands.is_empty() {
                    continue;
                }
                let program = operands.remove(0);
                let Some(text) = program.text else {
                    executions.values.push(program.source);
                    unknown_path(&mut writes);
                    continue;
                };
                text
            } else {
                call.programs.join("\n")
            };
            let program = match Program::parse(&programs, projection.max_operations) {
                Ok(program) => program,
                Err(_) => {
                    executions
                        .values
                        .push(decoded_value(programs.clone(), &evidence));
                    unknown_path(&mut moves);
                    unknown_path(&mut writes);
                    continue;
                }
            };
            if call.dry {
                continue;
            }
            if operands.is_empty() {
                if stdin.is_some_and(|text| text.len() > projection.max_bytes) {
                    unknown_path(&mut moves);
                    unknown_path(&mut writes);
                    continue;
                }
                operands = match stdin_files(stdin, call.null, &evidence, projection.max_operations)
                {
                    Ok(files) => files,
                    Err(_) => {
                        unknown_path(&mut moves);
                        unknown_path(&mut writes);
                        continue;
                    }
                };
            }
            for file in operands {
                let destination = file.text.as_ref().and_then(|s| {
                    filename_apply(s, call.filename, |s| {
                        program.apply_budget(s, projection.max_bytes, &mut work)
                    })
                    .ok()
                });
                if destination
                    .as_ref()
                    .is_some_and(|d| file.text.as_ref() == Some(d))
                {
                    continue;
                }
                add_path(&mut moves, file.source.clone(), file.text.clone());
                if let Some(s) = destination {
                    add_path(&mut writes, file.source.clone(), Some(s));
                } else if let Some(domain) = transformed_domain(
                    &file.source,
                    &program,
                    call.filename,
                    projection.max_bytes,
                    &mut work,
                ) {
                    add_path(&mut writes, domain, None);
                } else {
                    unknown_path(&mut writes);
                }
            }
        }
    }
    if executions.values.is_empty() {
        executions.projected_values = Some(Vec::new());
    }
    vec![reads, writes, deletes, moves, executions]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supported_transformations_never_evaluate_perl() {
        for (program, input, output) in [
            ("s/^/new./", "original.filename", "new.original.filename"),
            ("s/(.*)$/new.$1/", "one", "new.one"),
            ("s/\\.JPG$/.jpeg/i", "one.JPG", "one.jpeg"),
            ("s@Foo@Bar@gi", "Foo Foo", "Bar Bar"),
            ("s/ /_/g; s/$/.txt/;", "one two", "one_two.txt"),
            ("y/A-Z/a-z/", "AbC.TXT", "abc.txt"),
            ("tr/a-c/x/", "abc", "xxx"),
        ] {
            assert_eq!(
                Program::parse(program, 64)
                    .unwrap()
                    .apply(input, 4096)
                    .unwrap(),
                output,
                "{program}"
            );
        }
        for program in [
            "s/x/system('id')/e",
            "s/(?{system('id')})/x/",
            "s/$HOME/x/",
            "s/x/$ENV{HOME}/",
            "s/x/@array/",
            "s/x/y/; system('id')",
            "s//x/",
            "s/x/y/r",
            "s{x}{y}",
            "s/x/\\U$1/",
            "s/x/$0/",
            "s/a++a/y/",
            "s/[a&&b]/y/",
            "s/(x)/$1[system(\"id\")]/",
            "s/(x)/$1->{name}/",
            "s/x/\0/",
        ] {
            assert!(Program::parse(program, 64).is_err(), "{program}");
        }
    }
    #[test]
    fn whole_path_and_basename_relocations_differ() {
        assert_eq!(
            utility_apply("./file.txt", "./", "/opt/out/", false, false, 4096).unwrap(),
            "/opt/out/file.txt"
        );
        assert_eq!(
            utility_apply("dir/foo.txt", "foo", "bar", false, false, 4096).unwrap(),
            "dir/bar.txt"
        );
        assert_eq!(
            utility_apply("foo/foo.txt", "foo", "bar", false, false, 4096).unwrap(),
            "foo/bar.txt"
        );
    }
    #[test]
    fn only_component_safe_transformations_keep_unknown_path_bounds() {
        for p in ["s/\\.t1$/.t2/", "s/ /_/g", "y/A-Z/a-z/"] {
            assert!(Program::parse(p, 64).unwrap().bounded(), "{p}");
        }
        for p in [
            "s/\\.compiled$//",
            "s/.*$/new/",
            "s/x/../",
            "s@^@/opt/@",
            "s/ws|w/ws/",
        ] {
            assert!(!Program::parse(p, 64).unwrap().bounded(), "{p}");
        }
    }
    #[test]
    fn derived_domains_cover_descendants_and_intermediate_root_rewrites() {
        fn normalize(path: &str) -> String {
            let absolute = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/bench/workspace/{path}")
            };
            let mut components = Vec::new();
            for c in absolute.split('/') {
                match c {
                    "" | "." => {}
                    ".." => {
                        components.pop();
                    }
                    _ => components.push(c),
                }
            }
            format!("/{}", components.join("/"))
        }
        for root in [
            ".",
            "./foo",
            "/bench/workspace",
            "/bench/workspace/foo",
            "foo/..",
        ] {
            let source = BoundValue::ImplicitInput {
                source: ImplicitInputSource::DispatchOutput,
                domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
                    roots: vec![root.into()],
                    may_escape: false,
                }),
                origin: None,
            };
            for code in [
                "s/foo/bar/g",
                "s/^/new./",
                "s/$/.txt/",
                "s/ /_/g",
                "s@[a-z]@x@g",
                "s@[^/]@_@g",
                "y/A-Z/a-z/",
                "s/foo/bar/g; s/bar$/foo/",
            ] {
                let program = Program::parse(code, 64).unwrap();
                let Some(BoundValue::ImplicitInput {
                    domain: Some(caushell_types::RuntimeArgumentDomain::PathSet { roots, .. }),
                    ..
                }) = transformed_domain(&source, &program, false, 4096, &mut 1_000_000)
                else {
                    panic!("{root}: {code}");
                };
                let bounds: Vec<_> = roots.iter().map(|s| normalize(s)).collect();
                for suffix in ["", "/file", "/foo", "/foo/bar", "/foo..", "/a b"] {
                    let input = format!("{root}{suffix}");
                    let target = normalize(&program.apply(&input, 4096).unwrap());
                    assert!(
                        bounds
                            .iter()
                            .any(|b| target == *b || target.starts_with(&format!("{b}/"))),
                        "{code}: {input} -> {target}; {bounds:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn budgets_and_escaped_transliteration_ranges_do_not_expand_unbounded_outputs() {
        assert_eq!(
            Program::parse(r"y/a\-c/x/", 16)
                .unwrap()
                .apply("abc-", 4096)
                .unwrap(),
            "xbxx"
        );
        assert!(
            utility_apply(&"a".repeat(1000), "", &"b".repeat(1000), true, false, 4096).is_err()
        );
        assert!(Program::parse("s/x/y/; s/x/z/", 1).is_err());
        assert!(
            Program::parse("s/x/y/", 16)
                .unwrap()
                .apply_budget("xxxx", 4096, &mut 1)
                .is_err()
        );
        assert!(Program::parse("s`x`y`", 16).is_err());
    }
}
