//! Bounded AWK syntax/effect decoding. Regexes and programs are never evaluated.
//! A complete supported program is required before returning any effects.
use crate::ProjectionUnknownReason;
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, ProjectionUnknownReason>;
fn invalid<T>() -> Result<T> {
    Err(ProjectionUnknownReason::InvalidPayload)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AwkTargets {
    pub reads: Vec<(usize, Option<String>)>,
    pub writes: Vec<(usize, Option<String>)>,
    pub executions: Vec<usize>,
    pub shell_executions: Vec<(usize, String)>,
    pub stdout_emissions: Vec<usize>,
    pub read_domains: Vec<(usize, caushell_types::RuntimeArgumentDomain)>,
    pub write_domains: Vec<(usize, caushell_types::RuntimeArgumentDomain)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Number,
    String(String),
    Op(&'static str),
    Newline,
    End,
}
struct Lexer<'a> {
    text: &'a str,
    pos: usize,
    count: usize,
    limit: usize,
}
impl Lexer<'_> {
    fn token(&mut self) -> Result<(Token, usize)> {
        let bytes = self.text.as_bytes();
        loop {
            match bytes.get(self.pos) {
                Some(b' ' | b'\t' | b'\r') => self.pos += 1,
                Some(b'\\') if bytes.get(self.pos + 1) == Some(&b'\n') => self.pos += 2,
                Some(b'#') => {
                    while bytes.get(self.pos).is_some_and(|b| *b != b'\n') {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let start = self.pos;
        self.count += 1;
        if self.count > self.limit {
            return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
        }
        let Some(&c) = bytes.get(self.pos) else {
            return Ok((Token::End, start));
        };
        if c == b'\n' {
            self.pos += 1;
            return Ok((Token::Newline, start));
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            self.pos += 1;
            while bytes
                .get(self.pos)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                self.pos += 1;
            }
            return Ok((Token::Name(self.text[start..self.pos].into()), start));
        }
        if c.is_ascii_digit()
            || (c == b'.' && bytes.get(self.pos + 1).is_some_and(u8::is_ascii_digit))
        {
            self.pos += 1;
            while bytes
                .get(self.pos)
                .is_some_and(|b| b.is_ascii_digit() || *b == b'.')
            {
                self.pos += 1;
            }
            if bytes
                .get(self.pos)
                .is_some_and(|b| matches!(b, b'e' | b'E'))
            {
                self.pos += 1;
                if bytes
                    .get(self.pos)
                    .is_some_and(|b| matches!(b, b'+' | b'-'))
                {
                    self.pos += 1;
                }
                while bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                    self.pos += 1;
                }
            }
            return Ok((Token::Number, start));
        }
        if c == b'"' {
            return Ok((Token::String(self.string()?), start));
        }
        for op in [
            "++", "--", "+=", "-=", "*=", "/=", "%=", "^=", "**", "==", "!=", "<=", ">=", "!~",
            "&&", "||", ">>", "|&",
        ] {
            if self.text[self.pos..].starts_with(op) {
                self.pos += op.len();
                return Ok((Token::Op(op), start));
            }
        }
        let op = match c {
            b'{' => "{",
            b'}' => "}",
            b'(' => "(",
            b')' => ")",
            b'[' => "[",
            b']' => "]",
            b';' => ";",
            b',' => ",",
            b'$' => "$",
            b'+' => "+",
            b'-' => "-",
            b'*' => "*",
            b'/' => "/",
            b'%' => "%",
            b'^' => "^",
            b'!' => "!",
            b'~' => "~",
            b'<' => "<",
            b'>' => ">",
            b'=' => "=",
            b'?' => "?",
            b':' => ":",
            b'|' => "|",
            _ => return invalid(),
        };
        self.pos += 1;
        Ok((Token::Op(op), start))
    }
    fn string(&mut self) -> Result<String> {
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.text.len() {
            let c = self.text[self.pos..].chars().next().unwrap();
            self.pos += c.len_utf8();
            match c {
                '"' => return Ok(out),
                '\n' | '\0' => return invalid(),
                '\\' => {
                    let e = self.text[self.pos..]
                        .chars()
                        .next()
                        .ok_or(ProjectionUnknownReason::InvalidPayload)?;
                    self.pos += e.len_utf8();
                    let decoded = match e {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'v' => '\u{b}',
                        'a' => '\u{7}',
                        '"' => '"',
                        '\\' => '\\',
                        '\n' => continue,
                        '0'..='7' | 'x' => {
                            let radix = if e == 'x' { 16 } else { 8 };
                            let mut digits = if e == 'x' {
                                String::new()
                            } else {
                                e.to_string()
                            };
                            let max = if radix == 16 { 2 } else { 3 };
                            while digits.len() < max {
                                let Some(b) = self.text.as_bytes().get(self.pos) else {
                                    break;
                                };
                                if (*b as char).to_digit(radix).is_none() {
                                    break;
                                }
                                digits.push(*b as char);
                                self.pos += 1;
                            }
                            if digits.is_empty() {
                                return invalid();
                            }
                            if radix == 16
                                && self
                                    .text
                                    .as_bytes()
                                    .get(self.pos)
                                    .is_some_and(|b| b.is_ascii_hexdigit())
                            {
                                return invalid();
                            }
                            let n = u32::from_str_radix(&digits, radix)
                                .map_err(|_| ProjectionUnknownReason::InvalidPayload)?;
                            // Do not fabricate UTF-8 paths from implementation-dependent bytes.
                            if n == 0 || n > 127 {
                                return invalid();
                            }
                            char::from_u32(n).unwrap()
                        }
                        _ => return invalid(),
                    };
                    out.push(decoded);
                }
                _ => out.push(c),
            }
        }
        invalid()
    }
    fn regex_tail(&mut self) -> Result<()> {
        let bytes = self.text.as_bytes();
        let mut bracket = false;
        let mut first = false;
        while let Some(&c) = bytes.get(self.pos) {
            self.pos += 1;
            match c {
                b'\\' => {
                    if self.pos >= bytes.len() {
                        return invalid();
                    }
                    self.pos += 1;
                    first = false;
                }
                b'\n' => return invalid(),
                b'/' if !bracket => return Ok(()),
                b'[' if !bracket => {
                    bracket = true;
                    first = true;
                }
                b'[' if bracket
                    && bytes
                        .get(self.pos)
                        .is_some_and(|b| matches!(b, b':' | b'.' | b'=')) =>
                {
                    let marker = bytes[self.pos];
                    self.pos += 1;
                    while self.pos + 1 < bytes.len()
                        && !(bytes[self.pos] == marker && bytes[self.pos + 1] == b']')
                    {
                        self.pos += 1;
                    }
                    if self.pos + 1 >= bytes.len() {
                        return invalid();
                    }
                    self.pos += 2;
                    first = false;
                }
                b']' if bracket && !first => bracket = false,
                b'^' if bracket && first => {}
                _ => first = false,
            }
        }
        invalid()
    }
}

#[derive(Default)]
struct Value {
    literal: Option<String>,
    // A native numeric conversion, or a counter joined with its default empty
    // initial value. Never an exact value or an assertion about record count.
    numeric: bool,
    variable: Option<String>,
    template: Option<(String, String)>,
}
impl Value {
    fn number() -> Self {
        Self {
            numeric: true,
            ..Self::default()
        }
    }
    fn concat(self, other: Self) -> Self {
        let a = self.literal.as_ref().map(|s| (s.clone(), String::new()));
        let b = other.literal.as_ref().map(|s| (String::new(), s.clone()));
        let template = match (&self.template, &other.template, &a, &b) {
            (Some((p, s)), _, _, Some((_, b))) => Some((p.clone(), format!("{s}{b}"))),
            (_, Some((p, s)), Some((a, _)), _) => Some((format!("{a}{p}"), s.clone())),
            _ if self.literal.is_some() && other.numeric => {
                Some((self.literal.clone().unwrap(), String::new()))
            }
            _ if self.numeric && other.literal.is_some() => {
                Some((String::new(), other.literal.clone().unwrap()))
            }
            _ => None,
        };
        Self {
            literal: self.literal.zip(other.literal).map(|(a, b)| a + &b),
            template,
            ..Self::default()
        }
    }
    fn path_domain(&self) -> Option<caushell_types::RuntimeArgumentDomain> {
        let (prefix, suffix) = self.template.as_ref()?;
        if prefix.len() + suffix.len() > 4096
            || prefix.contains('\0')
            || suffix.contains(['/', '\0'])
        {
            return None;
        }
        let (parent, leaf) = prefix.rsplit_once('/').unwrap_or((".", prefix));
        // The default, uninitialized value can be empty. Retain a real leaf
        // and never turn that case into '.', '..', or the bounding directory.
        if !leaf.chars().chain(suffix.chars()).any(|c| c != '.') {
            return None;
        }
        Some(caushell_types::RuntimeArgumentDomain::PathSet {
            roots: vec![if parent.is_empty() {
                "/".into()
            } else {
                parent.into()
            }],
            may_escape: false,
            basename_suffix: None,
            no_adjacent_slashes: false,
        })
    }
}
struct Parser<'a> {
    lexer: Lexer<'a>,
    token: Token,
    offset: usize,
    depth: usize,
    targets: AwkTargets,
    functions: BTreeSet<String>,
    calls: Vec<(usize, String, Option<String>)>,
    numeric_variables: BTreeSet<String>,
    writes: BTreeMap<String, bool>,
}
impl Parser<'_> {
    fn write_variable(&mut self, value: &Value, numeric: bool) {
        if let Some(name) = &value.variable {
            self.writes
                .entry(name.clone())
                .and_modify(|n| *n &= numeric)
                .or_insert(numeric);
        }
    }
    fn next(&mut self) -> Result<()> {
        let (t, o) = self.lexer.token()?;
        self.token = t;
        self.offset = o;
        Ok(())
    }
    fn op(&self, s: &str) -> bool {
        matches!(&self.token, Token::Op(v) if *v==s)
    }
    fn name(&self, s: &str) -> bool {
        matches!(&self.token, Token::Name(v) if v==s)
    }
    fn need(&mut self, s: &str) -> Result<()> {
        if !self.op(s) {
            return invalid();
        }
        self.next()
    }
    fn separators(&mut self) -> Result<()> {
        while self.op(";") || self.token == Token::Newline {
            self.next()?;
        }
        Ok(())
    }
    fn newline(&mut self) -> Result<()> {
        while self.token == Token::Newline {
            self.next()?;
        }
        Ok(())
    }
    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > 64 {
            return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
        }
        Ok(())
    }
    fn program(&mut self) -> Result<()> {
        self.separators()?;
        while self.token != Token::End {
            if self.name("function") || self.name("func") {
                self.next()?;
                let Token::Name(name) = self.token.clone() else {
                    return invalid();
                };
                self.functions.insert(name);
                self.next()?;
                self.need("(")?;
                if !self.op(")") {
                    loop {
                        if !matches!(self.token, Token::Name(_)) {
                            return invalid();
                        }
                        self.next()?;
                        if !self.op(",") {
                            break;
                        }
                        self.next()?;
                    }
                }
                self.need(")")?;
                self.newline()?;
                self.block()?;
            } else if self.op("{") {
                self.block()?;
            } else {
                let offset = self.offset;
                self.expr(0, false)?;
                if self.op(",") {
                    self.next()?;
                    self.expr(0, false)?;
                }
                if self.op("{") {
                    self.block()?;
                } else {
                    self.targets.stdout_emissions.push(offset);
                }
            }
            self.separators()?;
        }
        for (offset, name, shell) in &self.calls {
            if !self.functions.contains(name) && !pure_builtin(name) {
                self.targets.executions.push(*offset);
                if name == "system" {
                    if let Some(text) = shell {
                        self.targets.shell_executions.push((*offset, text.clone()));
                    }
                }
            }
        }
        Ok(())
    }
    fn block(&mut self) -> Result<()> {
        self.enter()?;
        self.need("{")?;
        self.separators()?;
        while !self.op("}") {
            if self.token == Token::End {
                return invalid();
            }
            self.statement()?;
            self.separators()?;
        }
        self.need("}")?;
        self.depth -= 1;
        Ok(())
    }
    fn statement(&mut self) -> Result<()> {
        self.enter()?;
        let result = self.statement_inner();
        self.depth -= 1;
        result
    }
    fn statement_inner(&mut self) -> Result<()> {
        if self.op("{") {
            return self.block();
        }
        if self.op(";") {
            return self.next();
        }
        if self.name("if") || self.name("while") {
            let is_if = self.name("if");
            self.next()?;
            self.need("(")?;
            self.expr(0, false)?;
            self.need(")")?;
            self.newline()?;
            self.statement()?;
            if is_if {
                self.newline()?;
                if self.name("else") {
                    self.next()?;
                    self.newline()?;
                    self.statement()?;
                }
            }
            return Ok(());
        }
        if self.name("for") {
            self.next()?;
            self.need("(")?;
            if !self.op(";") {
                self.expr(0, false)?;
            }
            if self.op(";") {
                self.next()?;
                if !self.op(";") {
                    self.expr(0, false)?;
                }
                self.need(";")?;
                if !self.op(")") {
                    self.expr(0, false)?;
                }
            }
            self.need(")")?;
            self.newline()?;
            return self.statement();
        }
        if self.name("do") {
            self.next()?;
            self.newline()?;
            self.statement()?;
            self.newline()?;
            if !self.name("while") {
                return invalid();
            }
            self.next()?;
            self.need("(")?;
            self.expr(0, false)?;
            return self.need(")");
        }
        if self.name("print") || self.name("printf") {
            return self.print();
        }
        if self.name("next") || self.name("nextfile") || self.name("break") || self.name("continue")
        {
            return self.next();
        }
        if self.name("exit") || self.name("return") {
            self.next()?;
            if !self.end_statement() {
                self.expr(0, false)?;
            }
            return Ok(());
        }
        if self.name("delete") {
            self.next()?;
            self.expr(0, false)?;
            return Ok(());
        }
        self.expr(0, false)?;
        Ok(())
    }
    fn end_statement(&self) -> bool {
        self.token == Token::End || self.token == Token::Newline || self.op(";") || self.op("}")
    }
    fn print(&mut self) -> Result<()> {
        let offset = self.offset;
        self.next()?;
        if !self.end_statement()
            && !self.op(">")
            && !self.op(">>")
            && !self.op("|")
            && !self.op("|&")
        {
            self.expr(0, true)?;
            while self.op(",") {
                self.next()?;
                self.newline()?;
                self.expr(0, true)?;
            }
        }
        if self.op(">") || self.op(">>") {
            self.next()?;
            let target = self.expr(0, false)?;
            if let Some(domain) = target.path_domain() {
                self.targets
                    .write_domains
                    .push((self.targets.writes.len(), domain));
            }
            self.targets.writes.push((offset, target.literal));
        } else if self.op("|") || self.op("|&") {
            self.next()?;
            self.expr(0, false)?;
            self.targets.executions.push(offset);
        } else {
            self.targets.stdout_emissions.push(offset);
        }
        Ok(())
    }
    fn expr(&mut self, min: u8, print_arg: bool) -> Result<Value> {
        self.enter()?;
        let result = self.expr_inner(min, print_arg);
        self.depth -= 1;
        result
    }
    fn expr_inner(&mut self, min: u8, print_arg: bool) -> Result<Value> {
        let mut lhs = self.primary()?;
        loop {
            if self.op("[") {
                self.write_variable(&lhs, false);
                self.next()?;
                self.expr(0, false)?;
                while self.op(",") {
                    self.next()?;
                    self.expr(0, false)?;
                }
                self.need("]")?;
                lhs = Value::default();
                continue;
            }
            if self.op("++") || self.op("--") {
                let old_numeric = lhs.numeric;
                self.write_variable(&lhs, true);
                self.next()?;
                // The update establishes a numeric variable, but the returned
                // old value must not inherit that proof before the whole-
                // program join has ruled out a pre-existing string value.
                lhs = if old_numeric {
                    Value::number()
                } else {
                    Value::default()
                };
                continue;
            }
            if print_arg && (self.op(">") || self.op(">>") || self.op("|") || self.op("|&")) {
                break;
            }
            if self.op("?") && min <= 2 {
                self.next()?;
                self.expr(0, false)?;
                self.need(":")?;
                self.expr(2, print_arg)?;
                lhs = Value::default();
                continue;
            }
            if (self.op("|") || self.op("|&")) && min <= 7 {
                let offset = self.offset;
                self.next()?;
                if !self.name("getline") {
                    return invalid();
                }
                self.getline(true)?;
                self.targets.executions.push(offset);
                lhs = Value::default();
                continue;
            }
            let (bp, right) = match &self.token {
                Token::Op("=" | "+=" | "-=" | "*=" | "/=" | "%=" | "^=") => (1, true),
                Token::Op("||") => (3, false),
                Token::Op("&&") => (4, false),
                Token::Name(v) if v == "in" => (5, false),
                Token::Op("~" | "!~") => (6, false),
                Token::Op("<" | "<=" | "==" | "!=" | ">=" | ">") => (7, false),
                Token::Op("+" | "-") => (9, false),
                Token::Op("*" | "/" | "%") => (10, false),
                Token::Op("^" | "**") => (11, true),
                _ => {
                    if min <= 8 && self.starts_primary() {
                        let rhs = self.expr(9, print_arg)?;
                        lhs = lhs.concat(rhs);
                        continue;
                    }
                    break;
                }
            };
            if bp < min {
                break;
            }
            let numeric = !matches!(&self.token, Token::Op("="));
            let assignment = matches!(
                &self.token,
                Token::Op("=" | "+=" | "-=" | "*=" | "/=" | "%=" | "^=")
            );
            if matches!(&self.token, Token::Name(v) if v == "in") {
                self.write_variable(&lhs, false);
            }
            self.next()?;
            self.newline()?;
            let rhs = self.expr(if right { bp } else { bp + 1 }, print_arg)?;
            if assignment {
                self.write_variable(&lhs, numeric || rhs.numeric);
            }
            lhs = if numeric { Value::number() } else { rhs };
        }
        Ok(lhs)
    }
    fn starts_primary(&self) -> bool {
        match &self.token {
            Token::Name(n) => !matches!(
                n.as_str(),
                "else"
                    | "print"
                    | "printf"
                    | "if"
                    | "while"
                    | "for"
                    | "do"
                    | "return"
                    | "exit"
                    | "next"
                    | "nextfile"
                    | "break"
                    | "continue"
                    | "delete"
                    | "function"
                    | "func"
                    | "BEGIN"
                    | "END"
                    | "BEGINFILE"
                    | "ENDFILE"
                    | "in"
            ),
            Token::String(_) | Token::Number | Token::Op("(" | "$") => true,
            _ => false,
        }
    }
    fn primary(&mut self) -> Result<Value> {
        let offset = self.offset;
        match self.token.clone() {
            Token::String(s) => {
                self.next()?;
                Ok(Value {
                    literal: Some(s),
                    ..Value::default()
                })
            }
            Token::Number => {
                self.next()?;
                Ok(Value::number())
            }
            Token::Op("/") => {
                self.lexer.regex_tail()?;
                self.next()?;
                Ok(Value::default())
            }
            Token::Op("(") => {
                self.next()?;
                self.newline()?;
                let mut value = self.expr(0, false)?;
                while self.op(",") {
                    self.next()?;
                    self.expr(0, false)?;
                    value = Value::default();
                }
                self.newline()?;
                self.need(")")?;
                Ok(value)
            }
            Token::Op(op @ ("!" | "+" | "-" | "++" | "--" | "$")) => {
                self.next()?;
                let value = self.expr(12, false)?;
                if matches!(op, "++" | "--") {
                    self.write_variable(&value, true);
                }
                Ok(if op == "$" {
                    Value::default()
                } else {
                    Value::number()
                })
            }
            Token::Name(n) if n == "getline" => self.getline(false),
            Token::Name(n) => {
                self.next()?;
                if n == "PROCINFO" {
                    self.targets.executions.push(offset);
                }
                if n == "ARGV" || n == "ARGC" {
                    self.targets.reads.push((offset, None));
                }
                if self.op("(") {
                    let mut shell = None;
                    self.next()?;
                    self.newline()?;
                    if !self.op(")") {
                        let value = self.expr(0, false)?;
                        if n == "system" {
                            shell = value.literal.clone();
                        }
                        if matches!(
                            n.as_str(),
                            "sub" | "gsub" | "split" | "patsplit" | "asort" | "asorti" | "match"
                        ) {
                            self.write_variable(&value, false);
                        }
                        while self.op(",") {
                            shell = None;
                            self.next()?;
                            self.newline()?;
                            let value = self.expr(0, false)?;
                            if matches!(
                                n.as_str(),
                                "sub"
                                    | "gsub"
                                    | "split"
                                    | "patsplit"
                                    | "asort"
                                    | "asorti"
                                    | "match"
                            ) {
                                self.write_variable(&value, false);
                            }
                        }
                    }
                    self.newline()?;
                    self.need(")")?;
                    self.calls.push((offset, n.clone(), shell));
                    return Ok(Value::default());
                }
                Ok(Value {
                    numeric: self.numeric_variables.contains(&n),
                    variable: Some(n),
                    ..Value::default()
                })
            }
            _ => invalid(),
        }
    }
    fn getline(&mut self, pipe: bool) -> Result<Value> {
        let offset = self.offset;
        self.next()?;
        if let Token::Name(name) = &self.token {
            self.writes.insert(name.clone(), false);
            self.next()?;
            while self.op("[") {
                self.next()?;
                self.expr(0, false)?;
                while self.op(",") {
                    self.next()?;
                    self.expr(0, false)?;
                }
                self.need("]")?;
            }
        } else if self.op("$") {
            self.next()?;
            self.expr(12, false)?;
        }
        if !pipe && self.op("<") {
            self.next()?;
            let file = self.expr(8, false)?;
            if let Some(domain) = file.path_domain() {
                self.targets
                    .read_domains
                    .push((self.targets.reads.len(), domain));
            }
            self.targets.reads.push((offset, file.literal));
        }
        Ok(Value::default())
    }
}
fn pure_builtin(n: &str) -> bool {
    matches!(
        n,
        "length"
            | "substr"
            | "index"
            | "match"
            | "split"
            | "patsplit"
            | "sprintf"
            | "sub"
            | "gsub"
            | "gensub"
            | "tolower"
            | "toupper"
            | "int"
            | "sqrt"
            | "exp"
            | "log"
            | "sin"
            | "cos"
            | "atan2"
            | "rand"
            | "srand"
            | "asort"
            | "asorti"
            | "strtonum"
            | "and"
            | "or"
            | "xor"
            | "compl"
            | "lshift"
            | "rshift"
            | "mktime"
            | "strftime"
            | "systime"
            | "close"
            | "fflush"
    )
}
pub(crate) fn decode(text: &str, max_bytes: usize, max_operations: usize) -> Result<AwkTargets> {
    decode_with_variables(text, max_bytes, max_operations, true)
}

pub(crate) fn decode_with_variables(
    text: &str,
    max_bytes: usize,
    max_operations: usize,
    infer_variables: bool,
) -> Result<AwkTargets> {
    if text.len() > max_bytes {
        return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
    }
    if text.contains('\0') {
        return invalid();
    }
    let mut p = Parser {
        lexer: Lexer {
            text,
            pos: 0,
            count: 0,
            limit: max_operations,
        },
        token: Token::End,
        offset: 0,
        depth: 0,
        targets: AwkTargets::default(),
        functions: BTreeSet::new(),
        calls: Vec::new(),
        numeric_variables: BTreeSet::new(),
        writes: BTreeMap::new(),
    };
    p.next()?;
    p.program()?;
    // A whole-program join, not a guessed execution order. Any nonnumeric
    // write poisons a variable across branches, loops, records and -e pieces.
    // Functions/local scopes and custom number formats remain opaque here.
    let numeric = if infer_variables
        && p.functions.is_empty()
        && !p.writes.keys().any(|n| {
            matches!(
                n.as_str(),
                "CONVFMT" | "OFMT" | "SYMTAB" | "FUNCTAB" | "ARGV" | "ARGC" | "PROCINFO"
            )
        }) {
        p.writes
            .iter()
            .filter(|(name, numeric)| {
                **numeric
                    && !matches!(
                        name.as_str(),
                        "ARGC"
                            | "ARGV"
                            | "ENVIRON"
                            | "FILENAME"
                            | "FS"
                            | "RS"
                            | "OFS"
                            | "ORS"
                            | "SUBSEP"
                            | "CONVFMT"
                            | "OFMT"
                            | "IGNORECASE"
                            | "TEXTDOMAIN"
                            | "BINMODE"
                            | "PROCINFO"
                            | "LINT"
                            | "FPAT"
                            | "FIELDWIDTHS"
                            | "RT"
                            | "RSTART"
                            | "RLENGTH"
                            | "NF"
                            | "NR"
                            | "FNR"
                            | "ERRNO"
                            | "FUNCTAB"
                            | "SYMTAB"
                    )
            })
            .map(|(name, _)| name.clone())
            .collect()
    } else {
        BTreeSet::new()
    };
    if !numeric.is_empty() {
        let remaining = max_operations.saturating_sub(p.lexer.count);
        p.lexer.pos = 0;
        p.lexer.count = 0;
        p.lexer.limit = remaining;
        p.targets = AwkTargets::default();
        p.calls.clear();
        p.functions.clear();
        p.writes.clear();
        p.numeric_variables = numeric;
        p.next()?;
        p.program()?;
    }
    // Arithmetic expressions can also carry path bounds without variables;
    // custom formatting invalidates these in either parsing pass.
    if !p.functions.is_empty()
        || p.writes.keys().any(|n| {
            matches!(
                n.as_str(),
                "CONVFMT" | "OFMT" | "SYMTAB" | "FUNCTAB" | "ARGV" | "ARGC" | "PROCINFO"
            )
        })
    {
        p.targets.read_domains.clear();
        p.targets.write_domains.clear();
    }
    Ok(p.targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(s: &str) -> AwkTargets {
        decode(s, 65536, 4096).unwrap()
    }
    #[test]
    fn pure_processing_and_user_functions_have_no_external_effects() {
        for s in [
            "length < 20",
            "{print $1}",
            "!seen[$0]++",
            "{s+=$1} END {print s}",
            "FNR==NR{a[$1,$2]=$8;next} ($1,$2) in a {print a[$1,$2]}",
            "{for(i=1;i<=NF;i++) printf \"%s \", $i}",
            "function f(x){return substr(x,1,2)} {print f($1)}",
            "{gsub(/^[[:space:]]+|[[:space:]]+$/,\"\")}1",
            "{print ($1 > $2)}",
        ] {
            let t = run(s);
            assert!(t.writes.is_empty() && t.executions.is_empty(), "{s}: {t:?}");
        }
    }
    #[test]
    fn reads_writes_and_execution_are_separate_effects() {
        let t = run(
            "BEGIN{getline line < \"/etc/input\"; print line >> \"/tmp/output\"; system(\"date\")}",
        );
        assert_eq!(t.reads[0].1.as_deref(), Some("/etc/input"));
        assert_eq!(t.writes[0].1.as_deref(), Some("/tmp/output"));
        assert_eq!(t.executions.len(), 1);
        assert!(run("{print $0 | \"sh\"}").executions.len() == 1);
        assert!(
            run("BEGIN{\"date\" | getline dt; print dt}")
                .executions
                .len()
                == 1
        );
        assert!(
            run("BEGIN{s=\"/inet/tcp/0/x/1\";print $0 |& s}")
                .executions
                .len()
                == 1
        );
        assert_eq!(run("{print > output}").writes[0].1, None);
        for s in [
            "BEGIN{getline $1 < \".env\"}",
            "BEGIN{getline $(i+1) < \".env\"}",
            "BEGIN{getline a[i,j] < \".env\"}",
        ] {
            assert_eq!(run(s).reads[0].1.as_deref(), Some(".env"), "{s}");
        }
        assert_eq!(
            run("BEGIN{getline a[system(\"date\")] < \".env\"}")
                .executions
                .len(),
            1
        );
    }
    #[test]
    fn quotes_regexes_and_native_escapes_are_not_shell_syntax() {
        let t = run("/system\\(.*[>/]/ {print \"system(\\\"rm\\\") >x\"} # system(\"rm\")");
        assert!(t.writes.is_empty() && t.executions.is_empty());
        assert_eq!(
            run("BEGIN{print > \"/tmp/\\056\\056/etc/x\"}").writes[0]
                .1
                .as_deref(),
            Some("/tmp/../etc/x")
        );
        assert_eq!(
            run("{print > \"~/out\"}").writes[0].1.as_deref(),
            Some("~/out")
        );
        assert_eq!(
            run("{print > (\"/tmp/\" \"out\")}").writes[0].1.as_deref(),
            Some("/tmp/out")
        );
    }
    #[test]
    fn unknown_calls_suffixes_and_budgets_do_not_return_a_safe_prefix() {
        assert!(!run("{unknown($0)}").executions.is_empty());
        for s in [
            "{print $1} @load \"lib\"",
            "{print $1} @fun()",
            "{print $1",
            "{print > \"unterminated}",
            "{print > \"/tmp/\\q\"}",
        ] {
            assert!(decode(s, 65536, 4096).is_err(), "{s}");
        }
        assert!(decode("{print $1}", 2, 4096).is_err());
        assert!(decode("{print $1}", 65536, 2).is_err());
        let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
        assert!(decode(&deep, 65536, 4096).is_err());
    }
}
