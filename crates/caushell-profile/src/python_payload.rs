use std::collections::BTreeMap;
use tree_sitter::{Node, Parser};

mod control;
mod socket;

const SOURCE_LIMIT: usize = 65_536;
const VALUE_LIMIT: usize = 262_144;
const ITEM_LIMIT: usize = 4096;
const STEP_LIMIT: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonEffect {
    ReadFile(String),
    NativeCommand(Vec<String>),
    ShellCommand(String),
    ListenNetwork { host: String, port: u16 },
    RespondNetwork { host: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonInput {
    Environment { name: String, value: Option<String> },
    File { path: String, bytes: Vec<u8> },
}

/// Inputs belong to the Python process frame, not the analyser's environment.
pub trait PythonInputs {
    fn environment(&mut self, name: &str) -> Result<Option<String>>;
    fn file(&mut self, path: &str) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PythonAnalysis {
    pub effects: Vec<PythonEffect>,
    pub inputs: Vec<PythonInput>,
    pub imports: Vec<String>,
    pub stdout: Vec<u8>,
    pub stdout_complete: bool,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Text(String),
    Bytes(Vec<u8>),
    Int(i64),
    Bool(bool),
    None,
    List(Vec<Value>),
    Tuple(Vec<Value>),
    Range(Vec<Value>),
    Path(String),
    Symbol(String),
    Dictionary(Vec<(Value, Value)>),
    Socket(usize),
    Unknown(UnknownValue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnknownValue {
    Bytes,
    Integer,
    Text,
    Boolean,
}

type Result<T> = std::result::Result<T, String>;

pub fn python_isolated_startup(resolved: &crate::ResolvedInvocationArtifact) -> bool {
    let invocation = &resolved.materialized_projection.invocation;
    let executable = invocation
        .command_name
        .as_deref()
        .and_then(|n| std::path::Path::new(n).file_name())
        .and_then(|n| n.to_str());
    if !executable.is_some_and(|n| {
        n == "python3"
            || n.strip_prefix("python3.")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    }) {
        return false;
    }
    let (mut isolated, mut no_site) = (false, false);
    for arg in &invocation.args {
        if arg.text == "-c" || arg.text == "--" || !arg.text.starts_with('-') || arg.text == "-" {
            break;
        }
        if arg.text.starts_with("--") {
            return false;
        }
        for flag in arg.text[1..].chars() {
            match flag {
                'I' => isolated = true,
                'S' => no_site = true,
                'B' | 'u' | 'q' => {}
                _ => return false,
            }
        }
    }
    isolated && no_site
}

pub fn python_source_encoding_supported(source: &str) -> bool {
    if source.starts_with('\u{feff}') {
        return false;
    }
    static COOKIE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let cookie = COOKIE.get_or_init(|| {
        regex::Regex::new(r"^[ \t\x0c]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)").unwrap()
    });
    source.lines().take(2).all(|line| {
        cookie.captures(line).is_none_or(|capture| {
            matches!(
                capture[1].to_ascii_lowercase().as_str(),
                "utf-8" | "utf8" | "utf_8"
            )
        })
    })
}

pub fn analyze_python(
    source: &str,
    argv: &[String],
    inputs: &mut dyn PythonInputs,
) -> PythonAnalysis {
    let mut engine = Engine {
        source,
        inputs,
        names: BTreeMap::new(),
        argv: Value::List(argv.iter().cloned().map(Value::Text).collect()),
        steps: 0,
        statement_depth: 0,
        sockets: Vec::new(),
        report: PythonAnalysis {
            stdout_complete: true,
            ..PythonAnalysis::default()
        },
    };
    let result = (|| {
        if source.contains('\r') {
            return Err("unsupported Python source newline encoding".into());
        }
        if source.len() > SOURCE_LIMIT
            || source.contains('\0')
            || argv.len() > ITEM_LIMIT
            || argv.iter().map(String::len).sum::<usize>() > VALUE_LIMIT
        {
            return Err("Python input budget exceeded".into());
        }
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|_| "Python parser unavailable")?;
        let tree = parser
            .parse(source, None)
            .ok_or("Python parse budget exceeded")?;
        let root = tree.root_node();
        if root.has_error() {
            return Err("invalid Python syntax".into());
        }
        for statement in named(root) {
            engine.statement(statement)?;
        }
        Ok(())
    })();
    if let Err(gap) = result {
        // A prefix is not a complete program or a complete output stream.
        engine.report.effects.clear();
        engine.report.stdout.clear();
        engine.report.stdout_complete = false;
        engine.report.gap = Some(gap);
    }
    if !engine.report.stdout_complete {
        engine.report.stdout.clear();
    }
    engine.report
}

struct Engine<'a> {
    source: &'a str,
    inputs: &'a mut dyn PythonInputs,
    names: BTreeMap<String, Value>,
    argv: Value,
    steps: usize,
    statement_depth: usize,
    report: PythonAnalysis,
    sockets: Vec<socket::Socket>,
}

fn named(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}
fn field<'a>(node: Node<'a>, name: &str) -> Result<Node<'a>> {
    node.child_by_field_name(name)
        .ok_or_else(|| format!("missing Python {name}"))
}
fn text(value: Value) -> Result<String> {
    if let Value::Text(s) = value {
        Ok(s)
    } else {
        Err("Python string required".into())
    }
}
fn integer(value: Value) -> Result<i64> {
    if let Value::Int(n) = value {
        Ok(n)
    } else {
        Err("Python integer required".into())
    }
}
fn strings(value: Value) -> Result<Vec<String>> {
    match value {
        Value::List(v) | Value::Tuple(v) => v.into_iter().map(text).collect(),
        _ => Err("Python argv list required".into()),
    }
}
fn value_size(value: &Value) -> usize {
    let mut stack = vec![(value, 0)];
    let mut size = 0;
    while let Some((value, depth)) = stack.pop() {
        if depth > 48 {
            return VALUE_LIMIT + 1;
        }
        size += 32;
        match value {
            Value::Text(s) | Value::Path(s) | Value::Symbol(s) => size += s.len(),
            Value::Bytes(b) => size += b.len(),
            Value::List(v) | Value::Tuple(v) | Value::Range(v) => {
                stack.extend(v.iter().map(|v| (v, depth + 1)))
            }
            Value::Dictionary(v) => {
                stack.extend(v.iter().flat_map(|(k, v)| [(k, depth + 1), (v, depth + 1)]))
            }
            _ => {}
        }
        if size > VALUE_LIMIT {
            return size;
        }
    }
    size
}
impl Engine<'_> {
    fn raw(&self, node: Node<'_>) -> &str {
        &self.source[node.byte_range()]
    }
    fn step(&mut self) -> Result<()> {
        self.steps += 1;
        if self.steps > STEP_LIMIT {
            Err("Python analysis budget exceeded".into())
        } else {
            Ok(())
        }
    }
    fn input_budget(&self) -> Result<()> {
        let bytes = self
            .report
            .inputs
            .iter()
            .map(|input| match input {
                PythonInput::Environment { name, value } => {
                    name.len() + value.as_ref().map_or(0, String::len)
                }
                PythonInput::File { path, bytes } => path.len() + bytes.len(),
            })
            .sum::<usize>();
        if self.report.inputs.len() >= 128 || bytes > 1_048_576 {
            Err("Python input observation budget exceeded".into())
        } else {
            Ok(())
        }
    }
    fn statement(&mut self, node: Node<'_>) -> Result<()> {
        self.step()?;
        if self.statement_depth >= 48 {
            return Err("Python statement depth exceeded".into());
        }
        self.statement_depth += 1;
        let result = self.statement_inner(node);
        self.statement_depth -= 1;
        if self.report.effects.len() > 128 {
            return Err("Python effect budget exceeded".into());
        }
        result
    }
    fn statement_inner(&mut self, node: Node<'_>) -> Result<()> {
        match node.kind() {
            "comment" => Ok(()),
            "import_statement" => {
                for item in named(node) {
                    let (name, alias) = if item.kind() == "aliased_import" {
                        (
                            self.raw(field(item, "name")?).to_owned(),
                            Some(self.raw(field(item, "alias")?).to_owned()),
                        )
                    } else {
                        (self.raw(item).to_owned(), None)
                    };
                    self.import(&name)?;
                    let binding = alias.unwrap_or_else(|| name.split('.').next().unwrap().into());
                    let symbol = if item.kind() == "aliased_import" {
                        name
                    } else {
                        name.split('.').next().unwrap().into()
                    };
                    self.names.insert(binding, Value::Symbol(symbol));
                }
                Ok(())
            }
            "import_from_statement" => {
                let module = field(node, "module_name")?;
                let name = self.raw(module).to_owned();
                self.import(&name)?;
                for item in named(node).into_iter().filter(|n| n.id() != module.id()) {
                    let (member, alias) = if item.kind() == "aliased_import" {
                        (
                            self.raw(field(item, "name")?).to_owned(),
                            self.raw(field(item, "alias")?).to_owned(),
                        )
                    } else {
                        let member = self.raw(item).to_owned();
                        (member.clone(), member)
                    };
                    if !matches!(
                        (name.as_str(), member.as_str()),
                        ("pathlib", "Path") | ("urllib.parse", "quote_from_bytes")
                    ) {
                        return Err(format!("unsupported Python import {name}.{member}"));
                    }
                    self.names
                        .insert(alias, Value::Symbol(format!("{name}.{member}")));
                }
                Ok(())
            }
            "expression_statement" => {
                for expression in named(node) {
                    if expression.kind() == "assignment" {
                        // Chained, annotated and unpacking assignment remain outside the subset.
                        if named(expression).len() != 2 {
                            return Err("unsupported Python assignment".into());
                        }
                        let left = field(expression, "left")?;
                        let value = self.eval(field(expression, "right")?, 0)?;
                        self.assign(left, value, 0)?;
                    } else {
                        self.eval(expression, 0)?;
                    }
                }
                Ok(())
            }
            "pass_statement" => Ok(()),
            "assert_statement" | "for_statement" | "if_statement" => self.control(node),
            _ => Err(format!(
                "unsupported Python statement {} at byte {}",
                node.kind(),
                node.start_byte()
            )),
        }
    }
    fn import(&mut self, name: &str) -> Result<()> {
        if self.report.effects.iter().any(|effect| {
            matches!(
                effect,
                PythonEffect::NativeCommand(_) | PythonEffect::ShellCommand(_)
            )
        }) {
            return Err("Python module load follows a potentially mutating child".into());
        }
        if !matches!(
            name,
            "os" | "sys" | "pathlib" | "subprocess" | "urllib.parse" | "socket" | "json"
        ) {
            return Err(format!("unsupported Python module {name}"));
        }
        if !self.report.imports.iter().any(|s| s == name) {
            self.report.imports.push(name.into());
        }
        Ok(())
    }
    fn symbol(&self, node: Node<'_>) -> Result<String> {
        let mut node = node;
        let mut attributes = Vec::new();
        while node.kind() == "attribute" {
            if attributes.len() >= 48 {
                return Err("Python attribute depth exceeded".into());
            }
            attributes.push(self.raw(field(node, "attribute")?));
            node = field(node, "object")?;
        }
        let base: Result<String> = match node.kind() {
            "identifier" => match self.names.get(self.raw(node)) {
                Some(Value::Symbol(name)) => Ok(name.clone()),
                None if matches!(self.raw(node), "print" | "str" | "len" | "list" | "range") => {
                    Ok(self.raw(node).into())
                }
                _ => Err("unknown Python callable or attribute base".into()),
            },
            _ => Err("dynamic Python callable".into()),
        };
        let mut symbol = base?;
        for attribute in attributes.into_iter().rev() {
            symbol.push('.');
            symbol.push_str(attribute);
        }
        Ok(symbol)
    }
    fn eval(&mut self, node: Node<'_>, depth: usize) -> Result<Value> {
        self.step()?;
        if depth > 48 {
            return Err("Python expression depth exceeded".into());
        }
        let value = match node.kind() {
            "string" => decode_string(self.raw(node))?,
            "concatenated_string" => {
                let mut result = None;
                for item in named(node) {
                    let value = self.eval(item, depth + 1)?;
                    result = Some(match result {
                        None => value,
                        Some(left) => add(left, value)?,
                    });
                }
                result.ok_or("empty Python string")?
            }
            "integer" => Value::Int(
                self.raw(node)
                    .parse()
                    .map_err(|_| "unsupported Python integer")?,
            ),
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "none" => Value::None,
            "identifier" => self
                .names
                .get(self.raw(node))
                .cloned()
                .ok_or_else(|| format!("unknown Python name {}", self.raw(node)))?,
            "attribute" => {
                let symbol = self.symbol(node)?;
                if symbol == "sys.argv" {
                    self.argv.clone()
                } else if matches!(
                    symbol.as_str(),
                    "os.environ"
                        | "urllib.parse"
                        | "pathlib.Path"
                        | "urllib.parse.quote_from_bytes"
                        | "subprocess.run"
                        | "socket.socket"
                        | "socket.AF_INET"
                        | "socket.SOCK_STREAM"
                        | "socket.SOL_SOCKET"
                        | "socket.SO_REUSEADDR"
                        | "json.dumps"
                        | "os.getpid"
                ) {
                    Value::Symbol(symbol)
                } else {
                    return Err(format!("unsupported Python attribute {symbol}"));
                }
            }
            "list" | "tuple" => {
                let mut values = Vec::new();
                let mut bytes = 32;
                for item in named(node) {
                    if item.kind() == "list_splat" {
                        match self.eval(
                            item.named_child(0).ok_or("missing unpack value")?,
                            depth + 1,
                        )? {
                            Value::List(items) | Value::Tuple(items) | Value::Range(items) => {
                                bytes += items.iter().map(value_size).sum::<usize>();
                                values.extend(items);
                            }
                            _ => return Err("Python list unpack requires a list".into()),
                        }
                    } else {
                        let value = self.eval(item, depth + 1)?;
                        bytes += value_size(&value);
                        values.push(value);
                    }
                    if values.len() > ITEM_LIMIT || bytes > VALUE_LIMIT {
                        return Err("Python item budget exceeded".into());
                    }
                }
                if node.kind() == "tuple" {
                    Value::Tuple(values)
                } else {
                    Value::List(values)
                }
            }
            "parenthesized_expression" => self.eval(
                node.named_child(0).ok_or("empty Python expression")?,
                depth + 1,
            )?,
            "dictionary" => {
                let mut values = Vec::new();
                for pair in named(node) {
                    if pair.kind() != "pair" || values.len() >= ITEM_LIMIT {
                        return Err("unsupported Python dictionary item".into());
                    }
                    let key = self.eval(field(pair, "key")?, depth + 1)?;
                    if !matches!(key, Value::Text(_)) {
                        return Err("unsupported Python dictionary key".into());
                    }
                    let value = self.eval(field(pair, "value")?, depth + 1)?;
                    if let Some((_, old)) = values.iter_mut().find(|(k, _)| k == &key) {
                        *old = value;
                    } else {
                        values.push((key, value));
                    }
                    if values
                        .iter()
                        .map(|(k, v)| value_size(k) + value_size(v))
                        .sum::<usize>()
                        > VALUE_LIMIT
                    {
                        return Err("Python dictionary budget exceeded".into());
                    }
                }
                Value::Dictionary(values)
            }
            "comparison_operator" => self.compare(node, depth + 1)?,
            "binary_operator" => {
                if self.raw(field(node, "operator")?) != "+" {
                    return Err("unsupported Python operator".into());
                }
                let left = self.eval(field(node, "left")?, depth + 1)?;
                let right = self.eval(field(node, "right")?, depth + 1)?;
                add(left, right)?
            }
            "unary_operator" if self.raw(field(node, "operator")?) == "-" => Value::Int(
                integer(self.eval(field(node, "argument")?, depth + 1)?)?
                    .checked_neg()
                    .ok_or("Python integer overflow")?,
            ),
            "subscript" => {
                let value = self.eval(field(node, "value")?, depth + 1)?;
                let subscript = field(node, "subscript")?;
                if value == Value::Symbol("os.environ".into()) {
                    self.input_budget()?;
                    let name = text(self.eval(subscript, depth + 1)?)?;
                    let result = self.inputs.environment(&name)?;
                    self.report.inputs.push(PythonInput::Environment {
                        name: name.clone(),
                        value: result.clone(),
                    });
                    Value::Text(
                        result.ok_or_else(|| format!("Python environment key {name} is absent"))?,
                    )
                } else if subscript.kind() == "slice" {
                    let tuple = matches!(value, Value::Tuple(_));
                    let items = match value {
                        Value::List(items) | Value::Tuple(items) => items,
                        _ => return Err("Python slice requires a sequence".into()),
                    };
                    let parts = self.raw(subscript).split(':').collect::<Vec<_>>();
                    if parts.len() != 2 {
                        return Err("Python slice step is unsupported".into());
                    }
                    let bound = |s: &str, fallback| -> Result<usize> {
                        if s.trim().is_empty() {
                            Ok(fallback)
                        } else {
                            Ok(slice_index(
                                s.trim().parse().map_err(|_| "dynamic Python slice")?,
                                items.len(),
                            ))
                        }
                    };
                    let start = bound(parts[0], 0)?;
                    let end = bound(parts[1], items.len())?;
                    let items = if start >= end {
                        Vec::new()
                    } else {
                        items[start..end].to_vec()
                    };
                    if tuple {
                        Value::Tuple(items)
                    } else {
                        Value::List(items)
                    }
                } else {
                    let index = integer(self.eval(subscript, depth + 1)?)?;
                    let items = match value {
                        Value::List(items) | Value::Tuple(items) | Value::Range(items) => items,
                        _ => return Err("Python index requires a sequence".into()),
                    };
                    let index = if index < 0 {
                        items.len() as i64 + index
                    } else {
                        index
                    };
                    items
                        .get(usize::try_from(index).map_err(|_| "Python index out of range")?)
                        .cloned()
                        .ok_or("Python index out of range")?
                }
            }
            "call" => self.call(node, depth + 1)?,
            _ => {
                return Err(format!(
                    "unsupported Python expression {} at byte {}",
                    node.kind(),
                    node.start_byte()
                ));
            }
        };
        if value_size(&value) > VALUE_LIMIT {
            return Err("Python value budget exceeded".into());
        }
        Ok(value)
    }
    fn call(&mut self, node: Node<'_>, depth: usize) -> Result<Value> {
        let function = field(node, "function")?;
        let symbol = self.symbol(function).ok();
        let receiver = if function.kind() == "attribute" {
            Some(self.eval(field(function, "object")?, depth + 1)?)
        } else {
            None
        };
        let mut args = Vec::new();
        let mut kwargs = BTreeMap::new();
        let mut argument_bytes = 0;
        for arg in named(field(node, "arguments")?) {
            if arg.kind() == "keyword_argument" {
                let key = self.raw(field(arg, "name")?).to_owned();
                let value = self.eval(field(arg, "value")?, depth + 1)?;
                argument_bytes += key.len() + value_size(&value);
                if kwargs.insert(key, value).is_some() {
                    return Err("duplicate Python keyword".into());
                }
            } else {
                if !kwargs.is_empty() || matches!(arg.kind(), "list_splat" | "dictionary_splat") {
                    return Err("unsupported Python call unpack/order".into());
                }
                let value = self.eval(arg, depth + 1)?;
                argument_bytes += value_size(&value);
                args.push(value);
            }
            if argument_bytes > VALUE_LIMIT || args.len() + kwargs.len() > ITEM_LIMIT {
                return Err("Python call argument budget exceeded".into());
            }
        }
        let result = match symbol.as_deref() {
            Some("socket.socket") => self.new_socket(args, kwargs)?,
            Some("os.getpid") if args.is_empty() && kwargs.is_empty() => {
                Value::Unknown(UnknownValue::Integer)
            }
            Some("json.dumps") if args.len() == 1 && kwargs.is_empty() => {
                control::json(args.remove(0))?
            }
            Some("list") if args.len() == 1 && kwargs.is_empty() => match args.remove(0) {
                Value::List(items) | Value::Tuple(items) | Value::Range(items) => {
                    Value::List(items)
                }
                _ => return Err("unsupported Python list conversion".into()),
            },
            Some("range") if !args.is_empty() && args.len() <= 3 && kwargs.is_empty() => {
                control::range(args)?
            }
            Some("pathlib.Path") if args.len() == 1 && kwargs.is_empty() => {
                Value::Path(text(args.remove(0))?)
            }
            Some("subprocess.run") if args.len() == 1 => {
                let shell = kwargs.remove("shell").unwrap_or(Value::Bool(false));
                if !matches!(kwargs.remove("check"), None | Some(Value::Bool(_)))
                    || !kwargs.is_empty()
                {
                    return Err("unsupported Python subprocess options".into());
                }
                let effect = match shell {
                    Value::Bool(false) => {
                        let argv = strings(args.remove(0))?;
                        if argv.is_empty()
                            || argv[0].is_empty()
                            || argv.iter().any(|s| s.contains('\0'))
                        {
                            return Err("invalid Python subprocess argv".into());
                        }
                        PythonEffect::NativeCommand(argv)
                    }
                    Value::Bool(true) => {
                        let code = text(args.remove(0))?;
                        if code.contains('\0') {
                            return Err("invalid Python shell command".into());
                        }
                        PythonEffect::ShellCommand(code)
                    }
                    _ => return Err("unknown Python shell mode".into()),
                };
                self.report.effects.push(effect);
                self.report.stdout_complete = false;
                let mut bytes = 0;
                let mut fields = 0;
                for effect in &self.report.effects {
                    match effect {
                        PythonEffect::NativeCommand(argv) => {
                            fields += argv.len();
                            bytes += argv.iter().map(String::len).sum::<usize>();
                        }
                        PythonEffect::ShellCommand(code) => bytes += code.len(),
                        _ => {}
                    }
                }
                if self.report.effects.len() > 128 || bytes > VALUE_LIMIT || fields > ITEM_LIMIT {
                    return Err("Python effect budget exceeded".into());
                }
                // CompletedProcess fields are not a pure value contract.
                Value::Symbol("subprocess.CompletedProcess".into())
            }
            Some("urllib.parse.quote_from_bytes") if !args.is_empty() && args.len() <= 2 => {
                let Value::Bytes(bytes) = args.remove(0) else {
                    return Err("Python quote requires bytes".into());
                };
                let safe = if args.is_empty() {
                    kwargs.remove("safe").unwrap_or(Value::Text("/".into()))
                } else {
                    if kwargs.contains_key("safe") {
                        return Err("duplicate Python safe argument".into());
                    }
                    args.remove(0)
                };
                if !kwargs.is_empty() {
                    return Err("unsupported Python quote options".into());
                }
                let safe = match safe {
                    Value::Text(s) => s.into_bytes(),
                    Value::Bytes(b) => b,
                    _ => return Err("invalid Python quote safe value".into()),
                };
                let mut encoded = String::new();
                for byte in bytes {
                    if byte.is_ascii_alphanumeric()
                        || b"_.-~".contains(&byte)
                        || (byte < 128 && safe.contains(&byte))
                    {
                        encoded.push(byte as char);
                    } else {
                        encoded.push_str(&format!("%{byte:02X}"));
                    }
                }
                Value::Text(encoded)
            }
            Some("print") => {
                if !matches!(kwargs.remove("flush"), None | Some(Value::Bool(_))) {
                    return Err("invalid Python print flush".into());
                }
                let sep = text(kwargs.remove("sep").unwrap_or(Value::Text(" ".into())))?;
                let end = text(kwargs.remove("end").unwrap_or(Value::Text("\n".into())))?;
                if !kwargs.is_empty() {
                    return Err("unsupported Python print destination".into());
                }
                let pieces = args
                    .into_iter()
                    .map(control::print_value)
                    .collect::<Result<Option<Vec<_>>>>()?;
                let Some(pieces) = pieces else {
                    self.report.stdout_complete = false;
                    return Ok(Value::None);
                };
                let size = self.report.stdout.len()
                    + pieces.iter().map(String::len).sum::<usize>()
                    + sep.len() * pieces.len().saturating_sub(1)
                    + end.len();
                if size > VALUE_LIMIT {
                    return Err("Python stdout budget exceeded".into());
                }
                self.report
                    .stdout
                    .extend_from_slice(pieces.join(&sep).as_bytes());
                self.report.stdout.extend_from_slice(end.as_bytes());
                if self.report.stdout.len() > VALUE_LIMIT {
                    return Err("Python stdout budget exceeded".into());
                }
                Value::None
            }
            Some("str") if args.len() == 1 && kwargs.is_empty() => {
                Value::Text(display(args.remove(0))?)
            }
            Some("len") if args.len() == 1 && kwargs.is_empty() => {
                Value::Int(match args.remove(0) {
                    Value::Text(s) => s.chars().count() as i64,
                    Value::Bytes(b) => b.len() as i64,
                    Value::List(v) | Value::Tuple(v) | Value::Range(v) => v.len() as i64,
                    _ => return Err("unsupported Python len value".into()),
                })
            }
            _ if function.kind() == "attribute" => {
                let object = receiver.ok_or("missing Python method receiver")?;
                let method = self.raw(field(function, "attribute")?).to_owned();
                match (object, method.as_str()) {
                    (Value::Socket(id), method) => self.socket_call(id, method, args, kwargs)?,
                    (Value::Path(path), "read_bytes") if args.is_empty() && kwargs.is_empty() => {
                        self.input_budget()?;
                        if self.report.effects.iter().any(|effect| {
                            matches!(
                                effect,
                                PythonEffect::NativeCommand(_) | PythonEffect::ShellCommand(_)
                            )
                        }) {
                            return Err(
                                "Python file input follows a potentially mutating child".into()
                            );
                        }
                        let bytes = self.inputs.file(&path)?;
                        if bytes.len() > VALUE_LIMIT {
                            return Err("Python file budget exceeded".into());
                        }
                        self.report.inputs.push(PythonInput::File {
                            path: path.clone(),
                            bytes: bytes.clone(),
                        });
                        self.report.effects.push(PythonEffect::ReadFile(path));
                        Value::Bytes(bytes)
                    }
                    (Value::Bytes(bytes), "decode") if args.len() <= 2 => {
                        let encoding = if args.is_empty() {
                            kwargs
                                .remove("encoding")
                                .unwrap_or(Value::Text("utf-8".into()))
                        } else {
                            args.remove(0)
                        };
                        let errors = if args.is_empty() {
                            kwargs
                                .remove("errors")
                                .unwrap_or(Value::Text("strict".into()))
                        } else {
                            args.remove(0)
                        };
                        if !kwargs.is_empty()
                            || !matches!(text(encoding)?.as_str(), "utf-8" | "utf8" | "UTF-8")
                            || text(errors)? != "strict"
                        {
                            return Err("unsupported Python decode mode".into());
                        }
                        Value::Text(
                            String::from_utf8(bytes).map_err(|_| "Python UTF-8 decode failed")?,
                        )
                    }
                    (Value::Text(s), "split") if args.len() == 1 && kwargs.is_empty() => {
                        let separator = text(args.remove(0))?;
                        if separator.is_empty() {
                            return Err("empty Python split separator".into());
                        }
                        let values = s
                            .split(&separator)
                            .take(ITEM_LIMIT + 1)
                            .map(|s| Value::Text(s.into()))
                            .collect::<Vec<_>>();
                        if values.len() > ITEM_LIMIT {
                            return Err("Python split budget exceeded".into());
                        }
                        Value::List(values)
                    }
                    _ => return Err(format!("unsupported Python method {method}")),
                }
            }
            _ => return Err("unknown Python call".into()),
        };
        Ok(result)
    }
}
fn add(left: Value, right: Value) -> Result<Value> {
    Ok(match (left, right) {
        (Value::Text(mut a), Value::Text(b)) => {
            a.push_str(&b);
            Value::Text(a)
        }
        (Value::Bytes(mut a), Value::Bytes(b)) => {
            a.extend(b);
            Value::Bytes(a)
        }
        (Value::List(mut a), Value::List(b)) => {
            a.extend(b);
            if a.len() > ITEM_LIMIT {
                return Err("Python item budget exceeded".into());
            }
            Value::List(a)
        }
        (Value::Tuple(mut a), Value::Tuple(b)) => {
            a.extend(b);
            if a.len() > ITEM_LIMIT {
                return Err("Python item budget exceeded".into());
            }
            Value::Tuple(a)
        }
        (Value::Int(a), Value::Int(b)) => {
            Value::Int(a.checked_add(b).ok_or("Python integer overflow")?)
        }
        _ => return Err("unsupported Python addition operands".into()),
    })
}
fn display(value: Value) -> Result<String> {
    Ok(match value {
        Value::Text(s) => s,
        Value::Int(i) => i.to_string(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::None => "None".into(),
        _ => return Err("unsupported Python string conversion".into()),
    })
}
fn slice_index(index: i64, length: usize) -> usize {
    let index = if index < 0 {
        length as i64 + index
    } else {
        index
    };
    index.clamp(0, length as i64) as usize
}

fn decode_string(source: &str) -> Result<Value> {
    let quote_at = source.find(['\'', '"']).ok_or("invalid Python string")?;
    let prefix = source[..quote_at].to_ascii_lowercase();
    if !matches!(prefix.as_str(), "" | "u" | "r" | "b" | "br" | "rb") {
        return Err("unsupported Python string prefix".into());
    }
    let bytes = prefix.contains('b');
    let raw = prefix.contains('r');
    let quote = &source[quote_at..quote_at + 1];
    let width = if source[quote_at..].starts_with(&quote.repeat(3)) {
        3
    } else {
        1
    };
    if !source.ends_with(&quote.repeat(width)) || source.len() < quote_at + 2 * width {
        return Err("invalid Python string delimiter".into());
    }
    let body = &source[quote_at + width..source.len() - width];
    if bytes && !body.is_ascii() {
        return Err("non-ASCII Python byte literal".into());
    }
    let mut output = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' || raw {
            let mut buf = [0; 4];
            output.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let escaped = chars.next().ok_or("invalid Python escape")?;
        let value = match escaped {
            '\n' => continue,
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'a' => '\x07',
            'b' => '\x08',
            'f' => '\x0c',
            'v' => '\x0b',
            'x' | 'u' | 'U' => {
                if bytes && escaped != 'x' {
                    return Err("unsupported Python bytes escape".into());
                }
                let count = match escaped {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits = chars.by_ref().take(count).collect::<String>();
                if digits.len() != count {
                    return Err("invalid Python hex escape".into());
                }
                let code =
                    u32::from_str_radix(&digits, 16).map_err(|_| "invalid Python hex escape")?;
                if bytes {
                    output.push(code as u8);
                    continue;
                }
                char::from_u32(code).ok_or("unsupported Python Unicode scalar")?
            }
            '0'..='7' => {
                let mut digits = escaped.to_string();
                while digits.len() < 3 && chars.peek().is_some_and(|c| matches!(c, '0'..='7')) {
                    digits.push(chars.next().unwrap());
                }
                let code = u32::from_str_radix(&digits, 8).unwrap();
                if code > 255 {
                    return Err("unsupported Python octal escape".into());
                }
                if bytes {
                    output.push(code as u8);
                    continue;
                }
                char::from_u32(code).unwrap()
            }
            _ => return Err("unsupported Python escape".into()),
        };
        let mut buf = [0; 4];
        output.extend_from_slice(value.encode_utf8(&mut buf).as_bytes());
    }
    if bytes {
        Ok(Value::Bytes(output))
    } else {
        Ok(Value::Text(
            String::from_utf8(output).map_err(|_| "invalid Python Unicode string")?,
        ))
    }
}
