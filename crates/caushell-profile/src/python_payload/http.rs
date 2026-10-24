use super::*;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Method {
    parameters: Vec<String>,
    varargs: Option<String>,
    locals: Vec<String>,
    body: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HandlerClass {
    methods: BTreeMap<String, Method>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HttpServer {
    host: String,
    port: u16,
    handler: usize,
    closed: bool,
}

impl Engine<'_> {
    pub(super) fn define_handler(&mut self, node: Node<'_>) -> Result<()> {
        if self.function_depth != 0 || self.handlers.len() >= 128 {
            return Err("Python handler definition budget/scope exceeded".into());
        }
        if named(node).len() != 3 || node.child_by_field_name("type_parameters").is_some() {
            return Err("unsupported Python handler definition".into());
        }
        let bases = named(field(node, "superclasses")?);
        if bases.len() != 1
            || self.eval(bases[0], 0)? != Value::Symbol("http.server.BaseHTTPRequestHandler".into())
        {
            return Err("Python handler requires the declared HTTP base class".into());
        }
        let mut methods = BTreeMap::new();
        for item in named(field(node, "body")?) {
            match item.kind() {
                "comment" | "pass_statement" => continue,
                "expression_statement"
                    if named(item).len() == 1 && named(item)[0].kind() == "string" =>
                {
                    self.eval(named(item)[0], 0)?;
                    continue;
                }
                "function_definition" => {}
                _ => return Err("unsupported Python handler class member".into()),
            }
            let name = self.raw(field(item, "name")?).to_owned();
            if !(name.starts_with("do_")
                && name[3..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
                && name != "log_message"
            {
                return Err(format!("unsupported Python HTTP override {name}"));
            }
            if named(item).len() != 3 || self.raw(item).trim_start().starts_with("async ") {
                return Err("unsupported Python handler signature".into());
            }
            let mut parameters = Vec::new();
            let mut varargs = None;
            for parameter in named(field(item, "parameters")?) {
                match parameter.kind() {
                    "identifier" if varargs.is_none() => {
                        parameters.push(self.raw(parameter).into())
                    }
                    "list_splat_pattern" if name == "log_message" && varargs.is_none() => {
                        let argument = parameter.named_child(0).ok_or("missing Python varargs")?;
                        if argument.kind() != "identifier" {
                            return Err("unsupported Python varargs".into());
                        }
                        varargs = Some(self.raw(argument).into());
                    }
                    _ => return Err("unsupported Python handler parameters".into()),
                }
            }
            if parameters.is_empty()
                || (name != "log_message" && (parameters.len() != 1 || varargs.is_some()))
            {
                return Err("unsupported Python HTTP method arity".into());
            }
            let unique = parameters
                .iter()
                .chain(varargs.iter())
                .collect::<std::collections::BTreeSet<_>>();
            if unique.len() != parameters.len() + usize::from(varargs.is_some()) {
                return Err("duplicate Python HTTP parameter".into());
            }
            let body = field(item, "body")?;
            let locals = local_names(self.source, body)?;
            if methods
                .insert(
                    name,
                    Method {
                        parameters,
                        varargs,
                        locals,
                        body: body.byte_range(),
                    },
                )
                .is_some()
            {
                return Err("duplicate Python HTTP method definition".into());
            }
        }
        let id = self.handlers.len();
        self.handlers.push(HandlerClass { methods });
        self.names.insert(
            self.raw(field(node, "name")?).into(),
            Value::HandlerClass(id),
        );
        Ok(())
    }

    pub(super) fn new_http_server(
        &mut self,
        args: Vec<Value>,
        kwargs: BTreeMap<String, Value>,
    ) -> Result<Value> {
        if args.len() != 2 || !kwargs.is_empty() || self.servers.len() >= 128 {
            return Err("unsupported Python HTTPServer constructor".into());
        }
        let [Value::Tuple(address), Value::HandlerClass(handler)] = args.as_slice() else {
            return Err("Python HTTPServer requires a known address and handler".into());
        };
        let [Value::Text(host), Value::Int(port)] = address.as_slice() else {
            return Err("unknown Python HTTP bind address".into());
        };
        if host.parse::<std::net::Ipv4Addr>().is_err() {
            return Err("Python HTTP bind host is not numeric IPv4".into());
        }
        let port = u16::try_from(*port).map_err(|_| "invalid Python HTTP port")?;
        let id = self.servers.len();
        self.servers.push(HttpServer {
            host: host.clone(),
            port,
            handler: *handler,
            closed: false,
        });
        self.report.effects.push(PythonEffect::ListenNetwork {
            host: host.clone(),
            port,
        });
        self.report.stdout_complete = false;
        Ok(Value::HttpServer(id))
    }

    pub(super) fn http_attribute(&mut self, object: Value, name: &str) -> Result<Value> {
        match (object, name) {
            (Value::HttpServer(id), "server_address") => {
                let server = self.server(id)?;
                Ok(Value::Tuple(vec![
                    Value::Text(server.host.clone()),
                    if server.port == 0 {
                        Value::Unknown(UnknownValue::Integer)
                    } else {
                        Value::Int(i64::from(server.port))
                    },
                ]))
            }
            (Value::HttpRequest(_), "path" | "command" | "request_version" | "requestline") => {
                Ok(Value::Unknown(UnknownValue::Text))
            }
            (Value::HttpRequest(id), "wfile") => Ok(Value::ResponseWriter(id)),
            _ => Err(format!("unsupported Python HTTP attribute {name}")),
        }
    }

    pub(super) fn http_assignment(
        &mut self,
        object: Value,
        name: &str,
        value: Value,
    ) -> Result<()> {
        match (object, name, value) {
            (Value::HttpServer(id), "timeout", Value::Int(seconds)) if seconds >= 0 => {
                self.server(id)?;
                Ok(())
            }
            (Value::HttpServer(id), "timeout", Value::None) => {
                self.server(id)?;
                Ok(())
            }
            _ => Err("unsupported Python HTTP attribute assignment".into()),
        }
    }

    fn server(&self, id: usize) -> Result<&HttpServer> {
        self.servers
            .get(id)
            .filter(|s| !s.closed)
            .ok_or_else(|| "Python HTTP server is closed or unknown".into())
    }

    fn response(&mut self, id: usize) -> Result<()> {
        let server = self.server(id)?;
        self.report.effects.push(PythonEffect::RespondNetwork {
            host: server.host.clone(),
            port: server.port,
        });
        if self.report.effects.len() > 128 {
            return Err("Python effect budget exceeded".into());
        }
        Ok(())
    }

    pub(super) fn http_call(
        &mut self,
        object: Value,
        name: &str,
        args: Vec<Value>,
        kwargs: BTreeMap<String, Value>,
    ) -> Result<Value> {
        if !kwargs.is_empty() {
            return Err("unsupported Python HTTP keyword argument".into());
        }
        match (object, name, args.as_slice()) {
            (Value::HttpServer(id), "handle_request", []) => {
                let server = self.server(id)?.clone();
                let methods = self
                    .handlers
                    .get(server.handler)
                    .ok_or("unknown Python handler class")?
                    .methods
                    .clone();
                // Parsing errors and successful requests may both invoke the
                // logging hook; method selection belongs to untrusted input.
                if let Some(method) = methods.get("log_message") {
                    self.run_method(id, method)?;
                }
                for (name, method) in &methods {
                    if name.starts_with("do_") {
                        self.run_method(id, method)?;
                    }
                }
                self.response(id)?;
                Ok(Value::None)
            }
            (Value::HttpServer(id), "server_close", []) => {
                self.server(id)?;
                self.servers[id].closed = true;
                Ok(Value::None)
            }
            (
                Value::HttpRequest(id),
                "send_response" | "send_response_only" | "send_error",
                [Value::Int(_)],
            ) => {
                self.response(id)?;
                Ok(Value::None)
            }
            (
                Value::HttpRequest(id),
                "send_response" | "send_response_only" | "send_error",
                [
                    Value::Int(_),
                    Value::Text(_) | Value::None | Value::Unknown(UnknownValue::Text),
                ],
            ) => {
                self.response(id)?;
                Ok(Value::None)
            }
            (
                Value::HttpRequest(id),
                "send_header",
                [
                    Value::Text(_) | Value::Unknown(UnknownValue::Text),
                    Value::Text(_) | Value::Unknown(UnknownValue::Text),
                ],
            ) => {
                self.response(id)?;
                Ok(Value::None)
            }
            (Value::HttpRequest(id), "end_headers" | "flush_headers", []) => {
                self.response(id)?;
                Ok(Value::None)
            }
            (
                Value::ResponseWriter(id),
                "write",
                [Value::Bytes(_) | Value::Unknown(UnknownValue::Bytes)],
            ) => {
                self.response(id)?;
                Ok(Value::Unknown(UnknownValue::Integer))
            }
            _ => Err(format!("unsupported Python HTTP call {name}")),
        }
    }

    fn run_method(&mut self, server: usize, method: &Method) -> Result<()> {
        if self.function_depth >= 32 {
            return Err("Python function depth exceeded".into());
        }
        let tree = self
            .tree
            .as_ref()
            .ok_or("Python syntax tree unavailable")?
            .clone();
        let body = tree
            .root_node()
            .descendant_for_byte_range(method.body.start, method.body.end)
            .and_then(|node| {
                std::iter::successors(Some(node), |n| n.parent())
                    .find(|n| n.kind() == "block" && n.byte_range() == method.body)
            })
            .ok_or("Python method body unavailable")?;
        let saved_names = self.names.clone();
        let saved_argv = self.argv.clone();
        let saved_servers = self.servers.clone();
        let saved_sockets = self.sockets.clone();
        let saved_flow = std::mem::take(&mut self.flow);
        for name in &method.locals {
            self.names.insert(name.clone(), Value::Unbound);
        }
        for (index, name) in method.parameters.iter().enumerate() {
            self.names.insert(
                name.clone(),
                if index == 0 {
                    Value::HttpRequest(server)
                } else {
                    Value::Unknown(UnknownValue::Text)
                },
            );
        }
        if let Some(name) = &method.varargs {
            self.names
                .insert(name.clone(), Value::Unknown(UnknownValue::Sequence));
        }
        self.function_depth += 1;
        let result = self.block(body);
        self.function_depth -= 1;
        self.names = saved_names;
        self.flow = saved_flow;
        result?;
        if self.argv != saved_argv || self.servers != saved_servers || self.sockets != saved_sockets
        {
            return Err("Python HTTP handler changes shared process/service state".into());
        }
        Ok(())
    }
}

fn local_names(source: &str, body: Node<'_>) -> Result<Vec<String>> {
    fn target(
        source: &str,
        node: Node<'_>,
        out: &mut std::collections::BTreeSet<String>,
    ) -> Result<()> {
        let mut stack = vec![(node, 0)];
        while let Some((node, depth)) = stack.pop() {
            if depth > 48 {
                return Err("Python assignment depth exceeded".into());
            }
            if node.kind() == "identifier" {
                out.insert(source[node.byte_range()].into());
            } else if matches!(
                node.kind(),
                "pattern_list" | "tuple_pattern" | "list_pattern"
            ) {
                stack.extend(named(node).into_iter().map(|child| (child, depth + 1)));
            }
        }
        Ok(())
    }
    let mut names = std::collections::BTreeSet::new();
    let mut stack = vec![body];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > STEP_LIMIT {
            return Err("Python method syntax budget exceeded".into());
        }
        match node.kind() {
            "assignment" | "for_statement" => target(source, field(node, "left")?, &mut names)?,
            "function_definition"
            | "class_definition"
            | "global_statement"
            | "nonlocal_statement" => return Err("unsupported Python nested scope".into()),
            // Imports may bind names before a later read. Until local import
            // scope is modeled, they cannot borrow a global module contract.
            "import_statement" | "import_from_statement" => {
                return Err("unsupported Python method-local import".into());
            }
            _ => {}
        }
        stack.extend(named(node));
    }
    Ok(names.into_iter().collect())
}
