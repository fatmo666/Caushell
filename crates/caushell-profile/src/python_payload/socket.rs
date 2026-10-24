use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Socket {
    address: Option<(String, u16)>,
    listening: bool,
    connected: bool,
    closed: bool,
}

impl Engine<'_> {
    pub(super) fn new_socket(
        &mut self,
        args: Vec<Value>,
        mut kwargs: BTreeMap<String, Value>,
    ) -> Result<Value> {
        self.report.stdout_complete = false;
        if args.len() > 3 {
            return Err("unsupported Python socket constructor".into());
        }
        let mut options = Vec::new();
        for (index, (name, default)) in [
            ("family", Value::Symbol("socket.AF_INET".into())),
            ("type", Value::Symbol("socket.SOCK_STREAM".into())),
            ("proto", Value::Int(0)),
        ]
        .into_iter()
        .enumerate()
        {
            if index < args.len() && kwargs.contains_key(name) {
                return Err("duplicate Python socket option".into());
            }
            options.push(
                args.get(index)
                    .cloned()
                    .or_else(|| kwargs.remove(name))
                    .unwrap_or(default),
            );
        }
        if !kwargs.is_empty()
            || options
                != [
                    Value::Symbol("socket.AF_INET".into()),
                    Value::Symbol("socket.SOCK_STREAM".into()),
                    Value::Int(0),
                ]
        {
            return Err("unsupported Python socket transport".into());
        }
        self.allocate_socket(Socket {
            address: None,
            listening: false,
            connected: false,
            closed: false,
        })
    }

    fn allocate_socket(&mut self, socket: Socket) -> Result<Value> {
        if self.sockets.len() >= 128 {
            return Err("Python socket budget exceeded".into());
        }
        let id = self.sockets.len();
        self.sockets.push(socket);
        Ok(Value::Socket(id))
    }

    pub(super) fn socket_call(
        &mut self,
        id: usize,
        method: &str,
        args: Vec<Value>,
        kwargs: BTreeMap<String, Value>,
    ) -> Result<Value> {
        if !kwargs.is_empty() {
            return Err("unsupported Python socket keyword".into());
        }
        let state = self
            .sockets
            .get(id)
            .cloned()
            .ok_or("unknown Python socket")?;
        if state.closed {
            return Err("Python socket is closed".into());
        }
        match (method, args.as_slice()) {
            (
                "setsockopt",
                [
                    Value::Symbol(level),
                    Value::Symbol(option),
                    Value::Int(0 | 1),
                ],
            ) if level == "socket.SOL_SOCKET" && option == "socket.SO_REUSEADDR" => Ok(Value::None),
            ("settimeout", [Value::Int(seconds)]) if *seconds >= 0 => Ok(Value::None),
            ("bind", [Value::Tuple(address)]) if state.address.is_none() && !state.connected => {
                let [Value::Text(host), Value::Int(port)] = address.as_slice() else {
                    return Err("unknown Python bind address".into());
                };
                let port = u16::try_from(*port).map_err(|_| "invalid Python bind port")?;
                // DNS, platform aliases and wildcard spelling stay unresolved.
                if host.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err("Python bind host is not a numeric IPv4 address".into());
                }
                self.sockets[id].address = Some((host.clone(), port));
                Ok(Value::None)
            }
            ("listen", [] | [Value::Int(_)]) if state.address.is_some() && !state.connected => {
                if !state.listening {
                    let (host, port) = state.address.unwrap();
                    self.report
                        .effects
                        .push(PythonEffect::ListenNetwork { host, port });
                }
                self.sockets[id].listening = true;
                Ok(Value::None)
            }
            ("getsockname", []) if state.address.is_some() => {
                let (host, port) = state.address.unwrap();
                Ok(Value::Tuple(vec![
                    Value::Text(host),
                    if port == 0 {
                        Value::Unknown(UnknownValue::Integer)
                    } else {
                        Value::Int(i64::from(port))
                    },
                ]))
            }
            ("accept", []) if state.listening => {
                let peer = self.allocate_socket(Socket {
                    address: state.address,
                    listening: false,
                    connected: true,
                    closed: false,
                })?;
                Ok(Value::Tuple(vec![
                    peer,
                    Value::Tuple(vec![
                        Value::Unknown(UnknownValue::Text),
                        Value::Unknown(UnknownValue::Integer),
                    ]),
                ]))
            }
            ("recv", [Value::Int(size)])
                if state.connected && *size >= 0 && *size <= VALUE_LIMIT as i64 =>
            {
                Ok(Value::Unknown(UnknownValue::Bytes))
            }
            ("sendall", [Value::Bytes(_) | Value::Unknown(UnknownValue::Bytes)])
                if state.connected =>
            {
                let (host, port) = state
                    .address
                    .ok_or("unknown Python socket response route")?;
                self.report
                    .effects
                    .push(PythonEffect::RespondNetwork { host, port });
                if self.report.effects.len() > 128 {
                    return Err("Python effect budget exceeded".into());
                }
                Ok(Value::None)
            }
            ("close", []) => {
                self.sockets[id].closed = true;
                Ok(Value::None)
            }
            _ => Err(format!("unsupported Python socket operation {method}")),
        }
    }
}
