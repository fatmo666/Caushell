use super::*;

impl Engine<'_> {
    pub(super) fn assign(&mut self, target: Node<'_>, value: Value, depth: usize) -> Result<()> {
        self.step()?;
        if depth > 48 {
            return Err("Python assignment depth exceeded".into());
        }
        match target.kind() {
            "identifier" => {
                self.names.insert(self.raw(target).into(), value);
                if self.names.values().map(value_size).sum::<usize>() > 1_048_576 {
                    return Err("Python binding budget exceeded".into());
                }
            }
            "attribute" if self.symbol(target)? == "sys.argv" => self.argv = value,
            "pattern_list" | "tuple_pattern" | "list_pattern" => {
                let values = match value {
                    Value::List(v) | Value::Tuple(v) | Value::Range(v) => v,
                    _ => return Err("Python unpack requires a known sequence".into()),
                };
                let targets = named(target);
                if targets.len() != values.len() {
                    return Err("Python unpack length mismatch".into());
                }
                for (target, value) in targets.into_iter().zip(values) {
                    self.assign(target, value, depth + 1)?;
                }
            }
            _ => return Err("unsupported Python assignment target".into()),
        }
        Ok(())
    }

    fn block(&mut self, block: Node<'_>) -> Result<()> {
        for statement in named(block) {
            self.statement(statement)?;
        }
        Ok(())
    }

    pub(super) fn control(&mut self, node: Node<'_>) -> Result<()> {
        match node.kind() {
            "assert_statement" => {
                let expressions = named(node);
                let value =
                    self.eval(*expressions.first().ok_or("missing Python assertion")?, 0)?;
                match truth(&value)? {
                    Some(true) => Ok(()),
                    Some(false) => Err("Python assertion fails".into()),
                    None if expressions.len() == 1 => {
                        // A failed assertion can stop the program, but cannot
                        // make later effects or output more predictable.
                        self.report.stdout_complete = false;
                        Ok(())
                    }
                    None => Err("unknown Python assertion with an effectful message".into()),
                }
            }
            "if_statement" => {
                let condition = self.eval(field(node, "condition")?, 0)?;
                match truth(&condition)? {
                    Some(true) => self.block(field(node, "consequence")?),
                    Some(false) => match node.child_by_field_name("alternative") {
                        Some(alternative) if alternative.kind() == "else_clause" => {
                            self.block(field(alternative, "body")?)
                        }
                        Some(_) => Err("unsupported Python conditional alternative".into()),
                        None => Ok(()),
                    },
                    None => Err("Python conditional effects depend on unknown input".into()),
                }
            }
            "for_statement" => {
                if node.child_by_field_name("alternative").is_some()
                    || self.raw(node).trim_start().starts_with("async ")
                {
                    return Err("unsupported Python loop mode".into());
                }
                let items = match self.eval(field(node, "right")?, 0)? {
                    Value::List(v) | Value::Tuple(v) | Value::Range(v) => v,
                    _ => return Err("Python loop requires a bounded sequence".into()),
                };
                if items.len() > ITEM_LIMIT {
                    return Err("Python loop budget exceeded".into());
                }
                for value in items {
                    self.assign(field(node, "left")?, value, 0)?;
                    self.block(field(node, "body")?)?;
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn compare(&mut self, node: Node<'_>, depth: usize) -> Result<Value> {
        let expressions = named(node);
        if expressions.len() != 2 {
            return Err("unsupported Python chained comparison".into());
        }
        let left = self.eval(expressions[0], depth + 1)?;
        let right = self.eval(expressions[1], depth + 1)?;
        let operator = self.raw(field(node, "operators")?);
        let value = match operator {
            "==" => equal(&left, &right)?,
            "!=" => equal(&left, &right)?.map(|b| !b),
            "in" | "not in" => {
                let items = match right {
                    Value::List(v) | Value::Tuple(v) | Value::Range(v) => v,
                    _ => return Err("Python membership requires a bounded sequence".into()),
                };
                let mut any_unknown = false;
                let mut found = false;
                for item in items {
                    match equal(&left, &item)? {
                        Some(true) => {
                            found = true;
                            break;
                        }
                        Some(false) => {}
                        None => any_unknown = true,
                    }
                }
                if found || !any_unknown {
                    Some(found != (operator == "not in"))
                } else {
                    None
                }
            }
            _ => return Err("unsupported Python comparison operator".into()),
        };
        Ok(value
            .map(Value::Bool)
            .unwrap_or(Value::Unknown(UnknownValue::Boolean)))
    }
}

fn truth(value: &Value) -> Result<Option<bool>> {
    Ok(match value {
        Value::Unknown(_) => None,
        Value::None => Some(false),
        Value::Bool(b) => Some(*b),
        Value::Int(n) => Some(*n != 0),
        Value::Text(s) => Some(!s.is_empty()),
        Value::Bytes(b) => Some(!b.is_empty()),
        Value::List(v) | Value::Tuple(v) | Value::Range(v) => Some(!v.is_empty()),
        Value::Dictionary(v) => Some(!v.is_empty()),
        _ => return Err("unsupported Python truth value".into()),
    })
}

fn equal(left: &Value, right: &Value) -> Result<Option<bool>> {
    match (left, right) {
        (Value::Unknown(_), _) | (_, Value::Unknown(_)) => Ok(None),
        (Value::Int(a), Value::Bool(b)) | (Value::Bool(b), Value::Int(a)) => {
            Ok(Some(*a == i64::from(*b)))
        }
        (
            Value::Text(_) | Value::Bytes(_) | Value::Int(_) | Value::Bool(_) | Value::None,
            Value::Text(_) | Value::Bytes(_) | Value::Int(_) | Value::Bool(_) | Value::None,
        ) => Ok(Some(left == right)),
        _ => Err("unsupported Python equality operands".into()),
    }
}

pub(super) fn range(args: Vec<Value>) -> Result<Value> {
    let numbers = args.into_iter().map(integer).collect::<Result<Vec<_>>>()?;
    let (mut value, stop, step) = match numbers.as_slice() {
        [stop] => (0, *stop, 1),
        [start, stop] => (*start, *stop, 1),
        [start, stop, step] if *step != 0 => (*start, *stop, *step),
        _ => return Err("invalid Python range".into()),
    };
    let mut items = Vec::new();
    while if step > 0 { value < stop } else { value > stop } {
        if items.len() >= ITEM_LIMIT {
            return Err("Python range budget exceeded".into());
        }
        items.push(Value::Int(value));
        let Some(next) = value.checked_add(step) else {
            break;
        };
        value = next;
    }
    Ok(Value::Range(items))
}

pub(super) fn print_value(value: Value) -> Result<Option<String>> {
    if matches!(value, Value::Unknown(_)) {
        Ok(None)
    } else {
        display(value).map(Some)
    }
}

/// Default json.dumps syntax; no custom encoders or object protocols.
pub(super) fn json(value: Value) -> Result<Value> {
    fn encode(value: Value, depth: usize) -> Result<Option<String>> {
        if depth > 48 {
            return Err("Python JSON depth exceeded".into());
        }
        let result = match value {
            Value::Unknown(_) => return Ok(None),
            Value::Text(s) => {
                let mut out = String::from("\"");
                // CPython defaults to ensure_ascii=True, including surrogate pairs.
                for unit in s.encode_utf16() {
                    match unit {
                        34 => out.push_str("\\\""),
                        92 => out.push_str("\\\\"),
                        8 => out.push_str("\\b"),
                        9 => out.push_str("\\t"),
                        10 => out.push_str("\\n"),
                        12 => out.push_str("\\f"),
                        13 => out.push_str("\\r"),
                        0..=31 | 127..=65535 => out.push_str(&format!("\\u{unit:04x}")),
                        _ => out.push(char::from_u32(u32::from(unit)).unwrap()),
                    }
                }
                out.push('"');
                out
            }
            Value::Int(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::None => "null".into(),
            Value::List(v) | Value::Tuple(v) => {
                let Some(parts) = v
                    .into_iter()
                    .map(|v| encode(v, depth + 1))
                    .collect::<Result<Option<Vec<_>>>>()?
                else {
                    return Ok(None);
                };
                format!("[{}]", parts.join(", "))
            }
            Value::Dictionary(items) => {
                let mut parts = Vec::new();
                for (key, value) in items {
                    let key = match key {
                        Value::Text(s) => s,
                        Value::Int(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::None => "null".into(),
                        _ => return Err("unsupported Python JSON key".into()),
                    };
                    let Some(value) = encode(value, depth + 1)? else {
                        return Ok(None);
                    };
                    parts.push(format!(
                        "{}: {value}",
                        encode(Value::Text(key), depth + 1)?.unwrap()
                    ));
                }
                format!("{{{}}}", parts.join(", "))
            }
            _ => return Err("unsupported Python JSON value".into()),
        };
        if result.len() > VALUE_LIMIT {
            return Err("Python JSON budget exceeded".into());
        }
        Ok(Some(result))
    }
    Ok(encode(value, 0)?
        .map(Value::Text)
        .unwrap_or(Value::Unknown(UnknownValue::Text)))
}
