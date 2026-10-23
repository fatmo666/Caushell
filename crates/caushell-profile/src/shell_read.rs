use crate::{
    BoundInvocation, RuntimeInputBinding, SessionBindings, SessionValue, VariablePresence,
};
use caushell_types::{RuntimeProducedValueKind, ShellKind, ShellScalarValue, StructuredShellValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellReadResult {
    pub assignments: Vec<(String, SessionValue)>,
    pub terminated: bool,
}

/// Decode a complete, bounded input record without evaluating shell input as code.
pub fn decode_shell_read(
    bound: &BoundInvocation,
    args: &[String],
    bindings: &SessionBindings,
    input: &[u8],
) -> Option<ShellReadResult> {
    if bindings.shell_kind() != ShellKind::Bash
        || input.len() > 65536
        || args.len() > 256
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || !bound
            .effects
            .iter()
            .any(|e| e.runtime_input_binding == Some(RuntimeInputBinding::ShellRead))
    {
        return None;
    }
    let mut raw = false;
    let mut delimiter = b'\n';
    let mut array = None;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            index += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        let flags = arg.strip_prefix('-')?;
        if flags.is_empty() || !flags.is_ascii() {
            return None;
        }
        let mut flags = flags.char_indices();
        while let Some((offset, flag)) = flags.next() {
            match flag {
                'r' => raw = true,
                'd' | 'p' | 'a' => {
                    let rest = &arg[offset + 2..];
                    let operand = if rest.is_empty() {
                        index += 1;
                        args.get(index)?
                    } else {
                        rest
                    };
                    match flag {
                        'd' => {
                            if !operand.is_ascii() {
                                return None;
                            }
                            delimiter = operand.as_bytes().first().copied().unwrap_or(0);
                        }
                        'a' => array = Some(operand.to_owned()),
                        _ => {}
                    }
                    break;
                }
                _ => return None,
            }
        }
        index += 1;
    }
    let names = if let Some(name) = array.as_ref() {
        vec![name.clone()]
    } else if index == args.len() {
        vec!["REPLY".into()]
    } else {
        args[index..].to_vec()
    };
    if names.iter().any(|name| !crate::shell_identifier(name)) {
        return None;
    }
    let reply = array.is_none() && index == args.len();
    let ifs = if reply {
        String::new()
    } else {
        match bindings.get("IFS").map(|b| b.value) {
            Some(
                SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. },
            ) => value.clone(),
            None if bindings.variable_presence("IFS") == VariablePresence::Absent => " \t\n".into(),
            _ => return None,
        }
    };
    if !ifs.is_ascii() || ifs.contains('\0') {
        return None;
    }
    let mut record = Vec::new();
    let mut input = input.iter().copied();
    let mut terminated = false;
    while let Some(byte) = input.next() {
        if byte == delimiter {
            terminated = true;
            break;
        }
        if byte == 0 {
            continue;
        }
        if byte == b'\\' && !raw {
            let next = input.next()?;
            if next == b'\n' {
                continue;
            }
            if next == 0 {
                return None;
            }
            record.push((next, true));
        } else {
            record.push((byte, false));
        }
        if record.len() > 8192 {
            return None;
        }
    }
    let text = |start: usize, end: usize| {
        String::from_utf8(record[start..end].iter().map(|v| v.0).collect()).ok()
    };
    let separator = |index: usize| !record[index].1 && ifs.as_bytes().contains(&record[index].0);
    let white = |index: usize| separator(index) && b" \t\n".contains(&record[index].0);
    let mut end = record.len();
    while end > 0 && white(end - 1) {
        end -= 1;
    }
    let word = |mut position: usize| {
        while position < end && white(position) {
            position += 1;
        }
        let start = position;
        while position < end && !separator(position) {
            position += 1;
        }
        let finish = position;
        if position < end {
            if white(position) {
                while position < end && white(position) {
                    position += 1;
                }
                if position < end && separator(position) {
                    position += 1;
                }
            } else {
                position += 1;
            }
            while position < end && white(position) {
                position += 1;
            }
        }
        (start, finish, position)
    };
    let scalar = |value| SessionValue::runtime_produced(value, RuntimeProducedValueKind::Scalar);
    let assignments = if let Some(name) = array {
        let mut elements = std::collections::BTreeMap::new();
        let mut position = 0;
        while position < end && white(position) {
            position += 1;
        }
        while position < end {
            if elements.len() == 256 {
                return None;
            }
            let (start, finish, next) = word(position);
            elements.insert(
                elements.len() as u64,
                ShellScalarValue::try_from(&scalar(text(start, finish)?)).ok()?,
            );
            position = next;
        }
        vec![(
            name,
            SessionValue::structured(StructuredShellValue::IndexedArray {
                elements,
                complete: true,
            }),
        )]
    } else if reply {
        vec![(names[0].clone(), scalar(text(0, record.len())?))]
    } else {
        let mut position = 0;
        let mut assignments = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let (start, finish, next) = word(position);
            let finish = if index + 1 == names.len() && next < end {
                end
            } else {
                finish
            };
            assignments.push((name.clone(), scalar(text(start, finish)?)));
            position = next;
        }
        assignments
    };
    Some(ShellReadResult {
        assignments,
        terminated,
    })
}
