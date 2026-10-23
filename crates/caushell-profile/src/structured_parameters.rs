use std::collections::BTreeSet;

use caushell_types::{ShellReferenceTarget as T, StructuredShellValue as V};

use crate::{BindingOrigin, SessionBindings, SessionValue, VariablePresence};

pub const MAX_REFERENCE_DEPTH: usize = 16;
pub const MAX_ARRAY_FIELDS: usize = 256;
pub const MAX_EXPANDED_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedShellValue {
    pub name: String,
    pub value: SessionValue,
    pub origin: BindingOrigin,
    pub dependencies: Vec<String>,
}

pub fn shell_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn shell_reference_target(text: &str, bindings: &SessionBindings) -> Option<T> {
    parse_target(text, bindings, true)
}

pub fn shell_nameref_target(text: &str, bindings: &SessionBindings) -> Option<T> {
    parse_target(text, bindings, false)
}

fn parse_target(text: &str, bindings: &SessionBindings, bound_index: bool) -> Option<T> {
    if bindings.shell_kind() != caushell_types::ShellKind::Bash {
        return None;
    }
    if shell_identifier(text) {
        return Some(T::Variable { name: text.into() });
    }
    let (name, index) = text.split_once('[')?;
    let index = index.strip_suffix(']')?;
    if !shell_identifier(name)
        || index.is_empty()
        || matches!(index, "@" | "*")
        || index.len() > MAX_EXPANDED_BYTES
    {
        return None;
    }
    let container = resolve_shell_container(bindings, name).ok();
    if container.as_ref().is_some_and(|v| {
        matches!(
            v.value,
            SessionValue::Structured(V::AssociativeArray { .. })
        )
    }) {
        let key = parse_key(index, bindings, bound_index)?;
        return Some(T::AssociativeElement {
            name: name.into(),
            key,
        });
    }
    Some(T::IndexedElement {
        name: name.into(),
        index: parse_index(index, bindings, bound_index)?,
    })
}

pub fn shell_array_index(index: &str, bindings: &SessionBindings) -> Option<u64> {
    parse_index(index, bindings, true)
}

pub fn shell_array_key(index: &str, bindings: &SessionBindings) -> Option<String> {
    parse_key(index, bindings, true)
}

fn parse_key(index: &str, bindings: &SessionBindings, bound_index: bool) -> Option<String> {
    let value = if index.contains('$') {
        if !bound_index {
            return None;
        }
        bound_scalar(index, bindings)?
    } else {
        literal_key(index)?
    };
    (!value.is_empty() && !value.contains('\0')).then_some(value)
}

fn parse_index(index: &str, bindings: &SessionBindings, bound_index: bool) -> Option<u64> {
    if index.is_empty() || index.len() > MAX_EXPANDED_BYTES {
        return None;
    }
    let resolved;
    let index = if index.bytes().all(|b| b.is_ascii_digit()) {
        index
    } else {
        if !bound_index {
            return None;
        }
        resolved = bound_scalar(index, bindings)?;
        if resolved.is_empty() || !resolved.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        &resolved
    };
    // Bash treats a leading zero as octal; do not reinterpret it as decimal.
    let index = if index.len() > 1 && index.starts_with('0') {
        u64::from_str_radix(index, 8).ok()?
    } else {
        index.parse().ok()?
    };
    Some(index).filter(|index| *index <= i64::MAX as u64)
}

fn bound_scalar(text: &str, bindings: &SessionBindings) -> Option<String> {
    let text = text
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(text);
    let value = if shell_identifier(text) {
        resolve_shell_reference(bindings, T::Variable { name: text.into() })
            .ok()?
            .value
    } else {
        match crate::exact_shell_parameter_reference(text)? {
            crate::ShellParameterReference::Variable(name) => {
                resolve_shell_reference(bindings, T::Variable { name })
                    .ok()?
                    .value
            }
            crate::ShellParameterReference::Positional(index) => {
                bindings.positional_parameter(index)?.clone()
            }
            _ => return None,
        }
    };
    match value {
        SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. }
            if value.len() <= MAX_EXPANDED_BYTES && !value.contains('\0') =>
        {
            Some(value)
        }
        _ => None,
    }
}

pub(crate) fn subscript_dependencies(text: &str, bindings: &SessionBindings) -> Vec<String> {
    let Some((name, index)) = text.split_once('[') else {
        return Vec::new();
    };
    let Some(index) = index.strip_suffix(']') else {
        return Vec::new();
    };
    let index = index
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(index);
    let associative = resolve_shell_container(bindings, name).is_ok_and(|value| {
        matches!(
            value.value,
            SessionValue::Structured(V::AssociativeArray { .. })
        )
    });
    let name = if shell_identifier(index) && !associative {
        Some(index.to_owned())
    } else if let Some(crate::ShellParameterReference::Variable(name)) =
        crate::exact_shell_parameter_reference(index)
    {
        Some(name)
    } else {
        None
    };
    name.and_then(|name| resolve_shell_reference(bindings, T::Variable { name }).ok())
        .map(|value| value.dependencies)
        .unwrap_or_default()
}

fn literal_key(text: &str) -> Option<String> {
    let (text, quoted, kind) = if text.len() >= 2 && text.starts_with('\'') && text.ends_with('\'')
    {
        (&text[1..text.len() - 1], true, "raw_string")
    } else if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        (&text[1..text.len() - 1], true, "string")
    } else {
        (text, false, "word")
    };
    let value = caushell_parse::decode_static_shell_argument(text, quoted, kind)?;
    (!value.is_empty() && !value.contains('\0')).then_some(value)
}

pub fn resolve_shell_container(
    bindings: &SessionBindings,
    name: &str,
) -> Result<ResolvedShellValue, &'static str> {
    resolve(bindings, T::Variable { name: name.into() }, false)
}

pub fn resolve_shell_reference(
    bindings: &SessionBindings,
    target: T,
) -> Result<ResolvedShellValue, &'static str> {
    resolve(bindings, target, true)
}

fn resolve(
    bindings: &SessionBindings,
    mut target: T,
    scalar: bool,
) -> Result<ResolvedShellValue, &'static str> {
    let mut active = BTreeSet::new();
    let mut dependencies = Vec::new();
    for _ in 0..MAX_REFERENCE_DEPTH {
        let name = match &target {
            T::Variable { name }
            | T::IndexedElement { name, .. }
            | T::AssociativeElement { name, .. } => name,
            T::Unknown { .. } => return Err("unknown reference target"),
        };
        if !shell_identifier(name) || !active.insert(name.clone()) {
            return Err("invalid or cyclic shell reference");
        }
        dependencies.push(name.clone());
        if bindings.runtime_variable_target_is_unresolved(name) {
            return Err("unresolved shell write target");
        }
        let Some(binding) = bindings.get(name) else {
            if bindings.variable_presence(name) == VariablePresence::Absent {
                return Ok(ResolvedShellValue {
                    name: name.clone(),
                    value: SessionValue::exact_scalar(""),
                    origin: BindingOrigin::SessionBinding,
                    dependencies,
                });
            }
            return Err("missing shell reference binding");
        };
        if matches!(binding.value, SessionValue::Structured(_))
            && bindings.shell_kind() != caushell_types::ShellKind::Bash
        {
            return Err("structured values require Bash semantics");
        }
        if let SessionValue::Structured(V::NameReference { target: next }) = binding.value {
            target = compose_target(&target, next)?;
            continue;
        }
        let selected = match (&target, binding.value) {
            (T::Variable { .. }, _) if !scalar => binding.value.clone(),
            (
                T::Variable { .. },
                SessionValue::Structured(V::IndexedArray { elements, complete }),
            ) => member(elements.get(&0), *complete)?,
            (
                T::Variable { .. },
                SessionValue::Structured(V::AssociativeArray { elements, complete }),
            ) => member(elements.get("0"), *complete)?,
            (T::Variable { .. }, value) => value.clone(),
            (
                T::IndexedElement { index, .. },
                SessionValue::Structured(V::IndexedArray { elements, complete }),
            ) => member(elements.get(index), *complete)?,
            (
                T::AssociativeElement { key, .. },
                SessionValue::Structured(V::AssociativeArray { elements, complete }),
            ) => member(elements.get(key), *complete)?,
            (
                T::IndexedElement { index: 0, .. },
                SessionValue::ExactScalar(_) | SessionValue::RuntimeProduced { .. },
            ) => binding.value.clone(),
            _ => return Err("shell subscript type is unresolved"),
        };
        if selected.retained_bytes() > MAX_EXPANDED_BYTES {
            return Err("shell value byte budget exceeded");
        }
        return Ok(ResolvedShellValue {
            name: name.clone(),
            value: selected,
            origin: binding.origin,
            dependencies,
        });
    }
    Err("shell reference depth exceeded")
}

fn member(
    value: Option<&caushell_types::ShellScalarValue>,
    complete: bool,
) -> Result<SessionValue, &'static str> {
    match value {
        Some(value) => Ok(value.into()),
        None if complete => Ok(SessionValue::exact_scalar("")),
        None => Err("array member is not observed"),
    }
}

pub fn reference_name(target: &T) -> Option<&str> {
    match target {
        T::Variable { name }
        | T::IndexedElement { name, .. }
        | T::AssociativeElement { name, .. } => Some(name),
        T::Unknown { .. } => None,
    }
}

pub fn shell_write_target(bindings: &SessionBindings, mut target: T) -> Result<T, &'static str> {
    if bindings.shell_kind() != caushell_types::ShellKind::Bash {
        if matches!(&target, T::Variable { name } if !matches!(bindings.get(name).map(|b| b.value), Some(SessionValue::Structured(_))) && !bindings.runtime_variable_target_is_unresolved(name))
        {
            return Ok(target);
        }
        return Err("structured writes require Bash semantics");
    }
    let mut active = BTreeSet::new();
    for _ in 0..MAX_REFERENCE_DEPTH {
        let name = reference_name(&target).ok_or("unknown shell write target")?;
        if !active.insert(name.to_owned()) || bindings.runtime_variable_target_is_unresolved(name) {
            return Err("cyclic or unresolved shell write target");
        }
        match bindings.get(name).map(|b| b.value) {
            Some(SessionValue::Structured(V::Unknown { .. })) => {
                return Err("unknown shell target attributes");
            }
            Some(SessionValue::Structured(V::NameReference { target: next })) => {
                target = compose_target(&target, next)?
            }
            _ => return Ok(target),
        }
    }
    Err("shell reference depth exceeded")
}

fn compose_target(outer: &T, target: &T) -> Result<T, &'static str> {
    match (outer, target) {
        (T::Variable { .. }, _) => Ok(target.clone()),
        (T::IndexedElement { index, .. }, T::Variable { name }) => Ok(T::IndexedElement {
            name: name.clone(),
            index: *index,
        }),
        (T::AssociativeElement { key, .. }, T::Variable { name }) => Ok(T::AssociativeElement {
            name: name.clone(),
            key: key.clone(),
        }),
        _ => Err("nested reference subscripts are unresolved"),
    }
}
