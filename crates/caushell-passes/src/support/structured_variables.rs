use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{
    AssignmentOperator, AssignmentValueFact, DeclarationCommandFact, DeclarationCommandKind,
};
use caushell_profile::{
    SessionBindings, SessionValue, ShellArrayKind, ShellVariableFacts, VariablePresence,
    reference_name, shell_reference_target, shell_write_target,
};
use caushell_types::{ShellReferenceTarget as T, ShellScalarValue as S, StructuredShellValue as V};

fn unknown(reason: &str) -> SessionValue {
    SessionValue::structured(V::Unknown {
        reason: reason.into(),
    })
}

pub(super) fn insert(bindings: &mut SessionBindings, name: &str, value: SessionValue) {
    let kind = match &value {
        SessionValue::Structured(V::IndexedArray { .. }) => Some(ShellArrayKind::Indexed),
        SessionValue::Structured(V::AssociativeArray { .. }) => Some(ShellArrayKind::Associative),
        _ => None,
    };
    match value {
        SessionValue::ExactScalar(value) => bindings.insert_exact_scalar(name, value),
        SessionValue::RuntimeProduced { value, kind } => {
            bindings.insert_runtime_produced(name, value, kind)
        }
        SessionValue::OpaqueDynamic { repr } => bindings.insert_opaque_dynamic(name, repr),
        SessionValue::RuntimeInput { source, capture } => {
            bindings.insert_runtime_input(name, source, capture)
        }
        SessionValue::Structured(value) => bindings.insert_structured(name, value),
    }
    if kind.is_some() {
        bindings.set_variable_facts(
            name,
            ShellVariableFacts {
                array_kind: kind,
                ..Default::default()
            },
        );
    }
}

pub(super) fn array_value(
    value: &AssignmentValueFact,
    associative: bool,
    bindings: &SessionBindings,
) -> Result<SessionValue, &'static str> {
    array_value_with_existing(value, associative, bindings, BTreeMap::new())
}

pub(super) fn indexed_array_append_value(
    name: &str,
    value: &AssignmentValueFact,
    bindings: &SessionBindings,
) -> Option<SessionValue> {
    if value.node_kind != "array" {
        return None;
    }
    let T::Variable { name } = shell_write_target(
        bindings,
        T::Variable { name: name.into() },
    ).ok()? else {
        return None;
    };
    let SessionValue::Structured(V::IndexedArray { elements, complete: true }) =
        bindings.get(&name)?.value
    else {
        return None;
    };
    let result = array_value_with_existing(value, false, bindings, elements.clone()).ok()?;
    match &result {
        SessionValue::Structured(array) if !array.has_unknown_parts() => Some(result),
        // An unproved field or subscript may change the resulting indices.
        // Leave that write to the caller's ordinary unresolved-state handling.
        _ => None,
    }
}

fn array_value_with_existing(
    value: &AssignmentValueFact,
    associative: bool,
    bindings: &SessionBindings,
    mut indexed: BTreeMap<u64, S>,
) -> Result<SessionValue, &'static str> {
    if bindings.shell_kind() != caushell_types::ShellKind::Bash {
        return Err("array assignments require Bash semantics");
    }
    let Some(entries) = caushell_parse::array_assignment_entries(&value.text) else {
        return Err("array assignment is outside the bounded syntax");
    };
    let mut keyed = BTreeMap::new();
    // Implicit append starts after the highest occupied index, even when
    // the existing array has holes. An explicit subscript resets this cursor.
    let mut next = indexed
        .last_key_value()
        .map_or(0, |(index, _)| index.saturating_add(1));
    let mut complete = true;
    for (key, value) in entries {
        let values = caushell_profile::materialize_shell_array_element(&value, bindings);
        let Some(values) = values else {
            complete = false;
            break;
        };
        if associative {
            if values.len() != 1 {
                complete = false;
                break;
            }
            let Some(key) = key else {
                complete = false;
                break;
            };
            let Some(key) = caushell_profile::shell_array_key(&key, bindings) else {
                return Err("associative subscript requires evaluation");
            };
            keyed.insert(
                key,
                S::try_from(&values[0]).unwrap_or(S::Unknown {
                    reason: "non-scalar array member".into(),
                }),
            );
        } else {
            if let Some(key) = key {
                let Some(index) = caushell_profile::shell_array_index(&key, bindings) else {
                    return Err("indexed subscript requires evaluation");
                };
                next = index;
                if values.len() != 1 {
                    complete = false;
                    break;
                }
            }
            for value in values {
                if next > i64::MAX as u64 {
                    return Err("array index exceeds Bash integer range");
                }
                indexed.insert(
                    next,
                    S::try_from(&value).unwrap_or(S::Unknown {
                        reason: "non-scalar array member".into(),
                    }),
                );
                let Some(index) = next.checked_add(1) else {
                    complete = false;
                    break;
                };
                next = index;
            }
        }
    }
    Ok(SessionValue::structured(if associative {
        V::AssociativeArray {
            elements: keyed,
            complete,
        }
    } else {
        V::IndexedArray {
            elements: indexed,
            complete,
        }
    }))
}

pub(super) fn declaration(
    d: &DeclarationCommandFact,
    bindings: &mut SessionBindings,
    assigned: &mut BTreeSet<String>,
    mut observe: impl FnMut(&SessionBindings, &str),
) -> bool {
    if matches!(
        d.kind,
        DeclarationCommandKind::Declare
            | DeclarationCommandKind::Typeset
            | DeclarationCommandKind::Local
    ) && d.options == ["+n"]
    {
        if d.kind == DeclarationCommandKind::Local && !bindings.in_function_scope() {
            return false;
        }
        if !d.assignments.is_empty() || d.names.iter().any(|name| !super::scalar_identifier(name)) {
            assigned.extend(bindings.variable_names().map(str::to_owned));
            bindings.mark_shell_state_uncertain("unresolved nameref attribute operands");
            return true;
        }
        for name in &d.names {
            let Some(SessionValue::Structured(V::NameReference { target })) =
                bindings.get(name).map(|b| b.value)
            else {
                continue;
            };
            let text = match target {
                T::Variable { name } => Some(name.clone()),
                T::IndexedElement { name, index } => Some(format!("{name}[{index}]")),
                _ => None,
            };
            assigned.insert(name.clone());
            insert(
                bindings,
                name,
                if d.conditional_execution {
                    unknown("conditional nameref attribute")
                } else {
                    text.map(SessionValue::exact_scalar)
                        .unwrap_or_else(|| unknown("nameref target spelling"))
                },
            );
            observe(bindings, name);
        }
        return true;
    }
    if !matches!(
        d.kind,
        DeclarationCommandKind::Declare
            | DeclarationCommandKind::Typeset
            | DeclarationCommandKind::Local
    ) || !d
        .options
        .iter()
        .any(|o| o.starts_with('-') && o[1..].contains(['a', 'A', 'n']))
    {
        return false;
    }
    if d.options.iter().any(|o| {
        !o.starts_with('-') || o.starts_with("--") || o[1..].chars().any(|c| !"aAngx".contains(c))
    }) || d.kind == DeclarationCommandKind::Local && !bindings.in_function_scope()
        || bindings.in_function_scope() && d.options.iter().any(|o| o.contains('g'))
    {
        return false;
    }
    let nameref = d.options.iter().any(|o| o[1..].contains('n'));
    let associative = d.options.iter().any(|o| o[1..].contains('A'));
    if nameref && d.options.iter().any(|o| o[1..].contains(['a', 'A'])) {
        return false;
    }
    let prior = bindings.clone();
    if d.names
        .iter()
        .chain(d.assignments.iter().map(|a| &a.name))
        .any(|name| !super::scalar_identifier(name))
    {
        assigned.extend(bindings.variable_names().map(str::to_owned));
        bindings.mark_shell_state_uncertain("dynamic structured declaration target");
        return true;
    }
    for (name, assignment) in d
        .names
        .iter()
        .map(|name| (name, None))
        .chain(d.assignments.iter().map(|a| (&a.name, Some(a))))
    {
        assigned.insert(name.clone());
        let incompatible = !bindings.in_function_scope()
            && match prior.get(name).map(|b| b.value) {
                Some(SessionValue::Structured(V::IndexedArray { .. })) => associative || nameref,
                Some(SessionValue::Structured(V::AssociativeArray { .. })) => {
                    !associative || nameref
                }
                Some(SessionValue::Structured(V::NameReference { .. })) => !nameref,
                _ => false,
            };
        let blocked = incompatible || prior.runtime_variable_target_is_unresolved(name);
        let value = if blocked {
            unknown("incompatible or unresolved declaration attributes")
        } else if d.conditional_execution {
            unknown("conditional structured declaration")
        } else if let Some(a) = assignment {
            if a.operator != AssignmentOperator::Assign {
                unknown("structured declaration operator")
            } else if nameref {
                let target = caushell_profile::materialize_shell_assignment_value(
                    &a.value.text,
                    a.value.quoted,
                    &a.value.node_kind,
                    &prior,
                )
                .and_then(|text| caushell_profile::shell_nameref_target(&text, &prior))
                .unwrap_or(T::Unknown {
                    repr: a.value.text.clone(),
                });
                SessionValue::structured(V::NameReference { target })
            } else if a.value.node_kind == "array" {
                match array_value(&a.value, associative, &prior) {
                    Ok(value) => value,
                    Err(reason) => {
                        assigned.extend(bindings.variable_names().map(str::to_owned));
                        bindings.mark_shell_state_uncertain(reason);
                        unknown(reason)
                    }
                }
            } else {
                unknown("non-compound array declaration")
            }
        } else if nameref {
            unknown("unbound name reference")
        } else if bindings.in_function_scope()
            || prior.variable_presence(name) == VariablePresence::Absent
        {
            SessionValue::structured(if associative {
                V::AssociativeArray {
                    elements: BTreeMap::new(),
                    complete: true,
                }
            } else {
                V::IndexedArray {
                    elements: BTreeMap::new(),
                    complete: true,
                }
            })
        } else {
            prior
                .get(name)
                .map(|b| b.value.clone())
                .unwrap_or_else(|| unknown("unobserved array declaration state"))
        };
        insert(bindings, name, value);
        if blocked {
            bindings.mark_unresolved_runtime_variable_target(name);
        }
        if !nameref {
            bindings.set_variable_facts(
                name,
                ShellVariableFacts {
                    array_kind: Some(if associative {
                        ShellArrayKind::Associative
                    } else {
                        ShellArrayKind::Indexed
                    }),
                    ..Default::default()
                },
            );
        }
        if d.options.iter().any(|o| o[1..].contains('x')) {
            bindings.set_environment_value(
                name,
                SessionValue::opaque_dynamic("structured export attribute"),
            );
        }
        observe(bindings, name);
    }
    true
}

pub(super) fn unset(
    bindings: &mut SessionBindings,
    name: &str,
    reference_only: bool,
    conditional: bool,
) -> Option<Result<String, &'static str>> {
    let target = shell_reference_target(name, bindings)?;
    let base = reference_name(&target)?;
    let structured = name.contains('[')
        || matches!(
            bindings.get(base).map(|b| b.value),
            Some(SessionValue::Structured(_))
        );
    if !structured {
        return None;
    }
    if reference_only
        && (!matches!(target, T::Variable { .. })
            || !matches!(
                bindings.get(base).map(|b| b.value),
                Some(SessionValue::Structured(V::NameReference { .. }))
            ))
    {
        return Some(Ok(base.to_owned()));
    }
    let target = if reference_only {
        target
    } else {
        match shell_write_target(bindings, target) {
            Ok(target) => target,
            Err(reason) => return Some(Err(reason)),
        }
    };
    let name = reference_name(&target)?.to_owned();
    if conditional {
        insert(bindings, &name, unknown("conditional structured unset"));
        return Some(Ok(name));
    }
    match target {
        T::Variable { .. } => bindings.remove(&name),
        T::IndexedElement { index, .. } => {
            let Some(SessionValue::Structured(V::IndexedArray { elements, complete })) =
                bindings.get(&name).map(|b| b.value)
            else {
                insert(
                    bindings,
                    &name,
                    SessionValue::structured(V::IndexedArray {
                        elements: BTreeMap::new(),
                        complete: false,
                    }),
                );
                return Some(Ok(name));
            };
            let mut elements = elements.clone();
            elements.remove(&index);
            insert(
                bindings,
                &name,
                SessionValue::structured(V::IndexedArray {
                    elements,
                    complete: *complete,
                }),
            );
        }
        T::AssociativeElement { key, .. } => {
            let Some(SessionValue::Structured(V::AssociativeArray { elements, complete })) =
                bindings.get(&name).map(|b| b.value)
            else {
                return Some(Err("unset associative state unresolved"));
            };
            let mut elements = elements.clone();
            elements.remove(&key);
            insert(
                bindings,
                &name,
                SessionValue::structured(V::AssociativeArray {
                    elements,
                    complete: *complete,
                }),
            );
        }
        T::Unknown { .. } => return Some(Err("unknown unset target")),
    }
    Some(Ok(name))
}

pub(super) fn write(
    bindings: &mut SessionBindings,
    target: T,
    value: SessionValue,
    compound: bool,
) -> Result<String, &'static str> {
    let mut target = shell_write_target(bindings, target)?;
    let name = reference_name(&target)
        .ok_or("unknown write target")?
        .to_owned();
    if !compound && matches!(target, T::Variable { .. }) {
        match bindings.get(&name).map(|b| b.value) {
            Some(SessionValue::Structured(V::IndexedArray { .. })) => {
                target = T::IndexedElement {
                    name: name.clone(),
                    index: 0,
                }
            }
            Some(SessionValue::Structured(V::AssociativeArray { .. })) => {
                target = T::AssociativeElement {
                    name: name.clone(),
                    key: "0".into(),
                }
            }
            _ => {}
        }
    }
    let result = match target {
        T::Variable { .. } => value,
        T::IndexedElement { index, .. } => {
            let (mut elements, complete) = match bindings.get(&name).map(|b| b.value) {
                Some(SessionValue::Structured(V::IndexedArray { elements, complete })) => {
                    (elements.clone(), *complete)
                }
                None if bindings.variable_presence(&name) == VariablePresence::Absent => {
                    (BTreeMap::new(), true)
                }
                None => (BTreeMap::new(), false),
                _ => return Err("indexed write has unresolved array state"),
            };
            elements.insert(
                index,
                S::try_from(&value).map_err(|_| "non-scalar element")?,
            );
            SessionValue::structured(V::IndexedArray { elements, complete })
        }
        T::AssociativeElement { key, .. } => {
            let Some(SessionValue::Structured(V::AssociativeArray { elements, complete })) =
                bindings.get(&name).map(|b| b.value)
            else {
                return Err("associative write has unresolved array state");
            };
            let mut elements = elements.clone();
            elements.insert(key, S::try_from(&value).map_err(|_| "non-scalar element")?);
            SessionValue::structured(V::AssociativeArray {
                elements,
                complete: *complete,
            })
        }
        T::Unknown { .. } => return Err("unknown write target"),
    };
    if result.retained_bytes() > 32768 {
        return Err("structured write byte budget exceeded");
    }
    insert(bindings, &name, result);
    Ok(name)
}
