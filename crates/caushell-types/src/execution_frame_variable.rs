//! Bounded, executor-owned compound values. These facts never grant authority
//! or imply that a variable is exported into a child environment.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ExecutionFrameObservation, SessionVariableValue, ShellEnvironmentValue, ShellReferenceTarget,
    ShellScalarValue, StructuredShellValue,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFrameVariable {
    pub name: String,
    pub value: ExecutionFrameVariableValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionFrameVariableValue {
    Scalar {
        value: String,
        #[serde(default)]
        integer: bool,
    },
    IndexedArray {
        elements: Vec<(u64, String)>,
        complete: bool,
    },
    /// Keyed lookup only: a key set does not prove Bash's expansion order.
    AssociativeArray {
        elements: Vec<(String, String)>,
    },
    /// Only literal identifiers are accepted; executable subscripts are not read.
    NameReference {
        target: String,
    },
    Absent,
    /// The declaration exists, but its attributes/target are outside this reader.
    Unsupported,
    Unknown,
}

impl ExecutionFrameVariableValue {
    pub fn session_value(&self) -> Option<SessionVariableValue> {
        Some(match self {
            Self::Scalar { value, .. } => SessionVariableValue::exact_scalar(value),
            Self::IndexedArray { elements, complete } => {
                SessionVariableValue::structured(StructuredShellValue::IndexedArray {
                    elements: elements
                        .iter()
                        .map(|(k, v)| (*k, ShellScalarValue::exact(v)))
                        .collect(),
                    complete: *complete,
                })
            }
            Self::AssociativeArray { elements } => {
                SessionVariableValue::structured(StructuredShellValue::AssociativeArray {
                    elements: elements
                        .iter()
                        .map(|(k, v)| (k.clone(), ShellScalarValue::exact(v)))
                        .collect(),
                    complete: false,
                })
            }
            Self::NameReference { target } => {
                SessionVariableValue::structured(StructuredShellValue::NameReference {
                    target: ShellReferenceTarget::Variable {
                        name: target.clone(),
                    },
                })
            }
            Self::Absent => return None,
            Self::Unsupported => SessionVariableValue::structured(StructuredShellValue::Unknown {
                reason: "owning variable shape is unsupported".into(),
            }),
            Self::Unknown => SessionVariableValue::structured(StructuredShellValue::Unknown {
                reason: "owning variable shape is unobserved".into(),
            }),
        })
    }

    fn bytes(&self) -> Result<usize, String> {
        fn text(value: &str) -> Result<usize, String> {
            if value.len() > 8192 || value.contains('\0') {
                return Err("invalid or oversized variable bytes".into());
            }
            Ok(value.len())
        }
        Ok(match self {
            Self::Scalar { value, integer } => {
                if *integer {
                    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
                    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("integer variable proof conflicts with bytes".into());
                    }
                }
                text(value)?
            }
            Self::IndexedArray { elements, .. } => {
                let mut seen = BTreeSet::new();
                let mut bytes = 0;
                if elements.len() > 256 {
                    return Err("array element budget exceeded".into());
                }
                for (index, value) in elements {
                    if *index > i64::MAX as u64 || !seen.insert(index) {
                        return Err("invalid or duplicate array index".into());
                    }
                    bytes += 8 + text(value)?;
                }
                bytes
            }
            Self::AssociativeArray { elements } => {
                let mut seen = BTreeSet::new();
                let mut bytes = 0;
                if elements.len() > 256 {
                    return Err("array element budget exceeded".into());
                }
                for (key, value) in elements {
                    if key.is_empty() || !seen.insert(key) {
                        return Err("invalid or duplicate array key".into());
                    }
                    bytes += text(key)? + text(value)?;
                }
                bytes
            }
            Self::NameReference { target } => {
                if !super::execution_frame::valid_name(target) {
                    return Err("nonliteral nameref target".into());
                }
                target.len()
            }
            Self::Absent | Self::Unsupported | Self::Unknown => 0,
        })
    }
}

impl ExecutionFrameObservation {
    pub(crate) fn validate_variable_values(&self) -> Result<usize, String> {
        let roots: BTreeSet<_> = self.variables.iter().map(|v| v.name.as_str()).collect();
        let mut values = BTreeMap::new();
        let mut bytes = 0;
        if self.variable_values.len() > 128 {
            return Err("variable observation budget exceeded".into());
        }
        for entry in &self.variable_values {
            if !super::execution_frame::valid_name(&entry.name)
                || values.insert(entry.name.as_str(), &entry.value).is_some()
            {
                return Err("invalid or duplicate typed variable".into());
            }
            bytes += entry.name.len() + entry.value.bytes()?;
            if let Some(old) = self.variables.iter().find(|v| v.name == entry.name) {
                let consistent = match (&entry.value, &old.value) {
                    (
                        ExecutionFrameVariableValue::Unknown
                        | ExecutionFrameVariableValue::Unsupported,
                        _,
                    ) => true,
                    (_, ShellEnvironmentValue::Unknown) => true,
                    (ExecutionFrameVariableValue::Absent, ShellEnvironmentValue::Absent) => true,
                    (
                        ExecutionFrameVariableValue::Scalar { value, .. },
                        ShellEnvironmentValue::Present { value: old },
                    ) => value == old,
                    _ => false,
                };
                if !consistent {
                    return Err("typed variable conflicts with scalar channel".into());
                }
                if let ExecutionFrameVariableValue::Scalar { integer, .. } = &entry.value {
                    if *integer != self.integer_variables.contains(&entry.name) {
                        return Err("typed integer attribute conflicts with scalar channel".into());
                    }
                } else if !matches!(
                    entry.value,
                    ExecutionFrameVariableValue::Unknown | ExecutionFrameVariableValue::Unsupported
                ) && self.integer_variables.contains(&entry.name)
                {
                    return Err("compound variable has a scalar integer proof".into());
                }
            }
            for env in self.environment.iter().filter(|v| v.name == entry.name) {
                if let ShellEnvironmentValue::Present { value: env } = &env.value {
                    match &entry.value {
                        ExecutionFrameVariableValue::Unknown
                        | ExecutionFrameVariableValue::Unsupported => {}
                        ExecutionFrameVariableValue::Scalar { value, .. } if value == env => {}
                        _ => return Err("typed variable conflicts with environment".into()),
                    }
                }
            }
        }
        let mut reachable = roots.clone();
        for _ in 0..16 {
            let before = reachable.len();
            for (name, value) in &values {
                if reachable.contains(name) {
                    if let ExecutionFrameVariableValue::NameReference { target } = value {
                        if !values.contains_key(target.as_str()) && !roots.contains(target.as_str())
                        {
                            return Err("nameref target was not observed in this frame".into());
                        }
                        reachable.insert(target.as_str());
                    }
                }
            }
            if reachable.len() == before {
                break;
            }
        }
        if reachable.len() > 128 || values.keys().any(|name| !reachable.contains(name)) {
            return Err("unplanned or unreachable variable observation".into());
        }
        for start in values.keys() {
            let mut current = *start;
            let mut seen = BTreeSet::new();
            let mut ended = false;
            for _ in 0..16 {
                if !seen.insert(current) {
                    return Err("cyclic nameref observation".into());
                }
                match values.get(current) {
                    Some(ExecutionFrameVariableValue::NameReference { target }) => current = target,
                    _ => {
                        ended = true;
                        break;
                    }
                }
            }
            if !ended {
                return Err("nameref observation depth exceeded".into());
            }
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(values: Vec<ExecutionFrameVariable>) -> ExecutionFrameObservation {
        serde_json::from_value(serde_json::json!({
            "binding":{"protocol":1,"executor_instance_id":"owner","session_id":"s",
                "sequence_no":1,"runtime_name":"test","shell_kind":"bash","cwd":"/tmp",
                "command_sha256":"0".repeat(64)},
            "environment":[],"variables":[{"name":"ROOT","value":{"status":"unknown"}}],
            "variable_values":values,"pathname":null
        }))
        .unwrap()
    }
    fn value(name: &str, value: ExecutionFrameVariableValue) -> ExecutionFrameVariable {
        ExecutionFrameVariable {
            name: name.into(),
            value,
        }
    }
    #[test]
    fn reference_closure_is_current_bounded_and_reachable() {
        let current = frame(vec![
            value(
                "ROOT",
                ExecutionFrameVariableValue::NameReference {
                    target: "DATA".into(),
                },
            ),
            value(
                "DATA",
                ExecutionFrameVariableValue::Scalar {
                    value: "private".into(),
                    integer: false,
                },
            ),
        ]);
        assert!(current.validate_variable_values().is_ok());
        let mut missing = current.clone();
        missing.variable_values.pop();
        assert!(missing.validate_variable_values().is_err());
        let mut detached = current.clone();
        detached
            .variable_values
            .push(value("DETACHED", ExecutionFrameVariableValue::Absent));
        assert!(detached.validate_variable_values().is_err());
        let cycle = frame(vec![value(
            "ROOT",
            ExecutionFrameVariableValue::NameReference {
                target: "ROOT".into(),
            },
        )]);
        assert!(cycle.validate_variable_values().is_err());
        let executable = frame(vec![value(
            "ROOT",
            ExecutionFrameVariableValue::NameReference {
                target: "DATA[$(touch marker)]".into(),
            },
        )]);
        assert!(executable.validate_variable_values().is_err());
    }
    #[test]
    fn arrays_reject_duplicates_invalid_indices_and_oversized_values() {
        for elements in [
            vec![(1, "a".into()), (1, "b".into())],
            vec![(u64::MAX, "a".into())],
            vec![(0, "x".repeat(8193))],
            (0..257).map(|i| (i, "x".into())).collect(),
        ] {
            assert!(
                frame(vec![value(
                    "ROOT",
                    ExecutionFrameVariableValue::IndexedArray {
                        elements,
                        complete: true
                    }
                )])
                .validate_variable_values()
                .is_err()
            );
        }
        let valid = frame(vec![value(
            "ROOT",
            ExecutionFrameVariableValue::IndexedArray {
                elements: vec![(8, "a b".into()), (1, "".into())],
                complete: true,
            },
        )]);
        assert!(valid.validate_variable_values().is_ok());
        let mut duplicate = valid.clone();
        duplicate
            .variable_values
            .push(duplicate.variable_values[0].clone());
        assert!(duplicate.validate_variable_values().is_err());
    }
    #[test]
    fn typed_values_cannot_conflict_with_scalar_or_environment_channels() {
        let mut f = frame(vec![value(
            "ROOT",
            ExecutionFrameVariableValue::IndexedArray {
                elements: vec![],
                complete: true,
            },
        )]);
        f.environment.push(crate::ShellEnvironmentSnapshot {
            name: "ROOT".into(),
            value: ShellEnvironmentValue::Present {
                value: "exported".into(),
            },
        });
        assert!(f.validate_variable_values().is_err());
        f.environment.clear();
        f.variables[0].value = ShellEnvironmentValue::Present {
            value: "scalar".into(),
        };
        assert!(f.validate_variable_values().is_err());
    }
}
