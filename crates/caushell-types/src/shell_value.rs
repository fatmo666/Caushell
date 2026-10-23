use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShellScalarValue {
    Exact {
        value: String,
    },
    RuntimeProduced {
        value: String,
        value_kind: RuntimeProducedValueKind,
    },
    Opaque {
        repr: String,
    },
    RuntimeInput {
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    },
    Unknown {
        reason: String,
    },
}

impl ShellScalarValue {
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact {
            value: value.into(),
        }
    }

    pub fn has_unknown_parts(&self) -> bool {
        matches!(
            self,
            Self::Opaque { .. } | Self::RuntimeInput { .. } | Self::Unknown { .. }
        )
    }

    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::Exact { value } | Self::RuntimeProduced { value, .. } => value.len(),
            Self::Opaque { repr } => repr.len(),
            Self::Unknown { reason } => reason.len(),
            Self::RuntimeInput { capture, .. } => capture_bytes(capture),
        }
        .saturating_add(64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShellReferenceTarget {
    Variable { name: String },
    IndexedElement { name: String, index: u64 },
    AssociativeElement { name: String, key: String },
    Unknown { repr: String },
}

impl ShellReferenceTarget {
    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::Variable { name } => name.len(),
            Self::IndexedElement { name, .. } => name.len().saturating_add(8),
            Self::AssociativeElement { name, key } => name.len().saturating_add(key.len()),
            Self::Unknown { repr } => repr.len(),
        }
        .saturating_add(64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StructuredShellValue {
    IndexedArray {
        #[serde(deserialize_with = "deserialize_indexed_elements")]
        elements: BTreeMap<u64, ShellScalarValue>,
        /// The assigned-key set is complete; individual values may still be unknown.
        complete: bool,
    },
    AssociativeArray {
        elements: BTreeMap<String, ShellScalarValue>,
        complete: bool,
    },
    NameReference {
        /// Resolved in the consuming shell frame, never a copy of the target's value.
        target: ShellReferenceTarget,
    },
    Unknown {
        reason: String,
    },
}

fn deserialize_indexed_elements<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<u64, ShellScalarValue>, D::Error> {
    let elements = BTreeMap::<String, ShellScalarValue>::deserialize(deserializer)?;
    elements
        .into_iter()
        .map(|(key, value)| {
            let index = key.parse::<u64>().map_err(serde::de::Error::custom)?;
            if index.to_string() != key {
                return Err(serde::de::Error::custom("array index is not canonical"));
            }
            Ok((index, value))
        })
        .collect()
}

impl StructuredShellValue {
    pub fn has_unknown_parts(&self) -> bool {
        match self {
            Self::IndexedArray { elements, complete } => {
                !complete || elements.values().any(ShellScalarValue::has_unknown_parts)
            }
            Self::AssociativeArray { elements, complete } => {
                !complete || elements.values().any(ShellScalarValue::has_unknown_parts)
            }
            Self::NameReference { target } => {
                matches!(target, ShellReferenceTarget::Unknown { .. })
            }
            Self::Unknown { .. } => true,
        }
    }

    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::IndexedArray { elements, .. } => elements.values().fold(0usize, |size, value| {
                size.saturating_add(8)
                    .saturating_add(value.retained_bytes())
            }),
            Self::AssociativeArray { elements, .. } => {
                elements.iter().fold(0usize, |size, (key, value)| {
                    size.saturating_add(key.len())
                        .saturating_add(value.retained_bytes())
                })
            }
            Self::NameReference { target } => target.retained_bytes(),
            Self::Unknown { reason } => reason.len(),
        }
        .saturating_add(64)
    }
}

pub(crate) fn capture_bytes(capture: &RuntimeInputCapture) -> usize {
    match capture {
        RuntimeInputCapture::NotCaptured => 0,
        RuntimeInputCapture::Descriptor { descriptor } => descriptor.len(),
        RuntimeInputCapture::ContentRef { content_ref } => content_ref.len(),
    }
}

impl From<&ShellScalarValue> for crate::SessionVariableValue {
    fn from(value: &ShellScalarValue) -> Self {
        match value {
            ShellScalarValue::Exact { value } => Self::exact_scalar(value),
            ShellScalarValue::RuntimeProduced { value, value_kind } => {
                Self::runtime_produced(value, *value_kind)
            }
            ShellScalarValue::Opaque { repr } => Self::opaque_dynamic(repr),
            ShellScalarValue::RuntimeInput { source, capture } => {
                Self::runtime_input(*source, capture.clone())
            }
            ShellScalarValue::Unknown { reason } => {
                Self::structured(StructuredShellValue::Unknown {
                    reason: reason.clone(),
                })
            }
        }
    }
}

impl TryFrom<&crate::SessionVariableValue> for ShellScalarValue {
    type Error = &'static str;
    fn try_from(value: &crate::SessionVariableValue) -> Result<Self, Self::Error> {
        use crate::SessionVariableValue as V;
        Ok(match value {
            V::ExactScalar(value) => Self::exact(value),
            V::RuntimeProduced { value, kind } => Self::RuntimeProduced {
                value: value.clone(),
                value_kind: *kind,
            },
            V::OpaqueDynamic { repr } => Self::Opaque { repr: repr.clone() },
            V::RuntimeInput { source, capture } => Self::RuntimeInput {
                source: *source,
                capture: capture.clone(),
            },
            V::Structured(StructuredShellValue::Unknown { reason }) => Self::Unknown {
                reason: reason.clone(),
            },
            V::Structured(_) => return Err("array or reference is not a scalar element"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProvenanceVariableValueState, SessionVariableValue, ShellValueSnapshot};

    #[test]
    fn legacy_scalar_wire_formats_are_unchanged() {
        for (session, snapshot) in [
            (
                r#"{"ExactScalar":"value"}"#,
                r#"{"kind":"exact_scalar","value":"value"}"#,
            ),
            (
                r#"{"RuntimeProduced":{"value":"/path","kind":"path"}}"#,
                r#"{"kind":"runtime_produced","value":"/path","value_kind":"path"}"#,
            ),
            (
                r#"{"OpaqueDynamic":{"repr":"$unknown"}}"#,
                r#"{"kind":"opaque_dynamic","repr":"$unknown"}"#,
            ),
            (
                r#"{"RuntimeInput":{"source":"stdin_data","capture":{"kind":"not_captured"}}}"#,
                r#"{"kind":"runtime_input","source":"stdin_data","capture":{"kind":"not_captured"}}"#,
            ),
        ] {
            let stored: SessionVariableValue = serde_json::from_str(session).unwrap();
            let observed: ShellValueSnapshot = serde_json::from_str(snapshot).unwrap();
            let artifact: ProvenanceVariableValueState = serde_json::from_str(snapshot).unwrap();
            assert_eq!(SessionVariableValue::from(&observed), stored);
            assert_eq!(ProvenanceVariableValueState::from(&stored), artifact);
            assert_eq!(
                serde_json::to_value(&stored).unwrap(),
                serde_json::from_str::<serde_json::Value>(session).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&observed).unwrap(),
                serde_json::from_str::<serde_json::Value>(snapshot).unwrap()
            );
        }
    }

    #[test]
    fn empty_sparse_partial_arrays_and_references_roundtrip() {
        for value in [
            StructuredShellValue::IndexedArray {
                elements: BTreeMap::new(),
                complete: true,
            },
            StructuredShellValue::IndexedArray {
                elements: BTreeMap::new(),
                complete: false,
            },
            StructuredShellValue::IndexedArray {
                elements: BTreeMap::from([
                    (2, ShellScalarValue::exact("")),
                    (
                        19,
                        ShellScalarValue::Unknown {
                            reason: "unobserved".into(),
                        },
                    ),
                ]),
                complete: true,
            },
            StructuredShellValue::AssociativeArray {
                elements: BTreeMap::from([(
                    "key with spaces".into(),
                    ShellScalarValue::exact("a b"),
                )]),
                complete: true,
            },
            StructuredShellValue::NameReference {
                target: ShellReferenceTarget::Variable {
                    name: "target".into(),
                },
            },
            StructuredShellValue::NameReference {
                target: ShellReferenceTarget::IndexedElement {
                    name: "paths".into(),
                    index: 2,
                },
            },
            StructuredShellValue::NameReference {
                target: ShellReferenceTarget::AssociativeElement {
                    name: "paths".into(),
                    key: "selected".into(),
                },
            },
            StructuredShellValue::NameReference {
                target: ShellReferenceTarget::Unknown {
                    repr: "$target".into(),
                },
            },
            StructuredShellValue::Unknown {
                reason: "missing capture".into(),
            },
        ] {
            let stored = SessionVariableValue::structured(value);
            let observed = ShellValueSnapshot::from(&stored);
            assert_eq!(SessionVariableValue::from(&observed), stored);
            assert_eq!(
                serde_json::from_slice::<SessionVariableValue>(
                    &serde_json::to_vec(&stored).unwrap()
                )
                .unwrap(),
                stored
            );
            assert_eq!(
                serde_json::from_slice::<ShellValueSnapshot>(
                    &serde_json::to_vec(&observed).unwrap()
                )
                .unwrap(),
                observed
            );
        }
    }

    #[test]
    fn scalar_elements_keep_input_capture_and_cannot_contain_arrays() {
        for value in [
            ShellScalarValue::exact(""),
            ShellScalarValue::RuntimeProduced {
                value: "/tmp/file".into(),
                value_kind: RuntimeProducedValueKind::Path,
            },
            ShellScalarValue::Opaque {
                repr: "$source".into(),
            },
            ShellScalarValue::RuntimeInput {
                source: RuntimeInputSource::StdinData,
                capture: RuntimeInputCapture::Descriptor {
                    descriptor: "fd:3".into(),
                },
            },
            ShellScalarValue::Unknown {
                reason: "not observed".into(),
            },
        ] {
            assert_eq!(
                ShellScalarValue::try_from(&SessionVariableValue::from(&value)).unwrap(),
                value
            );
        }
        let array = SessionVariableValue::structured(StructuredShellValue::IndexedArray {
            elements: BTreeMap::new(),
            complete: true,
        });
        assert!(ShellScalarValue::try_from(&array).is_err());
        assert!(
            serde_json::from_str::<StructuredShellValue>(
                r#"{"kind":"indexed_array","elements":{}}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<StructuredShellValue>(r#"{"kind":"indexed_array","complete":true,"elements":{"0":{"kind":"indexed_array","elements":{},"complete":true}}}"#).is_err());
        for key in ["-1", "01", "1+1", "18446744073709551616"] {
            let value = format!(
                r#"{{"kind":"indexed_array","complete":true,"elements":{{"{key}":{{"kind":"exact","value":"data"}}}}}}"#
            );
            assert!(serde_json::from_str::<StructuredShellValue>(&value).is_err());
        }
    }

    #[test]
    fn payload_accounting_includes_keys_captures_and_unknowns() {
        let value = StructuredShellValue::AssociativeArray {
            elements: BTreeMap::from([
                (
                    "key".repeat(100),
                    ShellScalarValue::RuntimeInput {
                        source: RuntimeInputSource::StdinData,
                        capture: RuntimeInputCapture::ContentRef {
                            content_ref: "origin".repeat(100),
                        },
                    },
                ),
                (
                    "unknown".into(),
                    ShellScalarValue::Unknown {
                        reason: "reason".repeat(100),
                    },
                ),
            ]),
            complete: false,
        };
        assert!(value.retained_bytes() >= 1407);
        assert!(value.has_unknown_parts());
    }

    #[test]
    fn key_set_completeness_does_not_erase_unknown_element_values() {
        let mut elements = BTreeMap::new();
        assert!(
            !StructuredShellValue::IndexedArray {
                elements: elements.clone(),
                complete: true
            }
            .has_unknown_parts()
        );
        assert!(
            StructuredShellValue::IndexedArray {
                elements: elements.clone(),
                complete: false
            }
            .has_unknown_parts()
        );
        elements.insert(
            0,
            ShellScalarValue::Unknown {
                reason: "unknown bytes".into(),
            },
        );
        assert!(
            StructuredShellValue::IndexedArray {
                elements,
                complete: true
            }
            .has_unknown_parts()
        );
    }
}
