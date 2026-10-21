//! Assumed state alternatives, never proof that a replacement/cleanup ran.
use crate::{CommandSequenceNo, SessionVariableValue};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_OBJECTS: usize = 512;
const MAX_CANDIDATES: usize = 4;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyStateKind {
    Variable,
    Alias,
    Function,
    Cwd,
    Positionals,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SafetyStateValue {
    Absent,
    Variable {
        value: SessionVariableValue,
        exported: bool,
    },
    Definition {
        body: String,
        uncertainty: Option<String>,
    },
    Cwd(String),
    Positionals(Vec<SessionVariableValue>),
    Unknown,
}

impl SafetyStateValue {
    fn retained_bytes(&self) -> usize {
        fn variable_bytes(value: &SessionVariableValue) -> usize {
            match value {
                SessionVariableValue::ExactScalar(v)
                | SessionVariableValue::RuntimeProduced { value: v, .. } => v.len(),
                SessionVariableValue::OpaqueDynamic { repr } => repr.len(),
                SessionVariableValue::RuntimeInput { capture, .. } => match capture {
                    crate::RuntimeInputCapture::NotCaptured => 0,
                    crate::RuntimeInputCapture::Descriptor { descriptor } => descriptor.len(),
                    crate::RuntimeInputCapture::ContentRef { content_ref } => content_ref.len(),
                },
            }
            .saturating_add(64)
        }
        match self {
            Self::Absent | Self::Unknown => 0,
            Self::Variable { value, .. } => variable_bytes(value),
            Self::Definition { body, uncertainty } => body
                .len()
                .saturating_add(uncertainty.as_ref().map_or(0, String::len)),
            Self::Cwd(path) => path.len(),
            Self::Positionals(values) => values.iter().fold(0usize, |size, value| {
                size.saturating_add(variable_bytes(value))
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafetyStateRecord {
    pub kind: SafetyStateKind,
    pub name: String,
    pub first_observed_at: CommandSequenceNo,
    pub last_observed_at: CommandSequenceNo,
    pub candidates: Vec<SafetyStateValue>,
    pub widened: bool,
    pub replacement_unconfirmed: bool,
}

/// Limits retain uncertainty, not a sliding window of supposedly safe values.
/// Overflow is per state class and is queried only at a related state read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
pub struct SafetyHistory {
    records: BTreeMap<String, SafetyStateRecord>,
    overflow: BTreeSet<SafetyStateKind>,
}

impl<'de> Deserialize<'de> for SafetyHistory {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireHistory {
            records: BTreeMap<String, SafetyStateRecord>,
            overflow: BTreeSet<SafetyStateKind>,
        }
        let wire = WireHistory::deserialize(deserializer)?;
        let mut bounded = Self::default();
        bounded.merge(&Self {
            records: wire.records,
            overflow: wire.overflow,
        });
        Ok(bounded)
    }
}

impl SafetyHistory {
    pub fn observe(
        &mut self,
        kind: SafetyStateKind,
        name: &str,
        value: SafetyStateValue,
        sequence: CommandSequenceNo,
    ) {
        if name.len() > MAX_NAME_BYTES {
            self.overflow.insert(kind);
            return;
        }
        let key = format!("{kind:?}:{name}");
        if !self.records.contains_key(&key) && self.records.len() >= MAX_OBJECTS {
            self.overflow.insert(kind);
            return;
        }
        let record = self
            .records
            .entry(key)
            .or_insert_with(|| SafetyStateRecord {
                kind,
                name: name.into(),
                first_observed_at: sequence,
                last_observed_at: sequence,
                candidates: Vec::new(),
                widened: false,
                replacement_unconfirmed: false,
            });
        record.last_observed_at = record.last_observed_at.max(sequence);
        // A value too large to retain cannot become an exact safety proof.
        let size = value.retained_bytes();
        if size > MAX_VALUE_BYTES || matches!(value, SafetyStateValue::Unknown) {
            record.widened = true;
            record.replacement_unconfirmed = true;
            return;
        }
        if !record.candidates.contains(&value) {
            record.replacement_unconfirmed |= !record.candidates.is_empty();
            if record.candidates.len() < MAX_CANDIDATES {
                record.candidates.push(value);
            } else {
                record.widened = true;
            }
        }
    }

    pub fn mark_dependent(
        &mut self,
        kind: SafetyStateKind,
        name: &str,
        sequence: CommandSequenceNo,
    ) {
        self.observe(kind, name, SafetyStateValue::Unknown, sequence);
    }

    pub fn replacement_unconfirmed(&self, kind: SafetyStateKind, name: &str) -> bool {
        self.overflow.contains(&kind)
            || self
                .record(kind, name)
                .is_some_and(|r| r.replacement_unconfirmed || r.widened)
    }

    pub fn record(&self, kind: SafetyStateKind, name: &str) -> Option<&SafetyStateRecord> {
        self.records.get(&format!("{kind:?}:{name}"))
    }

    pub fn records(&self) -> impl Iterator<Item = &SafetyStateRecord> {
        self.records.values()
    }

    pub fn merge(&mut self, other: &Self) {
        self.overflow.extend(other.overflow.iter().copied());
        for record in other.records.values() {
            if record.candidates.is_empty() {
                self.mark_dependent(record.kind, &record.name, record.first_observed_at);
            }
            for candidate in &record.candidates {
                self.observe(
                    record.kind,
                    &record.name,
                    candidate.clone(),
                    record.first_observed_at,
                );
            }
            if let Some(merged) = self
                .records
                .get_mut(&format!("{:?}:{}", record.kind, record.name))
            {
                merged.first_observed_at = merged.first_observed_at.min(record.first_observed_at);
                merged.last_observed_at = merged.last_observed_at.max(record.last_observed_at);
                merged.widened |= record.widened;
                merged.replacement_unconfirmed |=
                    record.replacement_unconfirmed || record.candidates.len() > 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar(value: &str) -> SafetyStateValue {
        SafetyStateValue::Variable {
            value: SessionVariableValue::exact_scalar(value),
            exported: false,
        }
    }
    #[test]
    fn repeated_identical_value_is_not_a_replacement_but_cleanup_never_clears_history() {
        let mut h = SafetyHistory::default();
        h.observe(
            SafetyStateKind::Variable,
            "DEST",
            scalar("/outside"),
            CommandSequenceNo(1),
        );
        h.observe(
            SafetyStateKind::Variable,
            "DEST",
            scalar("/outside"),
            CommandSequenceNo(2),
        );
        assert!(!h.replacement_unconfirmed(SafetyStateKind::Variable, "DEST"));
        h.observe(
            SafetyStateKind::Variable,
            "DEST",
            scalar("./safe"),
            CommandSequenceNo(3),
        );
        h.observe(
            SafetyStateKind::Variable,
            "DEST",
            SafetyStateValue::Absent,
            CommandSequenceNo(4),
        );
        assert!(h.replacement_unconfirmed(SafetyStateKind::Variable, "DEST"));
        assert!(!h.replacement_unconfirmed(SafetyStateKind::Variable, "UNRELATED"));
        let restored: SafetyHistory =
            serde_json::from_slice(&serde_json::to_vec(&h).unwrap()).unwrap();
        assert_eq!(restored, h);
    }
    #[test]
    fn limits_widen_instead_of_discarding_old_candidates() {
        let mut h = SafetyHistory::default();
        for i in 0..20 {
            h.observe(
                SafetyStateKind::Variable,
                "X",
                scalar(&i.to_string()),
                CommandSequenceNo(i),
            );
        }
        let r = h.record(SafetyStateKind::Variable, "X").unwrap();
        assert_eq!(r.candidates.len(), MAX_CANDIDATES);
        assert_eq!(r.candidates[0], scalar("0"));
        assert!(r.widened && r.replacement_unconfirmed);
        for i in 0..MAX_OBJECTS + 10 {
            h.observe(
                SafetyStateKind::Variable,
                &format!("V{i}"),
                scalar("v"),
                CommandSequenceNo(30),
            );
        }
        assert_eq!(h.records().count(), MAX_OBJECTS);
        assert!(h.replacement_unconfirmed(SafetyStateKind::Variable, "OVERFLOW"));
        assert!(!h.replacement_unconfirmed(SafetyStateKind::Function, "f"));
    }
    #[test]
    fn decoding_reapplies_bounds_and_cannot_hide_conflicting_candidates() {
        let mut h = SafetyHistory::default();
        h.observe(
            SafetyStateKind::Variable,
            "X",
            scalar("first"),
            CommandSequenceNo(1),
        );
        let mut wire = serde_json::to_value(&h).unwrap();
        let record = wire["records"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        record["candidates"] =
            serde_json::to_value((0..12).map(|i| scalar(&i.to_string())).collect::<Vec<_>>())
                .unwrap();
        record["replacement_unconfirmed"] = false.into();
        let decoded: SafetyHistory = serde_json::from_value(wire).unwrap();
        let x = decoded.record(SafetyStateKind::Variable, "X").unwrap();
        assert_eq!(x.candidates.len(), MAX_CANDIDATES);
        assert!(x.widened && decoded.replacement_unconfirmed(SafetyStateKind::Variable, "X"));
        h.observe(
            SafetyStateKind::Alias,
            &"a".repeat(MAX_NAME_BYTES + 1),
            SafetyStateValue::Absent,
            CommandSequenceNo(2),
        );
        assert!(h.replacement_unconfirmed(SafetyStateKind::Alias, "any_alias"));
    }

    #[test]
    fn merging_is_monotone_and_preserves_dependent_uncertainty() {
        let mut a = SafetyHistory::default();
        let mut b = SafetyHistory::default();
        a.observe(
            SafetyStateKind::Variable,
            "X",
            scalar("/outside"),
            CommandSequenceNo(1),
        );
        b.observe(
            SafetyStateKind::Variable,
            "X",
            scalar("./safe"),
            CommandSequenceNo(2),
        );
        b.mark_dependent(SafetyStateKind::Variable, "Y", CommandSequenceNo(2));
        a.merge(&b);
        assert!(a.replacement_unconfirmed(SafetyStateKind::Variable, "X"));
        assert!(a.replacement_unconfirmed(SafetyStateKind::Variable, "Y"));
        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }
}
