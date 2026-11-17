use serde::{Deserialize, Serialize};

use crate::{CommandSequenceNo, DirectoryObservation, FilesystemObservation};

pub const MAX_OBSERVED_STREAM_RECORDS: usize = 4096;
pub const MAX_OBSERVED_STREAM_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamRecordOrder {
    Exact,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamRecordEncoding {
    Lines,
    Nul,
    NativeFormat,
}

/// One native path visit and its ordered output bytes, not a decoded argv item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedStreamRecord {
    pub path_spelling: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdoutRecordsEvidence {
    /// Resolver-owned identity of the native enumeration contract, never supplied output bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_contract_sha256: Option<String>,
    pub node_id: String,
    pub producer_node_id: String,
    pub session_id: String,
    pub sequence_no: CommandSequenceNo,
    pub cwd: Option<String>,
    /// Completeness of the record multiset, independent of its stream order.
    pub complete: bool,
    pub order: StreamRecordOrder,
    pub encoding: Option<StreamRecordEncoding>,
    pub records: Vec<ObservedStreamRecord>,
    pub namespace_observations: Vec<FilesystemObservation>,
    pub directory_observations: Vec<DirectoryObservation>,
    pub environment_observations: Vec<crate::ShellEnvironmentSnapshot>,
    pub forwarded_by: Vec<String>,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeInputDecodeEvidence {
    pub node_id: String,
    pub producer_node_id: String,
    pub complete: bool,
    pub alternative_groups: usize,
    pub gap: Option<String>,
    /// Encoding of a nonempty candidate that decoded completely before
    /// revalidation rejected it. The record bytes themselves are invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_candidate_encoding: Option<StreamRecordEncoding>,
}

/// A reviewed total native control contract, not an argument/output decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeArgvEffectEnvelope(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NativeEffectCapability {
    ContentRead,
    MetadataQuery,
    NetworkQuery,
}

#[allow(non_upper_case_globals)]
impl NativeArgvEffectEnvelope {
    pub const DataOnly: Self = Self(0);
    pub const ContentRead: Self = Self(1);
    pub const MetadataQuery: Self = Self(2);
    pub const NetworkQuery: Self = Self(4);
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn reads_content(self) -> bool {
        self.0 & 1 != 0
    }
    pub const fn queries_metadata(self) -> bool {
        self.0 & 2 != 0
    }
    pub const fn queries_network(self) -> bool {
        self.0 & 4 != 0
    }
}

impl Serialize for NativeArgvEffectEnvelope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Existing single-class wire values stay byte-compatible. Empty and
        // combined sets are explicit arrays, never a missing declaration.
        if *self == Self::ContentRead {
            return NativeEffectCapability::ContentRead.serialize(serializer);
        }
        if *self == Self::MetadataQuery {
            return NativeEffectCapability::MetadataQuery.serialize(serializer);
        }
        let mut capabilities = Vec::new();
        if self.reads_content() {
            capabilities.push(NativeEffectCapability::ContentRead);
        }
        if self.queries_metadata() {
            capabilities.push(NativeEffectCapability::MetadataQuery);
        }
        if self.queries_network() {
            capabilities.push(NativeEffectCapability::NetworkQuery);
        }
        capabilities.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NativeArgvEffectEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Legacy(NativeEffectCapability),
            Set(Vec<NativeEffectCapability>),
        }
        let capabilities = match Wire::deserialize(deserializer)? {
            Wire::Legacy(c) => vec![c],
            Wire::Set(cs) => cs,
        };
        let mut result = Self::DataOnly;
        for capability in capabilities {
            let next = match capability {
                NativeEffectCapability::ContentRead => Self::ContentRead,
                NativeEffectCapability::MetadataQuery => Self::MetadataQuery,
                NativeEffectCapability::NetworkQuery => Self::NetworkQuery,
            };
            if result.union(next) == result {
                return Err(serde::de::Error::custom(
                    "duplicate native effect capability",
                ));
            }
            result = result.union(next);
        }
        Ok(result)
    }
}

/// The launched native children retain a closed effect contract for
/// symbolic argv. This is not an observation of input bytes or an empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "NativeInputEffectEvidenceWire",
    into = "NativeInputEffectEvidenceWire"
)]
pub struct NativeInputEffectEvidence {
    pub control_envelope: bool,
    pub effect_envelope: Option<NativeArgvEffectEnvelope>,
    pub bound_effects: Option<NativeBoundEffectsProof>,
    pub node_id: String,
    pub producer_node_id: String,
    pub child_node_ids: Vec<String>,
    pub observation_gap: String,
}

/// References to the same resolved target facts consumed by policy guards.
/// These are completeness witnesses, never permissions or input-byte claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBoundEffectsProof {
    pub argument_ownership_complete: bool,
    pub path_targets: Vec<NativePathEffectReference>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePathEffectReference {
    pub source_node_id: String,
    pub effect_key: String,
    pub slot_name: String,
}

#[derive(Serialize, Deserialize)]
struct NativeInputEffectEvidenceWire {
    #[serde(default)]
    control_envelope: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_envelope: Option<NativeArgvEffectEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_capabilities: Option<NativeArgvEffectEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_effects: Option<NativeBoundEffectsProof>,
    node_id: String,
    producer_node_id: String,
    child_node_ids: Vec<String>,
    observation_gap: String,
}

impl From<NativeInputEffectEvidence> for NativeInputEffectEvidenceWire {
    fn from(e: NativeInputEffectEvidence) -> Self {
        let legacy = |c: &NativeArgvEffectEnvelope| {
            *c == NativeArgvEffectEnvelope::ContentRead
                || *c == NativeArgvEffectEnvelope::MetadataQuery
        };
        Self {
            control_envelope: e.control_envelope,
            effect_envelope: e.effect_envelope.filter(legacy),
            effect_capabilities: e.effect_envelope.filter(|c| !legacy(c)),
            bound_effects: e.bound_effects,
            node_id: e.node_id,
            producer_node_id: e.producer_node_id,
            child_node_ids: e.child_node_ids,
            observation_gap: e.observation_gap,
        }
    }
}

impl TryFrom<NativeInputEffectEvidenceWire> for NativeInputEffectEvidence {
    type Error = String;
    fn try_from(e: NativeInputEffectEvidenceWire) -> Result<Self, Self::Error> {
        if let (Some(a), Some(b)) = (e.effect_envelope, e.effect_capabilities) {
            if a != b {
                return Err("conflicting native effect declarations".into());
            }
        }
        Ok(Self {
            control_envelope: e.control_envelope,
            effect_envelope: e.effect_capabilities.or(e.effect_envelope),
            bound_effects: e.bound_effects,
            node_id: e.node_id,
            producer_node_id: e.producer_node_id,
            child_node_ids: e.child_node_ids,
            observation_gap: e.observation_gap,
        })
    }
}

impl StdoutRecordsEvidence {
    /// Exact bytes require both a complete record set and a proved order.
    pub fn complete_bytes(&self) -> Option<Vec<u8>> {
        if self.order != StreamRecordOrder::Exact {
            return None;
        }
        Some(
            self.complete_records()?
                .iter()
                .flat_map(|r| r.bytes.clone())
                .collect(),
        )
    }

    pub fn complete_records(&self) -> Option<&[ObservedStreamRecord]> {
        if !self.complete
            || self.gap.is_some()
            || self.encoding.is_none()
            || self.records.len() > MAX_OBSERVED_STREAM_RECORDS
        {
            return None;
        }
        if self.directory_observations.iter().any(|o| {
            o.status != crate::DirectoryReadStatus::Complete
                || o.source == crate::FilesystemObservationSource::Unavailable
                || o.identity.is_none()
                || o.sha256.is_none()
        }) || self.namespace_observations.iter().any(|o| {
            o.source == crate::FilesystemObservationSource::Unavailable
                || matches!(
                    o.entry,
                    crate::FilesystemEntry::Missing | crate::FilesystemEntry::Unavailable { .. }
                )
        }) {
            return None;
        }
        let bytes = self
            .records
            .iter()
            .try_fold(0usize, |n, r| n.checked_add(r.bytes.len()))?;
        (bytes <= MAX_OBSERVED_STREAM_BYTES).then_some(self.records.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_bytes_require_complete_ordered_records_and_an_intact_budget() {
        let mut p = StdoutRecordsEvidence {
            producer_contract_sha256: None,
            node_id: "node".into(),
            producer_node_id: "producer".into(),
            session_id: "session".into(),
            sequence_no: CommandSequenceNo(1),
            cwd: Some("/work".into()),
            complete: true,
            order: StreamRecordOrder::Exact,
            encoding: Some(StreamRecordEncoding::Nul),
            records: vec![ObservedStreamRecord {
                path_spelling: "a\nb".into(),
                bytes: b"a\nb\0".to_vec(),
            }],
            namespace_observations: vec![],
            directory_observations: vec![],
            environment_observations: vec![],
            forwarded_by: vec![],
            gap: None,
        };
        assert_eq!(p.complete_bytes(), Some(b"a\nb\0".to_vec()));
        let encoded = serde_json::to_vec(&p).unwrap();
        assert_eq!(
            serde_json::from_slice::<StdoutRecordsEvidence>(&encoded).unwrap(),
            p
        );
        p.order = StreamRecordOrder::Unspecified;
        assert!(p.complete_bytes().is_none());
        p.order = StreamRecordOrder::Exact;
        p.complete = false;
        assert!(p.complete_bytes().is_none());
        p.complete = true;
        p.gap = Some("incomplete".into());
        assert!(p.complete_bytes().is_none());
        p.gap = None;
        p.records[0].bytes = vec![0; MAX_OBSERVED_STREAM_BYTES + 1];
        assert!(p.complete_bytes().is_none());
        p.records.clear();
        assert_eq!(p.complete_bytes(), Some(vec![]));
    }
}

#[cfg(test)]
mod effect_evidence_compatibility {
    #[test]
    fn new_sets_round_trip_and_old_consumers_keep_reading_the_legacy_field() {
        use super::{NativeArgvEffectEnvelope as E, NativeInputEffectEvidence};
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum OldKind {
            ContentRead,
            MetadataQuery,
        }
        #[derive(serde::Deserialize)]
        struct OldReader {
            #[serde(default)]
            effect_envelope: Option<OldKind>,
        }
        for kind in [
            None,
            Some(E::DataOnly),
            Some(E::ContentRead),
            Some(E::MetadataQuery),
            Some(E::ContentRead.union(E::MetadataQuery)),
        ] {
            let original = NativeInputEffectEvidence {
                control_envelope: true,
                effect_envelope: kind,
                bound_effects: None,
                node_id: "n".into(),
                producer_node_id: "p".into(),
                child_node_ids: vec!["c".into()],
                observation_gap: "unknown bytes".into(),
            };
            let wire = serde_json::to_value(&original).unwrap();
            let legacy: OldReader = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(
                legacy.effect_envelope.is_some(),
                kind == Some(E::ContentRead) || kind == Some(E::MetadataQuery)
            );
            assert_eq!(
                serde_json::from_value::<NativeInputEffectEvidence>(wire).unwrap(),
                original
            );
        }
        let contradictory = serde_json::json!({"node_id":"n","producer_node_id":"p","child_node_ids":[],"observation_gap":"unknown","effect_envelope":"content_read","effect_capabilities":["metadata_query"]});
        assert!(serde_json::from_value::<NativeInputEffectEvidence>(contradictory).is_err());
    }
    #[test]
    fn target_completeness_is_distinct_from_a_read_envelope_and_byte_decode() {
        use super::{NativeInputEffectEvidence, NativeBoundEffectsProof, NativePathEffectReference};
        let original = NativeInputEffectEvidence {
            control_envelope: false, effect_envelope: None,
            bound_effects: Some(NativeBoundEffectsProof {
                argument_ownership_complete: true,
                path_targets: vec![NativePathEffectReference { source_node_id: "child".into(), effect_key: "effect:1".into(), slot_name: "files".into() }],
            }),
            node_id: "consumer".into(), producer_node_id: "find".into(),
            child_node_ids: vec!["child".into()], observation_gap: "namespace changed".into(),
        };
        let wire=serde_json::to_value(&original).unwrap();
        assert!(wire.get("effect_envelope").is_none() && wire.get("effect_capabilities").is_none());
        assert_eq!(serde_json::from_value::<NativeInputEffectEvidence>(wire).unwrap(),original);
        let legacy=serde_json::json!({"node_id":"n","producer_node_id":"p","child_node_ids":[],"observation_gap":"unknown","effect_envelope":"content_read"});
        assert!(serde_json::from_value::<NativeInputEffectEvidence>(legacy).unwrap().bound_effects.is_none());
    }
    #[test]
    fn capability_sets_compose_without_changing_legacy_wire_values() {
        use super::NativeArgvEffectEnvelope as E;
        let mixed = E::ContentRead.union(E::MetadataQuery);
        for (wire, expected) in [
            (serde_json::json!("content_read"), E::ContentRead),
            (serde_json::json!("metadata_query"), E::MetadataQuery),
            (serde_json::json!([]), E::DataOnly),
            (serde_json::json!(["content_read", "metadata_query"]), mixed),
        ] {
            let value: E = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(value, expected);
            assert_eq!(serde_json::to_value(value).unwrap(), wire);
        }
        for wire in [
            serde_json::json!(["content_read", "content_read"]),
            serde_json::json!(["execute_payload"]),
            serde_json::json!({}),
        ] {
            assert!(serde_json::from_value::<E>(wire).is_err());
        }
        assert!(mixed.reads_content() && mixed.queries_metadata());
        assert!(!E::DataOnly.reads_content() && !E::DataOnly.queries_metadata());
    }
    #[test]
    fn old_effect_evidence_does_not_claim_a_native_control_envelope() {
        let evidence:super::NativeInputEffectEvidence=serde_json::from_value(serde_json::json!({
            "node_id":"consumer","producer_node_id":"producer","child_node_ids":["child"],"observation_gap":"unknown records"
        })).unwrap();
        assert!(!evidence.control_envelope);
        assert!(evidence.effect_envelope.is_none());
    }
}
