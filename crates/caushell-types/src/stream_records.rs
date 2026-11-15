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
}

/// The launched native children retain a closed read/data-only contract for
/// symbolic argv. This is not an observation of input bytes or an empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeInputEffectEvidence {
    #[serde(default)]
    pub control_envelope: bool,
    pub node_id: String,
    pub producer_node_id: String,
    pub child_node_ids: Vec<String>,
    pub observation_gap: String,
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
    fn old_effect_evidence_does_not_claim_a_native_control_envelope() {
        let evidence:super::NativeInputEffectEvidence=serde_json::from_value(serde_json::json!({
            "node_id":"consumer","producer_node_id":"producer","child_node_ids":["child"],"observation_gap":"unknown records"
        })).unwrap();
        assert!(!evidence.control_envelope);
    }
}
