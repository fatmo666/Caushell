use serde::{Deserialize, Serialize};

use crate::{CommandSequenceNo, PathMetadataMutation, PathResolution};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SemanticResolution<T> {
    Resolved { value: T },
    Unresolved { gap: SemanticGap },
    NotApplicable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticGap {
    pub kind: SemanticGapKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticGapKind {
    UnknownTarget,
    FilesystemUnavailable,
    LinkCycle,
    BudgetExceeded,
    NamespaceMutation,
    UnresolvedOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTargetAccess {
    Follow,
    Entry,
    Either,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMutationKind {
    Write,
    Delete,
    MoveSource,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilesystemEntry {
    Directory,
    File,
    Symlink { target: String },
    Missing,
    Unavailable { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemObservationSource {
    CurrentProcess,
    SuppliedView,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilesystemObservation {
    pub source: FilesystemObservationSource,
    pub path: String,
    pub entry: FilesystemEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathTargetFact {
    pub sequence_no: CommandSequenceNo,
    pub source_node_id: String,
    pub effect_key: String,
    pub slot_name: String,
    pub operation: PathMutationKind,
    pub access: PathTargetAccess,
    pub lexical: PathResolution,
    pub spelling: Option<String>,
    pub resolution: SemanticResolution<PathResolution>,
    pub observations: Vec<FilesystemObservation>,
    pub metadata_mutation: Option<PathMetadataMutation>,
    pub implicit_incidental_cache: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_states_have_distinct_roundtrip_contracts() {
        let values = [
            SemanticResolution::Resolved {
                value: PathResolution::Concrete {
                    path: "/work/out".into(),
                },
            },
            SemanticResolution::Unresolved {
                gap: SemanticGap {
                    kind: SemanticGapKind::FilesystemUnavailable,
                    detail: "no view".into(),
                },
            },
            SemanticResolution::NotApplicable {
                reason: "discarded output".into(),
            },
        ];
        for value in values {
            let json = serde_json::to_value(&value).unwrap();
            let restored: SemanticResolution<PathResolution> =
                serde_json::from_value(json.clone()).unwrap();
            assert_eq!(restored, value);
            assert!(json.get("status").is_some());
        }
    }
}
