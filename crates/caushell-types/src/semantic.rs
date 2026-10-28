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
pub enum PathTargetOperation {
    Write,
    Delete,
    MoveSource,
    Metadata,
    ExecuteFile,
    LoadCode,
    StartupConfig,
    WorkingDirectory,
    WorkspaceRoot,
}

impl PathTargetOperation {
    pub fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Delete | Self::MoveSource | Self::Metadata
        )
    }
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

/// A tool contract about namespace changes, never a grant or a runtime result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathNamespaceEffect {
    /// May fail, write contents, or create/replace an ordinary file at the
    /// target leaf. Cannot introduce a symlink or change a parent directory.
    RegularFileWrite,
}

/// Request-local abstract-state dependency. Current filesystem observations
/// remain observations; a hypothetical output is never recorded as observed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathNamespaceProof {
    pub producer_node_id: String,
    pub producer_effect_key: String,
    pub path: String,
    pub effect: PathNamespaceEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathTargetFact {
    pub sequence_no: CommandSequenceNo,
    pub source_node_id: String,
    pub effect_key: String,
    pub slot_name: String,
    pub operation: PathTargetOperation,
    pub access: PathTargetAccess,
    pub lexical: PathResolution,
    pub spelling: Option<String>,
    pub resolution: SemanticResolution<PathResolution>,
    pub observations: Vec<FilesystemObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespace_proofs: Vec<PathNamespaceProof>,
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
