use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContentSource {
    CurrentProcess,
    SuppliedView,
    Graph,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContentStatus {
    Complete,
    Missing,
    Unreadable,
    NonRegular,
    TooLarge,
    Changed,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContentIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanos: i64,
    pub changed_seconds: i64,
    pub changed_nanos: i64,
}

/// The payload remains in the reader; persisted observations contain no bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContentObservation {
    pub source: FileContentSource,
    pub path: String,
    pub status: FileContentStatus,
    pub byte_limit: usize,
    pub bytes_observed: usize,
    pub sha256: Option<String>,
    pub identity: Option<FileContentIdentity>,
    pub detail: Option<String>,
}
