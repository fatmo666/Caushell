use serde::{Deserialize, Serialize};

use crate::{FileContentIdentity, FilesystemObservationSource};

pub const MAX_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_DIRECTORY_NAME_BYTES: usize = 65_536;
pub const MAX_DIRECTORY_DEPTH: usize = 32;
pub const MAX_DIRECTORY_OBSERVATIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryReadLimits {
    pub max_entries: usize,
    pub max_name_bytes: usize,
}

impl Default for DirectoryReadLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_DIRECTORY_ENTRIES,
            max_name_bytes: MAX_DIRECTORY_NAME_BYTES,
        }
    }
}

impl DirectoryReadLimits {
    pub fn is_valid(self) -> bool {
        (1..=MAX_DIRECTORY_ENTRIES).contains(&self.max_entries)
            && (1..=MAX_DIRECTORY_NAME_BYTES).contains(&self.max_name_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: DirectoryEntryKind,
    pub identity: FileContentIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryReadStatus {
    Complete,
    Missing,
    InvalidPath,
    NotDirectory,
    Unreadable,
    NonUtf8,
    TooLarge,
    Changed,
    Unavailable,
}

/// Entries form a set; their canonical order does not prove tool output order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryObservation {
    pub source: FilesystemObservationSource,
    pub path: String,
    pub status: DirectoryReadStatus,
    pub limits: DirectoryReadLimits,
    pub entries_observed: usize,
    pub name_bytes_observed: usize,
    pub sha256: Option<String>,
    pub identity: Option<FileContentIdentity>,
    pub detail: Option<String>,
}
