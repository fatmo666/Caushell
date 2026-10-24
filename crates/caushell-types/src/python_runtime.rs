use crate::{
    DirectoryEntryKind, DirectoryObservation, FileContentObservation, FilesystemObservation,
    ShellEnvironmentValue,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeContract {
    pub schema: String,
    pub version: [u32; 3],
    pub platform: String,
    pub executable: String,
    pub account: RuntimeAccount,
    pub account_home: String,
    pub search_paths: Vec<String>,
    pub extension_suffixes: Vec<String>,
    pub site_directories: Vec<String>,
    pub absent_configuration: Vec<String>,
    pub stdlib_names: Vec<String>,
    pub builtin_modules: Vec<String>,
    pub frozen_modules: Vec<String>,
    pub modules: BTreeMap<String, PythonModuleOrigin>,
    pub files: BTreeMap<String, RuntimeFile>,
    pub directories: BTreeMap<String, Vec<RuntimeDirectoryEntry>>,
    pub symlinks: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAccount {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFile {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDirectoryEntry {
    pub name: String,
    pub kind: DirectoryEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PythonModuleOrigin {
    Builtin,
    Frozen,
    File { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFileObservation {
    pub content: FileContentObservation,
    /// Execute permission for the observed execution account, not any mode bit.
    pub executable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonStartupEvidence {
    pub node_id: String,
    pub complete: bool,
    pub contract_sha256: Option<String>,
    pub executable: Option<String>,
    pub executable_lookup: Option<ShellExecutableObservation>,
    pub version: Option<[u32; 3]>,
    pub account: Option<RuntimeAccount>,
    pub environment: BTreeMap<String, ShellEnvironmentValue>,
    pub search_paths: Vec<String>,
    pub modules: BTreeMap<String, PythonModuleOrigin>,
    pub namespace: Vec<FilesystemObservation>,
    pub directories: Vec<DirectoryObservation>,
    pub files: Vec<RuntimeFileObservation>,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellExecutableObservation {
    pub source: crate::FilesystemObservationSource,
    pub command: String,
    pub cwd: String,
    pub shell_kind: crate::ShellKind,
    pub path_environment: ShellEnvironmentValue,
    pub executable: String,
}
