//! Host-owned loader facts and explicit permissions. Neither is a tool input.
use crate::{
    DirectoryObservation, ExecutionFrameBinding, FilesystemObservation, RuntimeFile,
    ShellEnvironmentValue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInvocation {
    pub binding: ExecutionFrameBinding,
    pub node_id: String,
    pub runtime: String,
    pub module: String,
    pub command: String,
    pub cwd: String,
}

/// A loader component certifies its complete startup/search/dependency closure
/// for this invocation. The core verifies freshness, not language import rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityFact {
    pub invocation: ModuleInvocation,
    pub namespace_id: String,
    pub loading_contract_sha256: String,
    pub executable: String,
    pub module_file: String,
    pub files: BTreeMap<String, RuntimeFile>,
    pub namespace: Vec<FilesystemObservation>,
    pub directories: Vec<DirectoryObservation>,
    pub environment: BTreeMap<String, ShellEnvironmentValue>,
}

impl ModuleIdentityFact {
    pub fn sha256(&self) -> String {
        // Value object maps are canonicalized independently of input key order.
        let value = serde_json::to_value(self).expect("module identity is serializable");
        format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()))
    }
}

/// A separate host policy decision authorizes use of the registered CLI
/// semantics, not arbitrary code or any of that CLI's file/network operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleContractPermission {
    pub grant_id: String,
    pub namespace_id: String,
    pub identity_sha256: String,
    pub loading_contract_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleContractEvidence {
    pub invocation: ModuleInvocation,
    pub identity_sha256: Option<String>,
    pub identity_verified: bool,
    pub grant_id: Option<String>,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryTreeEvidence {
    pub node_id: String,
    pub roots: Vec<String>,
    pub directories: Vec<DirectoryObservation>,
    pub complete: bool,
    pub gap: Option<String>,
}
