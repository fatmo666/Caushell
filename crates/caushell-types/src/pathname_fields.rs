use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOptionEnvironmentEvidence {
    pub node_id: String,
    pub name: String,
    pub value: crate::ShellEnvironmentValue,
    pub from_prefix_assignment: bool,
}

/// A complete upper bound when unobserved shell options may select one entry,
/// suppress expansion, or leave the pattern unmatched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathnameSingleMatchBound {
    pub literal: String,
    pub possible_match: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathnameFieldsEvidence {
    pub node_id: String,
    pub session_id: String,
    pub sequence_no: crate::CommandSequenceNo,
    pub start_byte: usize,
    pub end_byte: usize,
    pub source_word: String,
    pub cwd: Option<String>,
    pub complete: bool,
    pub exact_fields_required: bool,
    pub fields: Vec<String>,
    /// Quote-removed spelling for a pattern proved to have no possible match.
    /// Unknown shell options still permit retention, removal or no invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmatched_literal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_match_bound: Option<PathnameSingleMatchBound>,
    pub shell_options: Option<crate::ShellPathnameSnapshot>,
    pub environment_observations: Vec<crate::ShellEnvironmentSnapshot>,
    pub namespace_observations: Vec<crate::FilesystemObservation>,
    pub directory_observations: Vec<crate::DirectoryObservation>,
    pub gap: Option<String>,
}
