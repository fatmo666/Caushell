use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOptionEnvironmentEvidence {
    pub node_id: String,
    pub name: String,
    pub value: crate::ShellEnvironmentValue,
    pub from_prefix_assignment: bool,
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
    pub shell_options: Option<crate::ShellPathnameSnapshot>,
    pub environment_observations: Vec<crate::ShellEnvironmentSnapshot>,
    pub namespace_observations: Vec<crate::FilesystemObservation>,
    pub directory_observations: Vec<crate::DirectoryObservation>,
    pub gap: Option<String>,
}
