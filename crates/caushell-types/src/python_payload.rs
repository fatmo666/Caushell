use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PythonPayloadInputEvidence {
    Environment { name: String, value: Option<String> },
    File { path: String, bytes: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonPayloadEvidence {
    pub node_id: String,
    pub source: Option<String>,
    pub cwd: Option<String>,
    pub complete: bool,
    pub isolated_startup: bool,
    pub imports: Vec<String>,
    pub inputs: Vec<PythonPayloadInputEvidence>,
    pub native_argv: Vec<Vec<String>>,
    pub shell_commands: Vec<String>,
    pub stdout: Vec<u8>,
    pub stdout_complete: bool,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonStdoutFieldEvidence {
    pub node_id: String,
    pub argument_index: usize,
    pub expression: String,
    pub stdout: Vec<u8>,
    pub value: String,
    pub inputs: Vec<PythonPayloadInputEvidence>,
}
