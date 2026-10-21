//! Graph facts for possible state, distinct from content propagation edges.
use crate::{CommandSequenceNo, SafetyStateKind, SafetyStateValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SafetyScope {
    /// The persistent shell represented by this session graph.
    Shell,
    Invocation {
        sequence_no: CommandSequenceNo,
    },
    Frame {
        sequence_no: CommandSequenceNo,
        frame_id: String,
    },
    Workspace {
        root: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyObject {
    pub scope: SafetyScope,
    pub kind: SafetyStateKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCandidateFact {
    pub object: SafetyObject,
    pub value: SafetyStateValue,
    pub sequence_no: CommandSequenceNo,
    /// Order within the owning parsed frame. This is not a runtime timestamp.
    pub source_end: usize,
}

impl StateCandidateFact {
    pub fn precedes(&self, sequence: CommandSequenceNo, source_start: usize) -> bool {
        self.sequence_no < sequence
            || (self.sequence_no == sequence && self.source_end <= source_start)
    }
}
