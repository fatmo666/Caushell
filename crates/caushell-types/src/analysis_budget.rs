//! Exhaustion is an incomplete analysis, never evidence of safety.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisBudgetKind {
    HistoryNodes,
    HistoryEdges,
    StateObjects,
    StateCandidates,
    StateValueBytes,
    StateHistoryBytes,
    RequestBytes,
    Search,
}

impl AnalysisBudgetKind {
    pub const ALL: [Self; 8] = [
        Self::HistoryNodes,
        Self::HistoryEdges,
        Self::StateObjects,
        Self::StateCandidates,
        Self::StateValueBytes,
        Self::StateHistoryBytes,
        Self::RequestBytes,
        Self::Search,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::HistoryNodes => "history_nodes",
            Self::HistoryEdges => "history_edges",
            Self::StateObjects => "state_objects",
            Self::StateCandidates => "state_candidates",
            Self::StateValueBytes => "state_value_bytes",
            Self::StateHistoryBytes => "state_history_bytes",
            Self::RequestBytes => "request_bytes",
            Self::Search => "search",
        }
    }
}

/// Large but finite budgets. Zero means no capacity, not unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisBudgetPolicy {
    pub max_history_nodes: usize,
    pub max_history_edges: usize,
    pub max_state_objects: usize,
    pub max_candidates_per_object: usize,
    pub max_state_value_bytes: usize,
    pub max_state_history_bytes: usize,
    pub max_request_bytes: usize,
}

impl Default for AnalysisBudgetPolicy {
    fn default() -> Self {
        Self {
            max_history_nodes: 100_000,
            max_history_edges: 300_000,
            max_state_objects: 16_384,
            max_candidates_per_object: 256,
            max_state_value_bytes: 65_536,
            max_state_history_bytes: 64 * 1024 * 1024,
            max_request_bytes: 1_048_576,
        }
    }
}

impl AnalysisBudgetPolicy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}
