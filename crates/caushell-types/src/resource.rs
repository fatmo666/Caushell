use serde::{Deserialize, Serialize};

use crate::{ExecutionFrameBinding, ProvenanceEndpointUsage, StateOperation};

/// Selects declared endpoints on the same execution unit, not historical peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateResourceSelector {
    Endpoint { usage: ProvenanceEndpointUsage },
    RequestEndpoints,
}

impl StateResourceSelector {
    pub fn includes(self, usage: ProvenanceEndpointUsage) -> bool {
        match self {
            Self::Endpoint { usage: selected } => usage == selected,
            Self::RequestEndpoints => matches!(
                usage,
                ProvenanceEndpointUsage::FetchSource | ProvenanceEndpointUsage::UploadTarget
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAuthorizationEvidence {
    pub node_id: String,
    pub operation: StateOperation,
    pub targets: Vec<ResourceTargetEvidence>,
    pub binding: Option<ExecutionFrameBinding>,
    pub registry_revision: Option<u64>,
    pub authorized: bool,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTargetEvidence {
    pub slot_name: Option<String>,
    pub endpoint: Option<String>,
    pub resource_id: Option<String>,
    pub instance_id: Option<String>,
    pub generation: Option<u64>,
    pub namespace_id: Option<String>,
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_endpoint: Option<String>,
}
