//! Single-call authorization. These records assert permission, not execution.
use serde::{Deserialize, Serialize};

use crate::{CheckRequest, CommandSequenceNo, PolicyConfig, SessionId, SessionMutation};

/// A session and its monotonic check sequence already identify a check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckId {
    pub session_id: SessionId,
    pub sequence_no: CommandSequenceNo,
}

impl CheckId {
    pub fn for_request(request: &CheckRequest) -> Self {
        Self {
            session_id: request.session_id.clone(),
            sequence_no: request.sequence_no,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckIntent {
    #[default]
    ProposeForExecution,
    JudgeOnly,
}

impl CheckIntent {
    pub fn is_default(&self) -> bool {
        *self == Self::ProposeForExecution
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAuthority {
    User,
    Host,
    SimulatedUser,
}

/// Only the trusted Harness/experiment controller may submit authorization.
/// Tool stdout and model-generated text are never authorization evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub check_id: CheckId,
    pub state_revision: u64,
    pub approved: bool,
    pub authority: ApprovalAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReceipt {
    pub check_id: CheckId,
    pub state_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub check_id: CheckId,
    pub approved: bool,
    pub state_revision: u64,
}

/// The original analysis is retained; approval never rewrites its decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub receipt: CheckReceipt,
    pub request: CheckRequest,
    pub mutations: Vec<SessionMutation>,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResolution {
    pub request: ApprovalRequest,
    pub response: ApprovalResponse,
}

/// Included in snapshots as well as the append-only event stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionApprovalState {
    pub revision: u64,
    pub pending: Vec<PendingApproval>,
    pub resolutions: Vec<ApprovalResolution>,
}

impl SessionApprovalState {
    pub fn is_empty(&self) -> bool {
        self.revision == 0 && self.pending.is_empty() && self.resolutions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authorization_is_explicit_single_call_and_not_an_execution_receipt() {
        let value = json!({
            "check_id": {"session_id": "session-a", "sequence_no": 7},
            "state_revision": 9,
            "approved": true,
            "authority": "simulated_user"
        });
        let request: ApprovalRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(
            serde_json::from_value::<ApprovalRequest>(json!({
                "check_id": {"session_id": "session-a", "sequence_no": 7},
                "state_revision": 9,
                "approved": true,
                "authority": "tool_stdout"
            }))
            .is_err()
        );
    }

    #[test]
    fn authorization_requires_a_decision_revision_and_known_fields() {
        for value in [
            json!({"check_id": {"session_id": "a", "sequence_no": 1}}),
            json!({
                "check_id": {"session_id": "a", "sequence_no": 1},
                "state_revision": 0, "approved": true,
                "authority": "user", "approve_entire_session": true
            }),
        ] {
            assert!(serde_json::from_value::<ApprovalRequest>(value).is_err());
        }
    }
}
