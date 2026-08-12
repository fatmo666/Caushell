use caushell_types::PolicyConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureAction {
    Allow,
    #[default]
    NeedApproval,
    Deny,
}

impl FailureAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::NeedApproval => "need_approval",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexNeedApprovalMode {
    #[default]
    Block,
    Observe,
}

impl CodexNeedApprovalMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Observe => "observe",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CodexConfig {
    pub need_approval_mode: CodexNeedApprovalMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaushellConfig {
    pub version: u32,
    pub failure_action: FailureAction,
    pub codex: CodexConfig,
    pub policy: PolicyConfig,
}

impl Default for CaushellConfig {
    fn default() -> Self {
        Self {
            version: crate::CURRENT_CONFIG_VERSION,
            failure_action: FailureAction::NeedApproval,
            codex: CodexConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}
