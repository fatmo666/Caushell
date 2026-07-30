use caushell_types::PolicyConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureAction {
    #[default]
    Allow,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaushellConfig {
    pub version: u32,
    pub failure_action: FailureAction,
    pub policy: PolicyConfig,
}

impl Default for CaushellConfig {
    fn default() -> Self {
        Self {
            version: crate::CURRENT_CONFIG_VERSION,
            failure_action: FailureAction::Allow,
            policy: PolicyConfig::default(),
        }
    }
}
