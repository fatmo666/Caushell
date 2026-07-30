use serde::{Deserialize, Serialize};

use crate::RuleId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingEnforcementClass {
    Normal,
    HardDenyFloor,
}

impl Default for FindingEnforcementClass {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub message: String,
    #[serde(default)]
    pub enforcement_class: FindingEnforcementClass,
}

impl Finding {
    pub fn new(rule_id: RuleId, message: impl Into<String>) -> Self {
        Self {
            rule_id,
            message: message.into(),
            enforcement_class: FindingEnforcementClass::Normal,
        }
    }

    pub fn with_enforcement_class(mut self, enforcement_class: FindingEnforcementClass) -> Self {
        self.enforcement_class = enforcement_class;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Finding, FindingEnforcementClass};
    use crate::RuleId;
    use serde_json::json;

    #[test]
    fn finding_can_be_attached_to_a_rule() {
        let finding = Finding::new(
            RuleId::OutsideWorkspaceScriptSource,
            "script source path escapes workspace root",
        );

        assert_eq!(finding.rule_id, RuleId::OutsideWorkspaceScriptSource);
        assert_eq!(finding.message, "script source path escapes workspace root");
        assert_eq!(finding.enforcement_class, FindingEnforcementClass::Normal);
    }

    #[test]
    fn finding_roundtrips_through_json_contract() {
        let finding = Finding::new(
            RuleId::OutsideWorkspaceStartupConfig,
            "startup config path escapes workspace root",
        )
        .with_enforcement_class(FindingEnforcementClass::HardDenyFloor);

        let value = serde_json::to_value(&finding).expect("expected finding to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "outside_workspace_startup_config",
                "message": "startup config path escapes workspace root",
                "enforcement_class": "hard_deny_floor",
            })
        );

        let roundtrip: Finding =
            serde_json::from_value(value).expect("expected finding to deserialize");

        assert_eq!(roundtrip, finding);
    }

    #[test]
    fn finding_defaults_enforcement_class_when_missing_from_json() {
        let roundtrip: Finding = serde_json::from_value(json!({
            "rule_id": "outside_workspace_startup_config",
            "message": "startup config path escapes workspace root"
        }))
        .expect("expected finding to deserialize");

        assert_eq!(roundtrip.enforcement_class, FindingEnforcementClass::Normal);
    }
}
