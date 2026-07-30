use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    NeedApproval,
    Deny,
}

#[cfg(test)]
mod test {
    use super::Decision;
    use serde_json::json;

    #[test]
    fn decision_can_be_compared() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_ne!(Decision::Allow, Decision::Deny);
    }

    #[test]
    fn decision_uses_snake_case_wire_format() {
        let value =
            serde_json::to_value(Decision::NeedApproval).expect("expected decision to serialize");

        assert_eq!(value, json!("need_approval"));

        let roundtrip: Decision =
            serde_json::from_value(value).expect("expected decision to deserialize");

        assert_eq!(roundtrip, Decision::NeedApproval);
    }
}
