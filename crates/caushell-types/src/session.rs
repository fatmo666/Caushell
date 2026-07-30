use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandSequenceNo(pub u64);
impl CommandSequenceNo {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::session::CommandSequenceNo;

    use super::SessionId;
    use serde_json::json;

    #[test]
    fn session_id_can_be_created() {
        let id = SessionId::new("abc-123");
        assert_eq!(id.0, "abc-123");
    }

    #[test]
    fn command_sequence_can_advance() {
        let seq = CommandSequenceNo::new(7);
        assert_eq!(seq.next(), CommandSequenceNo(8));
    }

    #[test]
    fn session_id_uses_string_wire_format() {
        let value = serde_json::to_value(SessionId::new("sess-1"))
            .expect("expected session id to serialize");

        assert_eq!(value, json!("sess-1"));
    }

    #[test]
    fn command_sequence_uses_number_wire_format() {
        let value = serde_json::to_value(CommandSequenceNo::new(9))
            .expect("expected sequence number to serialize");

        assert_eq!(value, json!(9));
    }
}
