use serde::{Deserialize, Serialize};

use crate::{
    CheckRequest, CheckResponse, CommandSequenceNo, RuntimeMetadata, SessionId, ShellKind,
    ShellStateDelta, ShellStateSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCheckRequest {
    pub session_id: SessionId,
    pub command: String,
    pub shell_state_before: ShellStateSnapshot,
    pub shell_kind: ShellKind,
    pub runtime: RuntimeMetadata,
    pub home: Option<String>,
    pub workspace_root: Option<String>,
}

impl RuntimeCheckRequest {
    pub fn into_check_request(self, sequence_no: CommandSequenceNo) -> CheckRequest {
        CheckRequest {
            session_id: self.session_id,
            sequence_no,
            command: self.command,
            shell_state_before: self.shell_state_before,
            shell_kind: self.shell_kind,
            runtime: self.runtime,
            home: self.home,
            workspace_root: self.workspace_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeShellStateDeltaRequest {
    pub session_id: SessionId,
    pub sequence_no: CommandSequenceNo,
    pub runtime: RuntimeMetadata,
    pub delta: ShellStateDelta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeShellStateDeltaResponse {
    pub committed_mutation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePingResponse {
    pub status: String,
    pub runtime_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

impl RuntimePingResponse {
    pub fn ok(runtime_version: impl Into<String>) -> Self {
        Self {
            status: "ok".to_string(),
            runtime_version: runtime_version.into(),
            instance_id: None,
        }
    }

    pub fn with_instance_id(mut self, instance_id: Option<String>) -> Self {
        self.instance_id = instance_id.filter(|value| !value.is_empty());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum RuntimeTransportRequest {
    Check(RuntimeCheckRequest),
    ShellStateDelta(RuntimeShellStateDeltaRequest),
    Ping,
}

impl RuntimeTransportRequest {
    pub fn check(request: RuntimeCheckRequest) -> Self {
        Self::Check(request)
    }

    pub fn shell_state_delta(request: RuntimeShellStateDeltaRequest) -> Self {
        Self::ShellStateDelta(request)
    }

    pub fn ping() -> Self {
        Self::Ping
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum RuntimeTransportResponse {
    Check(CheckResponse),
    ShellStateDelta(RuntimeShellStateDeltaResponse),
    Ping(RuntimePingResponse),
}

impl RuntimeTransportResponse {
    pub fn check(response: CheckResponse) -> Self {
        Self::Check(response)
    }

    pub fn shell_state_delta(committed_mutation_count: usize) -> Self {
        Self::ShellStateDelta(RuntimeShellStateDeltaResponse {
            committed_mutation_count,
        })
    }

    pub fn ping(runtime_version: impl Into<String>) -> Self {
        Self::Ping(RuntimePingResponse::ok(runtime_version))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeCheckRequest, RuntimePingResponse, RuntimeShellStateDeltaRequest,
        RuntimeShellStateDeltaResponse, RuntimeTransportRequest, RuntimeTransportResponse,
    };
    use crate::{
        CheckRequest, CheckResponse, CommandSequenceNo, Decision, DecisionTrace, RuntimeMetadata,
        SessionAliasBinding, SessionFunctionBinding, SessionId, SessionVariableBinding,
        SessionVariableValue, ShellKind, ShellStateDelta, ShellStateKnowledge, ShellStateSnapshot,
    };
    use serde_json::json;

    #[test]
    fn runtime_check_request_roundtrips_through_json_contract() {
        let request = RuntimeCheckRequest {
            session_id: SessionId::new("sess-1"),
            command: "bash -c 'echo ok'".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project")
                .with_exact_scalar_variable("USER_CMD", "echo ok", true)
                .with_alias("runbuild", "bash ./scripts/build.sh")
                .with_function("deploy", "bash ./scripts/deploy.sh;")
                .with_variable_knowledge(ShellStateKnowledge::Complete)
                .with_alias_knowledge(ShellStateKnowledge::Complete)
                .with_function_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        };

        let value = serde_json::to_value(&request)
            .expect("expected runtime check request to serialize to json");

        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "command": "bash -c 'echo ok'",
                "shell_state_before": {
                    "cwd": "/tmp/project",
                    "variables": [
                        {
                            "name": "USER_CMD",
                            "value": {
                                "kind": "exact_scalar",
                                "value": "echo ok"
                            },
                            "exported": true
                        }
                    ],
                    "aliases": [
                        {
                            "name": "runbuild",
                            "body": "bash ./scripts/build.sh"
                        }
                    ],
                    "functions": [
                        {
                            "name": "deploy",
                            "body": "bash ./scripts/deploy.sh;"
                        }
                    ],
                    "observability": {
                        "variables": "complete",
                        "aliases": "complete",
                        "functions": "complete"
                    }
                },
                "shell_kind": "bash",
                "runtime": {
                    "runtime_name": "claude_code",
                    "tool_name": "Bash",
                    "shell_runtime_capabilities": {
                        "persists_cwd": true,
                        "persists_variables": true,
                        "persists_exported_environment": true,
                        "persists_aliases": true,
                        "persists_functions": true,
                        "persists_positionals": true
                    }
                },
                "home": "/home/alice",
                "workspace_root": "/tmp/project"
            })
        );

        let roundtrip: RuntimeCheckRequest =
            serde_json::from_value(value).expect("expected runtime check request to deserialize");

        assert_eq!(roundtrip, request);
    }

    #[test]
    fn runtime_check_request_can_materialize_internal_check_request() {
        let request = RuntimeCheckRequest {
            session_id: SessionId::new("sess-1"),
            command: "pwd".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project")
                .with_alias("ll", "ls -la")
                .with_function("deploy", "bash deploy.sh;")
                .with_alias_knowledge(ShellStateKnowledge::Complete)
                .with_function_knowledge(ShellStateKnowledge::Complete),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some("/tmp/project".to_string()),
        };

        let materialized = request.into_check_request(CommandSequenceNo::new(4));

        assert_eq!(
            materialized,
            CheckRequest {
                session_id: SessionId::new("sess-1"),
                sequence_no: CommandSequenceNo::new(4),
                command: "pwd".to_string(),
                shell_state_before: ShellStateSnapshot::new("/tmp/project")
                    .with_alias("ll", "ls -la")
                    .with_function("deploy", "bash deploy.sh;")
                    .with_alias_knowledge(ShellStateKnowledge::Complete)
                    .with_function_knowledge(ShellStateKnowledge::Complete),
                shell_kind: ShellKind::Bash,
                runtime: RuntimeMetadata {
                    runtime_name: "claude_code".to_string(),
                    tool_name: Some("Bash".to_string()),
                    shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
                },
                home: None,
                workspace_root: Some("/tmp/project".to_string()),
            }
        );
    }

    #[test]
    fn runtime_shell_state_delta_request_roundtrips_through_json_contract() {
        let request = RuntimeShellStateDeltaRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(8),
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
            },
            delta: ShellStateDelta::new()
                .with_cwd_after("/tmp/project/subdir")
                .with_upsert_variable(SessionVariableBinding::new(
                    "USER_CMD",
                    SessionVariableValue::exact_scalar("echo ok"),
                    false,
                    CommandSequenceNo::new(999),
                ))
                .with_unset_variable("OLD_VAR")
                .with_upsert_alias(SessionAliasBinding::new(
                    "ll",
                    "ls -la",
                    CommandSequenceNo::new(999),
                ))
                .with_upsert_function(SessionFunctionBinding::new(
                    "deploy",
                    "bash ./deploy.sh;",
                    CommandSequenceNo::new(999),
                )),
        };

        let value = serde_json::to_value(&request)
            .expect("expected runtime shell state delta request to serialize");

        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "sequence_no": 8,
                "runtime": {
                    "runtime_name": "claude_code",
                    "tool_name": "Bash",
                    "shell_runtime_capabilities": {
                        "persists_cwd": true,
                        "persists_variables": true,
                        "persists_exported_environment": true,
                        "persists_aliases": true,
                        "persists_functions": true,
                        "persists_positionals": true
                    }
                },
                "delta": {
                    "cwd_after": "/tmp/project/subdir",
                    "upsert_variables": [
                        {
                            "name": "USER_CMD",
                            "value": {
                                "ExactScalar": "echo ok"
                            },
                            "exported": false,
                            "observed_at": 999
                        }
                    ],
                    "unset_variables": ["OLD_VAR"],
                    "upsert_aliases": [
                        {
                            "name": "ll",
                            "body": "ls -la",
                            "observed_at": 999
                        }
                    ],
                    "upsert_functions": [
                        {
                            "name": "deploy",
                            "body": "bash ./deploy.sh;",
                            "observed_at": 999
                        }
                    ]
                }
            })
        );

        let roundtrip: RuntimeShellStateDeltaRequest = serde_json::from_value(value)
            .expect("expected runtime shell state delta request to deserialize");

        assert_eq!(roundtrip, request);
    }

    #[test]
    fn runtime_ping_transport_request_roundtrips_through_json_contract() {
        let request = RuntimeTransportRequest::ping();

        let value =
            serde_json::to_value(&request).expect("expected runtime ping request to serialize");

        assert_eq!(value, json!({ "kind": "ping" }));

        let roundtrip: RuntimeTransportRequest =
            serde_json::from_value(value).expect("expected runtime ping request to deserialize");

        assert_eq!(roundtrip, request);
    }

    #[test]
    fn runtime_ping_transport_response_roundtrips_through_json_contract() {
        let response = RuntimeTransportResponse::Ping(RuntimePingResponse::ok("0.1.0"));

        let value =
            serde_json::to_value(&response).expect("expected runtime ping response to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "ping",
                "payload": {
                    "status": "ok",
                    "runtime_version": "0.1.0"
                }
            })
        );

        let roundtrip: RuntimeTransportResponse =
            serde_json::from_value(value).expect("expected runtime ping response to deserialize");

        assert_eq!(roundtrip, response);
    }

    #[test]
    fn runtime_transport_request_roundtrips_check_variant() {
        let request = RuntimeTransportRequest::check(RuntimeCheckRequest {
            session_id: SessionId::new("sess-1"),
            command: "pwd".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        });

        let value =
            serde_json::to_value(&request).expect("expected transport request to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "check",
                "payload": {
                    "session_id": "sess-1",
                    "command": "pwd",
                    "shell_state_before": {
                        "cwd": "/tmp/project"
                    },
                    "shell_kind": "bash",
                    "runtime": {
                        "runtime_name": "claude_code",
                        "tool_name": "Bash",
                        "shell_runtime_capabilities": {
                            "persists_cwd": true,
                            "persists_variables": true,
                            "persists_exported_environment": true,
                            "persists_aliases": true,
                            "persists_functions": true,
                            "persists_positionals": true
                        }
                    },
                    "home": "/home/alice",
                    "workspace_root": "/tmp/project"
                }
            })
        );

        let roundtrip: RuntimeTransportRequest =
            serde_json::from_value(value).expect("expected transport request to deserialize");

        assert_eq!(roundtrip, request);
    }

    #[test]
    fn runtime_transport_response_roundtrips_delta_variant() {
        let response = RuntimeTransportResponse::ShellStateDelta(RuntimeShellStateDeltaResponse {
            committed_mutation_count: 3,
        });

        let value =
            serde_json::to_value(&response).expect("expected transport response to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "shell_state_delta",
                "payload": {
                    "committed_mutation_count": 3
                }
            })
        );

        let roundtrip: RuntimeTransportResponse =
            serde_json::from_value(value).expect("expected transport response to deserialize");

        assert_eq!(roundtrip, response);
    }

    #[test]
    fn runtime_transport_response_roundtrips_check_variant() {
        let response = RuntimeTransportResponse::check(CheckResponse {
            decision: Decision::Allow,
            reasons: vec![],
            decision_trace: DecisionTrace::default(),
        });

        let value =
            serde_json::to_value(&response).expect("expected transport response to serialize");

        let roundtrip: RuntimeTransportResponse =
            serde_json::from_value(value).expect("expected transport response to deserialize");

        assert_eq!(roundtrip, response);
    }
}
