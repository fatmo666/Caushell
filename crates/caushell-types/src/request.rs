use serde::{Deserialize, Serialize};

use crate::{CommandSequenceNo, SessionId, ShellStateSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShellRuntimeCapabilities {
    pub persists_cwd: bool,
    pub persists_variables: bool,
    pub persists_exported_environment: bool,
    pub persists_aliases: bool,
    pub persists_functions: bool,
    pub persists_positionals: bool,
}

impl ShellRuntimeCapabilities {
    pub const fn request_only() -> Self {
        Self {
            persists_cwd: false,
            persists_variables: false,
            persists_exported_environment: false,
            persists_aliases: false,
            persists_functions: false,
            persists_positionals: false,
        }
    }

    pub const fn cwd_persistent() -> Self {
        Self {
            persists_cwd: true,
            persists_variables: false,
            persists_exported_environment: false,
            persists_aliases: false,
            persists_functions: false,
            persists_positionals: false,
        }
    }

    pub const fn persistent_shell() -> Self {
        Self {
            persists_cwd: true,
            persists_variables: true,
            persists_exported_environment: true,
            persists_aliases: true,
            persists_functions: true,
            persists_positionals: true,
        }
    }

    pub fn persists_variable(&self, exported: bool) -> bool {
        self.persists_variables || (exported && self.persists_exported_environment)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    Bash,
    Sh,
    Zsh,
    Fish,
    Powershell,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    pub runtime_name: String,
    pub tool_name: Option<String>,
    pub shell_runtime_capabilities: ShellRuntimeCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRequest {
    pub session_id: SessionId,
    pub sequence_no: CommandSequenceNo,
    pub command: String,
    pub shell_state_before: ShellStateSnapshot,
    pub shell_kind: ShellKind,
    pub runtime: RuntimeMetadata,
    pub home: Option<String>,
    pub workspace_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{CheckRequest, RuntimeMetadata, ShellKind};
    use crate::{
        CommandSequenceNo, SessionId, ShellStateKnowledge, ShellStateSnapshot, ShellValueSnapshot,
        ShellVariableSnapshot,
    };
    use serde_json::json;

    #[test]
    fn check_request_holds_basic_fields() {
        let req = CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: "ls -la".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project")
                .with_exact_scalar_variable("USER_CMD", "echo ok", true)
                .with_alias("ll", "ls -la")
                .with_function("deploy", "bash ./deploy.sh;")
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

        assert_eq!(req.session_id.0, "sess-1");
        assert_eq!(req.sequence_no, CommandSequenceNo::new(1));
        assert_eq!(req.command, "ls -la");
        assert_eq!(req.shell_state_before.cwd(), "/tmp/project");
        assert_eq!(req.shell_kind, ShellKind::Bash);
        assert_eq!(req.runtime.runtime_name, "claude_code");
        assert_eq!(req.runtime.tool_name, Some("Bash".to_string()));
        assert_eq!(req.home, Some("/home/alice".to_string()));
        assert_eq!(req.workspace_root, Some("/tmp/project".to_string()));
        assert_eq!(
            req.shell_state_before.exported_variable("USER_CMD"),
            Some(&ShellVariableSnapshot::new(
                "USER_CMD",
                ShellValueSnapshot::exact_scalar("echo ok"),
                true,
            ))
        );
        assert_eq!(
            req.shell_state_before
                .alias("ll")
                .map(|alias| alias.body.as_str()),
            Some("ls -la")
        );
        assert_eq!(
            req.shell_state_before
                .function("deploy")
                .map(|function| function.body.as_str()),
            Some("bash ./deploy.sh;")
        );
    }

    #[test]
    fn check_request_can_have_no_home() {
        let req = CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
            command: "ls -la".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "cli".to_string(),
                tool_name: None,
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: None,
        };

        assert_eq!(req.sequence_no, CommandSequenceNo::new(2));
        assert_eq!(req.runtime.tool_name, None);
        assert_eq!(req.home, None);
        assert_eq!(req.workspace_root, None);
        assert!(req.shell_state_before.variables.is_empty());
        assert!(req.shell_state_before.aliases.is_empty());
        assert!(req.shell_state_before.functions.is_empty());
    }

    #[test]
    fn check_request_roundtrips_through_json_contract() {
        let request = CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(7),
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

        let value =
            serde_json::to_value(&request).expect("expected check request to serialize to json");

        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "sequence_no": 7,
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

        let roundtrip: CheckRequest =
            serde_json::from_value(value).expect("expected check request to deserialize");

        assert_eq!(roundtrip, request);
    }
}
