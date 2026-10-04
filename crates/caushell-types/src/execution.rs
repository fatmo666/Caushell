use serde::{Deserialize, Serialize};

/// Database state is not a filesystem path or evidence of workspace ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseOperationKind {
    Read,
    Write,
    Administration,
    Opaque,
}

/// Static operation labels, not evidence of a live session's shell state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalSessionOperationKind {
    Inspect,
    Create,
    Attach,
    Control,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveEscapeSurfaceKind {
    Pager,
    Editor,
    TerminalUi,
    LineEditor,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveEscapeCapability {
    SpawnShell,
    RunCommand,
    LaunchExternalEditor,
    WriteBufferToPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPayloadMode {
    CommandString,
    ScriptFile,
    SourcedScript,
    StdinExplicit,
    StdinImplicit,
    Interactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InProcessCodeLoadKind {
    ModuleName,
    Path,
    PluginName,
    LibraryPath,
    AgentPath,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessControlAction {
    Signal,
    ResumeForeground,
    ResumeBackground,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessControlTargetKind {
    Pid,
    ProcessName,
    ProcessPattern,
    JobSpec,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionSemantics {
    #[serde(default, skip_serializing_if = "is_false")]
    pub operation_semantics_unresolved: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_session_operations: Vec<TerminalSessionOperationKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub database_operations: Vec<DatabaseOperationKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_listeners: Vec<NetworkListener>,
    pub normalized_command_name: String,
    pub form_id: String,
    pub payload_mode: Option<ExecutionPayloadMode>,
    pub executes_payload: bool,
    pub opens_interactive_escape_surface: bool,
    pub interactive_escape_surface_kind: Option<InteractiveEscapeSurfaceKind>,
    pub interactive_escape_capabilities: Vec<InteractiveEscapeCapability>,
    pub interactive_escape_requires_tty: bool,
    pub executes_imported_package_logic: bool,
    pub loads_in_process_code: bool,
    pub in_process_code_load_kinds: Vec<InProcessCodeLoadKind>,
    pub mutates_current_shell: bool,
    pub executes_remote_command: bool,
    pub executes_hook: bool,
    pub loads_startup_config: bool,
    pub loads_project_config: bool,
    pub loads_tool_config: bool,
    pub executes_config_defined_task: bool,
    pub dispatches_child_command: bool,
    pub controls_process: bool,
    pub process_control_action: Option<ProcessControlAction>,
    pub process_control_target_kind: Option<ProcessControlTargetKind>,
    pub process_control_broad_target: bool,
}

impl ExecutionSemantics {
    pub fn new(normalized_command_name: impl Into<String>, form_id: impl Into<String>) -> Self {
        Self {
            terminal_session_operations: Vec::new(),
            operation_semantics_unresolved: false,
            database_operations: Vec::new(),
            network_listeners: Vec::new(),
            normalized_command_name: normalized_command_name.into(),
            form_id: form_id.into(),
            payload_mode: None,
            executes_payload: false,
            opens_interactive_escape_surface: false,
            interactive_escape_surface_kind: None,
            interactive_escape_capabilities: Vec::new(),
            interactive_escape_requires_tty: false,
            executes_imported_package_logic: false,
            loads_in_process_code: false,
            in_process_code_load_kinds: Vec::new(),
            mutates_current_shell: false,
            executes_remote_command: false,
            executes_hook: false,
            loads_startup_config: false,
            loads_project_config: false,
            loads_tool_config: false,
            executes_config_defined_task: false,
            dispatches_child_command: false,
            controls_process: false,
            process_control_action: None,
            process_control_target_kind: None,
            process_control_broad_target: false,
        }
    }

    pub fn with_payload_mode(mut self, payload_mode: ExecutionPayloadMode) -> Self {
        self.payload_mode = Some(payload_mode);
        self
    }

    pub fn executing_payload(mut self) -> Self {
        self.executes_payload = true;
        self
    }

    pub fn opening_interactive_escape_surface(
        mut self,
        surface_kind: InteractiveEscapeSurfaceKind,
        capabilities: impl IntoIterator<Item = InteractiveEscapeCapability>,
        requires_tty: bool,
    ) -> Self {
        self.opens_interactive_escape_surface = true;
        self.interactive_escape_surface_kind = Some(surface_kind);
        self.interactive_escape_capabilities = capabilities.into_iter().collect();
        self.interactive_escape_requires_tty = requires_tty;
        self
    }

    pub fn executing_imported_package_logic(mut self) -> Self {
        self.executes_imported_package_logic = true;
        self
    }

    pub fn loading_in_process_code(mut self, load_kind: InProcessCodeLoadKind) -> Self {
        self.loads_in_process_code = true;
        if !self.in_process_code_load_kinds.contains(&load_kind) {
            self.in_process_code_load_kinds.push(load_kind);
        }
        self
    }

    pub fn mutating_current_shell(mut self) -> Self {
        self.mutates_current_shell = true;
        self
    }

    pub fn executing_remote_command(mut self) -> Self {
        self.executes_remote_command = true;
        self
    }

    pub fn executing_hook(mut self) -> Self {
        self.executes_hook = true;
        self
    }

    pub fn loading_startup_config(mut self) -> Self {
        self.loads_startup_config = true;
        self
    }

    pub fn loading_project_config(mut self) -> Self {
        self.loads_project_config = true;
        self
    }

    pub fn loading_tool_config(mut self) -> Self {
        self.loads_tool_config = true;
        self
    }

    pub fn executing_config_defined_task(mut self) -> Self {
        self.executes_config_defined_task = true;
        self
    }

    pub fn dispatching_child_command(mut self) -> Self {
        self.dispatches_child_command = true;
        self
    }

    pub fn controlling_process(
        mut self,
        action: ProcessControlAction,
        target_kind: ProcessControlTargetKind,
        broad_target: bool,
    ) -> Self {
        self.controls_process = true;
        self.process_control_action = Some(action);
        self.process_control_target_kind = Some(target_kind);
        self.process_control_broad_target = broad_target;
        self
    }
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkListenScope {
    Loopback,
    NonLoopback,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum NetworkListener {
    Internet {
        host: Option<String>,
        port: Option<String>,
        scope: NetworkListenScope,
    },
    Unix {
        path: String,
    },
    InheritedFd {
        fd: Option<String>,
    },
    Unknown {
        reason: String,
    },
}

impl NetworkListener {
    pub fn has_local_scope(&self) -> bool {
        matches!(
            self,
            Self::Internet {
                scope: NetworkListenScope::Loopback,
                ..
            } | Self::Unix { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unresolved_operations_roundtrip_without_changing_legacy_json() {
        use super::*;
        let mut semantics = ExecutionSemantics::new("fixture", "run");
        let old = serde_json::to_value(&semantics).unwrap();
        assert!(old.get("operation_semantics_unresolved").is_none());
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(old).unwrap(),
            semantics
        );
        semantics.operation_semantics_unresolved = true;
        let wire = serde_json::to_value(&semantics).unwrap();
        assert_eq!(wire["operation_semantics_unresolved"], true);
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(wire).unwrap(),
            semantics
        );
    }
    #[test]
    fn terminal_operations_roundtrip_and_legacy_semantics_default_empty() {
        use super::*;
        let mut semantics = ExecutionSemantics::new("terminal-tool", "run");
        let old = serde_json::to_value(&semantics).unwrap();
        assert!(old.get("terminal_session_operations").is_none());
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(old).unwrap(),
            semantics
        );
        semantics.terminal_session_operations = vec![
            TerminalSessionOperationKind::Inspect,
            TerminalSessionOperationKind::Create,
            TerminalSessionOperationKind::Attach,
            TerminalSessionOperationKind::Control,
            TerminalSessionOperationKind::Opaque,
        ];
        let wire = serde_json::to_value(&semantics).unwrap();
        assert_eq!(
            wire["terminal_session_operations"],
            serde_json::json!(["inspect", "create", "attach", "control", "opaque"])
        );
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(wire).unwrap(),
            semantics
        );
    }
    #[test]
    fn database_operations_roundtrip_and_old_semantics_default_empty() {
        use super::*;
        let mut semantics = ExecutionSemantics::new("state-tool", "run");
        let old = serde_json::to_value(&semantics).unwrap();
        assert!(old.get("database_operations").is_none());
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(old).unwrap(),
            semantics
        );
        semantics.database_operations = vec![
            DatabaseOperationKind::Read,
            DatabaseOperationKind::Write,
            DatabaseOperationKind::Administration,
            DatabaseOperationKind::Opaque,
        ];
        let wire = serde_json::to_value(&semantics).unwrap();
        assert_eq!(
            wire["database_operations"],
            serde_json::json!(["read", "write", "administration", "opaque"])
        );
        assert_eq!(
            serde_json::from_value::<ExecutionSemantics>(wire).unwrap(),
            semantics
        );
    }
    #[test]
    fn listener_semantics_roundtrip_and_legacy_semantics_default_empty() {
        use super::*;
        let mut semantics = ExecutionSemantics::new("listener", "run");
        // Empty listeners are omitted, so the same JSON also exercises the
        // backward-compatible read of old stored execution semantics.
        let old = serde_json::to_string(&semantics).unwrap();
        assert!(!old.contains("network_listeners"));
        assert_eq!(
            serde_json::from_str::<ExecutionSemantics>(&old).unwrap(),
            semantics
        );
        semantics.network_listeners.push(NetworkListener::Internet {
            host: Some("0.0.0.0".into()),
            port: Some("8000".into()),
            scope: NetworkListenScope::NonLoopback,
        });
        let encoded = serde_json::to_string(&semantics).unwrap();
        assert_eq!(
            serde_json::from_str::<ExecutionSemantics>(&encoded).unwrap(),
            semantics
        );
    }

    use super::{
        ExecutionPayloadMode, ExecutionSemantics, InProcessCodeLoadKind,
        InteractiveEscapeCapability, InteractiveEscapeSurfaceKind,
    };

    #[test]
    fn execution_semantics_builder_sets_expected_flags() {
        let semantics = ExecutionSemantics::new("bash", "command_string")
            .with_payload_mode(ExecutionPayloadMode::CommandString)
            .executing_payload()
            .loading_startup_config();

        assert_eq!(semantics.normalized_command_name, "bash");
        assert_eq!(semantics.form_id, "command_string");
        assert_eq!(
            semantics.payload_mode,
            Some(ExecutionPayloadMode::CommandString)
        );
        assert!(semantics.executes_payload);
        assert!(!semantics.opens_interactive_escape_surface);
        assert_eq!(semantics.interactive_escape_surface_kind, None);
        assert!(semantics.interactive_escape_capabilities.is_empty());
        assert!(!semantics.interactive_escape_requires_tty);
        assert!(!semantics.executes_imported_package_logic);
        assert!(!semantics.mutates_current_shell);
        assert!(!semantics.executes_remote_command);
        assert!(!semantics.executes_hook);
        assert!(semantics.loads_startup_config);
        assert!(!semantics.loads_project_config);
        assert!(!semantics.loads_tool_config);
        assert!(!semantics.executes_config_defined_task);
        assert!(!semantics.dispatches_child_command);
        assert!(!semantics.loads_in_process_code);
        assert!(semantics.in_process_code_load_kinds.is_empty());
    }

    #[test]
    fn execution_semantics_builder_sets_config_defined_task_flags() {
        let semantics = ExecutionSemantics::new("npm", "run_script")
            .loading_project_config()
            .loading_tool_config()
            .executing_config_defined_task();

        assert!(semantics.loads_project_config);
        assert!(semantics.loads_tool_config);
        assert!(semantics.executes_config_defined_task);
        assert!(!semantics.opens_interactive_escape_surface);
        assert!(!semantics.executes_imported_package_logic);
        assert!(!semantics.mutates_current_shell);
        assert!(!semantics.executes_remote_command);
        assert!(!semantics.executes_hook);
        assert!(!semantics.loads_startup_config);
    }

    #[test]
    fn execution_semantics_builder_sets_current_shell_mutation_flag() {
        let semantics = ExecutionSemantics::new("source", "script_file")
            .with_payload_mode(ExecutionPayloadMode::SourcedScript)
            .executing_payload()
            .mutating_current_shell();

        assert!(semantics.executes_payload);
        assert!(semantics.mutates_current_shell);
        assert_eq!(
            semantics.payload_mode,
            Some(ExecutionPayloadMode::SourcedScript)
        );
        assert!(!semantics.opens_interactive_escape_surface);
    }

    #[test]
    fn execution_semantics_builder_sets_imported_package_logic_flag() {
        let semantics =
            ExecutionSemantics::new("pip", "install_packages").executing_imported_package_logic();

        assert!(semantics.executes_imported_package_logic);
        assert!(!semantics.executes_payload);
        assert!(!semantics.executes_config_defined_task);
        assert!(!semantics.opens_interactive_escape_surface);
        assert!(!semantics.loads_in_process_code);
    }

    #[test]
    fn execution_semantics_builder_sets_in_process_code_load_fields() {
        let semantics = ExecutionSemantics::new("node", "command_string")
            .loading_in_process_code(InProcessCodeLoadKind::Unknown)
            .loading_in_process_code(InProcessCodeLoadKind::Path)
            .loading_in_process_code(InProcessCodeLoadKind::Path);

        assert!(semantics.loads_in_process_code);
        assert_eq!(
            semantics.in_process_code_load_kinds,
            vec![InProcessCodeLoadKind::Unknown, InProcessCodeLoadKind::Path]
        );
        assert!(!semantics.executes_payload);
    }

    #[test]
    fn execution_semantics_builder_sets_interactive_escape_surface_fields() {
        let semantics = ExecutionSemantics::new("less", "interactive_file")
            .opening_interactive_escape_surface(
                InteractiveEscapeSurfaceKind::Pager,
                [
                    InteractiveEscapeCapability::SpawnShell,
                    InteractiveEscapeCapability::LaunchExternalEditor,
                ],
                true,
            );

        assert!(semantics.opens_interactive_escape_surface);
        assert_eq!(
            semantics.interactive_escape_surface_kind,
            Some(InteractiveEscapeSurfaceKind::Pager)
        );
        assert_eq!(
            semantics.interactive_escape_capabilities,
            vec![
                InteractiveEscapeCapability::SpawnShell,
                InteractiveEscapeCapability::LaunchExternalEditor
            ]
        );
        assert!(semantics.interactive_escape_requires_tty);
        assert!(!semantics.executes_payload);
    }
}
