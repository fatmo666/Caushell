use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
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
