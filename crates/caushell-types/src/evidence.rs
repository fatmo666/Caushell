use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    CommandSequenceNo, ImplicitInputSource, InteractiveEscapeCapability,
    InteractiveEscapeSurfaceKind, PackageLocatorKind, PackageManagerKind, RepositoryOperationKind,
    RuleId, RuntimeInputSource, ShellKind, UnresolvedExecutionPayloadSubtype,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: RuleId,
    pub kind: EvidenceKind,
    pub summary: String,
}

impl Evidence {
    pub fn outside_workspace_path(
        rule_id: RuleId,
        path: impl Into<String>,
        slot_name: impl Into<String>,
        normalized_command_name: impl Into<String>,
        workspace_root: impl Into<String>,
    ) -> Self {
        let path = path.into();
        let slot_name = slot_name.into();
        let normalized_command_name = normalized_command_name.into();
        let workspace_root = workspace_root.into();

        Self {
            rule_id,
            kind: EvidenceKind::OutsideWorkspacePath(OutsideWorkspacePathEvidence {
                path: path.clone(),
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
                workspace_root: workspace_root.clone(),
            }),
            summary: format!(
                "path {} for slot {} in command {} is outside workspace root {}",
                path, slot_name, normalized_command_name, workspace_root
            ),
        }
    }

    pub fn prior_path_write(
        rule_id: RuleId,
        path: impl Into<String>,
        sequence_no: CommandSequenceNo,
        command: impl Into<String>,
    ) -> Self {
        let path = path.into();
        let command = command.into();

        Self {
            rule_id,
            kind: EvidenceKind::PriorPathWrite(PriorPathWriteEvidence {
                path: path.clone(),
                sequence_no,
                command: command.clone(),
            }),
            summary: format!(
                "path {} was previously written at sequence {} by command {}",
                path, sequence_no.0, command
            ),
        }
    }

    pub fn nested_payload_parsed(
        context: NestedPayloadContextEvidence,
        shell_kind: ShellKind,
        parsed_command_count: usize,
    ) -> Self {
        let summary = format!(
            "nested payload record {} at depth {} parsed as {} with {} commands",
            context.record_id,
            context.depth,
            shell_kind_name(shell_kind),
            parsed_command_count
        );

        Self {
            rule_id: RuleId::NestedPayloadExpansion,
            kind: EvidenceKind::NestedPayloadParsed(NestedPayloadParsedEvidence {
                context,
                shell_kind,
                parsed_command_count,
            }),
            summary,
        }
    }

    pub fn nested_payload_truncated(
        context: NestedPayloadContextEvidence,
        max_depth: u8,
        next_candidate_count: usize,
    ) -> Self {
        let summary = format!(
            "nested payload record {} at depth {} was truncated by depth budget {} with {} expandable child candidates",
            context.record_id, context.depth, max_depth, next_candidate_count
        );

        Self {
            rule_id: RuleId::NestedPayloadExpansion,
            kind: EvidenceKind::NestedPayloadTruncated(NestedPayloadTruncatedEvidence {
                context,
                max_depth,
                next_candidate_count,
            }),
            summary,
        }
    }

    pub fn nested_payload_unresolved(
        context: NestedPayloadContextEvidence,
        reason: NestedPayloadUnresolvedReasonEvidence,
        unresolved_execution_payload_subtype: Option<UnresolvedExecutionPayloadSubtype>,
    ) -> Self {
        let summary = match &reason {
            NestedPayloadUnresolvedReasonEvidence::RequiresRuntimeInput { source } => format!(
                "nested payload record {} at depth {} requires runtime input from {} before it can be parsed",
                context.record_id,
                context.depth,
                runtime_input_source_name(*source)
            ),
            NestedPayloadUnresolvedReasonEvidence::UnsupportedLanguage => format!(
                "nested payload record {} at depth {} uses unsupported payload language {:?}",
                context.record_id, context.depth, context.language
            ),
            NestedPayloadUnresolvedReasonEvidence::ParseFailed { shell_kind, error } => format!(
                "nested payload record {} at depth {} failed to parse as {}: {}",
                context.record_id,
                context.depth,
                shell_kind_name(*shell_kind),
                error
            ),
            NestedPayloadUnresolvedReasonEvidence::MissingBinding { variable_name } => format!(
                "nested payload record {} at depth {} could not be materialized because variable {} is missing",
                context.record_id, context.depth, variable_name
            ),
            NestedPayloadUnresolvedReasonEvidence::UnsupportedDynamicBinding {
                variable_name,
                ..
            } => format!(
                "nested payload record {} at depth {} could not be materialized because variable {} is dynamically bound",
                context.record_id, context.depth, variable_name
            ),
            NestedPayloadUnresolvedReasonEvidence::UnsupportedDynamicText { .. } => format!(
                "nested payload record {} at depth {} contains unsupported dynamic text",
                context.record_id, context.depth
            ),
            NestedPayloadUnresolvedReasonEvidence::UnsafeUnquotedScalar {
                variable_name, ..
            } => format!(
                "nested payload record {} at depth {} expands variable {} in an unsafe unquoted position",
                context.record_id, context.depth, variable_name
            ),
        };

        Self {
            rule_id: RuleId::NestedPayloadExpansion,
            kind: EvidenceKind::NestedPayloadUnresolved(NestedPayloadUnresolvedEvidence {
                context,
                reason,
                unresolved_execution_payload_subtype,
            }),
            summary,
        }
    }

    pub fn tainted_execution_source(
        sink: TaintedExecutionSinkEvidence,
        source_node_id: impl Into<String>,
        source_kind: TaintSourceKindEvidence,
        source_summary: impl Into<String>,
        hop_count: u32,
    ) -> Self {
        let source_node_id = source_node_id.into();
        let source_summary = source_summary.into();

        Self {
            rule_id: RuleId::TaintedExecution,
            kind: EvidenceKind::TaintedExecutionSource(TaintedExecutionSourceEvidence {
                sink: sink.clone(),
                source_node_id: source_node_id.clone(),
                source_kind,
                source_summary: source_summary.clone(),
                hop_count,
            }),
            summary: format!(
                "execution sink {} at sequence {} with subtypes {:?} traces back to {} source {} within {} hops",
                sink.command,
                sink.sequence_no.0,
                sink.risk_subtypes,
                taint_source_kind_name(source_kind),
                source_summary,
                hop_count
            ),
        }
    }

    pub fn tainted_execution_budget_exceeded(
        sink: TaintedExecutionSinkEvidence,
        max_hops: u32,
        max_visited_nodes: usize,
        visited_nodes: usize,
        truncated_by_hops: bool,
        truncated_by_visited_nodes: bool,
    ) -> Self {
        Self {
            rule_id: RuleId::TaintedExecution,
            kind: EvidenceKind::TaintedExecutionBudgetExceeded(
                TaintedExecutionBudgetExceededEvidence {
                    sink: sink.clone(),
                    max_hops,
                    max_visited_nodes,
                    visited_nodes,
                    truncated_by_hops,
                    truncated_by_visited_nodes,
                },
            ),
            summary: format!(
                "taint analysis for execution sink {} at sequence {} with subtypes {:?} was truncated by runtime budget (max_hops={}, max_visited_nodes={}, visited_nodes={})",
                sink.command,
                sink.sequence_no.0,
                sink.risk_subtypes,
                max_hops,
                max_visited_nodes,
                visited_nodes
            ),
        }
    }

    pub fn tainted_execution_unresolved_origin(
        sink: TaintedExecutionSinkEvidence,
        unresolved_node_id: impl Into<String>,
        reason: TaintedExecutionUnresolvedReasonEvidence,
    ) -> Self {
        let unresolved_node_id = unresolved_node_id.into();
        let summary = match &reason {
            TaintedExecutionUnresolvedReasonEvidence::RequiresRuntimeInput { source } => format!(
                "execution sink {} at sequence {} with subtypes {:?} has unresolved payload origin because it requires runtime input from {}",
                sink.command,
                sink.sequence_no.0,
                sink.risk_subtypes,
                runtime_input_source_name(*source)
            ),
            TaintedExecutionUnresolvedReasonEvidence::MissingBinding { variable_name } => format!(
                "execution sink {} at sequence {} with subtypes {:?} has unresolved payload origin because variable {} is missing",
                sink.command, sink.sequence_no.0, sink.risk_subtypes, variable_name
            ),
            TaintedExecutionUnresolvedReasonEvidence::UnsupportedDynamicBinding {
                variable_name,
                ..
            } => format!(
                "execution sink {} at sequence {} with subtypes {:?} has unresolved payload origin because variable {} is dynamically bound",
                sink.command, sink.sequence_no.0, sink.risk_subtypes, variable_name
            ),
            TaintedExecutionUnresolvedReasonEvidence::UnsupportedDynamicText { .. } => format!(
                "execution sink {} at sequence {} with subtypes {:?} has unresolved payload origin because the payload text contains unsupported dynamic syntax",
                sink.command, sink.sequence_no.0, sink.risk_subtypes
            ),
            TaintedExecutionUnresolvedReasonEvidence::UnsafeUnquotedScalar {
                variable_name,
                ..
            } => format!(
                "execution sink {} at sequence {} with subtypes {:?} has unresolved payload origin because variable {} expands in an unsafe unquoted position",
                sink.command, sink.sequence_no.0, sink.risk_subtypes, variable_name
            ),
        };

        Self {
            rule_id: RuleId::TaintedExecution,
            kind: EvidenceKind::TaintedExecutionUnresolvedOrigin(
                TaintedExecutionUnresolvedOriginEvidence {
                    sink,
                    unresolved_node_id,
                    reason,
                },
            ),
            summary,
        }
    }

    pub fn imported_package_execution(
        sink: ImportedPackageExecutionSinkEvidence,
        source_summary: impl Into<String>,
    ) -> Self {
        let source_summary = source_summary.into();

        Self {
            rule_id: RuleId::ImportedPackageExecution,
            kind: EvidenceKind::ImportedPackageExecution(ImportedPackageExecutionEvidence {
                sink: sink.clone(),
                source_summary: source_summary.clone(),
            }),
            summary: format!(
                "imported package execution sink {} at sequence {} for subtype {} uses {} source {}",
                sink.command,
                sink.sequence_no.0,
                execution_risk_subtype_name(sink.risk_subtype),
                imported_package_source_class_name(sink.source_class),
                source_summary
            ),
        }
    }

    pub fn interactive_escape_surface(
        node_id: impl Into<String>,
        sequence_no: CommandSequenceNo,
        depth: u8,
        command: impl Into<String>,
        normalized_command_name: impl Into<String>,
        form_id: impl Into<String>,
        surface_kind: InteractiveEscapeSurfaceKind,
        capabilities: Vec<InteractiveEscapeCapability>,
        requires_tty: bool,
    ) -> Self {
        let node_id = node_id.into();
        let command = command.into();
        let normalized_command_name = normalized_command_name.into();
        let form_id = form_id.into();
        let capability_names = capabilities
            .iter()
            .map(|capability| interactive_escape_capability_name(*capability))
            .collect::<Vec<_>>()
            .join(", ");

        let summary = format!(
            "command {} at sequence {} opens {} interactive escape surface via {} form {} with capabilities [{}]{}",
            command,
            sequence_no.0,
            interactive_escape_surface_kind_name(surface_kind),
            normalized_command_name,
            form_id,
            capability_names,
            if requires_tty {
                " and requires tty"
            } else {
                ""
            }
        );

        Self {
            rule_id: RuleId::InteractiveEscapeSurface,
            kind: EvidenceKind::InteractiveEscapeSurface(InteractiveEscapeSurfaceEvidence {
                node_id,
                sequence_no,
                depth,
                command,
                normalized_command_name,
                form_id,
                surface_kind,
                capabilities,
                requires_tty,
            }),
            summary,
        }
    }

    pub fn catastrophic_shell_process_explosion(
        trigger_function: impl Into<String>,
        recursive_scc_members: Vec<String>,
        expansion_mode: CatastrophicShellExpansionModeEvidence,
        trigger_command: impl Into<String>,
    ) -> Self {
        let trigger_function = trigger_function.into();
        let trigger_command = trigger_command.into();
        let recursive_scc_members = recursive_scc_members;
        let members_summary = recursive_scc_members.join(", ");

        Self {
            rule_id: RuleId::CatastrophicShellProcessExplosion,
            kind: EvidenceKind::CatastrophicShellProcessExplosion(
                CatastrophicShellProcessExplosionEvidence {
                    trigger_function: trigger_function.clone(),
                    recursive_scc_members,
                    expansion_mode,
                    trigger_command: trigger_command.clone(),
                },
            ),
            summary: format!(
                "catastrophic shell process explosion via {} recursive function expansion triggered by {} through [{}]",
                catastrophic_shell_expansion_mode_name(expansion_mode),
                trigger_command,
                members_summary
            ),
        }
    }

    pub fn repository_operation(
        rule_id: RuleId,
        node_id: impl Into<String>,
        command: impl Into<String>,
        operation: RepositoryOperationKind,
    ) -> Self {
        let node_id = node_id.into();
        let command = command.into();

        Self {
            rule_id,
            kind: EvidenceKind::RepositoryOperation(RepositoryOperationEvidence {
                node_id,
                command: command.clone(),
                operation,
            }),
            summary: format!(
                "git command {} performs repository operation {} that can discard local state",
                command,
                repository_operation_name(operation)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceKind {
    CatastrophicShellProcessExplosion(CatastrophicShellProcessExplosionEvidence),
    ImportedPackageExecution(ImportedPackageExecutionEvidence),
    InteractiveEscapeSurface(InteractiveEscapeSurfaceEvidence),
    RepositoryOperation(RepositoryOperationEvidence),
    OutsideWorkspacePath(OutsideWorkspacePathEvidence),
    PriorPathWrite(PriorPathWriteEvidence),
    NestedPayloadParsed(NestedPayloadParsedEvidence),
    NestedPayloadTruncated(NestedPayloadTruncatedEvidence),
    NestedPayloadUnresolved(NestedPayloadUnresolvedEvidence),
    TaintedExecutionSource(TaintedExecutionSourceEvidence),
    TaintedExecutionUnresolvedOrigin(TaintedExecutionUnresolvedOriginEvidence),
    TaintedExecutionBudgetExceeded(TaintedExecutionBudgetExceededEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatastrophicShellProcessExplosionEvidence {
    pub trigger_function: String,
    pub recursive_scc_members: Vec<String>,
    pub expansion_mode: CatastrophicShellExpansionModeEvidence,
    pub trigger_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatastrophicShellExpansionModeEvidence {
    Pipeline,
    Background,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractiveEscapeSurfaceEvidence {
    pub node_id: String,
    pub sequence_no: CommandSequenceNo,
    pub depth: u8,
    pub command: String,
    pub normalized_command_name: String,
    pub form_id: String,
    pub surface_kind: InteractiveEscapeSurfaceKind,
    pub capabilities: Vec<InteractiveEscapeCapability>,
    pub requires_tty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryOperationEvidence {
    pub node_id: String,
    pub command: String,
    pub operation: RepositoryOperationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutsideWorkspacePathEvidence {
    pub path: String,
    pub slot_name: String,
    pub normalized_command_name: String,
    pub workspace_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorPathWriteEvidence {
    pub path: String,
    pub sequence_no: CommandSequenceNo,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPayloadParsedEvidence {
    pub context: NestedPayloadContextEvidence,
    pub shell_kind: ShellKind,
    pub parsed_command_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPayloadTruncatedEvidence {
    pub context: NestedPayloadContextEvidence,
    pub max_depth: u8,
    pub next_candidate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPayloadUnresolvedEvidence {
    pub context: NestedPayloadContextEvidence,
    pub reason: NestedPayloadUnresolvedReasonEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_execution_payload_subtype: Option<UnresolvedExecutionPayloadSubtype>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedExecutionSinkEvidence {
    pub node_id: String,
    pub sequence_no: CommandSequenceNo,
    pub depth: u8,
    pub command: String,
    pub risk_subtypes: BTreeSet<ExecutionRiskSubtype>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedPackageExecutionSinkEvidence {
    pub node_id: String,
    pub sequence_no: CommandSequenceNo,
    pub depth: u8,
    pub command: String,
    pub package_manager: PackageManagerKind,
    pub risk_subtype: ExecutionRiskSubtype,
    pub source_class: ImportedPackageSourceClass,
    pub locator: String,
    pub locator_kind: PackageLocatorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedPackageExecutionEvidence {
    pub sink: ImportedPackageExecutionSinkEvidence,
    pub source_summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRiskSubtype {
    GenericPayload,
    Hook,
    StartupConfig,
    ProjectConfig,
    ToolConfig,
    ConfigDefinedTask,
    ImportedPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceKindEvidence {
    NetworkEndpoint,
    ImportedPackage,
    InheritedEnvironment,
    RuntimeInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedPackageSourceClass {
    RegistryRef,
    DirectUrl,
    VcsUrl,
    LocalPath,
    RequirementFile,
    UnknownDynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedExecutionSourceEvidence {
    pub sink: TaintedExecutionSinkEvidence,
    pub source_node_id: String,
    pub source_kind: TaintSourceKindEvidence,
    pub source_summary: String,
    pub hop_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedExecutionUnresolvedOriginEvidence {
    pub sink: TaintedExecutionSinkEvidence,
    pub unresolved_node_id: String,
    pub reason: TaintedExecutionUnresolvedReasonEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedExecutionBudgetExceededEvidence {
    pub sink: TaintedExecutionSinkEvidence,
    pub max_hops: u32,
    pub max_visited_nodes: usize,
    pub visited_nodes: usize,
    pub truncated_by_hops: bool,
    pub truncated_by_visited_nodes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPayloadContextEvidence {
    pub record_id: usize,
    pub parent_ref: NestedPayloadParentEvidence,
    pub root_command_index: usize,
    pub depth: u8,
    pub language: NestedPayloadLanguageEvidence,
    pub source: NestedPayloadSourceEvidence,
    pub origin: NestedPayloadOriginEvidence,
    pub input: NestedPayloadInputEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NestedPayloadParentEvidence {
    RootCommand { command_index: usize },
    DerivedInvocation { node_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedPayloadLanguageEvidence {
    Bash,
    Sh,
    Dash,
    Python,
    Perl,
    Javascript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedPayloadSourceEvidence {
    InlineString,
    ScriptFileRef,
    Stdin,
    Interactive,
    DynamicReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NestedPayloadOriginEvidence {
    Parameter {
        slot_name: String,
    },
    FormImplicitInput,
    ConfigDefinedTask {
        config_path: String,
        task_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPayloadInputFragmentEvidence {
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NestedPayloadInputEvidence {
    ArgumentFragments {
        text: String,
        fragments: Vec<NestedPayloadInputFragmentEvidence>,
    },
    ImplicitInput {
        source: ImplicitInputSource,
    },
    LiteralText {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NestedPayloadUnresolvedReasonEvidence {
    RequiresRuntimeInput {
        source: RuntimeInputSource,
    },
    UnsupportedLanguage,
    ParseFailed {
        shell_kind: ShellKind,
        error: String,
    },
    MissingBinding {
        variable_name: String,
    },
    UnsupportedDynamicBinding {
        variable_name: String,
        repr: String,
    },
    UnsupportedDynamicText {
        text: String,
    },
    UnsafeUnquotedScalar {
        variable_name: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaintedExecutionUnresolvedReasonEvidence {
    RequiresRuntimeInput {
        source: RuntimeInputSource,
    },
    MissingBinding {
        variable_name: String,
    },
    UnsupportedDynamicBinding {
        variable_name: String,
        repr: String,
    },
    UnsupportedDynamicText {
        text: String,
    },
    UnsafeUnquotedScalar {
        variable_name: String,
        value: String,
    },
}

fn shell_kind_name(shell_kind: ShellKind) -> &'static str {
    match shell_kind {
        ShellKind::Bash => "bash",
        ShellKind::Sh => "sh",
        ShellKind::Zsh => "zsh",
        ShellKind::Fish => "fish",
        ShellKind::Powershell => "powershell",
    }
}

fn runtime_input_source_name(source: RuntimeInputSource) -> &'static str {
    match source {
        RuntimeInputSource::StdinPayload => "stdin_payload",
        RuntimeInputSource::StdinData => "stdin_data",
        RuntimeInputSource::InteractiveSession => "interactive_session",
    }
}

fn repository_operation_name(operation: RepositoryOperationKind) -> &'static str {
    match operation {
        RepositoryOperationKind::TrackedWorktreeDiscard => "tracked_worktree_discard",
        RepositoryOperationKind::UntrackedWorktreeDelete => "untracked_worktree_delete",
        RepositoryOperationKind::ForcedWorktreeSwitch => "forced_worktree_switch",
        RepositoryOperationKind::TrackedPathDelete => "tracked_path_delete",
        RepositoryOperationKind::SavedStateDestroy => "saved_state_destroy",
        RepositoryOperationKind::LocalRefDestroy => "local_ref_destroy",
    }
}

fn taint_source_kind_name(kind: TaintSourceKindEvidence) -> &'static str {
    match kind {
        TaintSourceKindEvidence::NetworkEndpoint => "network_endpoint",
        TaintSourceKindEvidence::ImportedPackage => "imported_package",
        TaintSourceKindEvidence::InheritedEnvironment => "inherited_environment",
        TaintSourceKindEvidence::RuntimeInput => "runtime_input",
    }
}

fn execution_risk_subtype_name(kind: ExecutionRiskSubtype) -> &'static str {
    match kind {
        ExecutionRiskSubtype::GenericPayload => "generic_payload",
        ExecutionRiskSubtype::Hook => "hook",
        ExecutionRiskSubtype::StartupConfig => "startup_config",
        ExecutionRiskSubtype::ProjectConfig => "project_config",
        ExecutionRiskSubtype::ToolConfig => "tool_config",
        ExecutionRiskSubtype::ConfigDefinedTask => "config_defined_task",
        ExecutionRiskSubtype::ImportedPackage => "imported_package",
    }
}

fn imported_package_source_class_name(kind: ImportedPackageSourceClass) -> &'static str {
    match kind {
        ImportedPackageSourceClass::RegistryRef => "registry_ref",
        ImportedPackageSourceClass::DirectUrl => "direct_url",
        ImportedPackageSourceClass::VcsUrl => "vcs_url",
        ImportedPackageSourceClass::LocalPath => "local_path",
        ImportedPackageSourceClass::RequirementFile => "requirement_file",
        ImportedPackageSourceClass::UnknownDynamic => "unknown_dynamic",
    }
}

fn interactive_escape_surface_kind_name(kind: InteractiveEscapeSurfaceKind) -> &'static str {
    match kind {
        InteractiveEscapeSurfaceKind::Pager => "pager",
        InteractiveEscapeSurfaceKind::Editor => "editor",
        InteractiveEscapeSurfaceKind::TerminalUi => "terminal_ui",
        InteractiveEscapeSurfaceKind::LineEditor => "line_editor",
        InteractiveEscapeSurfaceKind::Generic => "generic",
    }
}

fn interactive_escape_capability_name(capability: InteractiveEscapeCapability) -> &'static str {
    match capability {
        InteractiveEscapeCapability::SpawnShell => "spawn_shell",
        InteractiveEscapeCapability::RunCommand => "run_command",
        InteractiveEscapeCapability::LaunchExternalEditor => "launch_external_editor",
        InteractiveEscapeCapability::WriteBufferToPath => "write_buffer_to_path",
    }
}

fn catastrophic_shell_expansion_mode_name(
    mode: CatastrophicShellExpansionModeEvidence,
) -> &'static str {
    match mode {
        CatastrophicShellExpansionModeEvidence::Pipeline => "pipeline-concurrent",
        CatastrophicShellExpansionModeEvidence::Background => "background",
        CatastrophicShellExpansionModeEvidence::Mixed => "mixed",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CatastrophicShellExpansionModeEvidence, CatastrophicShellProcessExplosionEvidence,
        Evidence, EvidenceKind, ExecutionRiskSubtype, ImportedPackageExecutionSinkEvidence,
        ImportedPackageSourceClass, InteractiveEscapeSurfaceEvidence, NestedPayloadContextEvidence,
        NestedPayloadInputEvidence, NestedPayloadInputFragmentEvidence,
        NestedPayloadLanguageEvidence, NestedPayloadOriginEvidence, NestedPayloadParentEvidence,
        NestedPayloadSourceEvidence, NestedPayloadTruncatedEvidence,
        NestedPayloadUnresolvedEvidence, NestedPayloadUnresolvedReasonEvidence,
        OutsideWorkspacePathEvidence, PriorPathWriteEvidence, TaintedExecutionSinkEvidence,
        TaintedExecutionUnresolvedOriginEvidence, TaintedExecutionUnresolvedReasonEvidence,
    };
    use crate::{
        CommandSequenceNo, ImplicitInputSource, InteractiveEscapeCapability,
        InteractiveEscapeSurfaceKind, PackageLocatorKind, PackageManagerKind, RuleId,
        RuntimeInputSource, ShellKind,
    };
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn outside_workspace_path_evidence_captures_typed_fields() {
        let evidence = Evidence::outside_workspace_path(
            RuleId::OutsideWorkspaceStartupConfig,
            "/tmp/shared/team.rc",
            "startup_config",
            "bash",
            "/tmp/project/work",
        );

        assert_eq!(evidence.rule_id, RuleId::OutsideWorkspaceStartupConfig);
        assert_eq!(
            evidence.kind,
            EvidenceKind::OutsideWorkspacePath(OutsideWorkspacePathEvidence {
                path: "/tmp/shared/team.rc".to_string(),
                slot_name: "startup_config".to_string(),
                normalized_command_name: "bash".to_string(),
                workspace_root: "/tmp/project/work".to_string(),
            })
        );
        assert_eq!(
            evidence.summary,
            "path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project/work"
        );
    }

    #[test]
    fn outside_workspace_path_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::outside_workspace_path(
            RuleId::OutsideWorkspaceStartupConfig,
            "/tmp/shared/team.rc",
            "startup_config",
            "bash",
            "/tmp/project/work",
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "outside_workspace_startup_config",
                "kind": {
                    "kind": "outside_workspace_path",
                    "path": "/tmp/shared/team.rc",
                    "slot_name": "startup_config",
                    "normalized_command_name": "bash",
                    "workspace_root": "/tmp/project/work"
                },
                "summary": "path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project/work"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn prior_path_write_evidence_captures_typed_fields() {
        let evidence = Evidence::prior_path_write(
            RuleId::OutsideWorkspaceScriptSource,
            "/tmp/shared/build.sh",
            CommandSequenceNo::new(3),
            "echo hi > ../../shared/build.sh",
        );

        assert_eq!(evidence.rule_id, RuleId::OutsideWorkspaceScriptSource);
        assert_eq!(
            evidence.kind,
            EvidenceKind::PriorPathWrite(PriorPathWriteEvidence {
                path: "/tmp/shared/build.sh".to_string(),
                sequence_no: CommandSequenceNo::new(3),
                command: "echo hi > ../../shared/build.sh".to_string(),
            })
        );
        assert_eq!(
            evidence.summary,
            "path /tmp/shared/build.sh was previously written at sequence 3 by command echo hi > ../../shared/build.sh"
        );
    }

    #[test]
    fn imported_package_execution_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::imported_package_execution(
            ImportedPackageExecutionSinkEvidence {
                node_id: "command:sess-1:3:0".to_string(),
                sequence_no: CommandSequenceNo::new(3),
                depth: 0,
                command: "pip install git+https://example.test/pkg.git".to_string(),
                package_manager: PackageManagerKind::Pip,
                risk_subtype: ExecutionRiskSubtype::ImportedPackage,
                source_class: ImportedPackageSourceClass::VcsUrl,
                locator: "git+https://example.test/pkg.git".to_string(),
                locator_kind: PackageLocatorKind::VcsUrl,
            },
            "Pip package git+https://example.test/pkg.git (VcsUrl)",
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "imported_package_execution",
                "kind": {
                    "kind": "imported_package_execution",
                    "sink": {
                        "node_id": "command:sess-1:3:0",
                        "sequence_no": 3,
                        "depth": 0,
                        "command": "pip install git+https://example.test/pkg.git",
                        "package_manager": "pip",
                        "risk_subtype": "imported_package",
                        "source_class": "vcs_url",
                        "locator": "git+https://example.test/pkg.git",
                        "locator_kind": "vcs_url"
                    },
                    "source_summary": "Pip package git+https://example.test/pkg.git (VcsUrl)"
                },
                "summary": "imported package execution sink pip install git+https://example.test/pkg.git at sequence 3 for subtype imported_package uses vcs_url source Pip package git+https://example.test/pkg.git (VcsUrl)"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn prior_path_write_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::prior_path_write(
            RuleId::OutsideWorkspaceScriptSource,
            "/tmp/shared/build.sh",
            CommandSequenceNo::new(3),
            "echo hi > ../../shared/build.sh",
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "outside_workspace_script_source",
                "kind": {
                    "kind": "prior_path_write",
                    "path": "/tmp/shared/build.sh",
                    "sequence_no": 3,
                    "command": "echo hi > ../../shared/build.sh"
                },
                "summary": "path /tmp/shared/build.sh was previously written at sequence 3 by command echo hi > ../../shared/build.sh"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn interactive_escape_surface_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::interactive_escape_surface(
            "command:sess-1:4",
            CommandSequenceNo::new(4),
            0,
            "less README.md",
            "less",
            "interactive_read",
            InteractiveEscapeSurfaceKind::Pager,
            vec![
                InteractiveEscapeCapability::SpawnShell,
                InteractiveEscapeCapability::LaunchExternalEditor,
            ],
            true,
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "interactive_escape_surface",
                "kind": {
                    "kind": "interactive_escape_surface",
                    "node_id": "command:sess-1:4",
                    "sequence_no": 4,
                    "depth": 0,
                    "command": "less README.md",
                    "normalized_command_name": "less",
                    "form_id": "interactive_read",
                    "surface_kind": "pager",
                    "capabilities": [
                        "spawn_shell",
                        "launch_external_editor"
                    ],
                    "requires_tty": true
                },
                "summary": "command less README.md at sequence 4 opens pager interactive escape surface via less form interactive_read with capabilities [spawn_shell, launch_external_editor] and requires tty"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(
            roundtrip.kind,
            EvidenceKind::InteractiveEscapeSurface(InteractiveEscapeSurfaceEvidence {
                node_id: "command:sess-1:4".to_string(),
                sequence_no: CommandSequenceNo::new(4),
                depth: 0,
                command: "less README.md".to_string(),
                normalized_command_name: "less".to_string(),
                form_id: "interactive_read".to_string(),
                surface_kind: InteractiveEscapeSurfaceKind::Pager,
                capabilities: vec![
                    InteractiveEscapeCapability::SpawnShell,
                    InteractiveEscapeCapability::LaunchExternalEditor,
                ],
                requires_tty: true,
            })
        );
        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn catastrophic_shell_process_explosion_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::catastrophic_shell_process_explosion(
            ":",
            vec![":".to_string()],
            CatastrophicShellExpansionModeEvidence::Mixed,
            ":",
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "catastrophic_shell_process_explosion",
                "kind": {
                    "kind": "catastrophic_shell_process_explosion",
                    "trigger_function": ":",
                    "recursive_scc_members": [":"],
                    "expansion_mode": "mixed",
                    "trigger_command": ":"
                },
                "summary": "catastrophic shell process explosion via mixed recursive function expansion triggered by : through [:]"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(
            roundtrip.kind,
            EvidenceKind::CatastrophicShellProcessExplosion(
                CatastrophicShellProcessExplosionEvidence {
                    trigger_function: ":".to_string(),
                    recursive_scc_members: vec![":".to_string()],
                    expansion_mode: CatastrophicShellExpansionModeEvidence::Mixed,
                    trigger_command: ":".to_string(),
                }
            )
        );
        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn nested_payload_parsed_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::nested_payload_parsed(
            NestedPayloadContextEvidence {
                record_id: 0,
                parent_ref: NestedPayloadParentEvidence::RootCommand { command_index: 0 },
                root_command_index: 0,
                depth: 1,
                language: NestedPayloadLanguageEvidence::Bash,
                source: NestedPayloadSourceEvidence::InlineString,
                origin: NestedPayloadOriginEvidence::Parameter {
                    slot_name: "payload".to_string(),
                },
                input: NestedPayloadInputEvidence::ArgumentFragments {
                    text: "echo ok".to_string(),
                    fragments: vec![NestedPayloadInputFragmentEvidence {
                        text: "echo ok".to_string(),
                        quoted: true,
                        node_kind: "raw_string".to_string(),
                    }],
                },
            },
            ShellKind::Bash,
            1,
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "nested_payload_expansion",
                "kind": {
                    "kind": "nested_payload_parsed",
                    "context": {
                        "record_id": 0,
                        "parent_ref": {
                            "kind": "root_command",
                            "command_index": 0
                        },
                        "root_command_index": 0,
                        "depth": 1,
                        "language": "bash",
                        "source": "inline_string",
                        "origin": {
                            "kind": "parameter",
                            "slot_name": "payload"
                        },
                        "input": {
                            "kind": "argument_fragments",
                            "text": "echo ok",
                            "fragments": [
                                {
                                    "text": "echo ok",
                                    "quoted": true,
                                    "node_kind": "raw_string"
                                }
                            ]
                        }
                    },
                    "shell_kind": "bash",
                    "parsed_command_count": 1
                },
                "summary": "nested payload record 0 at depth 1 parsed as bash with 1 commands"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn nested_payload_truncated_evidence_captures_typed_fields() {
        let evidence = Evidence::nested_payload_truncated(
            NestedPayloadContextEvidence {
                record_id: 1,
                parent_ref: NestedPayloadParentEvidence::DerivedInvocation {
                    node_id: "derived:sess-1:2:0:0".to_string(),
                },
                root_command_index: 0,
                depth: 2,
                language: NestedPayloadLanguageEvidence::Sh,
                source: NestedPayloadSourceEvidence::InlineString,
                origin: NestedPayloadOriginEvidence::Parameter {
                    slot_name: "payload".to_string(),
                },
                input: NestedPayloadInputEvidence::ArgumentFragments {
                    text: "echo ok".to_string(),
                    fragments: vec![NestedPayloadInputFragmentEvidence {
                        text: "echo ok".to_string(),
                        quoted: true,
                        node_kind: "raw_string".to_string(),
                    }],
                },
            },
            1,
            1,
        );

        assert_eq!(evidence.rule_id, RuleId::NestedPayloadExpansion);
        assert_eq!(
            evidence.kind,
            EvidenceKind::NestedPayloadTruncated(NestedPayloadTruncatedEvidence {
                context: NestedPayloadContextEvidence {
                    record_id: 1,
                    parent_ref: NestedPayloadParentEvidence::DerivedInvocation {
                        node_id: "derived:sess-1:2:0:0".to_string(),
                    },
                    root_command_index: 0,
                    depth: 2,
                    language: NestedPayloadLanguageEvidence::Sh,
                    source: NestedPayloadSourceEvidence::InlineString,
                    origin: NestedPayloadOriginEvidence::Parameter {
                        slot_name: "payload".to_string(),
                    },
                    input: NestedPayloadInputEvidence::ArgumentFragments {
                        text: "echo ok".to_string(),
                        fragments: vec![NestedPayloadInputFragmentEvidence {
                            text: "echo ok".to_string(),
                            quoted: true,
                            node_kind: "raw_string".to_string(),
                        }],
                    },
                },
                max_depth: 1,
                next_candidate_count: 1,
            })
        );
    }

    #[test]
    fn nested_payload_unresolved_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::nested_payload_unresolved(
            NestedPayloadContextEvidence {
                record_id: 0,
                parent_ref: NestedPayloadParentEvidence::RootCommand { command_index: 0 },
                root_command_index: 0,
                depth: 1,
                language: NestedPayloadLanguageEvidence::Bash,
                source: NestedPayloadSourceEvidence::InlineString,
                origin: NestedPayloadOriginEvidence::Parameter {
                    slot_name: "payload".to_string(),
                },
                input: NestedPayloadInputEvidence::ArgumentFragments {
                    text: "$USER_CMD".to_string(),
                    fragments: vec![NestedPayloadInputFragmentEvidence {
                        text: "$USER_CMD".to_string(),
                        quoted: true,
                        node_kind: "double_quote".to_string(),
                    }],
                },
            },
            NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                variable_name: "USER_CMD".to_string(),
            },
            None,
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "nested_payload_expansion",
                "kind": {
                    "kind": "nested_payload_unresolved",
                    "context": {
                        "record_id": 0,
                        "parent_ref": {
                            "kind": "root_command",
                            "command_index": 0
                        },
                        "root_command_index": 0,
                        "depth": 1,
                        "language": "bash",
                        "source": "inline_string",
                        "origin": {
                            "kind": "parameter",
                            "slot_name": "payload"
                        },
                        "input": {
                            "kind": "argument_fragments",
                            "text": "$USER_CMD",
                            "fragments": [
                                {
                                    "text": "$USER_CMD",
                                    "quoted": true,
                                    "node_kind": "double_quote"
                                }
                            ]
                        }
                    },
                    "reason": {
                        "kind": "missing_binding",
                        "variable_name": "USER_CMD"
                    }
                },
                "summary": "nested payload record 0 at depth 1 could not be materialized because variable USER_CMD is missing"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
        assert_eq!(
            roundtrip.kind,
            EvidenceKind::NestedPayloadUnresolved(NestedPayloadUnresolvedEvidence {
                context: NestedPayloadContextEvidence {
                    record_id: 0,
                    parent_ref: NestedPayloadParentEvidence::RootCommand { command_index: 0 },
                    root_command_index: 0,
                    depth: 1,
                    language: NestedPayloadLanguageEvidence::Bash,
                    source: NestedPayloadSourceEvidence::InlineString,
                    origin: NestedPayloadOriginEvidence::Parameter {
                        slot_name: "payload".to_string(),
                    },
                    input: NestedPayloadInputEvidence::ArgumentFragments {
                        text: "$USER_CMD".to_string(),
                        fragments: vec![NestedPayloadInputFragmentEvidence {
                            text: "$USER_CMD".to_string(),
                            quoted: true,
                            node_kind: "double_quote".to_string(),
                        }],
                    },
                },
                reason: NestedPayloadUnresolvedReasonEvidence::MissingBinding {
                    variable_name: "USER_CMD".to_string(),
                },
                unresolved_execution_payload_subtype: None,
            })
        );
    }

    #[test]
    fn nested_payload_unresolved_runtime_input_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::nested_payload_unresolved(
            NestedPayloadContextEvidence {
                record_id: 1,
                parent_ref: NestedPayloadParentEvidence::RootCommand { command_index: 0 },
                root_command_index: 0,
                depth: 1,
                language: NestedPayloadLanguageEvidence::Bash,
                source: NestedPayloadSourceEvidence::Stdin,
                origin: NestedPayloadOriginEvidence::FormImplicitInput,
                input: NestedPayloadInputEvidence::ImplicitInput {
                    source: ImplicitInputSource::StdinPayload,
                },
            },
            NestedPayloadUnresolvedReasonEvidence::RequiresRuntimeInput {
                source: RuntimeInputSource::StdinPayload,
            },
            None,
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "nested_payload_expansion",
                "kind": {
                    "kind": "nested_payload_unresolved",
                    "context": {
                        "record_id": 1,
                        "parent_ref": {
                            "kind": "root_command",
                            "command_index": 0
                        },
                        "root_command_index": 0,
                        "depth": 1,
                        "language": "bash",
                        "source": "stdin",
                        "origin": {
                            "kind": "form_implicit_input"
                        },
                        "input": {
                            "kind": "implicit_input",
                            "source": "stdin_payload"
                        }
                    },
                    "reason": {
                        "kind": "requires_runtime_input",
                        "source": "stdin_payload"
                    }
                },
                "summary": "nested payload record 1 at depth 1 requires runtime input from stdin_payload before it can be parsed"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(roundtrip, evidence);
    }

    #[test]
    fn tainted_execution_unresolved_origin_evidence_roundtrips_through_json_contract() {
        let evidence = Evidence::tainted_execution_unresolved_origin(
            TaintedExecutionSinkEvidence {
                node_id: "command:sess-1:2".to_string(),
                sequence_no: CommandSequenceNo::new(2),
                depth: 0,
                command: r#"bash "$USER_CMD""#.to_string(),
                risk_subtypes: BTreeSet::from([ExecutionRiskSubtype::GenericPayload]),
            },
            "artifact:materialized-value:command:sess-1:2:0",
            TaintedExecutionUnresolvedReasonEvidence::UnsupportedDynamicBinding {
                variable_name: "USER_CMD".to_string(),
                repr: "$payload".to_string(),
            },
        );

        let value = serde_json::to_value(&evidence).expect("expected evidence to serialize");

        assert_eq!(
            value,
            json!({
                "rule_id": "tainted_execution",
                "kind": {
                    "kind": "tainted_execution_unresolved_origin",
                    "sink": {
                        "node_id": "command:sess-1:2",
                        "sequence_no": 2,
                        "depth": 0,
                        "command": "bash \"$USER_CMD\"",
                        "risk_subtypes": ["generic_payload"]
                    },
                    "unresolved_node_id": "artifact:materialized-value:command:sess-1:2:0",
                    "reason": {
                        "kind": "unsupported_dynamic_binding",
                        "variable_name": "USER_CMD",
                        "repr": "$payload"
                    }
                },
                "summary": "execution sink bash \"$USER_CMD\" at sequence 2 with subtypes {GenericPayload} has unresolved payload origin because variable USER_CMD is dynamically bound"
            })
        );

        let roundtrip: Evidence =
            serde_json::from_value(value).expect("expected evidence to deserialize");

        assert_eq!(
            roundtrip.kind,
            EvidenceKind::TaintedExecutionUnresolvedOrigin(
                TaintedExecutionUnresolvedOriginEvidence {
                    sink: TaintedExecutionSinkEvidence {
                        node_id: "command:sess-1:2".to_string(),
                        sequence_no: CommandSequenceNo::new(2),
                        depth: 0,
                        command: r#"bash "$USER_CMD""#.to_string(),
                        risk_subtypes: BTreeSet::from([ExecutionRiskSubtype::GenericPayload]),
                    },
                    unresolved_node_id: "artifact:materialized-value:command:sess-1:2:0"
                        .to_string(),
                    reason: TaintedExecutionUnresolvedReasonEvidence::UnsupportedDynamicBinding {
                        variable_name: "USER_CMD".to_string(),
                        repr: "$payload".to_string(),
                    },
                }
            )
        );
    }
}
