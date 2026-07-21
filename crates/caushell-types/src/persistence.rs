use serde::{Deserialize, Serialize};

use crate::{
    CheckRequest, CheckResponse, CommandSequenceNo, ExecutionSemantics, ImplicitInputSource,
    MutationScopeResolution, PathMetadataMutation, PathResolution, ProvenanceArtifact,
    ProvenanceEdgeSemantics, ResolvedMutationScopeOperation, ResolvedPathPurpose, ResolvedPathRole,
    RuntimeInputSource, RuntimeShellStateDeltaRequest, SessionAliasBinding, SessionFunctionBinding,
    SessionId, SessionSummary, SessionVariableBinding, SessionVariableValue,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasMutationAction {
    Unset,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NestedPayloadInputFragmentSnapshot {
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedInvocationOrigin {
    NestedPayload {
        nested_record_id: usize,
    },
    CommandSubstitutionBody {
        parent_node_id: String,
        token_index: usize,
        substitution_index: usize,
    },
    CommandSubstitutionMaterialization {
        parent_node_id: String,
        command_index: usize,
    },
    CommandSubstitutionAssignmentValue {
        parent_node_id: String,
        assignment_command_index: usize,
        assignment_index: usize,
        substitution_index: usize,
    },
    ProcessSubstitution {
        process_substitution_record_id: usize,
    },
    ProcessSubstitutionBody {
        parent_node_id: String,
        location_kind: String,
        outer_index: usize,
        location_subindex: usize,
        substitution_index: usize,
    },
    Dispatch {
        source_command_index: usize,
        dispatch_index: usize,
        command_slot: String,
    },
    AliasExpansion {
        source_command_index: usize,
        alias_name: String,
    },
    FunctionExpansion {
        source_command_index: usize,
        function_name: String,
    },
    ShellCommandStringPayload {
        command_index: usize,
    },
    StaticXargs {
        child_index: usize,
    },
    RecursivePayload {
        parent_node_id: String,
        command_index: usize,
    },
    PipelineSegment {
        command_index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutation {
    AddRequestAnchor {
        node_id: String,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: crate::ShellKind,
    },
    AddTopLevelCommandInvocation {
        node_id: String,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        command_index: usize,
        raw_text: String,
        cwd_before: String,
        shell_kind: crate::ShellKind,
    },
    AddShellStateReconciliationAnchor {
        node_id: String,
        sequence_no: CommandSequenceNo,
    },
    AddPathFact {
        source_node_id: String,
        node_id: String,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: String,
        normalized_command_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata_mutation: Option<PathMetadataMutation>,
        relation: SessionGraphEdgeKindSnapshot,
    },
    AddMutationScopeFact {
        source_node_id: String,
        node_id: String,
        resolution: MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: String,
        normalized_command_name: Option<String>,
        relation: SessionGraphEdgeKindSnapshot,
    },
    AddProvenanceArtifact {
        source_node_id: String,
        node_id: String,
        artifact: ProvenanceArtifact,
        relation: SessionGraphEdgeKindSnapshot,
        semantics: ProvenanceEdgeSemantics,
    },
    ReplaceProvenanceArtifact {
        node_id: String,
        artifact: ProvenanceArtifact,
    },
    AddDerivedInvocation {
        node_id: String,
        root_command_sequence_no: CommandSequenceNo,
        origin: DerivedInvocationOrigin,
        derived_command_index: usize,
        raw_text: String,
        command_name: Option<String>,
        shell_kind: crate::ShellKind,
        depth: u8,
        parent_node_id: String,
        relation_from_parent: SessionGraphEdgeKindSnapshot,
    },
    AddNestedPayload {
        node_id: String,
        root_command_sequence_no: CommandSequenceNo,
        root_command_index: usize,
        record_id: usize,
        depth: u8,
        language: String,
        source: String,
        origin_kind: String,
        origin_slot: Option<String>,
        input_kind: String,
        input_text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        input_fragments: Vec<NestedPayloadInputFragmentSnapshot>,
        input_source: Option<ImplicitInputSource>,
        resolution_kind: String,
        resolution_detail: Option<String>,
        resolution_runtime_input_source: Option<RuntimeInputSource>,
        relation_from_command: Option<SessionGraphEdgeKindSnapshot>,
        relation_from_parent: Option<SessionGraphEdgeKindSnapshot>,
        parent_node_id: Option<String>,
    },
    AddExecutionUnitFlow {
        from_node_id: String,
        to_node_id: String,
    },
    AddExecutionSemantics {
        source_node_id: String,
        node_id: String,
        semantics: ExecutionSemantics,
    },
    AddVariableBindingIntent {
        source_node_id: String,
        node_id: String,
        variable_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_input_source: Option<RuntimeInputSource>,
    },
    SetCurrentWorkingDirectory {
        path: String,
        observed_at: CommandSequenceNo,
        #[serde(
            default,
            skip_serializing_if = "crate::SessionCurrentWorkingDirectorySource::is_runtime_snapshot"
        )]
        source: crate::SessionCurrentWorkingDirectorySource,
    },
    SetPositionalParameters {
        values: Vec<SessionVariableValue>,
        observed_at: CommandSequenceNo,
    },
    ForgetPositionalParameters {
        observed_at: CommandSequenceNo,
    },
    UpsertVariableBinding {
        binding: SessionVariableBinding,
    },
    UpsertAliasBinding {
        binding: SessionAliasBinding,
    },
    UpsertFunctionBinding {
        binding: SessionFunctionBinding,
    },
    UnsetVariable {
        name: String,
        observed_at: CommandSequenceNo,
    },
    UnsetAlias {
        name: String,
        observed_at: CommandSequenceNo,
    },
    UnsetFunction {
        name: String,
        observed_at: CommandSequenceNo,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStateEffect {
    ObservedOnly {
        observed_sequence_no: CommandSequenceNo,
    },
    Committed {
        observed_sequence_no: CommandSequenceNo,
        committed_mutations: Vec<SessionMutation>,
    },
}

impl SessionStateEffect {
    pub fn observe_only(observed_sequence_no: CommandSequenceNo) -> Self {
        Self::ObservedOnly {
            observed_sequence_no,
        }
    }

    pub fn commit(
        observed_sequence_no: CommandSequenceNo,
        committed_mutations: Vec<SessionMutation>,
    ) -> Self {
        Self::Committed {
            observed_sequence_no,
            committed_mutations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEventKind {
    Check {
        request: CheckRequest,
        response: CheckResponse,
        state_effect: SessionStateEffect,
    },
    ShellStateDelta {
        request: RuntimeShellStateDeltaRequest,
        committed_mutations: Vec<SessionMutation>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub session_id: SessionId,
    pub event_index: u64,
    pub observed_at_ms: u64,
    #[serde(flatten)]
    pub kind: SessionEventKind,
}

impl SessionEvent {
    pub fn new_check(
        session_id: SessionId,
        event_index: u64,
        observed_at_ms: u64,
        request: CheckRequest,
        response: CheckResponse,
        state_effect: SessionStateEffect,
    ) -> Self {
        Self {
            session_id,
            event_index,
            observed_at_ms,
            kind: SessionEventKind::Check {
                request,
                response,
                state_effect,
            },
        }
    }

    pub fn new_shell_state_delta(
        session_id: SessionId,
        event_index: u64,
        observed_at_ms: u64,
        request: RuntimeShellStateDeltaRequest,
        committed_mutations: Vec<SessionMutation>,
    ) -> Self {
        Self {
            session_id,
            event_index,
            observed_at_ms,
            kind: SessionEventKind::ShellStateDelta {
                request,
                committed_mutations,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGraphNodeSnapshot {
    pub id: String,
    pub kind: SessionGraphNodeKindSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionGraphNodeKindSnapshot {
    RequestAnchor {
        session_id: SessionId,
        sequence_no: crate::CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: crate::ShellKind,
    },
    CommandInvocation {
        session_id: SessionId,
        sequence_no: crate::CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: crate::ShellKind,
    },
    ShellStateReconciliationAnchor {
        sequence_no: crate::CommandSequenceNo,
    },
    DerivedInvocation {
        root_command_sequence_no: crate::CommandSequenceNo,
        origin: DerivedInvocationOrigin,
        derived_command_index: usize,
        raw_text: String,
        command_name: Option<String>,
        shell_kind: crate::ShellKind,
        depth: u8,
    },
    NestedPayload {
        root_command_sequence_no: crate::CommandSequenceNo,
        root_command_index: usize,
        record_id: usize,
        depth: u8,
        language: String,
        source: String,
        origin_kind: String,
        origin_slot: Option<String>,
        input_kind: String,
        input_text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        input_fragments: Vec<NestedPayloadInputFragmentSnapshot>,
        input_source: Option<ImplicitInputSource>,
        resolution_kind: String,
        resolution_detail: Option<String>,
        resolution_runtime_input_source: Option<RuntimeInputSource>,
    },
    PathFact {
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: String,
        normalized_command_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata_mutation: Option<PathMetadataMutation>,
    },
    MutationScopeFact {
        resolution: MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: String,
        normalized_command_name: Option<String>,
    },
    ProvenanceArtifact {
        artifact: ProvenanceArtifact,
    },
    ExecutionSemantics {
        semantics: ExecutionSemantics,
    },
    VariableBindingIntent {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_input_source: Option<RuntimeInputSource>,
    },
    EnvBinding {
        name: String,
        value_repr: Option<String>,
        exported: bool,
        version: u64,
    },
    AliasBinding {
        name: String,
        body: String,
        version: u64,
    },
    AliasMutation {
        name: String,
        action: AliasMutationAction,
        version: u64,
    },
    FunctionBinding {
        name: String,
        body_repr: String,
        version: u64,
    },
    DirectoryState {
        path: String,
        version: u64,
    },
    CapabilityEvidence {
        capability: String,
        evidence_source: String,
    },
    FlowEvidence {
        flow_kind: String,
        source_kind: String,
        sink_kind: String,
    },
    DecisionRecord {
        decision: crate::Decision,
        reason_summary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGraphEdgeSnapshot {
    pub from: String,
    pub to: String,
    pub kind: SessionGraphEdgeKindSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<ProvenanceEdgeSemantics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionGraphEdgeKindSnapshot {
    Defines,
    Reads,
    Writes,
    MutatesMetadata,
    Targets,
    Consumes,
    Produces,
    Dispatches,
    ExpandsTo,
    DependsOn,
    FlowsTo,
    ChangesCwdTo,
    InheritsFrom,
    TriggeredBy,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionGraphSnapshot {
    pub nodes: Vec<SessionGraphNodeSnapshot>,
    pub edges: Vec<SessionGraphEdgeSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub session_id: SessionId,
    pub last_event_index: u64,
    pub summary: SessionSummary,
    pub graph: SessionGraphSnapshot,
}

impl SessionSnapshot {
    pub fn new(
        session_id: SessionId,
        last_event_index: u64,
        summary: SessionSummary,
        graph: SessionGraphSnapshot,
    ) -> Self {
        Self {
            session_id,
            last_event_index,
            summary,
            graph,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SessionEvent, SessionGraphEdgeKindSnapshot, SessionGraphEdgeSnapshot,
        SessionGraphNodeKindSnapshot, SessionGraphNodeSnapshot, SessionGraphSnapshot,
        SessionMutation, SessionSnapshot, SessionStateEffect,
    };
    use crate::{
        CheckRequest, CheckResponse, CommandSequenceNo, Decision, DecisionTrace,
        ExecutionPayloadMode, ExecutionSemantics, Finding, FindingEnforcementClass,
        NestedPayloadInputFragmentSnapshot, PathResolution, ResolvedPathPurpose, ResolvedPathRole,
        RuleId, RuntimeMetadata, RuntimeShellStateDeltaRequest, SessionId, SessionSummary,
        SessionVariableBinding, SessionVariableValue, ShellKind, ShellStateDelta,
        ShellStateSnapshot,
    };
    use serde_json::{Value, json};

    fn sample_request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(3),
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
        }
    }

    fn sample_runtime_metadata() -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_name: "claude_code".to_string(),
            tool_name: Some("Bash".to_string()),
            shell_runtime_capabilities: crate::ShellRuntimeCapabilities::persistent_shell(),
        }
    }

    fn sample_response() -> CheckResponse {
        CheckResponse {
            decision: Decision::Allow,
            reasons: vec![],
            decision_trace: DecisionTrace {
                findings: vec![
                    Finding::new(
                        RuleId::CatastrophicFileSystemDelete,
                        "raw block-device overwrite target /dev/sda via dd",
                    )
                    .with_enforcement_class(FindingEnforcementClass::HardDenyFloor),
                ],
                ..DecisionTrace::default()
            },
        }
    }

    fn sample_state_effect() -> SessionStateEffect {
        SessionStateEffect::commit(
            CommandSequenceNo::new(3),
            vec![
                SessionMutation::AddPathFact {
                    source_node_id: "command:sess-1:3".to_string(),
                    node_id: "resolved-path:0:script_path:/tmp/project/build.sh".to_string(),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/project/build.sh".to_string(),
                    },
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                    slot_name: "script_path".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    metadata_mutation: None,
                    relation: SessionGraphEdgeKindSnapshot::Reads,
                },
                SessionMutation::UpsertVariableBinding {
                    binding: SessionVariableBinding::new(
                        "SCRIPT",
                        SessionVariableValue::exact_scalar("build.sh"),
                        false,
                        CommandSequenceNo::new(3),
                    ),
                },
                SessionMutation::AddExecutionUnitFlow {
                    from_node_id: "pipeline-segment:sess-1:3:0".to_string(),
                    to_node_id: "pipeline-segment:sess-1:3:1".to_string(),
                },
                SessionMutation::AddExecutionSemantics {
                    source_node_id: "command:sess-1:3".to_string(),
                    node_id: "execution-semantics:command:sess-1:3".to_string(),
                    semantics: ExecutionSemantics::new("bash", "command_string")
                        .with_payload_mode(ExecutionPayloadMode::CommandString)
                        .executing_payload(),
                },
            ],
        )
    }

    #[test]
    fn session_event_roundtrips_through_json() {
        let event = SessionEvent::new_check(
            SessionId::new("sess-1"),
            7,
            1_746_000_000_000,
            sample_request(),
            sample_response(),
            sample_state_effect(),
        );

        let value = serde_json::to_value(&event).expect("expected session event to serialize");

        let expected: Value = serde_json::from_str(
            r#"{
                "session_id": "sess-1",
                "event_index": 7,
                "observed_at_ms": 1746000000000,
                "kind": "check",
                "request": {
                    "session_id": "sess-1",
                    "sequence_no": 3,
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
                },
                "response": {
                    "decision": "allow",
                    "reasons": [],
                    "decision_trace": {
                        "executed_passes": [],
                        "findings": [
                            {
                                "rule_id": "catastrophic_file_system_delete",
                                "message": "raw block-device overwrite target /dev/sda via dd",
                                "enforcement_class": "hard_deny_floor"
                            }
                        ],
                        "evidence": [],
                        "execution_units": [],
                        "derived_invocations": [],
                        "execution_unit_flows": [],
                        "nested_payloads": [],
                        "execution_semantics": [],
                        "decision_proposals": []
                    }
                },
                "state_effect": {
                    "Committed": {
                        "observed_sequence_no": 3,
                        "committed_mutations": [
                            {
                                "AddPathFact": {
                                    "source_node_id": "command:sess-1:3",
                                    "node_id": "resolved-path:0:script_path:/tmp/project/build.sh",
                                    "resolution": {
                                        "kind": "concrete",
                                        "path": "/tmp/project/build.sh"
                                    },
                                    "role": "read",
                                    "purpose": "script_source",
                                    "slot_name": "script_path",
                                    "normalized_command_name": "bash",
                                    "relation": "Reads"
                                }
                            },
                            {
                                "UpsertVariableBinding": {
                                    "binding": {
                                        "name": "SCRIPT",
                                        "value": {
                                            "ExactScalar": "build.sh"
                                        },
                                        "exported": false,
                                        "observed_at": 3
                                    }
                                }
                            },
                            {
                                "AddExecutionUnitFlow": {
                                    "from_node_id": "pipeline-segment:sess-1:3:0",
                                    "to_node_id": "pipeline-segment:sess-1:3:1"
                                }
                            },
                            {
                                "AddExecutionSemantics": {
                                    "source_node_id": "command:sess-1:3",
                                    "node_id": "execution-semantics:command:sess-1:3",
                                    "semantics": {
                                        "normalized_command_name": "bash",
                                        "form_id": "command_string",
                                        "payload_mode": "command_string",
                                        "executes_payload": true,
                                        "opens_interactive_escape_surface": false,
                                        "interactive_escape_surface_kind": null,
                                        "interactive_escape_capabilities": [],
                                        "interactive_escape_requires_tty": false,
                                        "executes_imported_package_logic": false,
                                        "loads_in_process_code": false,
                                        "in_process_code_load_kinds": [],
                                        "mutates_current_shell": false,
                                        "executes_remote_command": false,
                                        "executes_hook": false,
                                        "loads_startup_config": false,
                                        "loads_project_config": false,
                                        "loads_tool_config": false,
                                        "executes_config_defined_task": false,
                                        "dispatches_child_command": false,
                                        "controls_process": false,
                                        "process_control_action": null,
                                        "process_control_target_kind": null,
                                        "process_control_broad_target": false
                                    }
                                }
                            }
                        ]
                    }
                }
            }"#,
        )
        .expect("expected session event json fixture to parse");

        assert_eq!(value, expected);

        let roundtrip: SessionEvent =
            serde_json::from_value(value).expect("expected session event to deserialize");

        assert_eq!(roundtrip, event);
    }

    #[test]
    fn shell_state_delta_event_roundtrips_through_json() {
        let event = SessionEvent::new_shell_state_delta(
            SessionId::new("sess-1"),
            8,
            1_746_000_000_123,
            RuntimeShellStateDeltaRequest {
                session_id: SessionId::new("sess-1"),
                sequence_no: CommandSequenceNo::new(3),
                runtime: sample_runtime_metadata(),
                delta: ShellStateDelta::new().with_cwd_after("/tmp/project/subdir"),
            },
            vec![SessionMutation::SetCurrentWorkingDirectory {
                path: "/tmp/project/subdir".to_string(),
                observed_at: CommandSequenceNo::new(3),
                source: crate::SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
            }],
        );

        let value = serde_json::to_value(&event).expect("expected delta event to serialize");

        assert_eq!(
            value,
            json!({
                "session_id": "sess-1",
                "event_index": 8,
                "observed_at_ms": 1746000000123u64,
                "kind": "shell_state_delta",
                "request": {
                    "session_id": "sess-1",
                    "sequence_no": 3,
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
                        "cwd_after": "/tmp/project/subdir"
                    }
                },
                "committed_mutations": [
                    {
                        "SetCurrentWorkingDirectory": {
                            "path": "/tmp/project/subdir",
                            "observed_at": 3
                        }
                    }
                ]
            })
        );

        let roundtrip: SessionEvent =
            serde_json::from_value(value).expect("expected delta event to deserialize");

        assert_eq!(roundtrip, event);
    }

    #[test]
    fn session_state_effect_observe_only_roundtrips_through_json() {
        let value =
            serde_json::to_value(SessionStateEffect::observe_only(CommandSequenceNo::new(9)))
                .expect("expected session state effect to serialize");

        assert_eq!(
            value,
            json!({
                "ObservedOnly": {
                    "observed_sequence_no": 9
                }
            })
        );

        let roundtrip: SessionStateEffect =
            serde_json::from_value(value).expect("expected session state effect to deserialize");

        assert_eq!(
            roundtrip,
            SessionStateEffect::observe_only(CommandSequenceNo::new(9))
        );
    }

    #[test]
    fn session_mutation_set_current_working_directory_roundtrips_through_json() {
        let mutation = SessionMutation::SetCurrentWorkingDirectory {
            path: "/tmp/project/subdir".to_string(),
            observed_at: CommandSequenceNo::new(7),
            source: crate::SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
        };

        let value = serde_json::to_value(&mutation).expect("expected mutation to serialize");

        assert_eq!(
            value,
            json!({
                "SetCurrentWorkingDirectory": {
                    "path": "/tmp/project/subdir",
                    "observed_at": 7
                }
            })
        );

        let roundtrip: SessionMutation =
            serde_json::from_value(value).expect("expected mutation to deserialize");

        assert_eq!(roundtrip, mutation);
    }

    #[test]
    fn session_mutation_add_shell_state_reconciliation_anchor_roundtrips_through_json() {
        let mutation = SessionMutation::AddShellStateReconciliationAnchor {
            node_id: "shell-state-reconciliation:sess-1:7".to_string(),
            sequence_no: CommandSequenceNo::new(7),
        };

        let value = serde_json::to_value(&mutation).expect("expected mutation to serialize");

        assert_eq!(
            value,
            json!({
                "AddShellStateReconciliationAnchor": {
                    "node_id": "shell-state-reconciliation:sess-1:7",
                    "sequence_no": 7
                }
            })
        );

        let roundtrip: SessionMutation =
            serde_json::from_value(value).expect("expected mutation to deserialize");

        assert_eq!(roundtrip, mutation);
    }

    #[test]
    fn reconciliation_anchor_graph_node_roundtrips_through_json() {
        let node = SessionGraphNodeSnapshot {
            id: "shell-state-reconciliation:sess-1:7".to_string(),
            kind: SessionGraphNodeKindSnapshot::ShellStateReconciliationAnchor {
                sequence_no: CommandSequenceNo::new(7),
            },
        };

        let value = serde_json::to_value(&node).expect("expected graph node to serialize");

        assert_eq!(
            value,
            json!({
                "id": "shell-state-reconciliation:sess-1:7",
                "kind": {
                    "ShellStateReconciliationAnchor": {
                        "sequence_no": 7
                    }
                }
            })
        );

        let roundtrip: SessionGraphNodeSnapshot =
            serde_json::from_value(value).expect("expected graph node to deserialize");

        assert_eq!(roundtrip, node);
    }

    #[test]
    fn session_snapshot_roundtrips_through_json() {
        let snapshot = SessionSnapshot::new(
            SessionId::new("sess-1"),
            9,
            SessionSummary::default(),
            SessionGraphSnapshot {
                nodes: vec![
                    SessionGraphNodeSnapshot {
                        id: "command:sess-1:3".to_string(),
                        kind: SessionGraphNodeKindSnapshot::CommandInvocation {
                            session_id: SessionId::new("sess-1"),
                            sequence_no: CommandSequenceNo::new(3),
                            raw_text: "pwd".to_string(),
                            cwd_before: "/tmp/project".to_string(),
                            shell_kind: ShellKind::Bash,
                        },
                    },
                    SessionGraphNodeSnapshot {
                        id: "nested:1".to_string(),
                        kind: SessionGraphNodeKindSnapshot::NestedPayload {
                            root_command_sequence_no: CommandSequenceNo::new(3),
                            root_command_index: 0,
                            record_id: 1,
                            depth: 1,
                            language: "bash".to_string(),
                            source: "inline_string".to_string(),
                            origin_kind: "parameter".to_string(),
                            origin_slot: Some("payload".to_string()),
                            input_kind: "argument_fragments".to_string(),
                            input_text: Some("echo ok".to_string()),
                            input_fragments: vec![NestedPayloadInputFragmentSnapshot {
                                text: "echo ok".to_string(),
                                quoted: true,
                                node_kind: "raw_string".to_string(),
                            }],
                            input_source: None,
                            resolution_kind: "parsed".to_string(),
                            resolution_detail: Some("shell_kind=bash".to_string()),
                            resolution_runtime_input_source: None,
                        },
                    },
                    SessionGraphNodeSnapshot {
                        id: "execution-semantics:command:sess-1:3".to_string(),
                        kind: SessionGraphNodeKindSnapshot::ExecutionSemantics {
                            semantics: ExecutionSemantics::new("bash", "command_string")
                                .with_payload_mode(ExecutionPayloadMode::CommandString)
                                .executing_payload(),
                        },
                    },
                ],
                edges: vec![SessionGraphEdgeSnapshot {
                    from: "command:sess-1:3".to_string(),
                    to: "resolved-path:0:script_path:/tmp/project/build.sh".to_string(),
                    kind: SessionGraphEdgeKindSnapshot::Reads,
                    semantics: None,
                }],
            },
        );

        let value =
            serde_json::to_value(&snapshot).expect("expected session snapshot to serialize");
        let roundtrip: SessionSnapshot =
            serde_json::from_value(value).expect("expected session snapshot to deserialize");

        assert_eq!(roundtrip, snapshot);
    }

    #[test]
    fn nested_payload_snapshot_roundtrips_through_json() {
        let node = SessionGraphNodeSnapshot {
            id: "nested:2".to_string(),
            kind: SessionGraphNodeKindSnapshot::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(5),
                root_command_index: 1,
                record_id: 2,
                depth: 2,
                language: "bash".to_string(),
                source: "inline_string".to_string(),
                origin_kind: "parameter".to_string(),
                origin_slot: Some("payload".to_string()),
                input_kind: "argument_fragments".to_string(),
                input_text: Some("echo nested".to_string()),
                input_fragments: vec![NestedPayloadInputFragmentSnapshot {
                    text: "echo nested".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "truncated_by_depth_budget".to_string(),
                resolution_detail: Some("max_depth=2".to_string()),
                resolution_runtime_input_source: None,
            },
        };

        let value = serde_json::to_value(&node).expect("expected nested payload node to serialize");
        let roundtrip: SessionGraphNodeSnapshot =
            serde_json::from_value(value).expect("expected nested payload node to deserialize");

        assert_eq!(roundtrip, node);
    }

    #[test]
    fn execution_semantics_snapshot_roundtrips_through_json() {
        let node = SessionGraphNodeSnapshot {
            id: "execution-semantics:command:sess-1:3".to_string(),
            kind: SessionGraphNodeKindSnapshot::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "stdin_script_implicit")
                    .with_payload_mode(ExecutionPayloadMode::StdinImplicit)
                    .executing_payload(),
            },
        };

        let value =
            serde_json::to_value(&node).expect("expected execution semantics node to serialize");
        let roundtrip: SessionGraphNodeSnapshot = serde_json::from_value(value)
            .expect("expected execution semantics node to deserialize");

        assert_eq!(roundtrip, node);
    }
}
