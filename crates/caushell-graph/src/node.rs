use caushell_types::{
    AliasMutationAction, CommandSequenceNo, Decision, DerivedInvocationOrigin, ExecutionSemantics,
    ImplicitInputSource, MutationScopeResolution, NestedPayloadInputFragmentSnapshot,
    PathResolution, ProvenanceArtifact, ResolvedMutationScopeOperation, ResolvedPathPurpose,
    ResolvedPathRole, RuntimeInputSource, SessionGraphNodeKindSnapshot, SessionGraphNodeSnapshot,
    SessionId, ShellKind,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    RequestAnchor {
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: ShellKind,
    },
    CommandInvocation {
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: ShellKind,
    },
    ShellStateReconciliationAnchor {
        sequence_no: CommandSequenceNo,
    },
    DerivedInvocation {
        root_command_sequence_no: CommandSequenceNo,
        origin: DerivedInvocationOrigin,
        derived_command_index: usize,
        raw_text: String,
        command_name: Option<String>,
        shell_kind: ShellKind,
        depth: u8,
    },
    NestedPayload {
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
        metadata_mutation: Option<caushell_types::PathMetadataMutation>,
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
        decision: Decision,
        reason_summary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub id: NodeId,
    pub kind: NodeKind,
}

impl GraphNode {
    pub fn new(id: NodeId, kind: NodeKind) -> Self {
        Self { id, kind }
    }

    pub fn new_request_anchor(
        id: NodeId,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: impl Into<String>,
        cwd_before: impl Into<String>,
        shell_kind: ShellKind,
    ) -> Self {
        Self {
            id,
            kind: NodeKind::RequestAnchor {
                session_id,
                sequence_no,
                raw_text: raw_text.into(),
                cwd_before: cwd_before.into(),
                shell_kind,
            },
        }
    }

    pub fn new_command_invocation(
        id: NodeId,
        session_id: SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: impl Into<String>,
        cwd_before: impl Into<String>,
        shell_kind: ShellKind,
    ) -> Self {
        Self {
            id,
            kind: NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text: raw_text.into(),
                cwd_before: cwd_before.into(),
                shell_kind,
            },
        }
    }

    pub fn new_path_fact(
        id: NodeId,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
    ) -> Self {
        Self::new_path_fact_with_metadata_mutation(
            id,
            resolution,
            role,
            purpose,
            slot_name,
            normalized_command_name,
            None,
        )
    }

    pub fn new_path_fact_with_metadata_mutation(
        id: NodeId,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
        metadata_mutation: Option<caushell_types::PathMetadataMutation>,
    ) -> Self {
        Self {
            id,
            kind: NodeKind::PathFact {
                resolution,
                role,
                purpose,
                slot_name: slot_name.into(),
                normalized_command_name,
                metadata_mutation,
            },
        }
    }

    pub fn new_provenance_artifact(id: NodeId, artifact: ProvenanceArtifact) -> Self {
        Self {
            id,
            kind: NodeKind::ProvenanceArtifact { artifact },
        }
    }

    pub fn new_mutation_scope_fact(
        id: NodeId,
        resolution: MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: impl Into<String>,
        normalized_command_name: Option<String>,
    ) -> Self {
        Self {
            id,
            kind: NodeKind::MutationScopeFact {
                resolution,
                operation,
                slot_name: slot_name.into(),
                normalized_command_name,
            },
        }
    }
}

impl From<&GraphNode> for SessionGraphNodeSnapshot {
    fn from(node: &GraphNode) -> Self {
        let kind = match &node.kind {
            NodeKind::RequestAnchor {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => SessionGraphNodeKindSnapshot::RequestAnchor {
                session_id: session_id.clone(),
                sequence_no: *sequence_no,
                raw_text: raw_text.clone(),
                cwd_before: cwd_before.clone(),
                shell_kind: *shell_kind,
            },
            NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => SessionGraphNodeKindSnapshot::CommandInvocation {
                session_id: session_id.clone(),
                sequence_no: *sequence_no,
                raw_text: raw_text.clone(),
                cwd_before: cwd_before.clone(),
                shell_kind: *shell_kind,
            },
            NodeKind::ShellStateReconciliationAnchor { sequence_no } => {
                SessionGraphNodeKindSnapshot::ShellStateReconciliationAnchor {
                    sequence_no: *sequence_no,
                }
            }
            NodeKind::DerivedInvocation {
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
            } => SessionGraphNodeKindSnapshot::DerivedInvocation {
                root_command_sequence_no: *root_command_sequence_no,
                origin: origin.clone(),
                derived_command_index: *derived_command_index,
                raw_text: raw_text.clone(),
                command_name: command_name.clone(),
                shell_kind: *shell_kind,
                depth: *depth,
            },
            NodeKind::NestedPayload {
                root_command_sequence_no,
                root_command_index,
                record_id,
                depth,
                language,
                source,
                origin_kind,
                origin_slot,
                input_kind,
                input_text,
                input_fragments,
                input_source,
                resolution_kind,
                resolution_detail,
                resolution_runtime_input_source,
            } => SessionGraphNodeKindSnapshot::NestedPayload {
                root_command_sequence_no: *root_command_sequence_no,
                root_command_index: *root_command_index,
                record_id: *record_id,
                depth: *depth,
                language: language.clone(),
                source: source.clone(),
                origin_kind: origin_kind.clone(),
                origin_slot: origin_slot.clone(),
                input_kind: input_kind.clone(),
                input_text: input_text.clone(),
                input_fragments: input_fragments.clone(),
                input_source: input_source.clone(),
                resolution_kind: resolution_kind.clone(),
                resolution_detail: resolution_detail.clone(),
                resolution_runtime_input_source: *resolution_runtime_input_source,
            },
            NodeKind::PathFact {
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
            } => SessionGraphNodeKindSnapshot::PathFact {
                resolution: resolution.clone(),
                role: *role,
                purpose: *purpose,
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
                metadata_mutation: metadata_mutation.clone(),
            },
            NodeKind::MutationScopeFact {
                resolution,
                operation,
                slot_name,
                normalized_command_name,
            } => SessionGraphNodeKindSnapshot::MutationScopeFact {
                resolution: resolution.clone(),
                operation: *operation,
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
            },
            NodeKind::ProvenanceArtifact { artifact } => {
                SessionGraphNodeKindSnapshot::ProvenanceArtifact {
                    artifact: artifact.clone(),
                }
            }
            NodeKind::ExecutionSemantics { semantics } => {
                SessionGraphNodeKindSnapshot::ExecutionSemantics {
                    semantics: semantics.clone(),
                }
            }
            NodeKind::VariableBindingIntent {
                name,
                runtime_input_source,
            } => SessionGraphNodeKindSnapshot::VariableBindingIntent {
                name: name.clone(),
                runtime_input_source: *runtime_input_source,
            },
            NodeKind::EnvBinding {
                name,
                value_repr,
                exported,
                version,
            } => SessionGraphNodeKindSnapshot::EnvBinding {
                name: name.clone(),
                value_repr: value_repr.clone(),
                exported: *exported,
                version: *version,
            },
            NodeKind::AliasBinding {
                name,
                body,
                version,
            } => SessionGraphNodeKindSnapshot::AliasBinding {
                name: name.clone(),
                body: body.clone(),
                version: *version,
            },
            NodeKind::AliasMutation {
                name,
                action,
                version,
            } => SessionGraphNodeKindSnapshot::AliasMutation {
                name: name.clone(),
                action: *action,
                version: *version,
            },
            NodeKind::FunctionBinding {
                name,
                body_repr,
                version,
            } => SessionGraphNodeKindSnapshot::FunctionBinding {
                name: name.clone(),
                body_repr: body_repr.clone(),
                version: *version,
            },
            NodeKind::DirectoryState { path, version } => {
                SessionGraphNodeKindSnapshot::DirectoryState {
                    path: path.clone(),
                    version: *version,
                }
            }
            NodeKind::CapabilityEvidence {
                capability,
                evidence_source,
            } => SessionGraphNodeKindSnapshot::CapabilityEvidence {
                capability: capability.clone(),
                evidence_source: evidence_source.clone(),
            },
            NodeKind::FlowEvidence {
                flow_kind,
                source_kind,
                sink_kind,
            } => SessionGraphNodeKindSnapshot::FlowEvidence {
                flow_kind: flow_kind.clone(),
                source_kind: source_kind.clone(),
                sink_kind: sink_kind.clone(),
            },
            NodeKind::DecisionRecord {
                decision,
                reason_summary,
            } => SessionGraphNodeKindSnapshot::DecisionRecord {
                decision: *decision,
                reason_summary: reason_summary.clone(),
            },
        };

        Self {
            id: node.id.0.clone(),
            kind,
        }
    }
}

impl From<SessionGraphNodeSnapshot> for GraphNode {
    fn from(node: SessionGraphNodeSnapshot) -> Self {
        let kind = match node.kind {
            SessionGraphNodeKindSnapshot::RequestAnchor {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => NodeKind::RequestAnchor {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            },
            SessionGraphNodeKindSnapshot::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            },
            SessionGraphNodeKindSnapshot::ShellStateReconciliationAnchor { sequence_no } => {
                NodeKind::ShellStateReconciliationAnchor { sequence_no }
            }
            SessionGraphNodeKindSnapshot::DerivedInvocation {
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
            } => NodeKind::DerivedInvocation {
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
            },
            SessionGraphNodeKindSnapshot::NestedPayload {
                root_command_sequence_no,
                root_command_index,
                record_id,
                depth,
                language,
                source,
                origin_kind,
                origin_slot,
                input_kind,
                input_text,
                input_fragments,
                input_source,
                resolution_kind,
                resolution_detail,
                resolution_runtime_input_source,
            } => NodeKind::NestedPayload {
                root_command_sequence_no,
                root_command_index,
                record_id,
                depth,
                language,
                source,
                origin_kind,
                origin_slot,
                input_kind,
                input_text,
                input_fragments,
                input_source,
                resolution_kind,
                resolution_detail,
                resolution_runtime_input_source,
            },
            SessionGraphNodeKindSnapshot::PathFact {
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
            } => NodeKind::PathFact {
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
            },
            SessionGraphNodeKindSnapshot::MutationScopeFact {
                resolution,
                operation,
                slot_name,
                normalized_command_name,
            } => NodeKind::MutationScopeFact {
                resolution,
                operation,
                slot_name,
                normalized_command_name,
            },
            SessionGraphNodeKindSnapshot::ProvenanceArtifact { artifact } => {
                NodeKind::ProvenanceArtifact { artifact }
            }
            SessionGraphNodeKindSnapshot::ExecutionSemantics { semantics } => {
                NodeKind::ExecutionSemantics { semantics }
            }
            SessionGraphNodeKindSnapshot::VariableBindingIntent {
                name,
                runtime_input_source,
            } => NodeKind::VariableBindingIntent {
                name,
                runtime_input_source,
            },
            SessionGraphNodeKindSnapshot::EnvBinding {
                name,
                value_repr,
                exported,
                version,
            } => NodeKind::EnvBinding {
                name,
                value_repr,
                exported,
                version,
            },
            SessionGraphNodeKindSnapshot::AliasBinding {
                name,
                body,
                version,
            } => NodeKind::AliasBinding {
                name,
                body,
                version,
            },
            SessionGraphNodeKindSnapshot::AliasMutation {
                name,
                action,
                version,
            } => NodeKind::AliasMutation {
                name,
                action,
                version,
            },
            SessionGraphNodeKindSnapshot::FunctionBinding {
                name,
                body_repr,
                version,
            } => NodeKind::FunctionBinding {
                name,
                body_repr,
                version,
            },
            SessionGraphNodeKindSnapshot::DirectoryState { path, version } => {
                NodeKind::DirectoryState { path, version }
            }
            SessionGraphNodeKindSnapshot::CapabilityEvidence {
                capability,
                evidence_source,
            } => NodeKind::CapabilityEvidence {
                capability,
                evidence_source,
            },
            SessionGraphNodeKindSnapshot::FlowEvidence {
                flow_kind,
                source_kind,
                sink_kind,
            } => NodeKind::FlowEvidence {
                flow_kind,
                source_kind,
                sink_kind,
            },
            SessionGraphNodeKindSnapshot::DecisionRecord {
                decision,
                reason_summary,
            } => NodeKind::DecisionRecord {
                decision,
                reason_summary,
            },
        };

        Self {
            id: NodeId::new(node.id),
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GraphNode, NodeId, NodeKind};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode, ExecutionSemantics,
        NestedPayloadInputFragmentSnapshot, PathResolution, ResolvedPathPurpose, ResolvedPathRole,
        SessionGraphNodeSnapshot, SessionId, ShellKind,
    };

    #[test]
    fn node_id_can_be_created() {
        let id = NodeId::new("node-1");
        assert_eq!(id.0, "node-1");
    }

    #[test]
    fn graph_node_can_hold_command_invocation_payload() {
        let node = GraphNode::new(
            NodeId::new("cmd-1"),
            NodeKind::CommandInvocation {
                session_id: SessionId::new("sess-1"),
                sequence_no: CommandSequenceNo::new(1),
                raw_text: "ls -la".to_string(),
                cwd_before: "/tmp/project".to_string(),
                shell_kind: ShellKind::Bash,
            },
        );

        match node.kind {
            NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => {
                assert_eq!(node.id.0, "cmd-1");
                assert_eq!(session_id.0, "sess-1");
                assert_eq!(sequence_no, CommandSequenceNo(1));
                assert_eq!(raw_text, "ls -la");
                assert_eq!(cwd_before, "/tmp/project");
                assert_eq!(shell_kind, ShellKind::Bash);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    #[test]
    fn graph_node_helper_can_build_command_invocation() {
        let node = GraphNode::new_command_invocation(
            NodeId::new("cmd-2"),
            SessionId::new("sess-2"),
            CommandSequenceNo::new(2),
            "pwd",
            "/tmp/project",
            ShellKind::Bash,
        );

        match node.kind {
            NodeKind::CommandInvocation {
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => {
                assert_eq!(node.id.0, "cmd-2");
                assert_eq!(session_id.0, "sess-2");
                assert_eq!(sequence_no, CommandSequenceNo(2));
                assert_eq!(raw_text, "pwd");
                assert_eq!(cwd_before, "/tmp/project");
                assert_eq!(shell_kind, ShellKind::Bash);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    #[test]
    fn graph_node_helper_can_build_path_fact() {
        let node = GraphNode::new_path_fact(
            NodeId::new("path-2"),
            PathResolution::Concrete {
                path: "/tmp/project/src".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            Some("cat".to_string()),
        );

        match node.kind {
            NodeKind::PathFact {
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
            } => {
                assert_eq!(node.id.0, "path-2");
                assert_eq!(
                    resolution,
                    PathResolution::Concrete {
                        path: "/tmp/project/src".to_string()
                    }
                );
                assert_eq!(role, ResolvedPathRole::Read);
                assert_eq!(purpose, Some(ResolvedPathPurpose::GenericOperand));
                assert_eq!(slot_name, "path");
                assert_eq!(normalized_command_name, Some("cat".to_string()));
                assert_eq!(metadata_mutation, None);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }
    }

    #[test]
    fn nested_payload_node_roundtrips_through_snapshot() {
        let node = GraphNode::new(
            NodeId::new("nested:1"),
            NodeKind::NestedPayload {
                root_command_sequence_no: CommandSequenceNo::new(7),
                root_command_index: 0,
                record_id: 1,
                depth: 2,
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
        );

        let snapshot = SessionGraphNodeSnapshot::from(&node);
        let roundtrip = GraphNode::from(snapshot);

        assert_eq!(roundtrip, node);
    }

    #[test]
    fn derived_invocation_node_roundtrips_through_snapshot() {
        let node = GraphNode::new(
            NodeId::new("derived:1"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(7),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 1,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 2,
            },
        );

        let snapshot = SessionGraphNodeSnapshot::from(&node);
        let roundtrip = GraphNode::from(snapshot);

        assert_eq!(roundtrip, node);
    }

    #[test]
    fn execution_semantics_node_roundtrips_through_snapshot() {
        let node = GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:1"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload()
                    .loading_startup_config(),
            },
        );

        let snapshot = SessionGraphNodeSnapshot::from(&node);
        let roundtrip = GraphNode::from(snapshot);

        assert_eq!(roundtrip, node);
    }
}
