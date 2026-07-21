use std::collections::BTreeMap;

use caushell_graph::{Edge, EdgeKind, GraphError, GraphNode, GraphRead, NodeId, SessionGraph};
use caushell_types::{
    AliasMutationAction, CommandSequenceNo, DerivedInvocationOrigin, ExecutionSemantics,
    ImplicitInputSource, MutationScopeResolution, NestedPayloadInputFragmentSnapshot,
    PathResolution, ProvenanceArtifact, ProvenanceEdgeSemantics, ProvenanceProduceKind,
    ResolvedMutationScopeOperation, ResolvedPathPurpose, ResolvedPathRole, RuntimeInputSource,
    SessionAliasBinding, SessionCurrentWorkingDirectorySource, SessionFunctionBinding,
    SessionGraphEdgeKindSnapshot, SessionMutation, SessionSummary, SessionVariableBinding,
    SessionVariableValue, ShellRuntimeCapabilities,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PendingMutation {
    AddRequestAnchor {
        node_id: NodeId,
        session_id: caushell_types::SessionId,
        sequence_no: CommandSequenceNo,
        raw_text: String,
        cwd_before: String,
        shell_kind: caushell_types::ShellKind,
    },
    AddTopLevelCommandInvocation {
        node_id: NodeId,
        session_id: caushell_types::SessionId,
        sequence_no: CommandSequenceNo,
        command_index: usize,
        raw_text: String,
        cwd_before: String,
        shell_kind: caushell_types::ShellKind,
    },
    AddShellStateReconciliationAnchor {
        node_id: NodeId,
        sequence_no: CommandSequenceNo,
    },
    AddPathFact {
        source_node_id: NodeId,
        node_id: NodeId,
        resolution: PathResolution,
        role: ResolvedPathRole,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: String,
        normalized_command_name: Option<String>,
        relation: EdgeKind,
    },
    AddPathMetadataMutationFact {
        source_node_id: NodeId,
        node_id: NodeId,
        resolution: PathResolution,
        purpose: Option<ResolvedPathPurpose>,
        slot_name: String,
        normalized_command_name: Option<String>,
        metadata_mutation: caushell_types::PathMetadataMutation,
        relation: EdgeKind,
    },
    AddMutationScopeFact {
        source_node_id: NodeId,
        node_id: NodeId,
        resolution: MutationScopeResolution,
        operation: ResolvedMutationScopeOperation,
        slot_name: String,
        normalized_command_name: Option<String>,
        relation: EdgeKind,
    },
    AddProvenanceArtifact {
        source_node_id: NodeId,
        node_id: NodeId,
        artifact: ProvenanceArtifact,
        relation: EdgeKind,
        semantics: ProvenanceEdgeSemantics,
    },
    ReplaceProvenanceArtifact {
        node_id: NodeId,
        artifact: ProvenanceArtifact,
    },
    AddDerivedInvocation {
        node_id: NodeId,
        root_command_sequence_no: CommandSequenceNo,
        origin: DerivedInvocationOrigin,
        derived_command_index: usize,
        raw_text: String,
        command_name: Option<String>,
        shell_kind: caushell_types::ShellKind,
        depth: u8,
        parent_node_id: NodeId,
        relation_from_parent: EdgeKind,
    },
    AddNestedPayload {
        node_id: NodeId,
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
        relation_from_command: Option<EdgeKind>,
        relation_from_parent: Option<EdgeKind>,
        parent_node_id: Option<NodeId>,
    },
    AddExecutionUnitFlow {
        from_node_id: NodeId,
        to_node_id: NodeId,
    },
    AddExecutionSemantics {
        source_node_id: NodeId,
        node_id: NodeId,
        semantics: ExecutionSemantics,
    },
    AddVariableBindingIntent {
        source_node_id: NodeId,
        node_id: NodeId,
        variable_name: String,
        runtime_input_source: Option<RuntimeInputSource>,
    },
    SetCurrentWorkingDirectory {
        path: String,
        observed_at: CommandSequenceNo,
        source: SessionCurrentWorkingDirectorySource,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationGraphError {
    Graph(GraphError),
    ConflictingNode { node_id: NodeId },
}

impl std::fmt::Display for MutationGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Graph(error) => write!(f, "failed to apply graph mutation: {error:?}"),
            Self::ConflictingNode { node_id } => {
                write!(
                    f,
                    "graph mutation would overwrite conflicting node {}",
                    node_id.0
                )
            }
        }
    }
}

impl std::error::Error for MutationGraphError {}

impl From<GraphError> for MutationGraphError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GraphMutationProjection {
    pub nodes: Vec<GraphNode>,
    pub replace_nodes: Vec<GraphNode>,
    pub edges: Vec<Edge>,
}

impl PendingMutation {
    pub fn requires_graph_anchor(&self) -> bool {
        !matches!(
            self,
            Self::AddRequestAnchor { .. }
                | Self::AddTopLevelCommandInvocation { .. }
                | Self::AddShellStateReconciliationAnchor { .. }
                | Self::ReplaceProvenanceArtifact { .. }
                | Self::SetPositionalParameters { .. }
                | Self::ForgetPositionalParameters { .. }
                | Self::UpsertVariableBinding { .. }
                | Self::UnsetVariable { .. }
                | Self::UnsetFunction { .. }
        )
    }

    pub fn touches_graph(&self) -> bool {
        !matches!(
            self,
            Self::SetPositionalParameters { .. }
                | Self::ForgetPositionalParameters { .. }
                | Self::UpsertVariableBinding { .. }
                | Self::UnsetVariable { .. }
                | Self::UnsetFunction { .. }
        )
    }

    pub fn provided_graph_anchor(&self) -> Option<&NodeId> {
        match self {
            Self::AddRequestAnchor { node_id, .. } => Some(node_id),
            Self::AddShellStateReconciliationAnchor { node_id, .. } => Some(node_id),
            _ => None,
        }
    }

    pub fn apply_graph(
        &self,
        graph: &mut SessionGraph,
        command_node_id: &NodeId,
    ) -> Result<(), MutationGraphError> {
        Self::apply_graph_batch(graph, command_node_id, std::slice::from_ref(self))
    }

    pub fn validate_graph_batch(
        graph: &dyn GraphRead,
        command_node_id: &NodeId,
        mutations: &[Self],
    ) -> Result<(), MutationGraphError> {
        validate_graph_batch(graph, command_node_id, Some(command_node_id), mutations)
    }

    fn validate_graph_batch_against_actual_graph(
        graph: &dyn GraphRead,
        command_node_id: &NodeId,
        mutations: &[Self],
    ) -> Result<(), MutationGraphError> {
        validate_graph_batch(graph, command_node_id, None, mutations)
    }

    pub fn apply_graph_batch(
        graph: &mut SessionGraph,
        command_node_id: &NodeId,
        mutations: &[Self],
    ) -> Result<(), MutationGraphError> {
        Self::validate_graph_batch_against_actual_graph(graph, command_node_id, mutations)?;

        let projections = graph_projections(command_node_id, mutations);

        for projection in &projections {
            for node in &projection.nodes {
                if graph.get_node(&node.id).is_none() {
                    let _ = graph.add_node(node.clone());
                }
            }

            for node in &projection.replace_nodes {
                graph.add_node(node.clone());
            }
        }

        for projection in projections {
            for edge in projection.edges {
                graph.add_edge(edge)?;
            }
        }

        Ok(())
    }

    pub(crate) fn graph_projection(&self, command_node_id: &NodeId) -> GraphMutationProjection {
        match self {
            Self::AddRequestAnchor {
                node_id,
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_request_anchor(
                    node_id.clone(),
                    session_id.clone(),
                    *sequence_no,
                    raw_text.clone(),
                    cwd_before.clone(),
                    *shell_kind,
                )],
                ..Default::default()
            },
            Self::AddTopLevelCommandInvocation {
                node_id,
                session_id,
                sequence_no,
                command_index: _,
                raw_text,
                cwd_before,
                shell_kind,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_command_invocation(
                    node_id.clone(),
                    session_id.clone(),
                    *sequence_no,
                    raw_text.clone(),
                    cwd_before.clone(),
                    *shell_kind,
                )],
                ..Default::default()
            },
            Self::AddShellStateReconciliationAnchor {
                node_id,
                sequence_no,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new(
                    node_id.clone(),
                    caushell_graph::NodeKind::ShellStateReconciliationAnchor {
                        sequence_no: *sequence_no,
                    },
                )],
                ..Default::default()
            },
            Self::AddPathFact {
                source_node_id,
                node_id,
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                relation,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_path_fact(
                    node_id.clone(),
                    resolution.clone(),
                    *role,
                    *purpose,
                    slot_name.clone(),
                    normalized_command_name.clone(),
                )],
                edges: vec![Edge::new(
                    source_node_id.clone(),
                    node_id.clone(),
                    *relation,
                )],
                ..Default::default()
            },
            Self::AddPathMetadataMutationFact {
                source_node_id,
                node_id,
                resolution,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
                relation,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_path_fact_with_metadata_mutation(
                    node_id.clone(),
                    resolution.clone(),
                    ResolvedPathRole::MetadataMutation,
                    *purpose,
                    slot_name.clone(),
                    normalized_command_name.clone(),
                    Some(metadata_mutation.clone()),
                )],
                edges: vec![Edge::new(
                    source_node_id.clone(),
                    node_id.clone(),
                    *relation,
                )],
                ..Default::default()
            },
            Self::AddMutationScopeFact {
                source_node_id,
                node_id,
                resolution,
                operation,
                slot_name,
                normalized_command_name,
                relation,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_mutation_scope_fact(
                    node_id.clone(),
                    resolution.clone(),
                    *operation,
                    slot_name.clone(),
                    normalized_command_name.clone(),
                )],
                edges: vec![Edge::new(
                    source_node_id.clone(),
                    node_id.clone(),
                    *relation,
                )],
                ..Default::default()
            },
            Self::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact,
                relation,
                semantics,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new_provenance_artifact(
                    node_id.clone(),
                    artifact.clone(),
                )],
                edges: vec![Edge::with_semantics(
                    source_node_id.clone(),
                    node_id.clone(),
                    *relation,
                    semantics.clone(),
                )],
                ..Default::default()
            },
            Self::ReplaceProvenanceArtifact { node_id, artifact } => GraphMutationProjection {
                replace_nodes: vec![GraphNode::new_provenance_artifact(
                    node_id.clone(),
                    artifact.clone(),
                )],
                ..Default::default()
            },
            Self::AddDerivedInvocation {
                node_id,
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
                parent_node_id,
                relation_from_parent,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new(
                    node_id.clone(),
                    caushell_graph::NodeKind::DerivedInvocation {
                        root_command_sequence_no: *root_command_sequence_no,
                        origin: origin.clone(),
                        derived_command_index: *derived_command_index,
                        raw_text: raw_text.clone(),
                        command_name: command_name.clone(),
                        shell_kind: *shell_kind,
                        depth: *depth,
                    },
                )],
                edges: vec![Edge::new(
                    parent_node_id.clone(),
                    node_id.clone(),
                    *relation_from_parent,
                )],
                ..Default::default()
            },
            Self::AddNestedPayload {
                node_id,
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
                relation_from_command,
                relation_from_parent,
                parent_node_id,
            } => {
                let mut edges = Vec::new();
                if let Some(relation) = relation_from_command {
                    edges.push(Edge::new(
                        command_node_id.clone(),
                        node_id.clone(),
                        *relation,
                    ));
                }

                if let (Some(parent_node_id), Some(relation)) =
                    (parent_node_id, relation_from_parent)
                {
                    edges.push(Edge::new(
                        parent_node_id.clone(),
                        node_id.clone(),
                        *relation,
                    ));
                }

                GraphMutationProjection {
                    nodes: vec![GraphNode::new(
                        node_id.clone(),
                        caushell_graph::NodeKind::NestedPayload {
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
                    )],
                    edges,
                    ..Default::default()
                }
            }
            Self::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } => GraphMutationProjection {
                edges: vec![Edge::new(
                    from_node_id.clone(),
                    to_node_id.clone(),
                    EdgeKind::FlowsTo,
                )],
                ..Default::default()
            },
            Self::AddExecutionSemantics {
                source_node_id,
                node_id,
                semantics,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new(
                    node_id.clone(),
                    caushell_graph::NodeKind::ExecutionSemantics {
                        semantics: semantics.clone(),
                    },
                )],
                edges: vec![Edge::new(
                    source_node_id.clone(),
                    node_id.clone(),
                    EdgeKind::Defines,
                )],
                ..Default::default()
            },
            Self::AddVariableBindingIntent {
                source_node_id,
                node_id,
                variable_name,
                runtime_input_source,
            } => GraphMutationProjection {
                nodes: vec![GraphNode::new(
                    node_id.clone(),
                    caushell_graph::NodeKind::VariableBindingIntent {
                        name: variable_name.clone(),
                        runtime_input_source: *runtime_input_source,
                    },
                )],
                edges: vec![Edge::new(
                    source_node_id.clone(),
                    node_id.clone(),
                    EdgeKind::Defines,
                )],
                ..Default::default()
            },
            Self::SetCurrentWorkingDirectory {
                path, observed_at, ..
            } => {
                let node_id = directory_state_node_id(*observed_at);

                GraphMutationProjection {
                    nodes: vec![GraphNode::new(
                        node_id.clone(),
                        caushell_graph::NodeKind::DirectoryState {
                            path: path.clone(),
                            version: observed_at.0,
                        },
                    )],
                    edges: vec![Edge::with_semantics(
                        command_node_id.clone(),
                        node_id,
                        EdgeKind::ChangesCwdTo,
                        ProvenanceEdgeSemantics::Produce {
                            produce_kind: ProvenanceProduceKind::CwdState,
                            slot_name: None,
                            normalized_command_name: None,
                            domain_label: None,
                        },
                    )],
                    ..Default::default()
                }
            }
            Self::UpsertAliasBinding { binding } => {
                let node_id = alias_binding_node_id_for_binding(binding);
                GraphMutationProjection {
                    nodes: vec![GraphNode::new(
                        node_id.clone(),
                        caushell_graph::NodeKind::AliasBinding {
                            name: binding.name.clone(),
                            body: binding.body.clone(),
                            version: binding.observed_at.0,
                        },
                    )],
                    edges: vec![Edge::new(
                        command_node_id.clone(),
                        node_id,
                        EdgeKind::Defines,
                    )],
                    ..Default::default()
                }
            }
            Self::UpsertFunctionBinding { binding } => GraphMutationProjection {
                nodes: vec![GraphNode::new(
                    function_binding_node_id(&binding.name, binding.observed_at),
                    caushell_graph::NodeKind::FunctionBinding {
                        name: binding.name.clone(),
                        body_repr: binding.body.clone(),
                        version: binding.observed_at.0,
                    },
                )],
                edges: vec![Edge::new(
                    command_node_id.clone(),
                    function_binding_node_id(&binding.name, binding.observed_at),
                    EdgeKind::Defines,
                )],
                ..Default::default()
            },
            Self::UnsetAlias { name, observed_at } => {
                let node_id =
                    alias_mutation_node_id(name, *observed_at, AliasMutationAction::Unset);
                GraphMutationProjection {
                    nodes: vec![GraphNode::new(
                        node_id.clone(),
                        caushell_graph::NodeKind::AliasMutation {
                            name: name.clone(),
                            action: AliasMutationAction::Unset,
                            version: observed_at.0,
                        },
                    )],
                    edges: vec![Edge::new(
                        command_node_id.clone(),
                        node_id,
                        EdgeKind::Defines,
                    )],
                    ..Default::default()
                }
            }
            Self::UpsertVariableBinding { .. }
            | Self::SetPositionalParameters { .. }
            | Self::ForgetPositionalParameters { .. }
            | Self::UnsetVariable { .. }
            | Self::UnsetFunction { .. } => GraphMutationProjection::default(),
        }
    }

    pub fn apply_summary(&self, summary: &mut SessionSummary) {
        match self {
            Self::AddRequestAnchor { .. }
            | Self::AddTopLevelCommandInvocation { .. }
            | Self::AddShellStateReconciliationAnchor { .. }
            | Self::AddPathFact { .. }
            | Self::AddPathMetadataMutationFact { .. }
            | Self::AddMutationScopeFact { .. }
            | Self::AddProvenanceArtifact { .. }
            | Self::ReplaceProvenanceArtifact { .. }
            | Self::AddDerivedInvocation { .. }
            | Self::AddNestedPayload { .. }
            | Self::AddExecutionUnitFlow { .. }
            | Self::AddExecutionSemantics { .. }
            | Self::AddVariableBindingIntent { .. } => {}
            Self::SetCurrentWorkingDirectory {
                path,
                observed_at,
                source,
            } => {
                summary.set_current_working_directory_with_source(path, *observed_at, *source);
            }
            Self::SetPositionalParameters {
                values,
                observed_at,
            } => {
                summary.set_positional_parameters(values.clone(), *observed_at);
            }
            Self::ForgetPositionalParameters { observed_at } => {
                summary.forget_positional_parameters(*observed_at);
            }
            Self::UpsertVariableBinding { binding } => {
                summary.upsert_variable_binding(binding.clone());
            }
            Self::UpsertAliasBinding { binding } => {
                summary.upsert_alias_binding(binding.clone());
            }
            Self::UpsertFunctionBinding { binding } => {
                summary.upsert_function_binding(binding.clone());
            }
            Self::UnsetVariable { name, observed_at } => {
                summary.unset_variable(name, *observed_at);
            }
            Self::UnsetAlias { name, observed_at } => {
                summary.unset_alias(name, *observed_at);
            }
            Self::UnsetFunction { name, observed_at } => {
                summary.unset_function(name, *observed_at);
            }
        }
    }

    pub fn apply_live_summary(
        &self,
        summary: &mut SessionSummary,
        capabilities: ShellRuntimeCapabilities,
    ) {
        match self {
            Self::SetCurrentWorkingDirectory {
                path,
                observed_at,
                source,
            } => {
                if capabilities.persists_cwd {
                    summary.set_current_working_directory_with_source(path, *observed_at, *source);
                }
            }
            Self::SetPositionalParameters {
                values,
                observed_at,
            } => {
                if capabilities.persists_positionals {
                    summary.set_positional_parameters(values.clone(), *observed_at);
                }
            }
            Self::ForgetPositionalParameters { observed_at } => {
                if capabilities.persists_positionals {
                    summary.forget_positional_parameters(*observed_at);
                }
            }
            Self::UpsertVariableBinding { binding } => {
                if capabilities.persists_variable(binding.exported) {
                    summary.upsert_variable_binding(binding.clone());
                }
            }
            Self::UpsertAliasBinding { binding } => {
                if capabilities.persists_aliases {
                    summary.upsert_alias_binding(binding.clone());
                }
            }
            Self::UpsertFunctionBinding { binding } => {
                if capabilities.persists_functions {
                    summary.upsert_function_binding(binding.clone());
                }
            }
            Self::UnsetVariable { name, observed_at } => {
                if capabilities.persists_variables || capabilities.persists_exported_environment {
                    summary.unset_variable(name, *observed_at);
                }
            }
            Self::UnsetAlias { name, observed_at } => {
                if capabilities.persists_aliases {
                    summary.unset_alias(name, *observed_at);
                }
            }
            Self::UnsetFunction { name, observed_at } => {
                if capabilities.persists_functions {
                    summary.unset_function(name, *observed_at);
                }
            }
            _ => self.apply_summary(summary),
        }
    }

    pub fn to_session_mutation(&self) -> SessionMutation {
        match self {
            Self::AddRequestAnchor {
                node_id,
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => SessionMutation::AddRequestAnchor {
                node_id: node_id.0.clone(),
                session_id: session_id.clone(),
                sequence_no: *sequence_no,
                raw_text: raw_text.clone(),
                cwd_before: cwd_before.clone(),
                shell_kind: *shell_kind,
            },
            Self::AddTopLevelCommandInvocation {
                node_id,
                session_id,
                sequence_no,
                command_index,
                raw_text,
                cwd_before,
                shell_kind,
            } => SessionMutation::AddTopLevelCommandInvocation {
                node_id: node_id.0.clone(),
                session_id: session_id.clone(),
                sequence_no: *sequence_no,
                command_index: *command_index,
                raw_text: raw_text.clone(),
                cwd_before: cwd_before.clone(),
                shell_kind: *shell_kind,
            },
            Self::AddShellStateReconciliationAnchor {
                node_id,
                sequence_no,
            } => SessionMutation::AddShellStateReconciliationAnchor {
                node_id: node_id.0.clone(),
                sequence_no: *sequence_no,
            },
            Self::AddPathFact {
                source_node_id,
                node_id,
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                relation,
            } => SessionMutation::AddPathFact {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                resolution: resolution.clone(),
                role: *role,
                purpose: *purpose,
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
                metadata_mutation: None,
                relation: SessionGraphEdgeKindSnapshot::from(*relation),
            },
            Self::AddPathMetadataMutationFact {
                source_node_id,
                node_id,
                resolution,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
                relation,
            } => SessionMutation::AddPathFact {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                resolution: resolution.clone(),
                role: ResolvedPathRole::MetadataMutation,
                purpose: *purpose,
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
                metadata_mutation: Some(metadata_mutation.clone()),
                relation: SessionGraphEdgeKindSnapshot::from(*relation),
            },
            Self::AddMutationScopeFact {
                source_node_id,
                node_id,
                resolution,
                operation,
                slot_name,
                normalized_command_name,
                relation,
            } => SessionMutation::AddMutationScopeFact {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                resolution: resolution.clone(),
                operation: *operation,
                slot_name: slot_name.clone(),
                normalized_command_name: normalized_command_name.clone(),
                relation: SessionGraphEdgeKindSnapshot::from(*relation),
            },
            Self::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact,
                relation,
                semantics,
            } => SessionMutation::AddProvenanceArtifact {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                artifact: artifact.clone(),
                relation: SessionGraphEdgeKindSnapshot::from(*relation),
                semantics: semantics.clone(),
            },
            Self::ReplaceProvenanceArtifact { node_id, artifact } => {
                SessionMutation::ReplaceProvenanceArtifact {
                    node_id: node_id.0.clone(),
                    artifact: artifact.clone(),
                }
            }
            Self::AddDerivedInvocation {
                node_id,
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
                parent_node_id,
                relation_from_parent,
            } => SessionMutation::AddDerivedInvocation {
                node_id: node_id.0.clone(),
                root_command_sequence_no: *root_command_sequence_no,
                origin: origin.clone(),
                derived_command_index: *derived_command_index,
                raw_text: raw_text.clone(),
                command_name: command_name.clone(),
                shell_kind: *shell_kind,
                depth: *depth,
                parent_node_id: parent_node_id.0.clone(),
                relation_from_parent: SessionGraphEdgeKindSnapshot::from(*relation_from_parent),
            },
            Self::AddNestedPayload {
                node_id,
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
                relation_from_command,
                relation_from_parent,
                parent_node_id,
            } => SessionMutation::AddNestedPayload {
                node_id: node_id.0.clone(),
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
                relation_from_command: relation_from_command
                    .map(SessionGraphEdgeKindSnapshot::from),
                relation_from_parent: relation_from_parent.map(SessionGraphEdgeKindSnapshot::from),
                parent_node_id: parent_node_id.as_ref().map(|id| id.0.clone()),
            },
            Self::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } => SessionMutation::AddExecutionUnitFlow {
                from_node_id: from_node_id.0.clone(),
                to_node_id: to_node_id.0.clone(),
            },
            Self::AddExecutionSemantics {
                source_node_id,
                node_id,
                semantics,
            } => SessionMutation::AddExecutionSemantics {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                semantics: semantics.clone(),
            },
            Self::AddVariableBindingIntent {
                source_node_id,
                node_id,
                variable_name,
                runtime_input_source,
            } => SessionMutation::AddVariableBindingIntent {
                source_node_id: source_node_id.0.clone(),
                node_id: node_id.0.clone(),
                variable_name: variable_name.clone(),
                runtime_input_source: *runtime_input_source,
            },
            Self::SetCurrentWorkingDirectory {
                path,
                observed_at,
                source,
            } => SessionMutation::SetCurrentWorkingDirectory {
                path: path.clone(),
                observed_at: *observed_at,
                source: *source,
            },
            Self::SetPositionalParameters {
                values,
                observed_at,
            } => SessionMutation::SetPositionalParameters {
                values: values.clone(),
                observed_at: *observed_at,
            },
            Self::ForgetPositionalParameters { observed_at } => {
                SessionMutation::ForgetPositionalParameters {
                    observed_at: *observed_at,
                }
            }
            Self::UpsertVariableBinding { binding } => SessionMutation::UpsertVariableBinding {
                binding: binding.clone(),
            },
            Self::UpsertAliasBinding { binding } => SessionMutation::UpsertAliasBinding {
                binding: binding.clone(),
            },
            Self::UpsertFunctionBinding { binding } => SessionMutation::UpsertFunctionBinding {
                binding: binding.clone(),
            },
            Self::UnsetVariable { name, observed_at } => SessionMutation::UnsetVariable {
                name: name.clone(),
                observed_at: *observed_at,
            },
            Self::UnsetAlias { name, observed_at } => SessionMutation::UnsetAlias {
                name: name.clone(),
                observed_at: *observed_at,
            },
            Self::UnsetFunction { name, observed_at } => SessionMutation::UnsetFunction {
                name: name.clone(),
                observed_at: *observed_at,
            },
        }
    }

    pub fn from_session_mutation(mutation: SessionMutation) -> Self {
        match mutation {
            SessionMutation::AddRequestAnchor {
                node_id,
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            } => Self::AddRequestAnchor {
                node_id: NodeId::new(node_id),
                session_id,
                sequence_no,
                raw_text,
                cwd_before,
                shell_kind,
            },
            SessionMutation::AddTopLevelCommandInvocation {
                node_id,
                session_id,
                sequence_no,
                command_index,
                raw_text,
                cwd_before,
                shell_kind,
            } => Self::AddTopLevelCommandInvocation {
                node_id: NodeId::new(node_id),
                session_id,
                sequence_no,
                command_index,
                raw_text,
                cwd_before,
                shell_kind,
            },
            SessionMutation::AddShellStateReconciliationAnchor {
                node_id,
                sequence_no,
            } => Self::AddShellStateReconciliationAnchor {
                node_id: NodeId::new(node_id),
                sequence_no,
            },
            SessionMutation::AddPathFact {
                source_node_id,
                node_id,
                resolution,
                role,
                purpose,
                slot_name,
                normalized_command_name,
                metadata_mutation,
                relation,
            } => match metadata_mutation {
                Some(metadata_mutation) => Self::AddPathMetadataMutationFact {
                    source_node_id: NodeId::new(source_node_id),
                    node_id: NodeId::new(node_id),
                    resolution,
                    purpose,
                    slot_name,
                    normalized_command_name,
                    metadata_mutation,
                    relation: EdgeKind::from(relation),
                },
                None => Self::AddPathFact {
                    source_node_id: NodeId::new(source_node_id),
                    node_id: NodeId::new(node_id),
                    resolution,
                    role,
                    purpose,
                    slot_name,
                    normalized_command_name,
                    relation: EdgeKind::from(relation),
                },
            },
            SessionMutation::AddMutationScopeFact {
                source_node_id,
                node_id,
                resolution,
                operation,
                slot_name,
                normalized_command_name,
                relation,
            } => Self::AddMutationScopeFact {
                source_node_id: NodeId::new(source_node_id),
                node_id: NodeId::new(node_id),
                resolution,
                operation,
                slot_name,
                normalized_command_name,
                relation: EdgeKind::from(relation),
            },
            SessionMutation::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact,
                relation,
                semantics,
            } => Self::AddProvenanceArtifact {
                source_node_id: NodeId::new(source_node_id),
                node_id: NodeId::new(node_id),
                artifact,
                relation: EdgeKind::from(relation),
                semantics,
            },
            SessionMutation::ReplaceProvenanceArtifact { node_id, artifact } => {
                Self::ReplaceProvenanceArtifact {
                    node_id: NodeId::new(node_id),
                    artifact,
                }
            }
            SessionMutation::AddDerivedInvocation {
                node_id,
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
                parent_node_id,
                relation_from_parent,
            } => Self::AddDerivedInvocation {
                node_id: NodeId::new(node_id),
                root_command_sequence_no,
                origin,
                derived_command_index,
                raw_text,
                command_name,
                shell_kind,
                depth,
                parent_node_id: NodeId::new(parent_node_id),
                relation_from_parent: EdgeKind::from(relation_from_parent),
            },
            SessionMutation::AddNestedPayload {
                node_id,
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
                relation_from_command,
                relation_from_parent,
                parent_node_id,
            } => Self::AddNestedPayload {
                node_id: NodeId::new(node_id),
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
                relation_from_command: relation_from_command.map(EdgeKind::from),
                relation_from_parent: relation_from_parent.map(EdgeKind::from),
                parent_node_id: parent_node_id.map(NodeId::new),
            },
            SessionMutation::AddExecutionUnitFlow {
                from_node_id,
                to_node_id,
            } => Self::AddExecutionUnitFlow {
                from_node_id: NodeId::new(from_node_id),
                to_node_id: NodeId::new(to_node_id),
            },
            SessionMutation::AddExecutionSemantics {
                source_node_id,
                node_id,
                semantics,
            } => Self::AddExecutionSemantics {
                source_node_id: NodeId::new(source_node_id),
                node_id: NodeId::new(node_id),
                semantics,
            },
            SessionMutation::AddVariableBindingIntent {
                source_node_id,
                node_id,
                variable_name,
                runtime_input_source,
            } => Self::AddVariableBindingIntent {
                source_node_id: NodeId::new(source_node_id),
                node_id: NodeId::new(node_id),
                variable_name,
                runtime_input_source,
            },
            SessionMutation::SetCurrentWorkingDirectory {
                path,
                observed_at,
                source,
            } => Self::SetCurrentWorkingDirectory {
                path,
                observed_at,
                source,
            },
            SessionMutation::SetPositionalParameters {
                values,
                observed_at,
            } => Self::SetPositionalParameters {
                values,
                observed_at,
            },
            SessionMutation::ForgetPositionalParameters { observed_at } => {
                Self::ForgetPositionalParameters { observed_at }
            }
            SessionMutation::UpsertVariableBinding { binding } => {
                Self::UpsertVariableBinding { binding }
            }
            SessionMutation::UnsetVariable { name, observed_at } => {
                Self::UnsetVariable { name, observed_at }
            }
            SessionMutation::UpsertAliasBinding { binding } => Self::UpsertAliasBinding { binding },
            SessionMutation::UnsetAlias { name, observed_at } => {
                Self::UnsetAlias { name, observed_at }
            }
            SessionMutation::UpsertFunctionBinding { binding } => {
                Self::UpsertFunctionBinding { binding }
            }
            SessionMutation::UnsetFunction { name, observed_at } => {
                Self::UnsetFunction { name, observed_at }
            }
        }
    }
}

fn function_binding_node_id(name: &str, observed_at: caushell_types::CommandSequenceNo) -> NodeId {
    NodeId::new(format!("function-binding:{name}:{}", observed_at.0))
}

fn alias_binding_node_id_for_binding(binding: &SessionAliasBinding) -> NodeId {
    NodeId::new(format!(
        "alias-binding:{}:{}:{:016x}",
        binding.name,
        binding.observed_at.0,
        stable_str_fingerprint(&binding.name, &binding.body)
    ))
}

fn alias_mutation_node_id(
    name: &str,
    observed_at: caushell_types::CommandSequenceNo,
    action: AliasMutationAction,
) -> NodeId {
    let action = match action {
        AliasMutationAction::Unset => "unset",
    };

    NodeId::new(format!("alias-mutation:{name}:{action}:{}", observed_at.0))
}

fn directory_state_node_id(observed_at: caushell_types::CommandSequenceNo) -> NodeId {
    NodeId::new(format!("cwd-state:{}", observed_at.0))
}

fn stable_str_fingerprint(left: &str, right: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in left.bytes().chain([0]).chain(right.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn validate_graph_batch(
    graph: &dyn GraphRead,
    command_node_id: &NodeId,
    virtual_command_node_id: Option<&NodeId>,
    mutations: &[PendingMutation],
) -> Result<(), MutationGraphError> {
    let projections = graph_projections(command_node_id, mutations);
    let mut available_nodes: BTreeMap<NodeId, Option<GraphNode>> = BTreeMap::new();

    if let Some(command_node_id) = virtual_command_node_id {
        available_nodes
            .entry(command_node_id.clone())
            .or_insert(None);
    }

    let node_exists =
        |node_id: &NodeId, available_nodes: &BTreeMap<NodeId, Option<GraphNode>>| -> bool {
            available_nodes.contains_key(node_id) || graph.get_node(node_id).is_some()
        };

    for projection in &projections {
        for node in &projection.nodes {
            if let Some(entry) = available_nodes.get(&node.id) {
                match entry {
                    Some(existing) if existing == node => {}
                    None => {
                        available_nodes.insert(node.id.clone(), Some(node.clone()));
                    }
                    Some(_) => {
                        return Err(MutationGraphError::ConflictingNode {
                            node_id: node.id.clone(),
                        });
                    }
                }
                continue;
            }

            match graph.get_node(&node.id) {
                Some(existing) if existing == node => {}
                Some(_) => {
                    return Err(MutationGraphError::ConflictingNode {
                        node_id: node.id.clone(),
                    });
                }
                None => {
                    available_nodes.insert(node.id.clone(), Some(node.clone()));
                }
            }
        }

        for node in &projection.replace_nodes {
            let existing = available_nodes
                .get(&node.id)
                .and_then(|entry| entry.as_ref())
                .or_else(|| graph.get_node(&node.id));

            match existing {
                Some(existing) => match (&existing.kind, &node.kind) {
                    (
                        caushell_graph::NodeKind::ProvenanceArtifact { .. },
                        caushell_graph::NodeKind::ProvenanceArtifact { .. },
                    ) => {
                        available_nodes.insert(node.id.clone(), Some(node.clone()));
                    }
                    _ => {
                        return Err(MutationGraphError::ConflictingNode {
                            node_id: node.id.clone(),
                        });
                    }
                },
                None => {
                    return Err(MutationGraphError::ConflictingNode {
                        node_id: node.id.clone(),
                    });
                }
            }
        }
    }

    for projection in &projections {
        for edge in &projection.edges {
            if !node_exists(&edge.from, &available_nodes) {
                return Err(GraphError::MissingSourceNode(edge.from.clone()).into());
            }

            if !node_exists(&edge.to, &available_nodes) {
                return Err(GraphError::MissingTargetNode(edge.to.clone()).into());
            }
        }
    }

    Ok(())
}

fn graph_projections(
    command_node_id: &NodeId,
    mutations: &[PendingMutation],
) -> Vec<GraphMutationProjection> {
    let implicit_state_source_node_id = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            PendingMutation::AddTopLevelCommandInvocation {
                node_id,
                command_index,
                ..
            } if *command_index == 0 => Some(node_id),
            _ => None,
        })
        .next()
        .unwrap_or(command_node_id);

    mutations
        .iter()
        .map(|mutation| mutation.graph_projection(implicit_state_source_node_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{MutationGraphError, PendingMutation};
    use caushell_graph::{
        Edge, EdgeKind, GraphError, GraphNode, GraphRead, NodeId, NodeKind, SessionGraph,
    };
    use caushell_types::{
        AliasMutationAction, CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode,
        ExecutionSemantics, MutationScopeResolution, NestedPayloadInputFragmentSnapshot,
        PathResolution, ProvenanceEdgeSemantics, ProvenanceProduceKind, RepositoryWorktreePathSet,
        RepositoryWorktreeScopeResolution, ResolvedMutationScopeOperation, ResolvedPathPurpose,
        ResolvedPathRole, SessionAliasBinding, SessionCurrentWorkingDirectorySource,
        SessionFunctionBinding, SessionGraphEdgeKindSnapshot, SessionId, SessionMutation,
        SessionSummary, SessionVariableBinding, SessionVariableValue, ShellKind,
    };

    #[test]
    fn add_path_fact_mutation_creates_path_node_and_command_edge() {
        let mutation = PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:1");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "cat ./README.md",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.edges()[0].from, command_node_id);
        assert_eq!(graph.edges()[0].to, NodeId::new("path-1"));
        assert_eq!(graph.edges()[0].kind, EdgeKind::Reads);
        assert!(summary.variable_binding("SCRIPT").is_none());
    }

    #[test]
    fn upsert_variable_binding_mutation_only_touches_summary() {
        let mutation = PendingMutation::UpsertVariableBinding {
            binding: SessionVariableBinding::new(
                "SCRIPT",
                SessionVariableValue::exact_scalar("build.sh"),
                false,
                CommandSequenceNo::new(4),
            ),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:1");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "export SCRIPT=build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);

        let binding = summary
            .variable_binding("SCRIPT")
            .expect("expected SCRIPT binding to exist");

        assert_eq!(binding.name, "SCRIPT");
        assert_eq!(
            binding.value,
            SessionVariableValue::ExactScalar("build.sh".to_string())
        );
        assert_eq!(binding.observed_at, CommandSequenceNo::new(4));
    }

    #[test]
    fn set_positional_parameters_mutation_only_touches_summary() {
        let mutation = PendingMutation::SetPositionalParameters {
            values: vec![SessionVariableValue::exact_scalar("/")],
            observed_at: CommandSequenceNo::new(4),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:4");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "set -- /",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);

        let positional = summary
            .positional_parameters()
            .expect("expected positional parameters to exist");
        assert_eq!(
            positional.values,
            vec![SessionVariableValue::ExactScalar("/".to_string())]
        );
        assert_eq!(positional.observed_at, CommandSequenceNo::new(4));
    }

    #[test]
    fn forget_positional_parameters_mutation_clears_summary_state() {
        let mut summary = SessionSummary::new();
        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/")],
            CommandSequenceNo::new(3),
        );

        let mutation = PendingMutation::ForgetPositionalParameters {
            observed_at: CommandSequenceNo::new(4),
        };

        mutation.apply_summary(&mut summary);

        assert!(summary.positional_parameters().is_none());
        assert_eq!(
            summary.positional_parameters_observed_at(),
            Some(CommandSequenceNo::new(4))
        );
    }

    #[test]
    fn upsert_alias_binding_mutation_commits_binding_node_and_summary() {
        let mutation = PendingMutation::UpsertAliasBinding {
            binding: SessionAliasBinding::new(
                "runbuild",
                "bash ./scripts/build.sh",
                CommandSequenceNo::new(4),
            ),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:4");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "alias runbuild='bash ./scripts/build.sh'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .nodes()
            .find(|node| {
                matches!(
                    &node.kind,
                    NodeKind::AliasBinding { name, body, version }
                        if name == "runbuild"
                            && body == "bash ./scripts/build.sh"
                            && *version == 4
                )
            })
            .expect("expected alias binding node");
        match &node.kind {
            NodeKind::AliasBinding {
                name,
                body,
                version,
            } => {
                assert_eq!(name, "runbuild");
                assert_eq!(body, "bash ./scripts/build.sh");
                assert_eq!(*version, 4);
            }
            other => panic!("expected alias binding node, got {other:?}"),
        }
        assert!(graph.edges().iter().any(|edge| {
            edge.from == command_node_id && edge.to == node.id && edge.kind == EdgeKind::Defines
        }));

        let binding = summary
            .alias_binding("runbuild")
            .expect("expected runbuild binding to exist");
        assert_eq!(binding.body, "bash ./scripts/build.sh");
        assert_eq!(binding.observed_at, CommandSequenceNo::new(4));
    }

    #[test]
    fn multiple_alias_definitions_in_one_command_get_distinct_graph_nodes() {
        let mutations = vec![
            PendingMutation::UpsertAliasBinding {
                binding: SessionAliasBinding::new(
                    "runbuild",
                    "echo first",
                    CommandSequenceNo::new(4),
                ),
            },
            PendingMutation::UpsertAliasBinding {
                binding: SessionAliasBinding::new(
                    "runbuild",
                    "echo second",
                    CommandSequenceNo::new(4),
                ),
            },
        ];

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:4");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "alias runbuild='echo first' runbuild='echo second'",
            "/tmp/project",
            ShellKind::Bash,
        );

        PendingMutation::apply_graph_batch(&mut graph, &command_node_id, mutations.as_slice())
            .expect("expected repeated alias graph mutations to apply");

        let alias_nodes: Vec<_> = graph
            .nodes()
            .filter(|node| {
                matches!(
                    &node.kind,
                    NodeKind::AliasBinding { name, version, .. }
                        if name == "runbuild" && *version == 4
                )
            })
            .collect();

        assert_eq!(alias_nodes.len(), 2);
        assert_ne!(alias_nodes[0].id, alias_nodes[1].id);
    }

    #[test]
    fn upsert_function_binding_mutation_commits_binding_node_and_summary() {
        let mutation = PendingMutation::UpsertFunctionBinding {
            binding: SessionFunctionBinding::new(
                "deploy",
                "bash ./scripts/deploy.sh;",
                CommandSequenceNo::new(4),
            ),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:4");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "deploy() { bash ./scripts/deploy.sh; }",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("function-binding:deploy:4"))
            .expect("expected function binding node");
        match &node.kind {
            NodeKind::FunctionBinding {
                name,
                body_repr,
                version,
            } => {
                assert_eq!(name, "deploy");
                assert_eq!(body_repr, "bash ./scripts/deploy.sh;");
                assert_eq!(*version, 4);
            }
            other => panic!("expected function binding node, got {other:?}"),
        }
        assert!(graph.edges().iter().any(|edge| {
            edge.from == command_node_id
                && edge.to == NodeId::new("function-binding:deploy:4")
                && edge.kind == EdgeKind::Defines
        }));

        let binding = summary
            .function_binding("deploy")
            .expect("expected deploy binding to exist");
        assert_eq!(binding.body, "bash ./scripts/deploy.sh;");
        assert_eq!(binding.observed_at, CommandSequenceNo::new(4));
    }

    #[test]
    fn unset_variable_mutation_removes_summary_binding() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(2));

        let mutation = PendingMutation::UnsetVariable {
            name: "SCRIPT".to_string(),
            observed_at: CommandSequenceNo::new(5),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:1");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "unset SCRIPT",
            "/tmp/project",
            ShellKind::Bash,
        );

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
        assert!(summary.variable_binding("SCRIPT").is_none());
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(5)));
    }

    #[test]
    fn unset_alias_mutation_commits_mutation_node_and_removes_summary_binding() {
        let mut summary = SessionSummary::new();
        summary.upsert_alias_binding(SessionAliasBinding::new(
            "runbuild",
            "bash ./scripts/build.sh",
            CommandSequenceNo::new(2),
        ));

        let mutation = PendingMutation::UnsetAlias {
            name: "runbuild".to_string(),
            observed_at: CommandSequenceNo::new(5),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:5");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(5),
            "unalias runbuild",
            "/tmp/project",
            ShellKind::Bash,
        );

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("alias-mutation:runbuild:unset:5"))
            .expect("expected alias mutation node");
        match &node.kind {
            NodeKind::AliasMutation {
                name,
                action,
                version,
            } => {
                assert_eq!(name, "runbuild");
                assert_eq!(*action, AliasMutationAction::Unset);
                assert_eq!(*version, 5);
            }
            other => panic!("expected alias mutation node, got {other:?}"),
        }
        assert!(graph.edges().iter().any(|edge| {
            edge.from == command_node_id
                && edge.to == NodeId::new("alias-mutation:runbuild:unset:5")
                && edge.kind == EdgeKind::Defines
        }));

        assert!(summary.alias_binding("runbuild").is_none());
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(5)));
    }

    #[test]
    fn pending_mutation_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project/build.sh".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::ScriptSource),
            slot_name: "script_path".to_string(),
            normalized_command_name: Some("bash".to_string()),
            relation: EdgeKind::Reads,
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddPathFact {
                source_node_id: "command:sess-1:1".to_string(),
                node_id: "path-1".to_string(),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project/build.sh".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::ScriptSource),
                slot_name: "script_path".to_string(),
                normalized_command_name: Some("bash".to_string()),
                metadata_mutation: None,
                relation: SessionGraphEdgeKindSnapshot::Reads,
            }
        );

        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn mutation_scope_fact_mutation_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddMutationScopeFact {
            source_node_id: NodeId::new("command:sess-1:2"),
            node_id: NodeId::new("mutation-scope:command:sess-1:2:0:0:repository_worktree"),
            resolution: MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                path_set: RepositoryWorktreePathSet::Tracked,
                scope: RepositoryWorktreeScopeResolution::WholeWorktree,
            },
            operation: ResolvedMutationScopeOperation::Write,
            slot_name: "repository_worktree".to_string(),
            normalized_command_name: Some("git".to_string()),
            relation: EdgeKind::Writes,
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddMutationScopeFact {
                source_node_id: "command:sess-1:2".to_string(),
                node_id: "mutation-scope:command:sess-1:2:0:0:repository_worktree".to_string(),
                resolution: MutationScopeResolution::RepositoryWorktree {
                    root: PathResolution::Concrete {
                        path: "/tmp/project".to_string(),
                    },
                    path_set: RepositoryWorktreePathSet::Tracked,
                    scope: RepositoryWorktreeScopeResolution::WholeWorktree,
                },
                operation: ResolvedMutationScopeOperation::Write,
                slot_name: "repository_worktree".to_string(),
                normalized_command_name: Some("git".to_string()),
                relation: SessionGraphEdgeKindSnapshot::Writes,
            }
        );

        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_execution_unit_flow_mutation_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddExecutionUnitFlow {
            from_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
            to_node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddExecutionUnitFlow {
                from_node_id: "pipeline-segment:sess-1:3:0".to_string(),
                to_node_id: "pipeline-segment:sess-1:3:1".to_string(),
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_execution_unit_flow_mutation_creates_flow_edge() {
        let mutation = PendingMutation::AddExecutionUnitFlow {
            from_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
            to_node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:3");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "cat payload.sh | bash",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(caushell_graph::GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:3:0"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: caushell_types::DerivedInvocationOrigin::PipelineSegment {
                    command_index: 0,
                },
                derived_command_index: 0,
                raw_text: "cat payload.sh".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = graph.add_node(caushell_graph::GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:3:1"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: caushell_types::DerivedInvocationOrigin::PipelineSegment {
                    command_index: 1,
                },
                derived_command_index: 1,
                raw_text: "bash".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        assert_eq!(
            graph.edges().last().expect("expected flow edge").kind,
            EdgeKind::FlowsTo
        );
        assert_eq!(
            graph.edges().last().expect("expected flow edge").from,
            NodeId::new("pipeline-segment:sess-1:3:0")
        );
        assert_eq!(
            graph.edges().last().expect("expected flow edge").to,
            NodeId::new("pipeline-segment:sess-1:3:1")
        );
        assert_eq!(summary.last_sequence_no(), None);
    }

    #[test]
    fn add_execution_semantics_mutation_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddExecutionSemantics {
            source_node_id: NodeId::new("command:sess-1:3"),
            node_id: NodeId::new("execution-semantics:command:sess-1:3"),
            semantics: ExecutionSemantics::new("bash", "command_string")
                .with_payload_mode(ExecutionPayloadMode::CommandString)
                .executing_payload()
                .loading_startup_config(),
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddExecutionSemantics {
                source_node_id: "command:sess-1:3".to_string(),
                node_id: "execution-semantics:command:sess-1:3".to_string(),
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload()
                    .loading_startup_config(),
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_execution_semantics_mutation_creates_semantics_node_and_edge() {
        let mutation = PendingMutation::AddExecutionSemantics {
            source_node_id: NodeId::new("command:sess-1:3"),
            node_id: NodeId::new("execution-semantics:command:sess-1:3"),
            semantics: ExecutionSemantics::new("bash", "stdin_script_implicit")
                .with_payload_mode(ExecutionPayloadMode::StdinImplicit)
                .executing_payload(),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:3");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "cat payload.sh | bash",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("execution-semantics:command:sess-1:3"))
            .expect("expected semantics node to exist");

        match &node.kind {
            NodeKind::ExecutionSemantics { semantics } => {
                assert_eq!(semantics.normalized_command_name, "bash");
                assert_eq!(semantics.form_id, "stdin_script_implicit");
                assert_eq!(
                    semantics.payload_mode,
                    Some(ExecutionPayloadMode::StdinImplicit)
                );
                assert!(semantics.executes_payload);
            }
            other => panic!("unexpected node kind: {other:?}"),
        }

        let edge = graph.edges().last().expect("expected semantics edge");
        assert_eq!(edge.from, command_node_id);
        assert_eq!(edge.to, NodeId::new("execution-semantics:command:sess-1:3"));
        assert_eq!(edge.kind, EdgeKind::Defines);
        assert_eq!(summary.last_sequence_no(), None);
    }

    #[test]
    fn set_current_working_directory_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::SetCurrentWorkingDirectory {
            path: "/tmp/project/subdir".to_string(),
            observed_at: CommandSequenceNo::new(7),
            source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::SetCurrentWorkingDirectory {
                path: "/tmp/project/subdir".to_string(),
                observed_at: CommandSequenceNo::new(7),
                source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn set_positional_parameters_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::SetPositionalParameters {
            values: vec![SessionVariableValue::exact_scalar("/")],
            observed_at: CommandSequenceNo::new(7),
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::SetPositionalParameters {
                values: vec![SessionVariableValue::exact_scalar("/")],
                observed_at: CommandSequenceNo::new(7),
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn forget_positional_parameters_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::ForgetPositionalParameters {
            observed_at: CommandSequenceNo::new(8),
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::ForgetPositionalParameters {
                observed_at: CommandSequenceNo::new(8),
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_shell_state_reconciliation_anchor_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddShellStateReconciliationAnchor {
            node_id: NodeId::new("shell-state-reconciliation:sess-1:7"),
            sequence_no: CommandSequenceNo::new(7),
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddShellStateReconciliationAnchor {
                node_id: "shell-state-reconciliation:sess-1:7".to_string(),
                sequence_no: CommandSequenceNo::new(7),
            }
        );
        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_shell_state_reconciliation_anchor_creates_anchor_node_without_edges() {
        let mutation = PendingMutation::AddShellStateReconciliationAnchor {
            node_id: NodeId::new("shell-state-reconciliation:sess-1:7"),
            sequence_no: CommandSequenceNo::new(7),
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("shell-state-reconciliation:sess-1:7");
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("shell-state-reconciliation:sess-1:7"))
            .expect("expected reconciliation anchor node to exist");
        match &node.kind {
            NodeKind::ShellStateReconciliationAnchor { sequence_no } => {
                assert_eq!(*sequence_no, CommandSequenceNo::new(7));
            }
            other => panic!("expected reconciliation anchor node, got {other:?}"),
        }

        assert!(graph.edges().is_empty());
        assert_eq!(summary.last_sequence_no(), None);
    }

    #[test]
    fn set_current_working_directory_commits_directory_state_and_summary() {
        let mutation = PendingMutation::SetCurrentWorkingDirectory {
            path: "/tmp/project/subdir".to_string(),
            observed_at: CommandSequenceNo::new(7),
            source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:7");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(7),
            "cd subdir",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("cwd-state:7"))
            .expect("expected cwd state node to exist");
        match &node.kind {
            NodeKind::DirectoryState { path, version } => {
                assert_eq!(path, "/tmp/project/subdir");
                assert_eq!(*version, 7);
            }
            other => panic!("expected directory state node, got {other:?}"),
        }

        let edge = graph.edges().last().expect("expected cwd edge");
        assert_eq!(edge.from, command_node_id);
        assert_eq!(edge.to, NodeId::new("cwd-state:7"));
        assert_eq!(edge.kind, EdgeKind::ChangesCwdTo);
        assert_eq!(
            edge.semantics,
            Some(ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::CwdState,
                slot_name: None,
                normalized_command_name: None,
                domain_label: None,
            })
        );

        let cwd = summary
            .current_working_directory()
            .expect("expected cwd summary to exist");
        assert_eq!(cwd.path, "/tmp/project/subdir");
        assert_eq!(cwd.observed_at, CommandSequenceNo::new(7));
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(7)));
    }

    #[test]
    fn add_nested_payload_mutation_roundtrips_through_session_mutation() {
        let mutation = PendingMutation::AddNestedPayload {
            node_id: NodeId::new("nested:sess-1:3:0"),
            root_command_sequence_no: CommandSequenceNo::new(3),
            root_command_index: 0,
            record_id: 0,
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
            relation_from_command: Some(EdgeKind::ExpandsTo),
            relation_from_parent: None,
            parent_node_id: None,
        };

        let persisted = mutation.to_session_mutation();

        assert_eq!(
            persisted,
            SessionMutation::AddNestedPayload {
                node_id: "nested:sess-1:3:0".to_string(),
                root_command_sequence_no: CommandSequenceNo::new(3),
                root_command_index: 0,
                record_id: 0,
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
                relation_from_command: Some(SessionGraphEdgeKindSnapshot::ExpandsTo),
                relation_from_parent: None,
                parent_node_id: None,
            }
        );

        assert_eq!(PendingMutation::from_session_mutation(persisted), mutation);
    }

    #[test]
    fn add_nested_payload_mutation_creates_nested_payload_node() {
        let mutation = PendingMutation::AddNestedPayload {
            node_id: NodeId::new("nested:sess-1:3:0"),
            root_command_sequence_no: CommandSequenceNo::new(3),
            root_command_index: 0,
            record_id: 0,
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
            relation_from_command: Some(EdgeKind::ExpandsTo),
            relation_from_parent: None,
            parent_node_id: None,
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:3");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "bash -c 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let mut summary = SessionSummary::new();

        mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect("expected graph mutation to apply");
        mutation.apply_summary(&mut summary);

        let node = graph
            .get_node(&NodeId::new("nested:sess-1:3:0"))
            .expect("expected nested payload node to exist");

        match &node.kind {
            NodeKind::NestedPayload {
                record_id,
                depth,
                language,
                ..
            } => {
                assert_eq!(*record_id, 0);
                assert_eq!(*depth, 1);
                assert_eq!(language, "bash");
            }
            other => panic!("unexpected node kind: {other:?}"),
        }

        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.edges()[0].kind, EdgeKind::ExpandsTo);
    }

    #[test]
    fn graph_mutation_fails_when_edge_source_is_missing() {
        let mutation = PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:missing"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        };
        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:1");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "cat ./README.md",
            "/tmp/project",
            ShellKind::Bash,
        );

        let error = mutation
            .apply_graph(&mut graph, &command_node_id)
            .expect_err("expected missing source node to fail");

        assert_eq!(
            error,
            MutationGraphError::Graph(GraphError::MissingSourceNode(NodeId::new(
                "command:sess-1:missing"
            )))
        );
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn apply_graph_batch_allows_edge_to_node_created_by_later_mutation() {
        let mutations = vec![
            PendingMutation::AddExecutionUnitFlow {
                from_node_id: NodeId::new("pipeline-segment:sess-1:3:0"),
                to_node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
            },
            PendingMutation::AddDerivedInvocation {
                node_id: NodeId::new("pipeline-segment:sess-1:3:1"),
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                derived_command_index: 1,
                raw_text: "head -100".to_string(),
                command_name: Some("head".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
                parent_node_id: NodeId::new("command:sess-1:3"),
                relation_from_parent: EdgeKind::ExpandsTo,
            },
        ];

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:3");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "timeout 15 ~/go/bin/httpx ... | head -100",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:3:0"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                derived_command_index: 0,
                raw_text: "timeout 15 ~/go/bin/httpx ...".to_string(),
                command_name: Some("timeout".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));

        PendingMutation::validate_graph_batch(&graph, &command_node_id, &mutations)
            .expect("expected batch validation to allow forward references within one batch");

        PendingMutation::apply_graph_batch(&mut graph, &command_node_id, &mutations)
            .expect("expected forward-dependent batch apply to succeed");

        assert!(
            graph
                .get_node(&NodeId::new("pipeline-segment:sess-1:3:1"))
                .is_some()
        );
        assert!(graph.edges().iter().any(|edge| {
            edge.from == NodeId::new("pipeline-segment:sess-1:3:0")
                && edge.to == NodeId::new("pipeline-segment:sess-1:3:1")
                && edge.kind == EdgeKind::FlowsTo
        }));
        assert!(graph.edges().iter().any(|edge| {
            edge.from == command_node_id
                && edge.to == NodeId::new("pipeline-segment:sess-1:3:1")
                && edge.kind == EdgeKind::ExpandsTo
        }));
    }

    struct PanicOnNodesGraph<'a> {
        inner: &'a SessionGraph,
    }

    impl GraphRead for PanicOnNodesGraph<'_> {
        fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
            self.inner.get_node(id)
        }

        fn node_count(&self) -> usize {
            self.inner.node_count()
        }

        fn edge_count(&self) -> usize {
            self.inner.edge_count()
        }

        fn nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            panic!("validate_graph_batch should not scan graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            Box::new(self.inner.edges().iter())
        }

        fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.outgoing_edges(id)
        }

        fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.incoming_edges(id)
        }

        fn command_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .command_nodes_in_window(after_sequence, before_sequence)
        }

        fn derived_invocation_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .derived_invocation_nodes_in_window(after_sequence, before_sequence)
        }

        fn nested_payload_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .nested_payload_nodes_in_window(after_sequence, before_sequence)
        }

        fn execution_semantics_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .execution_semantics_nodes_in_window(after_sequence, before_sequence)
        }

        fn path_fact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes()
        }

        fn path_fact_nodes_by_concrete_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes_by_concrete_path(path)
        }

        fn path_content_artifact_nodes<'a>(
            &'a self,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes()
        }

        fn path_content_artifact_nodes_by_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes_by_path(path)
        }
    }

    #[test]
    fn validate_graph_batch_does_not_require_full_node_scan() {
        let mutation = PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project/README.md".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".to_string(),
            normalized_command_name: Some("cat".to_string()),
            relation: EdgeKind::Reads,
        };

        let mut graph = SessionGraph::new();
        let command_node_id = NodeId::new("command:sess-1:1");
        let _ = graph.add_command_invocation(
            command_node_id.clone(),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "cat ./README.md",
            "/tmp/project",
            ShellKind::Bash,
        );

        let wrapped = PanicOnNodesGraph { inner: &graph };
        PendingMutation::validate_graph_batch(&wrapped, &command_node_id, &[mutation])
            .expect("expected on-demand validation to succeed without scanning nodes");
    }
}
