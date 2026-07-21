use caushell_graph::{GraphRead, SessionGraph, SessionRead};
use caushell_parse::ParsedCommandArtifact;
use caushell_runner::{
    MutationGraphError, PendingMutation, request_anchor_node_id, request_anchor_node_id_for,
    top_level_command_node_id_for,
};
use caushell_types::{
    CheckRequest, CommandSequenceNo, RuntimeProducedValueKind, SessionAliasBinding,
    SessionCurrentWorkingDirectorySource, SessionFunctionBinding, SessionId, SessionSnapshot,
    SessionSummary, SessionVariableBinding, SessionVariableValue, ShellRuntimeCapabilities,
    ShellStateDelta, ShellStateKnowledge, ShellStateSnapshot, ShellValueSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCommitError {
    DuplicateCommandNode { node_id: caushell_graph::NodeId },
    MissingGraphAnchor { node_id: caushell_graph::NodeId },
    MutationGraph(MutationGraphError),
}

impl std::fmt::Display for SessionCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateCommandNode { node_id } => {
                write!(
                    f,
                    "command node {} already exists in session graph",
                    node_id.0
                )
            }
            Self::MissingGraphAnchor { node_id } => {
                write!(
                    f,
                    "graph anchor node {} does not exist in session graph",
                    node_id.0
                )
            }
            Self::MutationGraph(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SessionCommitError {}

impl From<MutationGraphError> for SessionCommitError {
    fn from(error: MutationGraphError) -> Self {
        Self::MutationGraph(error)
    }
}

#[derive(Debug, Default)]
pub struct SessionState {
    graph: SessionGraph,
    summary: SessionSummary,
}

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: SessionSnapshot) -> Result<Self, caushell_graph::GraphError> {
        Ok(Self {
            graph: SessionGraph::from_snapshot(snapshot.graph)?,
            summary: snapshot.summary,
        })
    }

    pub fn graph(&self) -> &SessionGraph {
        &self.graph
    }

    pub fn graph_mut(&mut self) -> &mut SessionGraph {
        &mut self.graph
    }

    pub fn summary(&self) -> &SessionSummary {
        &self.summary
    }

    pub fn summary_mut(&mut self) -> &mut SessionSummary {
        &mut self.summary
    }

    pub fn observe_request(&mut self, request: &CheckRequest) {
        self.seed_shell_state_before(request);
        self.summary.observe_sequence(request.sequence_no);
    }

    pub fn commit_allowed_request(
        &mut self,
        pending_mutations: &[PendingMutation],
        request: &CheckRequest,
    ) -> Result<(), SessionCommitError> {
        self.seed_shell_state_before(request);
        let anchor_node_id = request_anchor_node_id(request);

        if self.graph.get_node(&anchor_node_id).is_some() {
            return Err(SessionCommitError::DuplicateCommandNode {
                node_id: anchor_node_id,
            });
        }

        PendingMutation::validate_graph_batch(&self.graph, &anchor_node_id, pending_mutations)?;

        let replaced_anchor_node = self.graph.add_request_anchor(
            anchor_node_id.clone(),
            request.session_id.clone(),
            request.sequence_no,
            request.command.clone(),
            request.shell_state_before.cwd.clone(),
            request.shell_kind,
        );

        if let Some(existing) = replaced_anchor_node {
            let node_id = existing.id.clone();
            drop(self.graph.add_node(existing));
            return Err(SessionCommitError::DuplicateCommandNode { node_id });
        }

        PendingMutation::apply_graph_batch(&mut self.graph, &anchor_node_id, pending_mutations)?;

        for mutation in pending_mutations {
            mutation.apply_live_summary(
                &mut self.summary,
                request.runtime.shell_runtime_capabilities,
            );
        }

        self.observe_request(request);
        Ok(())
    }

    pub fn commit_observed_shell_state_mutations(
        &mut self,
        session_id: &SessionId,
        sequence_no: CommandSequenceNo,
        capabilities: ShellRuntimeCapabilities,
        pending_mutations: &[PendingMutation],
    ) -> Result<(), SessionCommitError> {
        let primary_command_node_id = top_level_command_node_id_for(session_id, sequence_no, 0);
        let request_node_id = request_anchor_node_id_for(session_id, sequence_no);
        let command_node_id = if self.graph.get_node(&primary_command_node_id).is_some() {
            primary_command_node_id
        } else {
            request_node_id
        };
        let synthetic_anchor_node_id = pending_mutations
            .iter()
            .find_map(PendingMutation::provided_graph_anchor)
            .cloned();
        let anchor_node_id = if self.graph.get_node(&command_node_id).is_some() {
            command_node_id.clone()
        } else if let Some(node_id) = &synthetic_anchor_node_id {
            node_id.clone()
        } else {
            command_node_id.clone()
        };

        if self.graph.get_node(&command_node_id).is_none()
            && pending_mutations
                .iter()
                .any(PendingMutation::requires_graph_anchor)
            && synthetic_anchor_node_id.is_none()
        {
            return Err(SessionCommitError::MissingGraphAnchor {
                node_id: command_node_id,
            });
        }

        if pending_mutations.iter().any(PendingMutation::touches_graph) {
            PendingMutation::validate_graph_batch(&self.graph, &anchor_node_id, pending_mutations)?;
            PendingMutation::apply_graph_batch(
                &mut self.graph,
                &anchor_node_id,
                pending_mutations,
            )?;
        }

        for mutation in pending_mutations {
            mutation.apply_live_summary(&mut self.summary, capabilities);
        }

        Ok(())
    }

    fn seed_shell_state_before(&mut self, request: &CheckRequest) {
        if self.summary.last_sequence_no().is_none() {
            seed_summary_from_shell_state_before(
                &mut self.summary,
                &request.shell_state_before,
                CommandSequenceNo::new(0),
                request.runtime.shell_runtime_capabilities,
            );
        } else if request.runtime.shell_runtime_capabilities.persists_cwd
            && self.summary.current_working_directory().is_none()
        {
            self.summary.set_current_working_directory(
                request.shell_state_before.cwd(),
                request.sequence_no,
            );
        }
    }
}

pub(crate) fn reconcile_shell_state_before(
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
    previous_command: Option<PreviousCommandContext<'_>>,
    capabilities: ShellRuntimeCapabilities,
) -> ShellStateDelta {
    let mut delta = ShellStateDelta::new();

    if capabilities.persists_cwd
        && should_reconcile_cwd(summary, shell_state_before, observed_at, previous_command)
    {
        delta = delta.with_cwd_after(shell_state_before.cwd().to_string());
    }

    if capabilities.persists_variables || capabilities.persists_exported_environment {
        delta = reconcile_variable_state(
            delta,
            summary,
            shell_state_before,
            observed_at,
            previous_command,
            capabilities,
        );
    }
    if capabilities.persists_positionals {
        delta = reconcile_positional_parameter_state(delta, summary, shell_state_before);
    }
    if capabilities.persists_aliases {
        delta = reconcile_alias_state(delta, summary, shell_state_before, observed_at);
    }
    if capabilities.persists_functions {
        delta = reconcile_function_state(delta, summary, shell_state_before, observed_at);
    }
    delta
}

fn should_reconcile_cwd(
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
    previous_command: Option<PreviousCommandContext<'_>>,
) -> bool {
    let Some(cwd) = summary.current_working_directory() else {
        return true;
    };

    if cwd.path == shell_state_before.cwd() {
        return false;
    }

    let Some(previous_command) = previous_command else {
        return true;
    };

    if cwd.source != SessionCurrentWorkingDirectorySource::StaticAnalysis {
        return true;
    }

    if cwd.observed_at == observed_at {
        return false;
    }

    previous_command_may_update_cwd(previous_command)
}

fn previous_command_may_update_cwd(previous_command: PreviousCommandContext<'_>) -> bool {
    let Ok(parsed) =
        caushell_parse::parse_command(previous_command.raw_text, previous_command.shell_kind)
    else {
        return true;
    };

    parsed.commands.iter().any(|command| {
        matches!(
            command.command_name.as_deref(),
            Some("cd" | "pushd" | "popd")
        )
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PreviousCommandContext<'a> {
    pub raw_text: &'a str,
    pub shell_kind: caushell_types::ShellKind,
}

fn seed_summary_from_shell_state_before(
    summary: &mut SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
    capabilities: ShellRuntimeCapabilities,
) {
    if capabilities.persists_cwd {
        summary.set_current_working_directory(shell_state_before.cwd(), observed_at);
    }

    match shell_state_before.observability.variables {
        ShellStateKnowledge::Complete => {
            for variable in &shell_state_before.variables {
                if !capabilities.persists_variable(variable.exported) {
                    continue;
                }
                summary.upsert_variable_binding(shell_variable_snapshot_to_binding(
                    variable,
                    observed_at,
                ));
            }
        }
        ShellStateKnowledge::ExportedOnly => {
            if !capabilities.persists_exported_environment {
                return;
            }
            for variable in shell_state_before
                .variables
                .iter()
                .filter(|variable| variable.exported)
            {
                summary.upsert_variable_binding(shell_variable_snapshot_to_binding(
                    variable,
                    observed_at,
                ));
            }
        }
        ShellStateKnowledge::Unknown => {}
    }

    if capabilities.persists_aliases
        && shell_state_before.observability.aliases == ShellStateKnowledge::Complete
    {
        for alias in &shell_state_before.aliases {
            summary.upsert_alias_binding(SessionAliasBinding::new(
                alias.name.clone(),
                alias.body.clone(),
                observed_at,
            ));
        }
    }

    if capabilities.persists_functions
        && shell_state_before.observability.functions == ShellStateKnowledge::Complete
    {
        for function in &shell_state_before.functions {
            summary.upsert_function_binding(SessionFunctionBinding::new(
                function.name.clone(),
                function.body.clone(),
                observed_at,
            ));
        }
    }

    if capabilities.persists_positionals
        && shell_state_before.observability.positional_parameters == ShellStateKnowledge::Complete
    {
        summary.set_positional_parameters(
            shell_state_before
                .positional_parameters
                .iter()
                .map(shell_value_snapshot_to_session_value),
            observed_at,
        );
    }
}

fn reconcile_variable_state(
    mut delta: ShellStateDelta,
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
    previous_command: Option<PreviousCommandContext<'_>>,
    capabilities: ShellRuntimeCapabilities,
) -> ShellStateDelta {
    match shell_state_before.observability.variables {
        ShellStateKnowledge::Complete => {
            let snapshot_bindings = shell_state_before
                .variables
                .iter()
                .filter(|variable| capabilities.persists_variable(variable.exported))
                .map(|variable| {
                    (
                        variable.name.clone(),
                        reconcile_shell_variable_snapshot_to_binding(
                            variable,
                            observed_at,
                            previous_command,
                        ),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();

            let persisted_names = shell_state_before
                .variables
                .iter()
                .filter(|variable| capabilities.persists_variable(variable.exported))
                .map(|variable| variable.name.clone())
                .collect::<std::collections::BTreeSet<_>>();

            for binding in snapshot_bindings.values() {
                if !summary_variable_matches(summary.variable_binding(&binding.name), binding) {
                    delta = delta.with_upsert_variable(binding.clone());
                }
            }

            for existing in summary.variable_bindings() {
                if capabilities.persists_variable(existing.exported)
                    && !persisted_names.contains(&existing.name)
                {
                    delta = delta.with_unset_variable(existing.name.clone());
                }
            }
        }
        ShellStateKnowledge::ExportedOnly => {
            if !capabilities.persists_exported_environment {
                return delta;
            }
            for variable in shell_state_before
                .variables
                .iter()
                .filter(|variable| variable.exported)
            {
                let binding = reconcile_shell_variable_snapshot_to_binding(
                    variable,
                    observed_at,
                    previous_command,
                );
                if !summary_variable_matches(summary.variable_binding(&binding.name), &binding) {
                    delta = delta.with_upsert_variable(binding);
                }
            }
        }
        ShellStateKnowledge::Unknown => {}
    }

    delta
}

fn reconcile_positional_parameter_state(
    mut delta: ShellStateDelta,
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
) -> ShellStateDelta {
    if shell_state_before.observability.positional_parameters != ShellStateKnowledge::Complete {
        return delta;
    }

    let snapshot_values = shell_state_before
        .positional_parameters
        .iter()
        .map(shell_value_snapshot_to_session_value)
        .collect::<Vec<_>>();

    let summary_values = summary
        .positional_parameters()
        .map(|positional| positional.values.as_slice());

    if summary_values != Some(snapshot_values.as_slice()) {
        delta = delta.with_positional_parameters_after(snapshot_values);
    }

    delta
}

fn reconcile_alias_state(
    mut delta: ShellStateDelta,
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
) -> ShellStateDelta {
    if shell_state_before.observability.aliases != ShellStateKnowledge::Complete {
        return delta;
    }

    let snapshot_aliases = shell_state_before
        .aliases
        .iter()
        .map(|alias| {
            (
                alias.name.clone(),
                SessionAliasBinding::new(alias.name.clone(), alias.body.clone(), observed_at),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    for binding in snapshot_aliases.values() {
        if !summary_alias_matches(summary.alias_binding(&binding.name), binding) {
            delta = delta.with_upsert_alias(binding.clone());
        }
    }

    for existing in summary.alias_bindings() {
        if !snapshot_aliases.contains_key(&existing.name) {
            delta = delta.with_unset_alias(existing.name.clone());
        }
    }

    delta
}

fn reconcile_function_state(
    mut delta: ShellStateDelta,
    summary: &SessionSummary,
    shell_state_before: &ShellStateSnapshot,
    observed_at: CommandSequenceNo,
) -> ShellStateDelta {
    if shell_state_before.observability.functions != ShellStateKnowledge::Complete {
        return delta;
    }

    let snapshot_functions = shell_state_before
        .functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                SessionFunctionBinding::new(
                    function.name.clone(),
                    function.body.clone(),
                    observed_at,
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    for binding in snapshot_functions.values() {
        if !summary_function_matches(summary.function_binding(&binding.name), binding) {
            delta = delta.with_upsert_function(binding.clone());
        }
    }

    for existing in summary.function_bindings() {
        if !snapshot_functions.contains_key(&existing.name) {
            delta = delta.with_unset_function(existing.name.clone());
        }
    }

    delta
}

fn shell_variable_snapshot_to_binding(
    variable: &caushell_types::ShellVariableSnapshot,
    observed_at: CommandSequenceNo,
) -> SessionVariableBinding {
    SessionVariableBinding::new(
        variable.name.clone(),
        shell_value_snapshot_to_session_value(&variable.value),
        variable.exported,
        observed_at,
    )
}

fn reconcile_shell_variable_snapshot_to_binding(
    variable: &caushell_types::ShellVariableSnapshot,
    observed_at: CommandSequenceNo,
    previous_command: Option<PreviousCommandContext<'_>>,
) -> SessionVariableBinding {
    let mut binding = shell_variable_snapshot_to_binding(variable, observed_at);

    if matches!(binding.value, SessionVariableValue::ExactScalar(_)) {
        if let Some(kind) = infer_runtime_produced_value_kind(variable, previous_command) {
            let SessionVariableValue::ExactScalar(value) = &binding.value else {
                unreachable!("exact-scalar match should hold")
            };
            binding.value = SessionVariableValue::runtime_produced(value.clone(), kind);
        }
    }

    binding
}

fn infer_runtime_produced_value_kind(
    variable: &caushell_types::ShellVariableSnapshot,
    previous_command: Option<PreviousCommandContext<'_>>,
) -> Option<RuntimeProducedValueKind> {
    let previous_command = previous_command?;
    let parsed =
        caushell_parse::parse_command(previous_command.raw_text, previous_command.shell_kind)
            .ok()?;

    if !previous_command_mints_variable_via_command_substitution(&parsed, &variable.name) {
        return None;
    }

    match &variable.value {
        ShellValueSnapshot::ExactScalar { value } => {
            if looks_like_shell_path(value) {
                Some(RuntimeProducedValueKind::Path)
            } else {
                Some(RuntimeProducedValueKind::Scalar)
            }
        }
        ShellValueSnapshot::RuntimeProduced { value_kind, .. } => Some(*value_kind),
        ShellValueSnapshot::OpaqueDynamic { .. } | ShellValueSnapshot::RuntimeInput { .. } => None,
    }
}

fn previous_command_mints_variable_via_command_substitution(
    parsed: &ParsedCommandArtifact,
    variable_name: &str,
) -> bool {
    parsed
        .declaration_commands
        .iter()
        .flat_map(|declaration| declaration.assignments.iter())
        .chain(
            parsed
                .assignment_commands
                .iter()
                .flat_map(|assignment_command| assignment_command.assignments.iter()),
        )
        .any(|assignment| {
            assignment.name == variable_name
                && assignment.operator == caushell_parse::AssignmentOperator::Assign
                && assignment_value_contains_runtime_mint(&assignment.value.text, parsed.shell_kind)
        })
}

fn assignment_value_contains_runtime_mint(
    text: &str,
    shell_kind: caushell_types::ShellKind,
) -> bool {
    caushell_parse::parse_command_substitutions(text, shell_kind)
        .map(|facts| !facts.is_empty())
        .unwrap_or(false)
        || caushell_parse::parse_process_substitutions(text, shell_kind)
            .map(|facts| !facts.is_empty())
            .unwrap_or(false)
}

fn looks_like_shell_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
}

fn shell_value_snapshot_to_session_value(value: &ShellValueSnapshot) -> SessionVariableValue {
    match value {
        ShellValueSnapshot::ExactScalar { value } => SessionVariableValue::exact_scalar(value),
        ShellValueSnapshot::RuntimeProduced { value, value_kind } => {
            SessionVariableValue::runtime_produced(value, *value_kind)
        }
        ShellValueSnapshot::OpaqueDynamic { repr } => SessionVariableValue::opaque_dynamic(repr),
        ShellValueSnapshot::RuntimeInput { source, capture } => {
            SessionVariableValue::runtime_input(*source, capture.clone())
        }
    }
}

fn summary_variable_matches(
    existing: Option<&SessionVariableBinding>,
    candidate: &SessionVariableBinding,
) -> bool {
    existing.is_some_and(|existing| {
        existing.value == candidate.value && existing.exported == candidate.exported
    })
}

fn summary_alias_matches(
    existing: Option<&SessionAliasBinding>,
    candidate: &SessionAliasBinding,
) -> bool {
    existing.is_some_and(|existing| existing.body == candidate.body)
}

fn summary_function_matches(
    existing: Option<&SessionFunctionBinding>,
    candidate: &SessionFunctionBinding,
) -> bool {
    existing.is_some_and(|existing| existing.body == candidate.body)
}

impl SessionRead for SessionState {
    fn graph(&self) -> &dyn GraphRead {
        &self.graph
    }

    fn summary(&self) -> &SessionSummary {
        &self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionCommitError, SessionState};
    use caushell_graph::{EdgeKind, NodeId, NodeKind};
    use caushell_runner::PendingMutation;
    use caushell_types::{
        CheckRequest, CommandSequenceNo, PathResolution, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ResolvedPathPurpose, ResolvedPathRole,
        RuntimeInputCapture, RuntimeInputSource, RuntimeMetadata, SessionAliasBinding,
        SessionCurrentWorkingDirectorySource, SessionId, SessionSummary, SessionVariableBinding,
        SessionVariableValue, ShellKind, ShellStateKnowledge,
    };

    fn sample_request(sequence_no: u64) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: "pwd".to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    #[test]
    fn observe_request_seeds_shell_state_baseline_for_new_session() {
        let mut state = SessionState::new();
        let mut request = sample_request(1);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_exact_scalar_variable("SCRIPT", "build.sh", true)
            .with_alias("runbuild", "bash ./scripts/build.sh")
            .with_function("deploy", "bash ./scripts/deploy.sh;")
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);

        state.observe_request(&request);

        let cwd = state
            .summary()
            .current_working_directory()
            .expect("expected cwd baseline to exist");
        assert_eq!(cwd.path, "/tmp/project");
        assert_eq!(cwd.observed_at, CommandSequenceNo::new(0));

        let variable = state
            .summary()
            .variable_binding("SCRIPT")
            .expect("expected variable baseline to exist");
        assert_eq!(
            variable.value,
            SessionVariableValue::exact_scalar("build.sh")
        );
        assert!(variable.exported);
        assert_eq!(variable.observed_at, CommandSequenceNo::new(0));

        let alias = state
            .summary()
            .alias_binding("runbuild")
            .expect("expected alias baseline to exist");
        assert_eq!(alias.body, "bash ./scripts/build.sh");
        assert_eq!(alias.observed_at, CommandSequenceNo::new(0));

        let function = state
            .summary()
            .function_binding("deploy")
            .expect("expected function baseline to exist");
        assert_eq!(function.body, "bash ./scripts/deploy.sh;");
        assert_eq!(function.observed_at, CommandSequenceNo::new(0));

        assert_eq!(
            state.summary().last_sequence_no(),
            Some(CommandSequenceNo::new(1))
        );
    }

    #[test]
    fn observe_request_seeds_runtime_input_variable_baseline_for_new_session() {
        let mut state = SessionState::new();
        let mut request = sample_request(1);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_runtime_input_variable(
                "USER_CMD",
                RuntimeInputSource::StdinData,
                RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
                false,
            )
            .with_variable_knowledge(ShellStateKnowledge::Complete);

        state.observe_request(&request);

        let variable = state
            .summary()
            .variable_binding("USER_CMD")
            .expect("expected runtime-input variable baseline to exist");
        assert_eq!(
            variable.value,
            SessionVariableValue::RuntimeInput {
                source: RuntimeInputSource::StdinData,
                capture: RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
            }
        );
        assert!(!variable.exported);
        assert_eq!(variable.observed_at, CommandSequenceNo::new(0));
    }

    #[test]
    fn commit_allowed_request_applies_variable_summary_mutations() {
        let mut state = SessionState::new();
        let request = sample_request(3);

        state
            .commit_allowed_request(
                &[PendingMutation::UpsertVariableBinding {
                    binding: SessionVariableBinding::new(
                        "SCRIPT",
                        SessionVariableValue::exact_scalar("build.sh"),
                        false,
                        CommandSequenceNo::new(3),
                    ),
                }],
                &request,
            )
            .expect("expected commit to succeed");

        let binding = state
            .summary()
            .variable_binding("SCRIPT")
            .expect("expected SCRIPT binding to exist");

        assert_eq!(binding.name, "SCRIPT");
        assert_eq!(
            binding.value,
            SessionVariableValue::ExactScalar("build.sh".to_string())
        );
        assert_eq!(binding.observed_at, CommandSequenceNo::new(3));
        assert_eq!(
            state.summary().last_sequence_no(),
            Some(CommandSequenceNo::new(3))
        );
    }

    #[test]
    fn commit_allowed_request_commits_path_fact_and_path_content_provenance() {
        let mut state = SessionState::new();
        let request = sample_request(3);

        state
            .commit_allowed_request(
                &[
                    PendingMutation::AddTopLevelCommandInvocation {
                        node_id: NodeId::new("command:sess-1:3:0"),
                        session_id: SessionId::new("sess-1"),
                        sequence_no: CommandSequenceNo::new(3),
                        command_index: 0,
                        raw_text: "pwd".to_string(),
                        cwd_before: "/tmp/project".to_string(),
                        shell_kind: caushell_types::ShellKind::Bash,
                    },
                    PendingMutation::AddPathFact {
                        source_node_id: caushell_graph::NodeId::new("command:sess-1:3:0"),
                        node_id: caushell_graph::NodeId::new("path-1"),
                        resolution: PathResolution::Concrete {
                            path: "/tmp/project/README.md".to_string(),
                        },
                        role: ResolvedPathRole::Read,
                        purpose: Some(ResolvedPathPurpose::GenericOperand),
                        slot_name: "path".to_string(),
                        normalized_command_name: None,
                        relation: EdgeKind::Reads,
                    },
                    PendingMutation::AddProvenanceArtifact {
                        source_node_id: caushell_graph::NodeId::new("command:sess-1:3:0"),
                        node_id: caushell_graph::NodeId::new(
                            "artifact:path-content:/tmp/project/README.md",
                        ),
                        artifact: ProvenanceArtifact::PathContent {
                            path: "/tmp/project/README.md".to_string(),
                            version: None,
                        },
                        relation: EdgeKind::Consumes,
                        semantics: ProvenanceEdgeSemantics::Consume {
                            consume_kind: ProvenanceConsumeKind::PathRead,
                            slot_name: Some("path".to_string()),
                            normalized_command_name: None,
                            domain_label: Some(ProvenanceDomainLabel::Path {
                                role: ResolvedPathRole::Read,
                                purpose: Some(ResolvedPathPurpose::GenericOperand),
                            }),
                        },
                    },
                ],
                &request,
            )
            .expect("expected commit to succeed");

        let command_node = state
            .graph()
            .get_node(&caushell_graph::NodeId::new("command:sess-1:3:0"))
            .expect("expected command node to exist");
        let path_node = state
            .graph()
            .get_node(&caushell_graph::NodeId::new("path-1"))
            .expect("expected resolved path node to exist");
        let artifact_node = state
            .graph()
            .get_node(&caushell_graph::NodeId::new(
                "artifact:path-content:/tmp/project/README.md",
            ))
            .expect("expected path content artifact node to exist");

        match &command_node.kind {
            NodeKind::CommandInvocation { raw_text, .. } => {
                assert_eq!(raw_text, "pwd");
            }
            other => panic!("unexpected command node kind: {other:?}"),
        }

        match &path_node.kind {
            NodeKind::PathFact { resolution, .. } => {
                assert_eq!(
                    resolution,
                    &PathResolution::Concrete {
                        path: "/tmp/project/README.md".to_string()
                    }
                );
            }
            other => panic!("unexpected path node kind: {other:?}"),
        }

        match &artifact_node.kind {
            NodeKind::ProvenanceArtifact { artifact } => {
                assert_eq!(
                    artifact,
                    &ProvenanceArtifact::PathContent {
                        path: "/tmp/project/README.md".to_string(),
                        version: None,
                    }
                );
            }
            other => panic!("unexpected provenance artifact node kind: {other:?}"),
        }

        assert_eq!(state.graph().edge_count(), 2);
        assert!(state.graph().edges().iter().any(|edge| {
            edge.from == NodeId::new("command:sess-1:3:0")
                && edge.to == NodeId::new("path-1")
                && edge.kind == EdgeKind::Reads
        }));
        assert!(state.graph().edges().iter().any(|edge| {
            edge.from == NodeId::new("command:sess-1:3:0")
                && edge.to == NodeId::new("artifact:path-content:/tmp/project/README.md")
                && edge.kind == EdgeKind::Consumes
                && matches!(
                    edge.semantics.as_ref(),
                    Some(ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PathRead,
                        slot_name,
                        normalized_command_name: None,
                        domain_label: Some(ProvenanceDomainLabel::Path {
                            role: ResolvedPathRole::Read,
                            purpose: Some(ResolvedPathPurpose::GenericOperand),
                        }),
                    }) if slot_name.as_deref() == Some("path")
                )
        }));
    }

    #[test]
    fn commit_allowed_request_applies_unset_variable_mutation() {
        let mut state = SessionState::new();

        state
            .commit_allowed_request(
                &[PendingMutation::UpsertVariableBinding {
                    binding: SessionVariableBinding::new(
                        "SCRIPT",
                        SessionVariableValue::exact_scalar("build.sh"),
                        false,
                        CommandSequenceNo::new(2),
                    ),
                }],
                &sample_request(2),
            )
            .expect("expected initial commit to succeed");

        state
            .commit_allowed_request(
                &[PendingMutation::UnsetVariable {
                    name: "SCRIPT".to_string(),
                    observed_at: CommandSequenceNo::new(4),
                }],
                &sample_request(4),
            )
            .expect("expected unset commit to succeed");

        assert!(state.summary().variable_binding("SCRIPT").is_none());
        assert_eq!(
            state.summary().last_sequence_no(),
            Some(CommandSequenceNo::new(4))
        );
    }

    #[test]
    fn commit_allowed_request_applies_current_working_directory_mutation() {
        let mut state = SessionState::new();
        let request = sample_request(5);

        state
            .commit_allowed_request(
                &[PendingMutation::SetCurrentWorkingDirectory {
                    path: "/tmp/project/subdir".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                    source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
                }],
                &request,
            )
            .expect("expected cwd commit to succeed");

        let cwd = state
            .summary()
            .current_working_directory()
            .expect("expected cwd summary to exist");
        assert_eq!(cwd.path, "/tmp/project/subdir");
        assert_eq!(cwd.observed_at, CommandSequenceNo::new(5));

        let node = state
            .graph()
            .get_node(&caushell_graph::NodeId::new("cwd-state:5"))
            .expect("expected cwd state node to exist");
        match &node.kind {
            NodeKind::DirectoryState { path, version } => {
                assert_eq!(path, "/tmp/project/subdir");
                assert_eq!(*version, 5);
            }
            other => panic!("unexpected cwd state node kind: {other:?}"),
        }

        assert!(state.graph().edges().iter().any(|edge| {
            edge.from == NodeId::new("command-request:sess-1:5")
                && edge.to == NodeId::new("cwd-state:5")
                && edge.kind == EdgeKind::ChangesCwdTo
        }));
    }

    #[test]
    fn commit_allowed_request_rejects_duplicate_command_node() {
        let mut state = SessionState::new();
        let request = sample_request(3);

        state
            .commit_allowed_request(&[], &request)
            .expect("expected first commit to succeed");

        let error = state
            .commit_allowed_request(&[], &request)
            .expect_err("expected duplicate command node to fail");

        assert_eq!(
            error,
            SessionCommitError::DuplicateCommandNode {
                node_id: NodeId::new("command-request:sess-1:3"),
            }
        );
    }

    #[test]
    fn commit_observed_shell_state_mutations_requires_graph_anchor_when_graph_state_changes() {
        let mut state = SessionState::new();

        let error = state
            .commit_observed_shell_state_mutations(
                &SessionId::new("sess-1"),
                CommandSequenceNo::new(5),
                caushell_types::ShellRuntimeCapabilities::persistent_shell(),
                &[PendingMutation::SetCurrentWorkingDirectory {
                    path: "/tmp/project/subdir".to_string(),
                    observed_at: CommandSequenceNo::new(5),
                    source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
                }],
            )
            .expect_err("expected missing command node to fail");

        assert_eq!(
            error,
            SessionCommitError::MissingGraphAnchor {
                node_id: NodeId::new("command-request:sess-1:5"),
            }
        );
    }

    #[test]
    fn commit_observed_shell_state_mutations_accepts_synthetic_reconciliation_anchor() {
        let mut state = SessionState::new();

        state
            .commit_observed_shell_state_mutations(
                &SessionId::new("sess-1"),
                CommandSequenceNo::new(5),
                caushell_types::ShellRuntimeCapabilities::persistent_shell(),
                &[
                    PendingMutation::AddShellStateReconciliationAnchor {
                        node_id: NodeId::new("shell-state-reconciliation:sess-1:5"),
                        sequence_no: CommandSequenceNo::new(5),
                    },
                    PendingMutation::SetCurrentWorkingDirectory {
                        path: "/tmp/project/subdir".to_string(),
                        observed_at: CommandSequenceNo::new(5),
                        source: SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
                    },
                    PendingMutation::UpsertAliasBinding {
                        binding: SessionAliasBinding::new(
                            "ll",
                            "ls -la",
                            CommandSequenceNo::new(5),
                        ),
                    },
                ],
            )
            .expect("expected synthetic anchor commit to succeed");

        let anchor = state
            .graph()
            .get_node(&NodeId::new("shell-state-reconciliation:sess-1:5"))
            .expect("expected synthetic anchor node to exist");
        match &anchor.kind {
            NodeKind::ShellStateReconciliationAnchor { sequence_no } => {
                assert_eq!(*sequence_no, CommandSequenceNo::new(5));
            }
            other => panic!("unexpected reconciliation anchor node kind: {other:?}"),
        }

        assert!(state.graph().edges().iter().any(|edge| {
            edge.from == NodeId::new("shell-state-reconciliation:sess-1:5")
                && edge.to == NodeId::new("cwd-state:5")
                && edge.kind == EdgeKind::ChangesCwdTo
        }));
        let alias_node = state
            .graph()
            .nodes()
            .find(|node| {
                matches!(
                    &node.kind,
                    NodeKind::AliasBinding { name, body, version }
                        if name == "ll" && body == "ls -la" && *version == 5
                )
            })
            .expect("expected alias binding node");
        assert!(state.graph().edges().iter().any(|edge| {
            edge.from == NodeId::new("shell-state-reconciliation:sess-1:5")
                && edge.to == alias_node.id
                && edge.kind == EdgeKind::Defines
        }));
        assert_eq!(
            state
                .summary()
                .current_working_directory()
                .expect("expected cwd summary")
                .path,
            "/tmp/project/subdir"
        );
        assert_eq!(
            state
                .summary()
                .alias_binding("ll")
                .expect("expected alias summary")
                .body,
            "ls -la"
        );
    }

    #[test]
    fn session_state_can_be_restored_from_snapshot() {
        let snapshot = caushell_types::SessionSnapshot::new(
            SessionId::new("sess-1"),
            9,
            SessionSummary::default(),
            caushell_types::SessionGraphSnapshot {
                nodes: vec![caushell_types::SessionGraphNodeSnapshot {
                    id: "command:sess-1:1:0".to_string(),
                    kind: caushell_types::SessionGraphNodeKindSnapshot::CommandInvocation {
                        session_id: SessionId::new("sess-1"),
                        sequence_no: CommandSequenceNo::new(1),
                        raw_text: "pwd".to_string(),
                        cwd_before: "/tmp/project".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                }],
                edges: vec![],
            },
        );

        let state =
            SessionState::from_snapshot(snapshot).expect("expected snapshot restore to succeed");

        assert!(
            state
                .graph()
                .get_node(&caushell_graph::NodeId::new("command:sess-1:1:0"))
                .is_some()
        );
    }
}
