use crate::{CommandInvocationRef, DerivedInvocationRef, QuerySession, SequenceWindow};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode, ExecutionSemanticsFact,
    ExecutionUnit, ExecutionUnitFlow, ExecutionUnitKind, InProcessCodeLoadKind,
    InteractiveEscapeSurfaceKind, ProcessControlAction, ProcessControlTargetKind, ShellKind,
};

// Structure query over execution-unit nodes.
//
// This exposes shell shape after structural expansion. It is intentionally
// separate from provenance traversal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionUnitHistoryQuery {
    window: SequenceWindow,
    before_execution_unit_node_id: Option<NodeId>,
}

impl ExecutionUnitHistoryQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn before_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.before_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> ExecutionUnitHistoryResult<'a> {
        let before_execution_unit = self
            .before_execution_unit_node_id
            .as_ref()
            .and_then(|node_id| session.graph().get_node(node_id))
            .and_then(ExecutionUnitRef::from_node);

        let mut execution_units: Vec<ExecutionUnitRef<'a>> = session
            .graph()
            .command_nodes_in_window(self.window.after_bound(), self.window.before_bound())
            .filter_map(ExecutionUnitRef::from_node)
            .chain(
                session
                    .graph()
                    .derived_invocation_nodes_in_window(
                        self.window.after_bound(),
                        self.window.before_bound(),
                    )
                    .filter_map(ExecutionUnitRef::from_node),
            )
            .filter(|unit| {
                before_execution_unit.is_none_or(|before| execution_unit_precedes(*unit, before))
            })
            .collect();

        execution_units.sort_by_key(|unit| execution_unit_order_key(*unit));

        ExecutionUnitHistoryResult { execution_units }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionUnitOrderKey {
    sequence_no: CommandSequenceNo,
    root_command_index: usize,
    depth: u8,
    origin_rank: u8,
    derived_command_index: usize,
    node_id: String,
}

pub fn execution_unit_precedes(left: ExecutionUnitRef<'_>, right: ExecutionUnitRef<'_>) -> bool {
    execution_unit_order_key(left) < execution_unit_order_key(right)
}

pub fn execution_unit_order_key(unit: ExecutionUnitRef<'_>) -> ExecutionUnitOrderKey {
    match unit {
        ExecutionUnitRef::TopLevel(command) => ExecutionUnitOrderKey {
            sequence_no: command.sequence_no(),
            root_command_index: top_level_command_index_from_node_id(command.node_id())
                .unwrap_or(usize::MAX),
            depth: 0,
            origin_rank: 0,
            derived_command_index: 0,
            node_id: command.node_id().0.clone(),
        },
        ExecutionUnitRef::Derived(derived) => ExecutionUnitOrderKey {
            sequence_no: derived.root_command_sequence_no(),
            root_command_index: derived_origin_root_command_index(derived.origin())
                .unwrap_or_else(|| derived.derived_command_index()),
            depth: derived.depth(),
            origin_rank: derived_origin_rank(derived.origin()),
            derived_command_index: derived.derived_command_index(),
            node_id: derived.node_id().0.clone(),
        },
    }
}

fn top_level_command_index_from_node_id(node_id: &NodeId) -> Option<usize> {
    if !node_id.0.starts_with("command:") {
        return None;
    }

    let parts: Vec<&str> = node_id.0.split(':').collect();
    match parts.as_slice() {
        ["command", _session_id, _sequence_no] => Some(0),
        ["command", _session_id, _sequence_no, index] => index.parse::<usize>().ok(),
        _ => None,
    }
}

fn derived_origin_root_command_index(origin: &DerivedInvocationOrigin) -> Option<usize> {
    match origin {
        DerivedInvocationOrigin::PipelineSegment { command_index }
        | DerivedInvocationOrigin::ShellCommandStringPayload { command_index }
        | DerivedInvocationOrigin::CommandSubstitutionMaterialization { command_index, .. } => {
            Some(*command_index)
        }
        DerivedInvocationOrigin::Dispatch {
            source_command_index,
            ..
        }
        | DerivedInvocationOrigin::AliasExpansion {
            source_command_index,
            ..
        }
        | DerivedInvocationOrigin::FunctionExpansion {
            source_command_index,
            ..
        } => Some(*source_command_index),
        DerivedInvocationOrigin::CommandSubstitutionAssignmentValue {
            assignment_command_index,
            ..
        } => Some(*assignment_command_index),
        DerivedInvocationOrigin::NestedPayload { .. }
        | DerivedInvocationOrigin::CommandSubstitutionBody { .. }
        | DerivedInvocationOrigin::ProcessSubstitution { .. }
        | DerivedInvocationOrigin::ProcessSubstitutionBody { .. }
        | DerivedInvocationOrigin::RecursivePayload { .. }
        | DerivedInvocationOrigin::StaticXargs { .. } => None,
    }
}

fn derived_origin_rank(origin: &DerivedInvocationOrigin) -> u8 {
    match origin {
        DerivedInvocationOrigin::PipelineSegment { .. } => 1,
        DerivedInvocationOrigin::CommandSubstitutionMaterialization { .. } => 2,
        DerivedInvocationOrigin::CommandSubstitutionAssignmentValue { .. } => 3,
        DerivedInvocationOrigin::CommandSubstitutionBody { .. } => 4,
        DerivedInvocationOrigin::ProcessSubstitution { .. } => 5,
        DerivedInvocationOrigin::ProcessSubstitutionBody { .. } => 6,
        DerivedInvocationOrigin::AliasExpansion { .. } => 7,
        DerivedInvocationOrigin::FunctionExpansion { .. } => 8,
        DerivedInvocationOrigin::Dispatch { .. } => 9,
        DerivedInvocationOrigin::ShellCommandStringPayload { .. } => 10,
        DerivedInvocationOrigin::StaticXargs { .. } => 11,
        DerivedInvocationOrigin::RecursivePayload { .. } => 12,
        DerivedInvocationOrigin::NestedPayload { .. } => 13,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionUnitHistoryResult<'a> {
    execution_units: Vec<ExecutionUnitRef<'a>>,
}

impl<'a> ExecutionUnitHistoryResult<'a> {
    pub fn execution_units(&self) -> &[ExecutionUnitRef<'a>] {
        self.execution_units.as_slice()
    }

    pub fn len(&self) -> usize {
        self.execution_units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.execution_units.is_empty()
    }
}

// Structure query over FlowsTo adjacency between execution units.
//
// This is useful for pipeline or dispatch shape inspection, but it must not
// be confused with content lineage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionUnitFlowQuery {
    from_node_id: Option<NodeId>,
    to_node_id: Option<NodeId>,
    window: SequenceWindow,
}

impl ExecutionUnitFlowQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_node_id(mut self, node_id: NodeId) -> Self {
        self.from_node_id = Some(node_id);
        self
    }

    pub fn to_node_id(mut self, node_id: NodeId) -> Self {
        self.to_node_id = Some(node_id);
        self
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> ExecutionUnitFlowResult<'a> {
        let mut flows = Vec::new();

        for from in self.flow_sources(session) {
            for edge in session.graph().outgoing_edges(from.node_id()) {
                if edge.kind != EdgeKind::FlowsTo {
                    continue;
                }

                if self.to_node_id.as_ref().is_some_and(|id| id != &edge.to) {
                    continue;
                }

                let Some(to_node) = session.graph().get_node(&edge.to) else {
                    continue;
                };
                let Some(to) = ExecutionUnitRef::from_node(to_node) else {
                    continue;
                };

                if !self.window.contains(to.root_command_sequence_no()) {
                    continue;
                }

                flows.push(ExecutionUnitFlowRef { from, to });
            }
        }

        flows.sort_by(|left, right| {
            left.from()
                .root_command_sequence_no()
                .cmp(&right.from().root_command_sequence_no())
                .then_with(|| left.from().depth().cmp(&right.from().depth()))
                .then_with(|| left.from().node_id().0.cmp(&right.from().node_id().0))
                .then_with(|| left.to().node_id().0.cmp(&right.to().node_id().0))
        });

        ExecutionUnitFlowResult { flows }
    }

    fn flow_sources<'a>(&self, session: QuerySession<'a>) -> Vec<ExecutionUnitRef<'a>> {
        match self.from_node_id.as_ref() {
            Some(node_id) => session
                .graph()
                .get_node(node_id)
                .and_then(ExecutionUnitRef::from_node)
                .filter(|unit| self.window.contains(unit.root_command_sequence_no()))
                .into_iter()
                .collect(),
            None => ExecutionUnitHistoryQuery::new()
                .window(self.window)
                .execute(session)
                .execution_units()
                .to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionUnitFlowResult<'a> {
    flows: Vec<ExecutionUnitFlowRef<'a>>,
}

impl<'a> ExecutionUnitFlowResult<'a> {
    pub fn flows(&self) -> &[ExecutionUnitFlowRef<'a>] {
        self.flows.as_slice()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionUnitFlowRef<'a> {
    from: ExecutionUnitRef<'a>,
    to: ExecutionUnitRef<'a>,
}

impl<'a> ExecutionUnitFlowRef<'a> {
    pub fn from(&self) -> ExecutionUnitRef<'a> {
        self.from
    }

    pub fn to(&self) -> ExecutionUnitRef<'a> {
        self.to
    }

    pub fn to_execution_unit_flow(&self) -> ExecutionUnitFlow {
        ExecutionUnitFlow {
            from: self.from.to_execution_unit(),
            to: self.to.to_execution_unit(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionUnitOrigin {
    TopLevel,
    Derived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionUnitRef<'a> {
    TopLevel(CommandInvocationRef<'a>),
    Derived(DerivedInvocationRef<'a>),
}

impl<'a> ExecutionUnitRef<'a> {
    pub(crate) fn from_node(node: &'a caushell_graph::GraphNode) -> Option<Self> {
        if let Some(command) = CommandInvocationRef::from_node(node) {
            return Some(Self::TopLevel(command));
        }

        DerivedInvocationRef::from_node(node).map(Self::Derived)
    }

    pub fn origin(&self) -> ExecutionUnitOrigin {
        match self {
            Self::TopLevel(_) => ExecutionUnitOrigin::TopLevel,
            Self::Derived(_) => ExecutionUnitOrigin::Derived,
        }
    }

    pub fn node_id(&self) -> &'a NodeId {
        match self {
            Self::TopLevel(command) => command.node_id(),
            Self::Derived(derived) => derived.node_id(),
        }
    }

    pub fn root_command_sequence_no(&self) -> CommandSequenceNo {
        match self {
            Self::TopLevel(command) => command.sequence_no(),
            Self::Derived(derived) => derived.root_command_sequence_no(),
        }
    }

    pub fn depth(&self) -> u8 {
        match self {
            Self::TopLevel(_) => 0,
            Self::Derived(derived) => derived.depth(),
        }
    }

    pub fn raw_text(&self) -> &'a str {
        match self {
            Self::TopLevel(command) => command.raw_text(),
            Self::Derived(derived) => derived.raw_text(),
        }
    }

    pub fn shell_kind(&self) -> ShellKind {
        match self {
            Self::TopLevel(command) => command.shell_kind(),
            Self::Derived(derived) => derived.shell_kind(),
        }
    }

    pub fn top_level(&self) -> Option<CommandInvocationRef<'a>> {
        match self {
            Self::TopLevel(command) => Some(*command),
            Self::Derived(_) => None,
        }
    }

    pub fn derived(&self) -> Option<DerivedInvocationRef<'a>> {
        match self {
            Self::TopLevel(_) => None,
            Self::Derived(derived) => Some(*derived),
        }
    }

    pub fn to_execution_unit(&self) -> ExecutionUnit {
        ExecutionUnit {
            node_id: self.node_id().0.clone(),
            execution_kind: match self.origin() {
                ExecutionUnitOrigin::TopLevel => ExecutionUnitKind::TopLevel,
                ExecutionUnitOrigin::Derived => ExecutionUnitKind::Derived,
            },
            root_sequence_no: self.root_command_sequence_no(),
            depth: self.depth(),
            raw_text: self.raw_text().to_string(),
            shell_kind: self.shell_kind(),
        }
    }
}

// Semantic-label query over ExecutionSemantics nodes attached to execution
// units through Defines edges.
//
// This reports execution-role meaning such as payload mode or config loading.
// It is not itself a provenance query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionSemanticsQuery {
    window: SequenceWindow,
    execution_unit_node_id: Option<NodeId>,
    normalized_command_name: Option<String>,
    form_id: Option<String>,
    payload_mode: Option<Option<ExecutionPayloadMode>>,
    executes_payload: Option<bool>,
    opens_interactive_escape_surface: Option<bool>,
    interactive_escape_surface_kind: Option<Option<InteractiveEscapeSurfaceKind>>,
    interactive_escape_requires_tty: Option<bool>,
    controls_process: Option<bool>,
    process_control_action: Option<Option<ProcessControlAction>>,
    process_control_target_kind: Option<Option<ProcessControlTargetKind>>,
    process_control_broad_target: Option<bool>,
    mutates_current_shell: Option<bool>,
    executes_remote_command: Option<bool>,
    executes_hook: Option<bool>,
    executes_imported_package_logic: Option<bool>,
    loads_in_process_code: Option<bool>,
    in_process_code_load_kind: Option<InProcessCodeLoadKind>,
    loads_startup_config: Option<bool>,
    loads_project_config: Option<bool>,
    loads_tool_config: Option<bool>,
    executes_config_defined_task: Option<bool>,
    dispatches_child_command: Option<bool>,
}

impl ExecutionSemanticsQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.execution_unit_node_id = Some(node_id);
        self
    }

    pub fn normalized_command_name(mut self, normalized_command_name: impl Into<String>) -> Self {
        self.normalized_command_name = Some(normalized_command_name.into());
        self
    }

    pub fn form_id(mut self, form_id: impl Into<String>) -> Self {
        self.form_id = Some(form_id.into());
        self
    }

    pub fn payload_mode(mut self, payload_mode: ExecutionPayloadMode) -> Self {
        self.payload_mode = Some(Some(payload_mode));
        self
    }

    pub fn without_payload_mode(mut self) -> Self {
        self.payload_mode = Some(None);
        self
    }

    pub fn executes_payload(mut self, executes_payload: bool) -> Self {
        self.executes_payload = Some(executes_payload);
        self
    }

    pub fn opens_interactive_escape_surface(
        mut self,
        opens_interactive_escape_surface: bool,
    ) -> Self {
        self.opens_interactive_escape_surface = Some(opens_interactive_escape_surface);
        self
    }

    pub fn interactive_escape_surface_kind(
        mut self,
        interactive_escape_surface_kind: InteractiveEscapeSurfaceKind,
    ) -> Self {
        self.interactive_escape_surface_kind = Some(Some(interactive_escape_surface_kind));
        self
    }

    pub fn without_interactive_escape_surface_kind(mut self) -> Self {
        self.interactive_escape_surface_kind = Some(None);
        self
    }

    pub fn interactive_escape_requires_tty(
        mut self,
        interactive_escape_requires_tty: bool,
    ) -> Self {
        self.interactive_escape_requires_tty = Some(interactive_escape_requires_tty);
        self
    }

    pub fn controls_process(mut self, controls_process: bool) -> Self {
        self.controls_process = Some(controls_process);
        self
    }

    pub fn process_control_action(mut self, action: ProcessControlAction) -> Self {
        self.process_control_action = Some(Some(action));
        self
    }

    pub fn without_process_control_action(mut self) -> Self {
        self.process_control_action = Some(None);
        self
    }

    pub fn process_control_target_kind(mut self, target_kind: ProcessControlTargetKind) -> Self {
        self.process_control_target_kind = Some(Some(target_kind));
        self
    }

    pub fn without_process_control_target_kind(mut self) -> Self {
        self.process_control_target_kind = Some(None);
        self
    }

    pub fn process_control_broad_target(mut self, broad_target: bool) -> Self {
        self.process_control_broad_target = Some(broad_target);
        self
    }

    pub fn mutates_current_shell(mut self, mutates_current_shell: bool) -> Self {
        self.mutates_current_shell = Some(mutates_current_shell);
        self
    }

    pub fn executes_remote_command(mut self, executes_remote_command: bool) -> Self {
        self.executes_remote_command = Some(executes_remote_command);
        self
    }

    pub fn executes_hook(mut self, executes_hook: bool) -> Self {
        self.executes_hook = Some(executes_hook);
        self
    }

    pub fn executes_imported_package_logic(
        mut self,
        executes_imported_package_logic: bool,
    ) -> Self {
        self.executes_imported_package_logic = Some(executes_imported_package_logic);
        self
    }

    pub fn loads_in_process_code(mut self, loads_in_process_code: bool) -> Self {
        self.loads_in_process_code = Some(loads_in_process_code);
        self
    }

    pub fn in_process_code_load_kind(mut self, load_kind: InProcessCodeLoadKind) -> Self {
        self.in_process_code_load_kind = Some(load_kind);
        self
    }

    pub fn loads_startup_config(mut self, loads_startup_config: bool) -> Self {
        self.loads_startup_config = Some(loads_startup_config);
        self
    }

    pub fn loads_project_config(mut self, loads_project_config: bool) -> Self {
        self.loads_project_config = Some(loads_project_config);
        self
    }

    pub fn loads_tool_config(mut self, loads_tool_config: bool) -> Self {
        self.loads_tool_config = Some(loads_tool_config);
        self
    }

    pub fn executes_config_defined_task(mut self, executes_config_defined_task: bool) -> Self {
        self.executes_config_defined_task = Some(executes_config_defined_task);
        self
    }

    pub fn dispatches_child_command(mut self, dispatches_child_command: bool) -> Self {
        self.dispatches_child_command = Some(dispatches_child_command);
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> ExecutionSemanticsResult<'a> {
        let mut semantics: Vec<ExecutionSemanticsRef<'a>> = self
            .semantics_candidate_nodes(session)
            .into_iter()
            .filter_map(|node| ExecutionSemanticsRef::from_node(node, session))
            .filter(|semantics| self.matches(semantics))
            .collect();

        semantics.sort_by(|left, right| {
            left.source()
                .root_command_sequence_no()
                .cmp(&right.source().root_command_sequence_no())
                .then_with(|| left.source().depth().cmp(&right.source().depth()))
                .then_with(|| left.source().node_id().0.cmp(&right.source().node_id().0))
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        ExecutionSemanticsResult { semantics }
    }

    fn matches(&self, semantics: &ExecutionSemanticsRef<'_>) -> bool {
        self.window
            .contains(semantics.source().root_command_sequence_no())
            && self
                .execution_unit_node_id
                .as_ref()
                .is_none_or(|node_id| semantics.source().node_id() == node_id)
            && self
                .normalized_command_name
                .as_deref()
                .is_none_or(|name| semantics.normalized_command_name() == name)
            && self
                .form_id
                .as_deref()
                .is_none_or(|form_id| semantics.form_id() == form_id)
            && self
                .payload_mode
                .is_none_or(|payload_mode| semantics.payload_mode() == payload_mode)
            && self
                .executes_payload
                .is_none_or(|executes_payload| semantics.executes_payload() == executes_payload)
            && self
                .opens_interactive_escape_surface
                .is_none_or(|value| semantics.opens_interactive_escape_surface() == value)
            && self
                .interactive_escape_surface_kind
                .is_none_or(|kind| semantics.interactive_escape_surface_kind() == kind)
            && self
                .interactive_escape_requires_tty
                .is_none_or(|value| semantics.interactive_escape_requires_tty() == value)
            && self
                .controls_process
                .is_none_or(|value| semantics.controls_process() == value)
            && self
                .process_control_action
                .is_none_or(|value| semantics.process_control_action() == value)
            && self
                .process_control_target_kind
                .is_none_or(|value| semantics.process_control_target_kind() == value)
            && self
                .process_control_broad_target
                .is_none_or(|value| semantics.process_control_broad_target() == value)
            && self
                .mutates_current_shell
                .is_none_or(|mutates_current_shell| {
                    semantics.mutates_current_shell() == mutates_current_shell
                })
            && self
                .executes_remote_command
                .is_none_or(|executes_remote_command| {
                    semantics.executes_remote_command() == executes_remote_command
                })
            && self
                .executes_hook
                .is_none_or(|executes_hook| semantics.executes_hook() == executes_hook)
            && self
                .executes_imported_package_logic
                .is_none_or(|executes_imported_package_logic| {
                    semantics.executes_imported_package_logic() == executes_imported_package_logic
                })
            && self
                .loads_in_process_code
                .is_none_or(|loads_in_process_code| {
                    semantics.loads_in_process_code() == loads_in_process_code
                })
            && self
                .in_process_code_load_kind
                .is_none_or(|load_kind| semantics.in_process_code_load_kinds().contains(&load_kind))
            && self
                .loads_startup_config
                .is_none_or(|loads_startup_config| {
                    semantics.loads_startup_config() == loads_startup_config
                })
            && self
                .loads_project_config
                .is_none_or(|loads_project_config| {
                    semantics.loads_project_config() == loads_project_config
                })
            && self
                .loads_tool_config
                .is_none_or(|loads_tool_config| semantics.loads_tool_config() == loads_tool_config)
            && self
                .executes_config_defined_task
                .is_none_or(|executes_config_defined_task| {
                    semantics.executes_config_defined_task() == executes_config_defined_task
                })
            && self
                .dispatches_child_command
                .is_none_or(|dispatches_child_command| {
                    semantics.dispatches_child_command() == dispatches_child_command
                })
    }

    fn semantics_candidate_nodes<'a>(
        &self,
        session: QuerySession<'a>,
    ) -> Vec<&'a caushell_graph::GraphNode> {
        match self.execution_unit_node_id.as_ref() {
            Some(node_id) => session
                .graph()
                .outgoing_edges(node_id)
                .filter(|edge| edge.kind == EdgeKind::Defines)
                .filter_map(|edge| session.graph().get_node(&edge.to))
                .collect(),
            None => session
                .graph()
                .execution_semantics_nodes_in_window(
                    self.window.after_bound(),
                    self.window.before_bound(),
                )
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSemanticsResult<'a> {
    semantics: Vec<ExecutionSemanticsRef<'a>>,
}

impl<'a> ExecutionSemanticsResult<'a> {
    pub fn semantics(&self) -> &[ExecutionSemanticsRef<'a>] {
        self.semantics.as_slice()
    }

    pub fn len(&self) -> usize {
        self.semantics.len()
    }

    pub fn is_empty(&self) -> bool {
        self.semantics.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionSemanticsRef<'a> {
    node_id: &'a NodeId,
    source: ExecutionUnitRef<'a>,
    semantics: &'a caushell_types::ExecutionSemantics,
}

impl<'a> ExecutionSemanticsRef<'a> {
    pub(crate) fn from_node(
        node: &'a caushell_graph::GraphNode,
        session: QuerySession<'a>,
    ) -> Option<Self> {
        let NodeKind::ExecutionSemantics { semantics } = &node.kind else {
            return None;
        };

        Some(Self {
            node_id: &node.id,
            source: collect_execution_semantics_source(session, &node.id)?,
            semantics,
        })
    }

    pub fn node_id(&self) -> &'a NodeId {
        self.node_id
    }

    pub fn source(&self) -> ExecutionUnitRef<'a> {
        self.source
    }

    pub fn semantics(&self) -> &'a caushell_types::ExecutionSemantics {
        self.semantics
    }

    pub fn normalized_command_name(&self) -> &'a str {
        self.semantics.normalized_command_name.as_str()
    }

    pub fn form_id(&self) -> &'a str {
        self.semantics.form_id.as_str()
    }

    pub fn payload_mode(&self) -> Option<ExecutionPayloadMode> {
        self.semantics.payload_mode
    }

    pub fn executes_payload(&self) -> bool {
        self.semantics.executes_payload
    }

    pub fn opens_interactive_escape_surface(&self) -> bool {
        self.semantics.opens_interactive_escape_surface
    }

    pub fn interactive_escape_surface_kind(&self) -> Option<InteractiveEscapeSurfaceKind> {
        self.semantics.interactive_escape_surface_kind
    }

    pub fn interactive_escape_capabilities(
        &self,
    ) -> &[caushell_types::InteractiveEscapeCapability] {
        self.semantics.interactive_escape_capabilities.as_slice()
    }

    pub fn interactive_escape_requires_tty(&self) -> bool {
        self.semantics.interactive_escape_requires_tty
    }

    pub fn controls_process(&self) -> bool {
        self.semantics.controls_process
    }

    pub fn process_control_action(&self) -> Option<ProcessControlAction> {
        self.semantics.process_control_action
    }

    pub fn process_control_target_kind(&self) -> Option<ProcessControlTargetKind> {
        self.semantics.process_control_target_kind
    }

    pub fn process_control_broad_target(&self) -> bool {
        self.semantics.process_control_broad_target
    }

    pub fn mutates_current_shell(&self) -> bool {
        self.semantics.mutates_current_shell
    }

    pub fn executes_remote_command(&self) -> bool {
        self.semantics.executes_remote_command
    }

    pub fn executes_hook(&self) -> bool {
        self.semantics.executes_hook
    }

    pub fn executes_imported_package_logic(&self) -> bool {
        self.semantics.executes_imported_package_logic
    }

    pub fn loads_in_process_code(&self) -> bool {
        self.semantics.loads_in_process_code
    }

    pub fn in_process_code_load_kinds(&self) -> &[InProcessCodeLoadKind] {
        self.semantics.in_process_code_load_kinds.as_slice()
    }

    pub fn loads_startup_config(&self) -> bool {
        self.semantics.loads_startup_config
    }

    pub fn loads_project_config(&self) -> bool {
        self.semantics.loads_project_config
    }

    pub fn loads_tool_config(&self) -> bool {
        self.semantics.loads_tool_config
    }

    pub fn executes_config_defined_task(&self) -> bool {
        self.semantics.executes_config_defined_task
    }

    pub fn dispatches_child_command(&self) -> bool {
        self.semantics.dispatches_child_command
    }

    pub fn to_execution_semantics_fact(&self) -> ExecutionSemanticsFact {
        ExecutionSemanticsFact {
            node_id: self.node_id.0.clone(),
            source: self.source.to_execution_unit(),
            normalized_command_name: self.normalized_command_name().to_string(),
            form_id: self.form_id().to_string(),
            payload_mode: self.payload_mode(),
            executes_payload: self.executes_payload(),
            opens_interactive_escape_surface: self.opens_interactive_escape_surface(),
            interactive_escape_surface_kind: self.interactive_escape_surface_kind(),
            interactive_escape_capabilities: self.interactive_escape_capabilities().to_vec(),
            interactive_escape_requires_tty: self.interactive_escape_requires_tty(),
            controls_process: self.controls_process(),
            process_control_action: self.process_control_action(),
            process_control_target_kind: self.process_control_target_kind(),
            process_control_broad_target: self.process_control_broad_target(),
            mutates_current_shell: self.mutates_current_shell(),
            executes_remote_command: self.executes_remote_command(),
            executes_hook: self.executes_hook(),
            executes_imported_package_logic: self.executes_imported_package_logic(),
            loads_in_process_code: self.loads_in_process_code(),
            in_process_code_load_kinds: self.in_process_code_load_kinds().to_vec(),
            loads_startup_config: self.loads_startup_config(),
            loads_project_config: self.loads_project_config(),
            loads_tool_config: self.loads_tool_config(),
            executes_config_defined_task: self.executes_config_defined_task(),
            dispatches_child_command: self.dispatches_child_command(),
        }
    }
}

fn collect_execution_semantics_source<'a>(
    session: QuerySession<'a>,
    semantics_node_id: &NodeId,
) -> Option<ExecutionUnitRef<'a>> {
    for edge in session.graph().incoming_edges(semantics_node_id) {
        if edge.kind != EdgeKind::Defines {
            continue;
        }

        let Some(source_node) = session.graph().get_node(&edge.from) else {
            continue;
        };

        if let Some(source) = ExecutionUnitRef::from_node(source_node) {
            return Some(source);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutionSemanticsQuery, ExecutionUnitFlowQuery, ExecutionUnitHistoryQuery,
        ExecutionUnitOrigin, ExecutionUnitRef,
    };
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode, ExecutionSemantics,
        ExecutionSemanticsFact, ExecutionUnit, ExecutionUnitFlow, ExecutionUnitKind,
        InProcessCodeLoadKind, PathResolution, ResolvedPathPurpose, ResolvedPathRole, SessionId,
        SessionSummary, ShellKind,
    };

    fn graph_with_execution_units() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:7"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(7),
            "bash -c 'echo later'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "bash -c 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:9"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(9),
            "ssh build.example.test 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:2:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(2),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "echo ok".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:7:1:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(7),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 1,
                },
                derived_command_index: 0,
                raw_text: "echo later".to_string(),
                command_name: Some("echo".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 2,
            },
        ));

        graph
    }

    fn graph_with_execution_unit_flows() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:4:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(4),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                derived_command_index: 0,
                raw_text: "cat payload.sh".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:4:1"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(4),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                derived_command_index: 1,
                raw_text: "bash".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:4:2"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(4),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 2 },
                derived_command_index: 2,
                raw_text: "wc -l".to_string(),
                command_name: Some("wc".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));

        graph
            .add_edge(Edge::new(
                NodeId::new("pipeline-segment:sess-1:4:0"),
                NodeId::new("pipeline-segment:sess-1:4:1"),
                EdgeKind::FlowsTo,
            ))
            .expect("expected first flow edge to be valid");
        graph
            .add_edge(Edge::new(
                NodeId::new("pipeline-segment:sess-1:4:1"),
                NodeId::new("pipeline-segment:sess-1:4:2"),
                EdgeKind::FlowsTo,
            ))
            .expect("expected second flow edge to be valid");

        graph
    }

    fn graph_with_execution_semantics() -> SessionGraph {
        let mut graph = graph_with_execution_units();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:2"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload()
                    .loading_startup_config(),
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:derived:sess-1:2:0:0"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("echo", "default"),
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:7"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:orphan"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:9"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("ssh", "remote_command")
                    .executing_remote_command(),
            },
        ));

        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:2"),
                NodeId::new("execution-semantics:command:sess-1:2"),
                EdgeKind::Defines,
            ))
            .expect("expected top-level semantics edge to be valid");
        graph
            .add_edge(Edge::new(
                NodeId::new("derived:sess-1:2:0:0"),
                NodeId::new("execution-semantics:derived:sess-1:2:0:0"),
                EdgeKind::Defines,
            ))
            .expect("expected derived semantics edge to be valid");
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:7"),
                NodeId::new("execution-semantics:command:sess-1:7"),
                EdgeKind::Defines,
            ))
            .expect("expected second top-level semantics edge to be valid");
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:9"),
                NodeId::new("execution-semantics:command:sess-1:9"),
                EdgeKind::Defines,
            ))
            .expect("expected remote execution semantics edge to be valid");

        graph
    }

    struct PanicOnFullScanGraph<'a> {
        inner: &'a SessionGraph,
    }

    impl GraphRead for PanicOnFullScanGraph<'_> {
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
            panic!("execution query should not require graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("execution query should not require graph.edges()");
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
    fn execution_unit_history_query_returns_empty_when_graph_has_none() {
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new().execute(session);

        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn execution_unit_history_query_returns_top_level_and_derived_sorted_together() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new().execute(session);
        let ids: Vec<&str> = result
            .execution_units()
            .iter()
            .map(|unit| unit.node_id().0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "command:sess-1:2",
                "derived:sess-1:2:0:0",
                "command:sess-1:7",
                "derived:sess-1:7:1:0",
                "command:sess-1:9",
            ]
        );
    }

    #[test]
    fn execution_unit_history_query_filters_strictly_before_sequence() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(7))
            .execute(session);

        assert_eq!(result.len(), 2);
        assert!(
            result
                .execution_units()
                .iter()
                .all(|unit| unit.root_command_sequence_no().0 == 2)
        );
    }

    #[test]
    fn execution_unit_history_query_filters_strictly_after_sequence() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new()
            .after_sequence(CommandSequenceNo::new(2))
            .execute(session);

        assert_eq!(result.len(), 3);
        let roots: Vec<u64> = result
            .execution_units()
            .iter()
            .map(|unit| unit.root_command_sequence_no().0)
            .collect();
        assert_eq!(roots, vec![7, 7, 9]);
    }

    #[test]
    fn execution_unit_history_query_can_use_shared_sequence_window() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new()
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(2))
                    .before_sequence(CommandSequenceNo::new(8)),
            )
            .execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.execution_units()[0].origin(),
            ExecutionUnitOrigin::TopLevel
        );
        assert_eq!(
            result.execution_units()[1].origin(),
            ExecutionUnitOrigin::Derived
        );
    }

    #[test]
    fn execution_unit_history_query_exposes_unified_fields() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session);

        assert_eq!(
            result.execution_units()[0].origin(),
            ExecutionUnitOrigin::TopLevel
        );
        assert_eq!(result.execution_units()[0].depth(), 0);
        assert_eq!(result.execution_units()[0].raw_text(), "bash -c 'echo ok'");
        assert_eq!(result.execution_units()[0].shell_kind(), ShellKind::Bash);

        assert_eq!(
            result.execution_units()[1].origin(),
            ExecutionUnitOrigin::Derived
        );
        assert_eq!(result.execution_units()[1].depth(), 1);
        assert_eq!(result.execution_units()[1].raw_text(), "echo ok");
        assert_eq!(result.execution_units()[1].shell_kind(), ShellKind::Bash);
    }

    #[test]
    fn execution_unit_ref_can_be_downcast_to_specific_origin() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session);

        let top_level = result.execution_units()[0]
            .top_level()
            .expect("expected top-level unit");
        let derived = result.execution_units()[1]
            .derived()
            .expect("expected derived unit");

        assert_eq!(top_level.sequence_no(), CommandSequenceNo::new(2));
        assert_eq!(derived.nested_record_id(), Some(0));
    }

    #[test]
    fn execution_unit_ref_converts_to_contract_value() {
        let graph = graph_with_execution_units();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let result = ExecutionUnitHistoryQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session);

        assert_eq!(
            result.execution_units()[0].to_execution_unit(),
            ExecutionUnit {
                node_id: "command:sess-1:2".to_string(),
                execution_kind: ExecutionUnitKind::TopLevel,
                root_sequence_no: CommandSequenceNo::new(2),
                depth: 0,
                raw_text: "bash -c 'echo ok'".to_string(),
                shell_kind: ShellKind::Bash,
            }
        );
        assert_eq!(
            result.execution_units()[1].to_execution_unit(),
            ExecutionUnit {
                node_id: "derived:sess-1:2:0:0".to_string(),
                execution_kind: ExecutionUnitKind::Derived,
                root_sequence_no: CommandSequenceNo::new(2),
                depth: 1,
                raw_text: "echo ok".to_string(),
                shell_kind: ShellKind::Bash,
            }
        );
    }

    #[test]
    fn execution_unit_ref_ignores_non_execution_nodes() {
        let mut graph = SessionGraph::new();
        let _ = graph.add_path_fact(
            NodeId::new("path-1"),
            PathResolution::Concrete {
                path: "/tmp/project/file".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            None,
        );

        let node = graph
            .get_node(&NodeId::new("path-1"))
            .expect("expected path node to exist");

        assert_eq!(ExecutionUnitRef::from_node(node), None);
    }

    #[test]
    fn execution_unit_flow_query_returns_adjacent_execution_flows() {
        let graph = graph_with_execution_unit_flows();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionUnitFlowQuery::new().execute(session);
        let flows: Vec<(&str, &str)> = result
            .flows()
            .iter()
            .map(|flow| {
                (
                    flow.from().node_id().0.as_str(),
                    flow.to().node_id().0.as_str(),
                )
            })
            .collect();

        assert_eq!(
            flows,
            vec![
                ("pipeline-segment:sess-1:4:0", "pipeline-segment:sess-1:4:1"),
                ("pipeline-segment:sess-1:4:1", "pipeline-segment:sess-1:4:2"),
            ]
        );
    }

    #[test]
    fn execution_unit_flow_query_can_filter_by_from_or_to_node() {
        let graph = graph_with_execution_unit_flows();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let downstream = ExecutionUnitFlowQuery::new()
            .from_node_id(NodeId::new("pipeline-segment:sess-1:4:1"))
            .execute(session);
        let upstream = ExecutionUnitFlowQuery::new()
            .to_node_id(NodeId::new("pipeline-segment:sess-1:4:1"))
            .execute(session);

        assert_eq!(downstream.len(), 1);
        assert_eq!(
            downstream.flows()[0].to().node_id(),
            &NodeId::new("pipeline-segment:sess-1:4:2")
        );
        assert_eq!(upstream.len(), 1);
        assert_eq!(
            upstream.flows()[0].from().node_id(),
            &NodeId::new("pipeline-segment:sess-1:4:0")
        );
    }

    #[test]
    fn execution_unit_flow_ref_converts_to_contract_value() {
        let graph = graph_with_execution_unit_flows();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let flow = ExecutionUnitFlowQuery::new().execute(session).flows()[0].clone();

        assert_eq!(
            flow.to_execution_unit_flow(),
            ExecutionUnitFlow {
                from: ExecutionUnit {
                    node_id: "pipeline-segment:sess-1:4:0".to_string(),
                    execution_kind: ExecutionUnitKind::Derived,
                    root_sequence_no: CommandSequenceNo::new(4),
                    depth: 0,
                    raw_text: "cat payload.sh".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                to: ExecutionUnit {
                    node_id: "pipeline-segment:sess-1:4:1".to_string(),
                    execution_kind: ExecutionUnitKind::Derived,
                    root_sequence_no: CommandSequenceNo::new(4),
                    depth: 0,
                    raw_text: "bash".to_string(),
                    shell_kind: ShellKind::Bash,
                },
            }
        );
    }

    #[test]
    fn execution_semantics_query_returns_semantics_sorted_by_execution_unit() {
        let graph = graph_with_execution_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionSemanticsQuery::new().execute(session);
        let ids: Vec<&str> = result
            .semantics()
            .iter()
            .map(|semantics| semantics.node_id().0.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "execution-semantics:command:sess-1:2",
                "execution-semantics:derived:sess-1:2:0:0",
                "execution-semantics:command:sess-1:7",
                "execution-semantics:command:sess-1:9",
            ]
        );
    }

    #[test]
    fn execution_semantics_query_can_filter_by_payload_and_sequence_window() {
        let graph = graph_with_execution_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionSemanticsQuery::new()
            .payload_mode(ExecutionPayloadMode::CommandString)
            .executes_payload(true)
            .before_sequence(CommandSequenceNo::new(7))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.semantics()[0].normalized_command_name(), "bash");
        assert_eq!(
            result.semantics()[0].payload_mode(),
            Some(ExecutionPayloadMode::CommandString)
        );
        assert!(result.semantics()[0].loads_startup_config());
    }

    #[test]
    fn execution_semantics_query_can_filter_by_execution_unit_and_missing_payload_mode() {
        let graph = graph_with_execution_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionSemanticsQuery::new()
            .execution_unit_node_id(NodeId::new("derived:sess-1:2:0:0"))
            .without_payload_mode()
            .dispatches_child_command(false)
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.semantics()[0].source().node_id(),
            &NodeId::new("derived:sess-1:2:0:0")
        );
        assert_eq!(result.semantics()[0].normalized_command_name(), "echo");
        assert_eq!(result.semantics()[0].payload_mode(), None);
    }

    #[test]
    fn execution_semantics_ref_converts_to_contract_value() {
        let graph = graph_with_execution_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let semantics = ExecutionSemanticsQuery::new()
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .semantics()[0]
            .clone();

        assert_eq!(
            semantics.to_execution_semantics_fact(),
            ExecutionSemanticsFact {
                node_id: "execution-semantics:command:sess-1:2".to_string(),
                source: ExecutionUnit {
                    node_id: "command:sess-1:2".to_string(),
                    execution_kind: ExecutionUnitKind::TopLevel,
                    root_sequence_no: CommandSequenceNo::new(2),
                    depth: 0,
                    raw_text: "bash -c 'echo ok'".to_string(),
                    shell_kind: ShellKind::Bash,
                },
                normalized_command_name: "bash".to_string(),
                form_id: "command_string".to_string(),
                payload_mode: Some(ExecutionPayloadMode::CommandString),
                executes_payload: true,
                opens_interactive_escape_surface: false,
                interactive_escape_surface_kind: None,
                interactive_escape_capabilities: vec![],
                interactive_escape_requires_tty: false,
                controls_process: false,
                process_control_action: None,
                process_control_target_kind: None,
                process_control_broad_target: false,
                mutates_current_shell: false,
                executes_remote_command: false,
                executes_hook: false,
                executes_imported_package_logic: false,
                loads_in_process_code: false,
                in_process_code_load_kinds: vec![],
                loads_startup_config: true,
                loads_project_config: false,
                loads_tool_config: false,
                executes_config_defined_task: false,
                dispatches_child_command: false,
            }
        );
    }

    #[test]
    fn execution_semantics_query_can_filter_config_defined_task_semantics() {
        let mut graph = graph_with_execution_units();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:7"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("npm", "run_script")
                    .loading_project_config()
                    .executing_config_defined_task(),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:7"),
                NodeId::new("execution-semantics:command:sess-1:7"),
                EdgeKind::Defines,
            ))
            .expect("expected semantics edge to be valid");

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let result = ExecutionSemanticsQuery::new()
            .loads_project_config(true)
            .loads_tool_config(false)
            .executes_config_defined_task(true)
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.semantics()[0].normalized_command_name(), "npm");
        assert!(!result.semantics()[0].executes_payload());
        assert!(result.semantics()[0].loads_project_config());
        assert!(!result.semantics()[0].loads_tool_config());
        assert!(result.semantics()[0].executes_config_defined_task());
    }

    #[test]
    fn execution_semantics_query_can_filter_hook_execution_semantics() {
        let mut graph = graph_with_execution_units();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:8"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(8),
            "git commit -m 'ship it'",
            "/tmp/project",
            ShellKind::Bash,
        );

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:8"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("git", "commit_with_hooks")
                    .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                    .executing_payload()
                    .executing_hook()
                    .loading_tool_config(),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:8"),
                NodeId::new("execution-semantics:command:sess-1:8"),
                EdgeKind::Defines,
            ))
            .expect("expected semantics edge to be valid");

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let result = ExecutionSemanticsQuery::new()
            .executes_hook(true)
            .loads_tool_config(true)
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.semantics()[0].normalized_command_name(), "git");
        assert!(result.semantics()[0].executes_payload());
        assert!(result.semantics()[0].executes_hook());
        assert!(result.semantics()[0].loads_tool_config());
        assert_eq!(
            result.semantics()[0].payload_mode(),
            Some(ExecutionPayloadMode::ScriptFile)
        );
    }

    #[test]
    fn execution_semantics_query_can_filter_in_process_code_load_kind() {
        let mut graph = graph_with_execution_units();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:10"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(10),
            "python -m http.server",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:10"),
            caushell_graph::NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("python", "module")
                    .loading_in_process_code(InProcessCodeLoadKind::ModuleName),
            },
        ));
        graph
            .add_edge(Edge::new(
                NodeId::new("command:sess-1:10"),
                NodeId::new("execution-semantics:command:sess-1:10"),
                EdgeKind::Defines,
            ))
            .expect("expected semantics edge to be valid");

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let result = ExecutionSemanticsQuery::new()
            .loads_in_process_code(true)
            .in_process_code_load_kind(InProcessCodeLoadKind::ModuleName)
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.semantics()[0].normalized_command_name(), "python");
        assert!(result.semantics()[0].loads_in_process_code());
        assert_eq!(
            result.semantics()[0].in_process_code_load_kinds(),
            &[InProcessCodeLoadKind::ModuleName]
        );
    }

    #[test]
    fn execution_semantics_query_can_filter_remote_command_semantics() {
        let graph = graph_with_execution_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = ExecutionSemanticsQuery::new()
            .executes_remote_command(true)
            .without_payload_mode()
            .execute(session);

        assert_eq!(result.len(), 1);
        let semantics = result.semantics()[0];
        assert_eq!(semantics.normalized_command_name(), "ssh");
        assert_eq!(semantics.form_id(), "remote_command");
        assert!(semantics.executes_remote_command());
        assert!(!semantics.executes_payload());
        assert_eq!(semantics.payload_mode(), None);
        assert_eq!(
            semantics.source().node_id(),
            &NodeId::new("command:sess-1:9")
        );
    }

    #[test]
    fn execution_queries_do_not_require_full_graph_scan() {
        let graph = graph_with_execution_semantics();
        let wrapped = PanicOnFullScanGraph { inner: &graph };
        let summary = SessionSummary::new();
        let session = QuerySession::new(&wrapped, &summary);

        let units = ExecutionUnitHistoryQuery::new().execute(session);
        assert!(!units.is_empty());

        let flow_graph = graph_with_execution_unit_flows();
        let flow_wrapped = PanicOnFullScanGraph { inner: &flow_graph };
        let flow_session = QuerySession::new(&flow_wrapped, &summary);
        let flows = ExecutionUnitFlowQuery::new()
            .after_sequence(CommandSequenceNo::new(3))
            .before_sequence(CommandSequenceNo::new(5))
            .execute(flow_session);
        assert!(!flows.is_empty());

        let semantics = ExecutionSemanticsQuery::new().execute(session);
        assert!(!semantics.is_empty());
    }
}
