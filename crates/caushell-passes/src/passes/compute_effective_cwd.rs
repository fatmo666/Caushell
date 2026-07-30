use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::NodeId;
use caushell_parse::{CommandFact, ParsedCommandArtifact, SourceSpan, StatementTerminator};
use caushell_profile::{
    BoundArgumentMaterialization, BoundInvocation, BoundValue, EffectKind, EffectTarget,
    PathPurpose, PathRole, ResolveInvocationArtifactResult, SemanticType,
};
use caushell_runner::{
    EffectiveCwd, ExecutionUnitOriginKind, ExecutionUnitOriginLocator, ExecutionUnitResolveRecord,
    NestedPayloadParentRef, NestedPayloadResolution, RunnerContext, SessionTransformPass,
    SessionView,
};

use crate::path::{normalize_shell_path, resolve_path_operand};
use crate::support::source_node_id_for_command;

pub struct ComputeEffectiveCwdPass;

impl SessionTransformPass for ComputeEffectiveCwdPass {
    fn name(&self) -> &'static str {
        "compute_effective_cwd"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let (effective_cwds, request_exit_cwd) = {
            let records_by_node = ctx
                .execution_unit_resolve_records()
                .iter()
                .map(|record| (record.source_node_id.clone(), record))
                .collect::<BTreeMap<_, _>>();
            let function_records_by_parent =
                function_records_by_parent(ctx.execution_unit_resolve_records());
            let mut effective_cwds = BTreeMap::new();
            let known_existing_dirs = known_existing_dirs(ctx);

            let initial_cwd = initial_cwd(ctx, _session);
            let request_exit_cwd = if let Some(parsed) = ctx.parsed_command() {
                compute_request_scope_cwds(
                    ctx,
                    parsed,
                    initial_cwd,
                    &records_by_node,
                    &function_records_by_parent,
                    &known_existing_dirs,
                    &mut effective_cwds,
                )
            } else {
                EffectiveCwd::known(initial_cwd)
            };

            compute_derived_scope_cwds(
                ctx,
                initial_cwd,
                &records_by_node,
                &known_existing_dirs,
                &mut effective_cwds,
            );
            (effective_cwds, request_exit_cwd)
        };

        ctx.set_effective_cwds(effective_cwds);
        ctx.set_request_exit_cwd(request_exit_cwd);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CwdState {
    known: BTreeSet<String>,
    unknown: bool,
}

impl CwdState {
    fn empty() -> Self {
        Self {
            known: BTreeSet::new(),
            unknown: false,
        }
    }

    fn known(cwd: impl Into<String>) -> Self {
        Self {
            known: BTreeSet::from([cwd.into()]),
            unknown: false,
        }
    }

    fn unknown() -> Self {
        Self {
            known: BTreeSet::new(),
            unknown: true,
        }
    }

    fn add_known(&mut self, cwd: impl Into<String>) {
        self.known.insert(cwd.into());
    }

    fn add_unknown(&mut self) {
        self.unknown = true;
    }

    fn is_empty(&self) -> bool {
        self.known.is_empty() && !self.unknown
    }

    fn merge(&mut self, other: &Self) {
        self.known.extend(other.known.iter().cloned());
        self.unknown |= other.unknown;
    }

    fn merged(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.merge(other);
        merged
    }

    fn to_effective(&self) -> EffectiveCwd {
        if self.is_empty() {
            return EffectiveCwd::Unreachable;
        }

        if self.unknown {
            return EffectiveCwd::known_or_unknown(self.known.iter().cloned());
        }

        EffectiveCwd::known_one_of(self.known.iter().cloned())
    }
}

impl From<&EffectiveCwd> for CwdState {
    fn from(value: &EffectiveCwd) -> Self {
        let mut state = CwdState::empty();
        if value.is_unreachable() {
            return state;
        }
        for cwd in value.known_cwds() {
            state.add_known(cwd.to_string());
        }
        if value.has_unknown() {
            state.add_unknown();
        }
        state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CwdScopeKind {
    Subshell,
    ControlFlow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CwdScopeId {
    kind: CwdScopeKind,
    span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveCwdScope {
    id: CwdScopeId,
    outer_state: CwdState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandConnector {
    Sequence,
    And,
    Or,
    Background,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CwdUpdate {
    success: CwdState,
    success_guaranteed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CwdOutcome {
    success: CwdState,
    failure: CwdState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedCwdState {
    cwd: CwdState,
    active_scopes: Vec<ActiveCwdScope>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ScopedCwdOutcome {
    success: Vec<ScopedCwdState>,
    failure: Vec<ScopedCwdState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CwdFlow {
    entry: Vec<ScopedCwdState>,
    list_entry: Vec<ScopedCwdState>,
    list_success: Vec<ScopedCwdState>,
    list_failure: Vec<ScopedCwdState>,
    prev_connector: Option<CommandConnector>,
}

impl CwdFlow {
    fn new(cwd: CwdState) -> Self {
        Self {
            entry: scoped_states_from_cwd(cwd),
            list_entry: Vec::new(),
            list_success: Vec::new(),
            list_failure: Vec::new(),
            prev_connector: None,
        }
    }

    fn prepare_command(&mut self, command: &CommandFact) -> Vec<ScopedCwdState> {
        let mut states = match self.prev_connector {
            Some(CommandConnector::And) => self.list_success.clone(),
            Some(CommandConnector::Or) => self.list_failure.clone(),
            Some(CommandConnector::Sequence) | Some(CommandConnector::Background) => {
                unreachable!("sequence and background connectors terminate the active list")
            }
            None => {
                self.list_entry = self.entry.clone();
                self.entry.clone()
            }
        };

        for state in &mut states {
            close_completed_scopes(
                &mut state.cwd,
                &mut state.active_scopes,
                command.span.start_byte,
            );
            open_command_scopes(command, &mut state.cwd, &mut state.active_scopes);
        }

        normalize_scoped_states(states)
    }

    fn record_outcome(&mut self, outcome: ScopedCwdOutcome, connector: CommandConnector) {
        match self.prev_connector {
            Some(CommandConnector::And) => {
                self.list_success = outcome.success;
                merge_scoped_states_into(&mut self.list_failure, outcome.failure);
            }
            Some(CommandConnector::Or) => {
                merge_scoped_states_into(&mut self.list_success, outcome.success);
                self.list_failure = outcome.failure;
            }
            Some(CommandConnector::Sequence) | Some(CommandConnector::Background) => {
                unreachable!("sequence and background connectors terminate the active list")
            }
            None => {
                self.list_success = outcome.success;
                self.list_failure = outcome.failure;
            }
        }

        match connector {
            CommandConnector::And | CommandConnector::Or => {
                self.prev_connector = Some(connector);
            }
            CommandConnector::Sequence => {
                self.entry = merged_scoped_states(&self.list_success, &self.list_failure);
                self.clear_active_list();
            }
            CommandConnector::Background => {
                self.entry = self.list_entry.clone();
                self.clear_active_list();
            }
        }
    }

    fn finish(self) -> Vec<ScopedCwdState> {
        if self.prev_connector.is_some() {
            return merged_scoped_states(&self.list_success, &self.list_failure);
        }

        self.entry
    }

    fn finish_closed(self) -> Vec<ScopedCwdState> {
        let mut states = self.finish();
        for state in &mut states {
            close_all_scopes(&mut state.cwd, &mut state.active_scopes);
        }
        normalize_scoped_states(states)
    }

    fn clear_active_list(&mut self) {
        self.list_entry.clear();
        self.list_success.clear();
        self.list_failure.clear();
        self.prev_connector = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScopeKey {
    parent_execution_node_id: NodeId,
    origin_kind: ExecutionUnitOriginKind,
    origin_locator: ExecutionUnitOriginLocator,
    root_command_index: usize,
    raw_command: String,
}

fn compute_request_scope_cwds(
    ctx: &RunnerContext,
    parsed: &ParsedCommandArtifact,
    initial_cwd: &str,
    records_by_node: &BTreeMap<NodeId, &ExecutionUnitResolveRecord>,
    function_records_by_parent: &BTreeMap<NodeId, Vec<&ExecutionUnitResolveRecord>>,
    known_existing_dirs: &BTreeSet<String>,
    effective_cwds: &mut BTreeMap<NodeId, EffectiveCwd>,
) -> EffectiveCwd {
    let mut flow = CwdFlow::new(CwdState::known(initial_cwd));
    let home = ctx.request().home.as_deref();

    for (command_index, command) in parsed.commands.iter().enumerate() {
        let source_node_id =
            source_node_id_for_command(ctx.request(), parsed, command_index, command);
        let states = flow.prepare_command(command);
        effective_cwds.insert(
            source_node_id.clone(),
            cwd_state_for_scoped_states(&states).to_effective(),
        );

        let record = records_by_node
            .get(&source_node_id)
            .copied()
            .filter(|record| record.origin_kind == ExecutionUnitOriginKind::TopLevel);
        let function_records = function_records_by_parent
            .get(&source_node_id)
            .map(Vec::as_slice);
        let outcome = request_command_outcome_for_scoped_states(
            ctx,
            command_index,
            command,
            record,
            function_records,
            states,
            home,
            known_existing_dirs,
        );
        flow.record_outcome(
            outcome,
            connector_after_command(parsed, command_index, command),
        );
    }

    cwd_state_for_scoped_states(&flow.finish_closed()).to_effective()
}

fn initial_cwd<'a>(ctx: &'a RunnerContext, _session: SessionView<'a>) -> &'a str {
    ctx.request().shell_state_before.cwd()
}

fn compute_derived_scope_cwds(
    ctx: &RunnerContext,
    initial_cwd: &str,
    records_by_node: &BTreeMap<NodeId, &ExecutionUnitResolveRecord>,
    known_existing_dirs: &BTreeSet<String>,
    effective_cwds: &mut BTreeMap<NodeId, EffectiveCwd>,
) {
    let mut single_records = Vec::new();
    let mut grouped_records: BTreeMap<ScopeKey, Vec<&ExecutionUnitResolveRecord>> = BTreeMap::new();
    let max_depth = ctx
        .execution_unit_resolve_records()
        .iter()
        .map(|record| record.depth)
        .max()
        .unwrap_or(0);

    for record in ctx.execution_unit_resolve_records() {
        match record.origin_kind {
            ExecutionUnitOriginKind::TopLevel => {}
            ExecutionUnitOriginKind::Dispatch | ExecutionUnitOriginKind::StaticXargs => {
                single_records.push(record);
            }
            ExecutionUnitOriginKind::FunctionExpansion
            | ExecutionUnitOriginKind::NestedPayload
            | ExecutionUnitOriginKind::ShellCommandStringPayload
            | ExecutionUnitOriginKind::CommandSubstitutionBody
            | ExecutionUnitOriginKind::CommandSubstitutionMaterialization
            | ExecutionUnitOriginKind::ProcessSubstitutionBody
            | ExecutionUnitOriginKind::RecursivePayload => {
                grouped_records
                    .entry(scope_key_for_record(record))
                    .or_default()
                    .push(record);
            }
        }
    }

    single_records.sort_by(record_execution_order);
    for records in grouped_records.values_mut() {
        records.sort_by(record_execution_order);
    }

    for depth in 1..=max_depth {
        for record in single_records
            .iter()
            .copied()
            .filter(|record| record.depth == depth)
        {
            let state =
                base_cwd_for_record(ctx, record, initial_cwd, records_by_node, effective_cwds);
            effective_cwds.insert(record.source_node_id.clone(), state.to_effective());
        }

        for records in grouped_records
            .values()
            .filter(|records| records.first().is_some_and(|record| record.depth == depth))
        {
            let Some(first) = records.first().copied() else {
                continue;
            };
            let mut flow = CwdFlow::new(base_cwd_for_record(
                ctx,
                first,
                initial_cwd,
                records_by_node,
                effective_cwds,
            ));
            let home = ctx.request().home.as_deref();

            for record in records {
                let Some(command) = record
                    .parsed_scope
                    .commands
                    .get(record.command_ref.command_index)
                else {
                    continue;
                };
                let states = flow.prepare_command(command);
                effective_cwds.insert(
                    record.source_node_id.clone(),
                    cwd_state_for_scoped_states(&states).to_effective(),
                );
                let outcome = record_command_outcome_for_scoped_states(
                    record,
                    command,
                    states,
                    home,
                    known_existing_dirs,
                );
                flow.record_outcome(
                    outcome,
                    connector_after_command(
                        &record.parsed_scope,
                        record.command_ref.command_index,
                        command,
                    ),
                );
            }
        }
    }
}

fn scope_key_for_record(record: &ExecutionUnitResolveRecord) -> ScopeKey {
    ScopeKey {
        parent_execution_node_id: record.parent_execution_node_id.clone(),
        origin_kind: record.origin_kind,
        origin_locator: record.origin_locator.clone(),
        root_command_index: record.root_command_index,
        raw_command: record.parsed_scope.raw_command.clone(),
    }
}

fn function_records_by_parent(
    records: &[ExecutionUnitResolveRecord],
) -> BTreeMap<NodeId, Vec<&ExecutionUnitResolveRecord>> {
    let mut grouped = BTreeMap::<NodeId, Vec<&ExecutionUnitResolveRecord>>::new();
    for record in records {
        if record.origin_kind == ExecutionUnitOriginKind::FunctionExpansion {
            grouped
                .entry(record.parent_execution_node_id.clone())
                .or_default()
                .push(record);
        }
    }

    for records in grouped.values_mut() {
        records.sort_by(record_execution_order);
    }

    grouped
}

fn record_execution_order(
    left: &&ExecutionUnitResolveRecord,
    right: &&ExecutionUnitResolveRecord,
) -> std::cmp::Ordering {
    left.depth
        .cmp(&right.depth)
        .then_with(|| left.root_command_index.cmp(&right.root_command_index))
        .then_with(|| {
            left.command_ref
                .span
                .start_byte
                .cmp(&right.command_ref.span.start_byte)
        })
        .then_with(|| {
            left.command_ref
                .command_index
                .cmp(&right.command_ref.command_index)
        })
        .then_with(|| left.source_node_id.0.cmp(&right.source_node_id.0))
}

fn scoped_states_from_cwd(cwd: CwdState) -> Vec<ScopedCwdState> {
    if cwd.is_empty() {
        return Vec::new();
    }

    vec![ScopedCwdState {
        cwd,
        active_scopes: Vec::new(),
    }]
}

fn normalize_scoped_states(states: Vec<ScopedCwdState>) -> Vec<ScopedCwdState> {
    let mut normalized = Vec::new();
    merge_scoped_states_into(&mut normalized, states);
    normalized
}

fn merged_scoped_states(left: &[ScopedCwdState], right: &[ScopedCwdState]) -> Vec<ScopedCwdState> {
    let mut merged = Vec::new();
    merge_scoped_states_into(&mut merged, left.iter().cloned());
    merge_scoped_states_into(&mut merged, right.iter().cloned());
    merged
}

fn merge_scoped_states_into(
    target: &mut Vec<ScopedCwdState>,
    states: impl IntoIterator<Item = ScopedCwdState>,
) {
    for state in states {
        push_scoped_state(target, state);
    }
}

fn push_scoped_state(target: &mut Vec<ScopedCwdState>, state: ScopedCwdState) {
    if state.cwd.is_empty() {
        return;
    }

    if let Some(existing) = target
        .iter_mut()
        .find(|existing| existing.active_scopes == state.active_scopes)
    {
        existing.cwd.merge(&state.cwd);
        return;
    }

    target.push(state);
}

fn cwd_state_for_scoped_states(states: &[ScopedCwdState]) -> CwdState {
    let mut cwd = CwdState::empty();
    for state in states {
        cwd.merge(&state.cwd);
    }
    cwd
}

fn scoped_outcome_from_cwd(state: &ScopedCwdState, outcome: CwdOutcome) -> ScopedCwdOutcome {
    let mut scoped = ScopedCwdOutcome::default();
    push_scoped_state(
        &mut scoped.success,
        ScopedCwdState {
            cwd: outcome.success,
            active_scopes: state.active_scopes.clone(),
        },
    );
    push_scoped_state(
        &mut scoped.failure,
        ScopedCwdState {
            cwd: outcome.failure,
            active_scopes: state.active_scopes.clone(),
        },
    );
    scoped
}

fn merge_scoped_outcome_into(target: &mut ScopedCwdOutcome, outcome: ScopedCwdOutcome) {
    merge_scoped_states_into(&mut target.success, outcome.success);
    merge_scoped_states_into(&mut target.failure, outcome.failure);
}

fn compute_record_sequence_exit_state(
    records: &[&ExecutionUnitResolveRecord],
    current: CwdState,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> CwdState {
    let mut flow = CwdFlow::new(current);

    for record in records {
        let Some(command) = record
            .parsed_scope
            .commands
            .get(record.command_ref.command_index)
        else {
            continue;
        };

        let states = flow.prepare_command(command);
        let outcome = record_command_outcome_for_scoped_states(
            record,
            command,
            states,
            home,
            known_existing_dirs,
        );
        flow.record_outcome(
            outcome,
            connector_after_command(
                &record.parsed_scope,
                record.command_ref.command_index,
                command,
            ),
        );
    }

    cwd_state_for_scoped_states(&flow.finish_closed())
}

fn request_command_outcome_for_scoped_states(
    ctx: &RunnerContext,
    command_index: usize,
    command: &CommandFact,
    record: Option<&ExecutionUnitResolveRecord>,
    function_records: Option<&[&ExecutionUnitResolveRecord]>,
    states: Vec<ScopedCwdState>,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> ScopedCwdOutcome {
    let mut scoped = ScopedCwdOutcome::default();

    for state in states {
        let outcome = request_command_outcome(
            ctx,
            command_index,
            command,
            record,
            function_records,
            &state.cwd,
            home,
            known_existing_dirs,
        );
        merge_scoped_outcome_into(&mut scoped, scoped_outcome_from_cwd(&state, outcome));
    }

    scoped
}

fn request_command_outcome(
    ctx: &RunnerContext,
    command_index: usize,
    command: &CommandFact,
    record: Option<&ExecutionUnitResolveRecord>,
    function_records: Option<&[&ExecutionUnitResolveRecord]>,
    current: &CwdState,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> CwdOutcome {
    if current.is_empty() {
        return CwdOutcome {
            success: CwdState::empty(),
            failure: CwdState::empty(),
        };
    }

    if command_can_update_current_shell(command) {
        if let Some(function_records) = function_records {
            let exit = compute_record_sequence_exit_state(
                function_records,
                current.clone(),
                home,
                known_existing_dirs,
            );
            return CwdOutcome {
                success: exit.clone(),
                failure: exit,
            };
        }

        if let Some(record) = record {
            if sources_script_into_current_shell(record)
                && let Some(exit) = sourced_script_exit_state(
                    ctx,
                    command_index,
                    current.clone(),
                    home,
                    known_existing_dirs,
                )
            {
                return CwdOutcome {
                    success: exit.clone(),
                    failure: exit,
                };
            }
        }
    }

    record
        .map(|record| record_command_outcome(record, command, current, home, known_existing_dirs))
        .unwrap_or_else(|| unchanged_command_outcome(current))
}

fn record_command_outcome_for_scoped_states(
    record: &ExecutionUnitResolveRecord,
    command: &CommandFact,
    states: Vec<ScopedCwdState>,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> ScopedCwdOutcome {
    let mut scoped = ScopedCwdOutcome::default();

    for state in states {
        let outcome =
            record_command_outcome(record, command, &state.cwd, home, known_existing_dirs);
        merge_scoped_outcome_into(&mut scoped, scoped_outcome_from_cwd(&state, outcome));
    }

    scoped
}

fn record_command_outcome(
    record: &ExecutionUnitResolveRecord,
    command: &CommandFact,
    current: &CwdState,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> CwdOutcome {
    if current.is_empty() {
        return CwdOutcome {
            success: CwdState::empty(),
            failure: CwdState::empty(),
        };
    }

    let Some(update) =
        current_shell_cwd_update(record, command, current, home, known_existing_dirs)
    else {
        return unchanged_command_outcome(current);
    };

    let failure = if update.success_guaranteed {
        CwdState::empty()
    } else {
        current.clone()
    };

    CwdOutcome {
        success: update.success,
        failure,
    }
}

fn unchanged_command_outcome(current: &CwdState) -> CwdOutcome {
    CwdOutcome {
        success: current.clone(),
        failure: current.clone(),
    }
}

fn sources_script_into_current_shell(record: &ExecutionUnitResolveRecord) -> bool {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return false;
    };

    resolved
        .bound
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::SourceScriptIntoCurrentShell)
}

fn sourced_script_exit_state(
    ctx: &RunnerContext,
    command_index: usize,
    current: CwdState,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> Option<CwdState> {
    let mut next = current;
    let mut saw_sourced_payload = false;

    for nested in ctx.nested_payload_records() {
        if !matches!(
            &nested.parent_ref,
            NestedPayloadParentRef::RootCommand { command_index: nested_command_index }
                if *nested_command_index == command_index
        ) {
            continue;
        }
        let NestedPayloadResolution::Parsed { parsed, .. } = &nested.resolution else {
            continue;
        };

        let mut records = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter(|record| {
                record.origin_kind == ExecutionUnitOriginKind::NestedPayload
                    && record.root_command_index == nested.root_command_index
                    && record.depth == nested.depth
                    && record.parsed_scope.raw_command == parsed.raw_command
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            continue;
        }
        records.sort_by(record_execution_order);

        next = compute_record_sequence_exit_state(&records, next, home, known_existing_dirs);
        saw_sourced_payload = true;
    }

    saw_sourced_payload.then_some(next)
}

fn base_cwd_for_record(
    ctx: &RunnerContext,
    record: &ExecutionUnitResolveRecord,
    initial_cwd: &str,
    records_by_node: &BTreeMap<NodeId, &ExecutionUnitResolveRecord>,
    effective_cwds: &BTreeMap<NodeId, EffectiveCwd>,
) -> CwdState {
    let parent_state = parent_cwd_for_record(ctx, record, effective_cwds)
        .unwrap_or_else(|| CwdState::known(initial_cwd));

    if record.origin_kind != ExecutionUnitOriginKind::Dispatch {
        return parent_state;
    }

    let Some(parent_record) = records_by_node.get(&record.parent_execution_node_id) else {
        return parent_state;
    };
    cwd_anchor_override(parent_record, &parent_state, ctx.request().home.as_deref())
        .unwrap_or(parent_state)
}

fn parent_cwd_for_record(
    ctx: &RunnerContext,
    record: &ExecutionUnitResolveRecord,
    effective_cwds: &BTreeMap<NodeId, EffectiveCwd>,
) -> Option<CwdState> {
    if let Some(cwd) = effective_cwds.get(&record.parent_execution_node_id) {
        return Some(CwdState::from(cwd));
    }

    if record.origin_kind != ExecutionUnitOriginKind::NestedPayload {
        return None;
    }

    nested_payload_parent_cwd(ctx, record, effective_cwds)
}

fn nested_payload_parent_cwd(
    ctx: &RunnerContext,
    record: &ExecutionUnitResolveRecord,
    effective_cwds: &BTreeMap<NodeId, EffectiveCwd>,
) -> Option<CwdState> {
    let parsed_request = ctx.parsed_command()?;

    for nested in ctx.nested_payload_records() {
        if nested.root_command_index != record.root_command_index || nested.depth != record.depth {
            continue;
        }

        let NestedPayloadResolution::Parsed { parsed, .. } = &nested.resolution else {
            continue;
        };
        if parsed.raw_command != record.parsed_scope.raw_command {
            continue;
        }

        let parent_node_id = match &nested.parent_ref {
            NestedPayloadParentRef::RootCommand { command_index } => {
                let command = parsed_request.commands.get(*command_index)?;
                source_node_id_for_command(ctx.request(), parsed_request, *command_index, command)
            }
            NestedPayloadParentRef::DerivedInvocation { node_id } => node_id.clone(),
        };

        return effective_cwds.get(&parent_node_id).map(CwdState::from);
    }

    None
}

fn close_completed_scopes(
    current: &mut CwdState,
    active_scopes: &mut Vec<ActiveCwdScope>,
    command_start: usize,
) {
    while active_scopes
        .last()
        .is_some_and(|scope| !span_contains_byte(&scope.id.span, command_start))
    {
        let Some(scope) = active_scopes.pop() else {
            break;
        };
        match scope.id.kind {
            CwdScopeKind::Subshell => {
                *current = scope.outer_state;
            }
            CwdScopeKind::ControlFlow => {
                *current = scope.outer_state.merged(current);
            }
        }
    }
}

fn close_all_scopes(current: &mut CwdState, active_scopes: &mut Vec<ActiveCwdScope>) {
    while let Some(scope) = active_scopes.pop() {
        match scope.id.kind {
            CwdScopeKind::Subshell => {
                *current = scope.outer_state;
            }
            CwdScopeKind::ControlFlow => {
                *current = scope.outer_state.merged(current);
            }
        }
    }
}

fn open_command_scopes(
    command: &CommandFact,
    current: &mut CwdState,
    active_scopes: &mut Vec<ActiveCwdScope>,
) {
    let mut desired = command_cwd_scopes(command);
    desired.sort_by(|left, right| {
        left.span
            .start_byte
            .cmp(&right.span.start_byte)
            .then_with(|| right.span.end_byte.cmp(&left.span.end_byte))
            .then_with(|| left.kind.cmp(&right.kind))
    });

    for id in desired {
        if active_scopes.iter().any(|scope| scope.id == id) {
            continue;
        }
        active_scopes.push(ActiveCwdScope {
            id,
            outer_state: current.clone(),
        });
    }
}

fn command_cwd_scopes(command: &CommandFact) -> Vec<CwdScopeId> {
    let mut scopes = Vec::new();
    if let Some(span) = &command.control_flow_span {
        scopes.push(CwdScopeId {
            kind: CwdScopeKind::ControlFlow,
            span: span.clone(),
        });
    }
    if let Some(span) = &command.subshell_span {
        scopes.push(CwdScopeId {
            kind: CwdScopeKind::Subshell,
            span: span.clone(),
        });
    }
    scopes
}

fn span_contains_byte(span: &SourceSpan, byte: usize) -> bool {
    span.start_byte <= byte && byte < span.end_byte
}

fn connector_after_command(
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    command: &CommandFact,
) -> CommandConnector {
    if command.terminator == Some(StatementTerminator::Background) {
        return CommandConnector::Background;
    }

    let Some(next) = parsed.commands.get(command_index.saturating_add(1)) else {
        return CommandConnector::Sequence;
    };

    let start = command.span.end_byte.min(parsed.raw_command.len());
    let end = next.span.start_byte.min(parsed.raw_command.len());
    let gap = if start <= end {
        parsed.raw_command.get(start..end).unwrap_or("")
    } else {
        ""
    };

    if gap.contains("&&") {
        CommandConnector::And
    } else if gap.contains("||") {
        CommandConnector::Or
    } else {
        CommandConnector::Sequence
    }
}

fn current_shell_cwd_update(
    record: &ExecutionUnitResolveRecord,
    command: &CommandFact,
    current: &CwdState,
    home: Option<&str>,
    known_existing_dirs: &BTreeSet<String>,
) -> Option<CwdUpdate> {
    if !command_can_update_current_shell(command) {
        return None;
    }

    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return unresolved_cwd_command_updates_unknown(record).map(|success| CwdUpdate {
            success,
            success_guaranteed: false,
        });
    };

    if has_applied_modifier(&resolved.bound, "no_cd") {
        return None;
    }

    let mut update = None;
    for effect in &resolved.bound.effects {
        if effect.kind != EffectKind::SetCurrentWorkingDirectory {
            continue;
        }
        let success = cwd_update_for_effect(
            &resolved.normalized_command_name,
            &resolved.bound,
            &effect.target,
            current,
            home,
        );
        update = Some(CwdUpdate {
            success_guaranteed: cwd_success_guaranteed(&success, known_existing_dirs),
            success,
        });
    }

    update
}

fn command_can_update_current_shell(command: &CommandFact) -> bool {
    !command.in_pipeline && command.terminator != Some(StatementTerminator::Background)
}

fn unresolved_cwd_command_updates_unknown(record: &ExecutionUnitResolveRecord) -> Option<CwdState> {
    let command_name = match &record.result {
        ResolveInvocationArtifactResult::MissingCommandName { .. } => record
            .parsed_scope
            .commands
            .get(record.command_ref.command_index)
            .and_then(|command| command.command_name.as_deref()),
        ResolveInvocationArtifactResult::NoProfile {
            normalized_command_name,
            ..
        }
        | ResolveInvocationArtifactResult::SelectionError {
            normalized_command_name,
            ..
        } => Some(normalized_command_name.as_str()),
        ResolveInvocationArtifactResult::Resolved(_) => None,
    };

    matches!(command_name, Some("cd" | "pushd" | "popd")).then_some(CwdState::unknown())
}

fn cwd_update_for_effect(
    normalized_command_name: &str,
    bound: &BoundInvocation,
    target: &EffectTarget,
    current: &CwdState,
    home: Option<&str>,
) -> CwdState {
    match target {
        EffectTarget::Slot(slot_name) => {
            cwd_state_from_slot(bound, slot_name.as_str(), current, home)
        }
        EffectTarget::None if normalized_command_name == "cd" => home
            .map(|home| CwdState::known(normalize_shell_path(home)))
            .unwrap_or_else(CwdState::unknown),
        EffectTarget::None => CwdState::unknown(),
        EffectTarget::ToolConventionPath(_)
        | EffectTarget::DerivedPath(_)
        | EffectTarget::MutationScope(_)
        | EffectTarget::ImplicitInput(_)
        | EffectTarget::Dispatch(_) => CwdState::unknown(),
    }
}

fn cwd_state_from_slot(
    bound: &BoundInvocation,
    slot_name: &str,
    current: &CwdState,
    home: Option<&str>,
) -> CwdState {
    let Some(value) = bound_argument_values_for_slot(bound, slot_name)
        .last()
        .copied()
    else {
        return CwdState::unknown();
    };

    resolve_bound_path_value(value, current, home)
}

fn cwd_anchor_override(
    record: &ExecutionUnitResolveRecord,
    base: &CwdState,
    home: Option<&str>,
) -> Option<CwdState> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return None;
    };

    let value = resolved
        .bound
        .bound_parameters
        .iter()
        .filter(|parameter| is_working_directory_cwd_anchor(parameter.semantic.clone()))
        .flat_map(|parameter| parameter.values.iter())
        .last()?;

    Some(resolve_bound_path_value(value, base, home))
}

fn is_working_directory_cwd_anchor(semantic: SemanticType) -> bool {
    matches!(
        semantic,
        SemanticType::Path(path)
            if path.role == PathRole::CwdAnchor
                && path.purpose == Some(PathPurpose::WorkingDirectory)
    )
}

fn bound_argument_values_for_slot<'a>(
    bound: &'a BoundInvocation,
    slot_name: &str,
) -> Vec<&'a BoundValue> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.values.iter())
        .collect()
}

fn resolve_bound_path_value(value: &BoundValue, cwd: &CwdState, home: Option<&str>) -> CwdState {
    let BoundValue::Argument {
        text,
        quoted,
        node_kind,
        materialization,
        ..
    } = value
    else {
        return CwdState::unknown();
    };

    let (effective_quoted, effective_node_kind) = match materialization {
        BoundArgumentMaterialization::Literal => (*quoted, node_kind.as_str()),
        BoundArgumentMaterialization::ResolvedExactScalar { .. }
        | BoundArgumentMaterialization::ResolvedRuntimeProduced { .. } => (true, "string"),
    };

    resolve_cwd_operand(text, effective_quoted, effective_node_kind, cwd, home)
}

fn resolve_cwd_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &CwdState,
    home: Option<&str>,
) -> CwdState {
    let trimmed = text.trim();

    if cwd_independent_operand(trimmed, quoted) {
        return resolve_path_operand(trimmed, quoted, node_kind, "/", home)
            .map(CwdState::known)
            .unwrap_or_else(CwdState::unknown);
    }

    let mut state = CwdState::empty();
    for base in &cwd.known {
        if let Some(resolved) = resolve_path_operand(trimmed, quoted, node_kind, base, home) {
            state.add_known(resolved);
        }
    }

    if cwd.unknown || state.is_empty() {
        state.add_unknown();
    }

    state
}

fn cwd_independent_operand(text: &str, quoted: bool) -> bool {
    text.starts_with('/') || (!quoted && (text == "~" || text.starts_with("~/")))
}

fn cwd_success_guaranteed(state: &CwdState, known_existing_dirs: &BTreeSet<String>) -> bool {
    !state.unknown
        && !state.known.is_empty()
        && state.known.iter().all(|cwd| {
            known_existing_dirs.contains(cwd)
                || known_existing_dirs.contains(normalize_shell_path(cwd).as_str())
        })
}

fn known_existing_dirs(ctx: &RunnerContext) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for dir in [
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/tmp", "/usr", "/usr/bin", "/var",
    ] {
        insert_dir_with_ancestors(&mut dirs, dir);
    }

    insert_dir_with_ancestors(&mut dirs, ctx.request().shell_state_before.cwd());
    if let Some(home) = ctx.request().home.as_deref() {
        insert_dir_with_ancestors(&mut dirs, home);
    }
    if let Some(workspace_root) = ctx.request().workspace_root.as_deref() {
        insert_dir_with_ancestors(&mut dirs, workspace_root);
    }

    dirs
}

fn insert_dir_with_ancestors(dirs: &mut BTreeSet<String>, path: &str) {
    let normalized = normalize_shell_path(path);
    if normalized.is_empty() {
        return;
    }

    let mut current = normalized.as_str();
    loop {
        dirs.insert(current.to_string());
        if current == "/" {
            break;
        }
        let Some(parent) = current.rsplit_once('/').map(|(parent, _)| parent) else {
            break;
        };
        current = if parent.is_empty() { "/" } else { parent };
    }
}

fn has_applied_modifier(bound: &BoundInvocation, modifier_id: &str) -> bool {
    bound
        .applied_modifiers
        .iter()
        .any(|modifier| modifier.as_str() == modifier_id)
}

#[cfg(test)]
mod tests {
    use super::ComputeEffectiveCwdPass;
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
    use caushell_graph::{NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{EffectiveCwd, PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str, cwd: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new(cwd.to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn run_pass(command: &str, cwd: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().expect("expected built-in registry"),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(command, cwd));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn compute_effective_cwd_tracks_static_cd_for_following_command() {
        let ctx = run_pass("cd / && rm -rf etc", "/tmp/project");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_keeps_subshell_cd_local() {
        let ctx = run_pass("(cd /tmp/project); rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_merges_control_flow_exit() {
        let ctx = run_pass("if false; then cd /tmp/project; fi; rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:2")),
            Some(&EffectiveCwd::KnownOneOf(vec![
                "/".to_string(),
                "/tmp/project".to_string()
            ]))
        );
        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::KnownOneOf(vec![
                "/".to_string(),
                "/tmp/project".to_string()
            ]))
        );
    }

    #[test]
    fn compute_effective_cwd_preserves_failure_branch_after_sequence_cd() {
        let ctx = run_pass("cd /no-such; rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::KnownOneOf(vec![
                "/".to_string(),
                "/no-such".to_string()
            ]))
        );
    }

    #[test]
    fn compute_effective_cwd_uses_success_branch_after_and_cd() {
        let ctx = run_pass("cd /no-such && rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Known("/no-such".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_merges_and_list_failure_after_sequence() {
        let ctx = run_pass("cd /no-such && true; rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:2")),
            Some(&EffectiveCwd::KnownOneOf(vec![
                "/".to_string(),
                "/no-such".to_string()
            ]))
        );
    }

    #[test]
    fn compute_effective_cwd_carries_or_list_success_after_sequence() {
        let ctx = run_pass("cd / || echo fail; rm -rf etc", "/tmp/project");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Unreachable)
        );
        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:2")),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_marks_or_rhs_unreachable_after_guaranteed_cd() {
        let ctx = run_pass("cd /tmp/project || rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Unreachable)
        );
    }

    #[test]
    fn compute_effective_cwd_trusts_known_workspace_cd_sequence() {
        let ctx = run_pass("cd /tmp/project; rm -rf etc", "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Known("/tmp/project".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_applies_function_expansion_exit_to_following_command() {
        let ctx = run_pass("f(){ cd /; }; f; rm -rf etc", "/tmp/project");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:2")),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
    }

    #[test]
    fn compute_effective_cwd_marks_dynamic_cd_as_unknown_for_following_command() {
        let ctx = run_pass(r#"cd "$TARGET" && rm -rf etc"#, "/");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("command:sess-1:1:1")),
            Some(&EffectiveCwd::Unknown)
        );
    }

    #[test]
    fn compute_effective_cwd_applies_wrapper_cwd_anchor_to_dispatch_child() {
        let ctx = run_pass("env --chdir=/ rm -rf etc", "/tmp/project");

        assert_eq!(
            ctx.effective_cwd_for_node(&NodeId::new("derived-dispatch:sess-1:1:0:0")),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
    }
}
