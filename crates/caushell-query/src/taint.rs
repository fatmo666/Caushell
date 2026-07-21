use std::collections::{BTreeMap, BTreeSet};

use crate::{ExecutionSemanticsQuery, ExecutionUnitRef, QuerySession};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{
    ProvenanceArtifact, TaintTrace, TaintTraceDirection, TaintTraceEndpoint, TaintTraceHop,
    TaintTraceHopKind, TaintTraceMatch, TaintTraceStats,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTraceQuery {
    direction: TaintTraceDirection,
    sources: Vec<TraceEndpointSelector>,
    sinks: Vec<TraceEndpointSelector>,
    barriers: Vec<TraceEndpointSelector>,
    max_depth: Option<u32>,
    max_paths: Option<u32>,
}

impl Default for TaintTraceQuery {
    fn default() -> Self {
        Self {
            direction: TaintTraceDirection::Forward,
            sources: Vec::new(),
            sinks: Vec::new(),
            barriers: Vec::new(),
            max_depth: None,
            max_paths: None,
        }
    }
}

impl TaintTraceQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn direction(mut self, direction: TaintTraceDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn source_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.sources.push(TraceEndpointSelector::Endpoint(
            TraceEndpointKey::ExecutionUnit(node_id),
        ));
        self
    }

    pub fn source_artifact_node_id(mut self, node_id: NodeId) -> Self {
        self.sources
            .push(TraceEndpointSelector::Endpoint(TraceEndpointKey::Artifact(
                node_id,
            )));
        self
    }

    pub fn source_execution_payload(mut self) -> Self {
        self.sources.push(TraceEndpointSelector::ExecutionPayload);
        self
    }

    pub fn source_startup_config_load(mut self) -> Self {
        self.sources.push(TraceEndpointSelector::StartupConfigLoad);
        self
    }

    pub fn sink_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.sinks.push(TraceEndpointSelector::Endpoint(
            TraceEndpointKey::ExecutionUnit(node_id),
        ));
        self
    }

    pub fn sink_artifact_node_id(mut self, node_id: NodeId) -> Self {
        self.sinks
            .push(TraceEndpointSelector::Endpoint(TraceEndpointKey::Artifact(
                node_id,
            )));
        self
    }

    pub fn sink_execution_payload(mut self) -> Self {
        self.sinks.push(TraceEndpointSelector::ExecutionPayload);
        self
    }

    pub fn sink_startup_config_load(mut self) -> Self {
        self.sinks.push(TraceEndpointSelector::StartupConfigLoad);
        self
    }

    pub fn barrier_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.barriers.push(TraceEndpointSelector::Endpoint(
            TraceEndpointKey::ExecutionUnit(node_id),
        ));
        self
    }

    pub fn barrier_artifact_node_id(mut self, node_id: NodeId) -> Self {
        self.barriers
            .push(TraceEndpointSelector::Endpoint(TraceEndpointKey::Artifact(
                node_id,
            )));
        self
    }

    pub fn barrier_execution_payload(mut self) -> Self {
        self.barriers.push(TraceEndpointSelector::ExecutionPayload);
        self
    }

    pub fn barrier_startup_config_load(mut self) -> Self {
        self.barriers.push(TraceEndpointSelector::StartupConfigLoad);
        self
    }

    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn max_paths(mut self, max_paths: u32) -> Self {
        self.max_paths = Some(max_paths);
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> TaintTraceResult<'a> {
        let trace = match self.direction {
            TaintTraceDirection::Forward => self.search_forward(session),
            TaintTraceDirection::Backward => self.search_backward(session),
        };

        TaintTraceResult { trace }
    }

    fn search_forward<'a>(&self, session: QuerySession<'a>) -> TaintTraceRef<'a> {
        self.search(
            session,
            resolve_selector_keys(session, &self.sources),
            resolve_selector_keys(session, &self.sinks),
            resolve_selector_keys(session, &self.barriers),
            SearchDirection::Forward,
        )
    }

    fn search_backward<'a>(&self, session: QuerySession<'a>) -> TaintTraceRef<'a> {
        self.search(
            session,
            resolve_selector_keys(session, &self.sinks),
            resolve_selector_keys(session, &self.sources),
            resolve_selector_keys(session, &self.barriers),
            SearchDirection::Backward,
        )
    }

    fn search<'a>(
        &self,
        session: QuerySession<'a>,
        starts: BTreeSet<TraceEndpointKey>,
        targets: BTreeSet<TraceEndpointKey>,
        barrier_keys: BTreeSet<TraceEndpointKey>,
        search_direction: SearchDirection,
    ) -> TaintTraceRef<'a> {
        let mut matches = Vec::new();
        let mut over_max_depth = false;
        let mut over_max_paths = false;

        let mut stack = Vec::new();
        for start in starts {
            let mut visited = BTreeSet::new();
            visited.insert(start.clone());
            stack.push(SearchState {
                anchor: start.clone(),
                current: start,
                visited,
                hops: Vec::new(),
            });
        }

        while let Some(state) = stack.pop() {
            if targets.contains(&state.current) {
                if let Some(found) = build_match_ref(session, &state, search_direction) {
                    matches.push(found);
                    if self.max_paths_reached(matches.len()) {
                        over_max_paths = true;
                        break;
                    }
                }
                continue;
            }

            let neighbors = next_hops(session, &state.current, search_direction);

            if self.max_depth_exhausted(state.hops.len()) {
                if !neighbors.is_empty() {
                    over_max_depth = true;
                }
                continue;
            }

            for candidate in neighbors {
                if barrier_keys.contains(&candidate.next) {
                    continue;
                }

                if state.visited.contains(&candidate.next) {
                    continue;
                }

                let mut visited = state.visited.clone();
                visited.insert(candidate.next.clone());

                let mut hops = state.hops.clone();
                hops.push(candidate.forward_hop);

                stack.push(SearchState {
                    anchor: state.anchor.clone(),
                    current: candidate.next,
                    visited,
                    hops,
                });
            }
        }

        TaintTraceRef {
            direction: self.direction,
            matches,
            stats: TaintTraceStatsRef {
                truncated: over_max_depth || over_max_paths,
                over_max_depth,
                over_max_paths,
            },
        }
    }

    fn max_depth_exhausted(&self, current_hops: usize) -> bool {
        self.max_depth
            .is_some_and(|max_depth| current_hops as u32 >= max_depth)
    }

    fn max_paths_reached(&self, current_matches: usize) -> bool {
        self.max_paths
            .is_some_and(|max_paths| current_matches as u32 >= max_paths)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTraceResult<'a> {
    trace: TaintTraceRef<'a>,
}

impl<'a> TaintTraceResult<'a> {
    pub fn trace(&self) -> &TaintTraceRef<'a> {
        &self.trace
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTraceRef<'a> {
    direction: TaintTraceDirection,
    matches: Vec<TaintTraceMatchRef<'a>>,
    stats: TaintTraceStatsRef,
}

impl<'a> TaintTraceRef<'a> {
    pub fn direction(&self) -> TaintTraceDirection {
        self.direction
    }

    pub fn matches(&self) -> &[TaintTraceMatchRef<'a>] {
        self.matches.as_slice()
    }

    pub fn stats(&self) -> TaintTraceStatsRef {
        self.stats
    }

    pub fn to_taint_trace(&self) -> TaintTrace {
        TaintTrace {
            direction: self.direction,
            matches: self
                .matches
                .iter()
                .map(TaintTraceMatchRef::to_taint_trace_match)
                .collect(),
            stats: self.stats.to_taint_trace_stats(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTraceMatchRef<'a> {
    source: TaintTraceEndpointRef<'a>,
    sink: TaintTraceEndpointRef<'a>,
    hops: Vec<TaintTraceHopRef<'a>>,
}

impl<'a> TaintTraceMatchRef<'a> {
    pub fn source(&self) -> TaintTraceEndpointRef<'a> {
        self.source
    }

    pub fn sink(&self) -> TaintTraceEndpointRef<'a> {
        self.sink
    }

    pub fn hops(&self) -> &[TaintTraceHopRef<'a>] {
        self.hops.as_slice()
    }

    pub fn to_taint_trace_match(&self) -> TaintTraceMatch {
        TaintTraceMatch {
            source: self.source.to_taint_trace_endpoint(),
            sink: self.sink.to_taint_trace_endpoint(),
            hops: self
                .hops
                .iter()
                .map(TaintTraceHopRef::to_taint_trace_hop)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintTraceHopRef<'a> {
    kind: TaintTraceHopKind,
    from: TaintTraceEndpointRef<'a>,
    to: TaintTraceEndpointRef<'a>,
}

impl<'a> TaintTraceHopRef<'a> {
    pub fn kind(&self) -> TaintTraceHopKind {
        self.kind
    }

    pub fn from(&self) -> TaintTraceEndpointRef<'a> {
        self.from
    }

    pub fn to(&self) -> TaintTraceEndpointRef<'a> {
        self.to
    }

    pub fn to_taint_trace_hop(&self) -> TaintTraceHop {
        TaintTraceHop {
            kind: self.kind,
            from: self.from.to_taint_trace_endpoint(),
            to: self.to.to_taint_trace_endpoint(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintTraceEndpointRef<'a> {
    ExecutionUnit(ExecutionUnitRef<'a>),
    Artifact {
        node_id: &'a NodeId,
        artifact: &'a ProvenanceArtifact,
    },
}

impl<'a> TaintTraceEndpointRef<'a> {
    pub fn node_id(&self) -> &'a NodeId {
        match self {
            Self::ExecutionUnit(unit) => unit.node_id(),
            Self::Artifact { node_id, .. } => node_id,
        }
    }

    pub fn execution_unit(&self) -> Option<ExecutionUnitRef<'a>> {
        match self {
            Self::ExecutionUnit(unit) => Some(*unit),
            Self::Artifact { .. } => None,
        }
    }

    pub fn artifact(&self) -> Option<&'a ProvenanceArtifact> {
        match self {
            Self::ExecutionUnit(_) => None,
            Self::Artifact { artifact, .. } => Some(*artifact),
        }
    }

    pub fn to_taint_trace_endpoint(&self) -> TaintTraceEndpoint {
        match self {
            Self::ExecutionUnit(unit) => TaintTraceEndpoint::ExecutionUnit {
                unit: unit.to_execution_unit(),
            },
            Self::Artifact { node_id, artifact } => TaintTraceEndpoint::Artifact {
                node_id: node_id.0.clone(),
                artifact: (*artifact).clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintTraceStatsRef {
    truncated: bool,
    over_max_depth: bool,
    over_max_paths: bool,
}

impl TaintTraceStatsRef {
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn over_max_depth(&self) -> bool {
        self.over_max_depth
    }

    pub fn over_max_paths(&self) -> bool {
        self.over_max_paths
    }

    pub fn to_taint_trace_stats(self) -> TaintTraceStats {
        TaintTraceStats {
            truncated: self.truncated,
            over_max_depth: self.over_max_depth,
            over_max_paths: self.over_max_paths,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchState {
    anchor: TraceEndpointKey,
    current: TraceEndpointKey,
    visited: BTreeSet<TraceEndpointKey>,
    hops: Vec<TraceHopKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NeighborCandidate {
    next: TraceEndpointKey,
    forward_hop: TraceHopKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TraceEndpointKey {
    ExecutionUnit(NodeId),
    Artifact(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceHopKey {
    kind: TaintTraceHopKind,
    from: TraceEndpointKey,
    to: TraceEndpointKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEndpointSelector {
    Endpoint(TraceEndpointKey),
    ExecutionPayload,
    StartupConfigLoad,
}

fn build_match_ref<'a>(
    session: QuerySession<'a>,
    state: &SearchState,
    search_direction: SearchDirection,
) -> Option<TaintTraceMatchRef<'a>> {
    let (source_key, sink_key, hop_keys): (TraceEndpointKey, TraceEndpointKey, Vec<TraceHopKey>) =
        match search_direction {
            SearchDirection::Forward => (
                state.anchor.clone(),
                state.current.clone(),
                state.hops.clone(),
            ),
            SearchDirection::Backward => (
                state.current.clone(),
                state.anchor.clone(),
                state.hops.iter().cloned().rev().collect(),
            ),
        };

    let source = endpoint_ref(session, &source_key)?;
    let sink = endpoint_ref(session, &sink_key)?;
    let mut hops = Vec::with_capacity(hop_keys.len());
    for hop_key in hop_keys {
        let from = endpoint_ref(session, &hop_key.from)?;
        let to = endpoint_ref(session, &hop_key.to)?;
        hops.push(TaintTraceHopRef {
            kind: hop_key.kind,
            from,
            to,
        });
    }

    Some(TaintTraceMatchRef { source, sink, hops })
}

fn endpoint_ref<'a>(
    session: QuerySession<'a>,
    key: &TraceEndpointKey,
) -> Option<TaintTraceEndpointRef<'a>> {
    let node = match key {
        TraceEndpointKey::ExecutionUnit(node_id) | TraceEndpointKey::Artifact(node_id) => {
            session.graph().get_node(node_id)?
        }
    };

    match key {
        TraceEndpointKey::ExecutionUnit(_) => {
            ExecutionUnitRef::from_node(node).map(TaintTraceEndpointRef::ExecutionUnit)
        }
        TraceEndpointKey::Artifact(_) => match &node.kind {
            NodeKind::ProvenanceArtifact { artifact } => Some(TaintTraceEndpointRef::Artifact {
                node_id: &node.id,
                artifact,
            }),
            _ => None,
        },
    }
}

fn resolve_selector_keys(
    session: QuerySession<'_>,
    selectors: &[TraceEndpointSelector],
) -> BTreeSet<TraceEndpointKey> {
    let mut keys = BTreeSet::new();

    for selector in selectors {
        match selector {
            TraceEndpointSelector::Endpoint(key) => {
                if endpoint_ref(session, key).is_some() {
                    keys.insert(key.clone());
                }
            }
            TraceEndpointSelector::ExecutionPayload => {
                for semantics in ExecutionSemanticsQuery::new()
                    .executes_payload(true)
                    .execute(session)
                    .semantics()
                {
                    keys.insert(TraceEndpointKey::ExecutionUnit(
                        semantics.source().node_id().clone(),
                    ));
                }
            }
            TraceEndpointSelector::StartupConfigLoad => {
                for semantics in ExecutionSemanticsQuery::new()
                    .loads_startup_config(true)
                    .execute(session)
                    .semantics()
                {
                    keys.insert(TraceEndpointKey::ExecutionUnit(
                        semantics.source().node_id().clone(),
                    ));
                }
            }
        }
    }

    keys
}

fn next_hops(
    session: QuerySession<'_>,
    current: &TraceEndpointKey,
    direction: SearchDirection,
) -> Vec<NeighborCandidate> {
    match direction {
        SearchDirection::Forward => next_hops_forward(session, current),
        SearchDirection::Backward => next_hops_backward(session, current),
    }
}

fn next_hops_forward(
    session: QuerySession<'_>,
    current: &TraceEndpointKey,
) -> Vec<NeighborCandidate> {
    let graph = session.graph();

    match current {
        TraceEndpointKey::ExecutionUnit(node_id) => {
            let mut candidates = BTreeMap::new();
            let mut projected_expands = false;

            for edge in graph.outgoing_edges(node_id) {
                match edge.kind {
                    EdgeKind::Produces => {
                        if artifact_key(session, &edge.to).is_some() {
                            let next = TraceEndpointKey::Artifact(edge.to.clone());
                            insert_candidate(
                                &mut candidates,
                                next.clone(),
                                TraceHopKey {
                                    kind: TaintTraceHopKind::Produces,
                                    from: current.clone(),
                                    to: next,
                                },
                            );
                        }
                    }
                    EdgeKind::FlowsTo => {
                        if execution_unit_key(session, &edge.to).is_some() {
                            let next = TraceEndpointKey::ExecutionUnit(edge.to.clone());
                            insert_candidate(
                                &mut candidates,
                                next.clone(),
                                TraceHopKey {
                                    kind: TaintTraceHopKind::FlowsTo,
                                    from: current.clone(),
                                    to: next,
                                },
                            );
                        }
                    }
                    EdgeKind::Dispatches => {
                        if execution_unit_key(session, &edge.to).is_some() {
                            let next = TraceEndpointKey::ExecutionUnit(edge.to.clone());
                            insert_candidate(
                                &mut candidates,
                                next.clone(),
                                TraceHopKey {
                                    kind: TaintTraceHopKind::Dispatches,
                                    from: current.clone(),
                                    to: next,
                                },
                            );
                        }
                    }
                    EdgeKind::ExpandsTo => {
                        if !projected_expands {
                            projected_expands = true;

                            for next in projected_expand_children(session, node_id) {
                                insert_candidate(
                                    &mut candidates,
                                    next.clone(),
                                    TraceHopKey {
                                        kind: TaintTraceHopKind::ExpandsTo,
                                        from: current.clone(),
                                        to: next,
                                    },
                                );
                            }
                        }
                    }
                    EdgeKind::Defines
                    | EdgeKind::Reads
                    | EdgeKind::Writes
                    | EdgeKind::MutatesMetadata
                    | EdgeKind::Targets
                    | EdgeKind::Consumes
                    | EdgeKind::DependsOn
                    | EdgeKind::ChangesCwdTo
                    | EdgeKind::InheritsFrom
                    | EdgeKind::TriggeredBy => {}
                }
            }

            candidates.into_values().collect()
        }
        TraceEndpointKey::Artifact(node_id) => {
            let mut candidates = BTreeMap::new();

            for edge in graph.incoming_edges(node_id) {
                if edge.kind != EdgeKind::Consumes {
                    continue;
                }

                if execution_unit_key(session, &edge.from).is_none() {
                    continue;
                }

                let next = TraceEndpointKey::ExecutionUnit(edge.from.clone());
                insert_candidate(
                    &mut candidates,
                    next.clone(),
                    TraceHopKey {
                        kind: TaintTraceHopKind::Consumes,
                        from: current.clone(),
                        to: next,
                    },
                );
            }

            candidates.into_values().collect()
        }
    }
}

fn next_hops_backward(
    session: QuerySession<'_>,
    current: &TraceEndpointKey,
) -> Vec<NeighborCandidate> {
    let graph = session.graph();

    match current {
        TraceEndpointKey::ExecutionUnit(node_id) => {
            let mut candidates = BTreeMap::new();
            let mut projected_expands = false;

            for edge in graph.outgoing_edges(node_id) {
                if edge.kind != EdgeKind::Consumes {
                    continue;
                }

                if artifact_key(session, &edge.to).is_some() {
                    let next = TraceEndpointKey::Artifact(edge.to.clone());
                    insert_candidate(
                        &mut candidates,
                        next.clone(),
                        TraceHopKey {
                            kind: TaintTraceHopKind::Consumes,
                            from: next.clone(),
                            to: current.clone(),
                        },
                    );
                }
            }

            for edge in graph.incoming_edges(node_id) {
                match edge.kind {
                    EdgeKind::FlowsTo => {
                        if execution_unit_key(session, &edge.from).is_some() {
                            let next = TraceEndpointKey::ExecutionUnit(edge.from.clone());
                            insert_candidate(
                                &mut candidates,
                                next.clone(),
                                TraceHopKey {
                                    kind: TaintTraceHopKind::FlowsTo,
                                    from: next.clone(),
                                    to: current.clone(),
                                },
                            );
                        }
                    }
                    EdgeKind::Dispatches => {
                        if execution_unit_key(session, &edge.from).is_some() {
                            let next = TraceEndpointKey::ExecutionUnit(edge.from.clone());
                            insert_candidate(
                                &mut candidates,
                                next.clone(),
                                TraceHopKey {
                                    kind: TaintTraceHopKind::Dispatches,
                                    from: next.clone(),
                                    to: current.clone(),
                                },
                            );
                        }
                    }
                    EdgeKind::ExpandsTo => {
                        if !projected_expands {
                            projected_expands = true;

                            for next in projected_expand_parents(session, node_id) {
                                insert_candidate(
                                    &mut candidates,
                                    next.clone(),
                                    TraceHopKey {
                                        kind: TaintTraceHopKind::ExpandsTo,
                                        from: next.clone(),
                                        to: current.clone(),
                                    },
                                );
                            }
                        }
                    }
                    EdgeKind::Defines
                    | EdgeKind::Reads
                    | EdgeKind::Writes
                    | EdgeKind::MutatesMetadata
                    | EdgeKind::Targets
                    | EdgeKind::Consumes
                    | EdgeKind::Produces
                    | EdgeKind::DependsOn
                    | EdgeKind::ChangesCwdTo
                    | EdgeKind::InheritsFrom
                    | EdgeKind::TriggeredBy => {}
                }
            }

            candidates.into_values().collect()
        }
        TraceEndpointKey::Artifact(node_id) => {
            let mut candidates = BTreeMap::new();

            for edge in graph.incoming_edges(node_id) {
                if edge.kind != EdgeKind::Produces {
                    continue;
                }

                if execution_unit_key(session, &edge.from).is_none() {
                    continue;
                }

                let next = TraceEndpointKey::ExecutionUnit(edge.from.clone());
                insert_candidate(
                    &mut candidates,
                    next.clone(),
                    TraceHopKey {
                        kind: TaintTraceHopKind::Produces,
                        from: next.clone(),
                        to: current.clone(),
                    },
                );
            }

            candidates.into_values().collect()
        }
    }
}

fn projected_expand_children(
    session: QuerySession<'_>,
    execution_unit_node_id: &NodeId,
) -> Vec<TraceEndpointKey> {
    let graph = session.graph();
    let mut children = BTreeSet::new();

    for nested_edge in graph.outgoing_edges(execution_unit_node_id) {
        if nested_edge.kind != EdgeKind::ExpandsTo {
            continue;
        }

        let Some(nested_node) = graph.get_node(&nested_edge.to) else {
            continue;
        };
        if !matches!(nested_node.kind, NodeKind::NestedPayload { .. }) {
            continue;
        }

        for child_edge in graph.outgoing_edges(&nested_node.id) {
            if child_edge.kind != EdgeKind::ExpandsTo {
                continue;
            }

            if execution_unit_key(session, &child_edge.to).is_none() {
                continue;
            }

            children.insert(TraceEndpointKey::ExecutionUnit(child_edge.to.clone()));
        }
    }

    children.into_iter().collect()
}

fn projected_expand_parents(
    session: QuerySession<'_>,
    execution_unit_node_id: &NodeId,
) -> Vec<TraceEndpointKey> {
    let graph = session.graph();
    let mut parents = BTreeSet::new();

    for child_edge in graph.incoming_edges(execution_unit_node_id) {
        if child_edge.kind != EdgeKind::ExpandsTo {
            continue;
        }

        let Some(parent_node) = graph.get_node(&child_edge.from) else {
            continue;
        };
        if !matches!(parent_node.kind, NodeKind::NestedPayload { .. }) {
            continue;
        }

        for parent_edge in graph.incoming_edges(&parent_node.id) {
            if parent_edge.kind != EdgeKind::ExpandsTo {
                continue;
            }

            if execution_unit_key(session, &parent_edge.from).is_none() {
                continue;
            }

            parents.insert(TraceEndpointKey::ExecutionUnit(parent_edge.from.clone()));
        }
    }

    parents.into_iter().collect()
}

fn execution_unit_key(session: QuerySession<'_>, node_id: &NodeId) -> Option<TraceEndpointKey> {
    let node = session.graph().get_node(node_id)?;
    ExecutionUnitRef::from_node(node)?;
    Some(TraceEndpointKey::ExecutionUnit(node_id.clone()))
}

fn artifact_key(session: QuerySession<'_>, node_id: &NodeId) -> Option<TraceEndpointKey> {
    let node = session.graph().get_node(node_id)?;
    match node.kind {
        NodeKind::ProvenanceArtifact { .. } => Some(TraceEndpointKey::Artifact(node_id.clone())),
        _ => None,
    }
}

fn insert_candidate(
    candidates: &mut BTreeMap<(TraceEndpointKey, u8), NeighborCandidate>,
    next: TraceEndpointKey,
    forward_hop: TraceHopKey,
) {
    candidates.insert(
        (next.clone(), hop_kind_rank(forward_hop.kind)),
        NeighborCandidate { next, forward_hop },
    );
}

fn hop_kind_rank(kind: TaintTraceHopKind) -> u8 {
    match kind {
        TaintTraceHopKind::Produces => 0,
        TaintTraceHopKind::Consumes => 1,
        TaintTraceHopKind::FlowsTo => 2,
        TaintTraceHopKind::Dispatches => 3,
        TaintTraceHopKind::ExpandsTo => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::{TaintTraceEndpointRef, TaintTraceQuery};
    use crate::QuerySession;
    use caushell_graph::{Edge, EdgeKind, GraphNode, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode, ExecutionSemantics,
        ProvenanceArtifact, ProvenanceEdgeSemantics, ProvenanceProduceKind, SessionId,
        SessionSummary, ShellKind, TaintTraceDirection, TaintTraceEndpoint, TaintTraceHopKind,
        TaintTraceStats,
    };

    fn build_produce_consume_graph() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "echo hi > ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "bash ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:1"),
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: None,
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:2"),
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            EdgeKind::Consumes,
        ));

        graph
    }

    fn build_projected_expand_graph() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "bash -c 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("nested:sess-1:3:0"),
            caushell_graph::NodeKind::NestedPayload {
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
                input_fragments: vec![caushell_types::NestedPayloadInputFragmentSnapshot {
                    text: "echo ok".to_string(),
                    quoted: true,
                    node_kind: "raw_string".to_string(),
                }],
                input_source: None,
                resolution_kind: "parsed".to_string(),
                resolution_detail: None,
                resolution_runtime_input_source: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:3:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(3),
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
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:3"),
            NodeId::new("nested:sess-1:3:0"),
            EdgeKind::ExpandsTo,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("nested:sess-1:3:0"),
            NodeId::new("derived:sess-1:3:0:0"),
            EdgeKind::ExpandsTo,
        ));

        graph
    }

    fn build_dispatch_and_flow_graph() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:4"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "sudo bash ./build.sh | bash",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived-dispatch:sess-1:4:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(4),
                origin: DerivedInvocationOrigin::Dispatch {
                    source_command_index: 0,
                    dispatch_index: 0,
                    command_slot: "wrapped_command".to_string(),
                },
                derived_command_index: 0,
                raw_text: "bash ./build.sh".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
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
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:4"),
            NodeId::new("derived-dispatch:sess-1:4:0:0"),
            EdgeKind::Dispatches,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("derived-dispatch:sess-1:4:0:0"),
            NodeId::new("pipeline-segment:sess-1:4:1"),
            EdgeKind::FlowsTo,
        ));

        graph
    }

    fn attach_execution_semantics(
        graph: &mut SessionGraph,
        execution_unit_node_id: &str,
        semantics_node_id: &str,
        semantics: ExecutionSemantics,
    ) {
        let _ = graph.add_node(GraphNode::new(
            NodeId::new(semantics_node_id),
            caushell_graph::NodeKind::ExecutionSemantics { semantics },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new(execution_unit_node_id),
            NodeId::new(semantics_node_id),
            EdgeKind::Defines,
        ));
    }

    #[test]
    fn taint_trace_query_forward_from_artifact_reaches_consumer_execution_unit() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(
            trace.matches()[0].source().node_id().0,
            "artifact:path-content:/tmp/project/build.sh"
        );
        assert_eq!(trace.matches()[0].sink().node_id().0, "command:sess-1:2");
        assert_eq!(trace.matches()[0].hops().len(), 1);
        assert_eq!(
            trace.matches()[0].hops()[0].kind(),
            TaintTraceHopKind::Consumes
        );
    }

    #[test]
    fn taint_trace_query_backward_reverses_consume_produce_search_into_forward_path() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Backward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:1"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        let matched = &trace.matches()[0];
        assert_eq!(matched.source().node_id().0, "command:sess-1:1");
        assert_eq!(matched.sink().node_id().0, "command:sess-1:2");
        assert_eq!(
            matched
                .hops()
                .iter()
                .map(|hop| hop.kind())
                .collect::<Vec<_>>(),
            vec![TaintTraceHopKind::Produces, TaintTraceHopKind::Consumes]
        );
    }

    #[test]
    fn taint_trace_query_projects_nested_payload_expand_into_one_execution_hop() {
        let graph = build_projected_expand_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:3"))
            .sink_execution_unit_node_id(NodeId::new("derived:sess-1:3:0:0"))
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(trace.matches()[0].hops().len(), 1);
        assert_eq!(
            trace.matches()[0].hops()[0].kind(),
            TaintTraceHopKind::ExpandsTo
        );
    }

    #[test]
    fn taint_trace_query_follows_dispatch_then_flow_between_execution_units() {
        let graph = build_dispatch_and_flow_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:4"))
            .sink_execution_unit_node_id(NodeId::new("pipeline-segment:sess-1:4:1"))
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(
            trace.matches()[0]
                .hops()
                .iter()
                .map(|hop| hop.kind())
                .collect::<Vec<_>>(),
            vec![TaintTraceHopKind::Dispatches, TaintTraceHopKind::FlowsTo]
        );
    }

    #[test]
    fn taint_trace_query_blocks_paths_through_barrier_endpoint() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Backward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:1"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .barrier_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .execute(session);

        let trace = result.trace();
        assert!(trace.matches().is_empty());
        assert!(!trace.stats().truncated());
    }

    #[test]
    fn taint_trace_query_reports_depth_truncation() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Backward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:1"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .max_depth(1)
            .execute(session);

        let trace = result.trace();
        assert!(trace.matches().is_empty());
        assert!(trace.stats().truncated());
        assert!(trace.stats().over_max_depth());
        assert!(!trace.stats().over_max_paths());
    }

    #[test]
    fn taint_trace_endpoint_ref_exposes_typed_views() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);

        let source = result.trace().matches()[0].source();
        let sink = result.trace().matches()[0].sink();

        assert!(matches!(source, TaintTraceEndpointRef::Artifact { .. }));
        assert!(source.artifact().is_some());
        assert!(source.execution_unit().is_none());
        assert!(sink.artifact().is_none());
        assert!(sink.execution_unit().is_some());
    }

    #[test]
    fn taint_trace_endpoint_ref_converts_to_contract_value() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);

        let source = result.trace().matches()[0]
            .source()
            .to_taint_trace_endpoint();
        let sink = result.trace().matches()[0].sink().to_taint_trace_endpoint();

        assert!(matches!(source, TaintTraceEndpoint::Artifact { .. }));
        assert!(matches!(sink, TaintTraceEndpoint::ExecutionUnit { .. }));
    }

    #[test]
    fn taint_trace_ref_converts_to_contract_value() {
        let graph = build_produce_consume_graph();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Backward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:1"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);

        let trace = result.trace().to_taint_trace();

        assert_eq!(trace.direction, TaintTraceDirection::Backward);
        assert_eq!(trace.matches.len(), 1);
        assert_eq!(trace.matches[0].hops.len(), 2);
        assert_eq!(trace.matches[0].hops[0].kind, TaintTraceHopKind::Produces);
        assert_eq!(trace.matches[0].hops[1].kind, TaintTraceHopKind::Consumes);
        assert_eq!(
            trace.stats,
            TaintTraceStats {
                truncated: false,
                over_max_depth: false,
                over_max_paths: false,
            }
        );
    }

    #[test]
    fn taint_trace_query_resolves_execution_payload_sink_selector() {
        let mut graph = build_produce_consume_graph();
        attach_execution_semantics(
            &mut graph,
            "command:sess-1:2",
            "execution-semantics:command:sess-1:2",
            ExecutionSemantics::new("bash", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload(),
        );

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_execution_payload()
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(trace.matches()[0].sink().node_id().0, "command:sess-1:2");
        assert_eq!(
            trace.matches()[0].hops()[0].kind(),
            TaintTraceHopKind::Consumes
        );
    }

    #[test]
    fn taint_trace_query_resolves_execution_payload_sink_selector_in_backward_search() {
        let mut graph = build_produce_consume_graph();
        attach_execution_semantics(
            &mut graph,
            "command:sess-1:2",
            "execution-semantics:command:sess-1:2",
            ExecutionSemantics::new("bash", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload(),
        );

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Backward)
            .source_execution_unit_node_id(NodeId::new("command:sess-1:1"))
            .sink_execution_payload()
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(trace.matches()[0].source().node_id().0, "command:sess-1:1");
        assert_eq!(trace.matches()[0].sink().node_id().0, "command:sess-1:2");
        assert_eq!(
            trace.matches()[0]
                .hops()
                .iter()
                .map(|hop| hop.kind())
                .collect::<Vec<_>>(),
            vec![TaintTraceHopKind::Produces, TaintTraceHopKind::Consumes]
        );
    }

    #[test]
    fn taint_trace_query_resolves_startup_config_sink_selector() {
        let mut graph = build_produce_consume_graph();
        attach_execution_semantics(
            &mut graph,
            "command:sess-1:2",
            "execution-semantics:command:sess-1:2",
            ExecutionSemantics::new("bash", "startup_config")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .loading_startup_config(),
        );

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_startup_config_load()
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(trace.matches()[0].sink().node_id().0, "command:sess-1:2");
        assert_eq!(
            trace.matches()[0].hops()[0].kind(),
            TaintTraceHopKind::Consumes
        );
    }

    #[test]
    fn taint_trace_query_resolves_execution_payload_source_selector_in_forward_search() {
        let mut graph = build_produce_consume_graph();
        attach_execution_semantics(
            &mut graph,
            "command:sess-1:1",
            "execution-semantics:command:sess-1:1",
            ExecutionSemantics::new("bash", "command_string")
                .with_payload_mode(ExecutionPayloadMode::CommandString)
                .executing_payload(),
        );

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_execution_payload()
            .sink_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .execute(session);

        let trace = result.trace();
        assert_eq!(trace.matches().len(), 1);
        assert_eq!(trace.matches()[0].source().node_id().0, "command:sess-1:1");
        assert_eq!(
            trace.matches()[0].sink().node_id().0,
            "artifact:path-content:/tmp/project/build.sh"
        );
        assert_eq!(
            trace.matches()[0].hops()[0].kind(),
            TaintTraceHopKind::Produces
        );
    }

    #[test]
    fn taint_trace_query_blocks_paths_through_execution_payload_barrier_selector() {
        let mut graph = build_produce_consume_graph();
        attach_execution_semantics(
            &mut graph,
            "command:sess-1:2",
            "execution-semantics:command:sess-1:2",
            ExecutionSemantics::new("bash", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload(),
        );

        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = TaintTraceQuery::new()
            .direction(TaintTraceDirection::Forward)
            .source_artifact_node_id(NodeId::new("artifact:path-content:/tmp/project/build.sh"))
            .sink_execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .barrier_execution_payload()
            .execute(session);

        let trace = result.trace();
        assert!(trace.matches().is_empty());
        assert!(!trace.stats().truncated());
    }
}
