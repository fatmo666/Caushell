use std::collections::BTreeMap;

use crate::{ExecutionUnitHistoryQuery, ExecutionUnitRef, QuerySession, SequenceWindow};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, PathFact, PathResolution, PathUsage, PathUsageRelation, ResolvedPathPurpose,
    ResolvedPathRole,
};

// Path-identity query surface over typed PathFact nodes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathFactsQuery {
    path: Option<String>,
    role: Option<ResolvedPathRole>,
    purpose: Option<Option<ResolvedPathPurpose>>,
    used_by_root_sequence: Option<CommandSequenceNo>,
    used_by_execution_unit_node_id: Option<NodeId>,
}

impl PathFactsQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn role(mut self, role: ResolvedPathRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn purpose(mut self, purpose: ResolvedPathPurpose) -> Self {
        self.purpose = Some(Some(purpose));
        self
    }

    pub fn without_purpose(mut self) -> Self {
        self.purpose = Some(None);
        self
    }

    pub fn used_by_root_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.used_by_root_sequence = Some(sequence_no);
        self
    }

    pub fn used_by_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.used_by_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathFactsResult<'a> {
        let mut facts: Vec<PathFactRef<'a>> = candidate_path_fact_nodes(session, self)
            .into_iter()
            .filter_map(|node| PathFactRef::from_node(node, session))
            .collect();
        facts.retain(|fact| self.matches(fact));

        facts.sort_by(|left, right| {
            path_resolution_sort_key(left.resolution())
                .cmp(&path_resolution_sort_key(right.resolution()))
                .then_with(|| left.node_id().0.cmp(&right.node_id().0))
        });

        PathFactsResult { facts }
    }

    fn matches(&self, fact: &PathFactRef<'_>) -> bool {
        self.path
            .as_deref()
            .is_none_or(|path| fact.concrete_path() == Some(path))
            && self.role.is_none_or(|role| fact.role() == role)
            && self.purpose.is_none_or(|purpose| fact.purpose() == purpose)
            && self.used_by_root_sequence.is_none_or(|sequence_no| {
                fact.used_by()
                    .iter()
                    .any(|usage| usage.execution_unit().root_command_sequence_no() == sequence_no)
            })
            && self
                .used_by_execution_unit_node_id
                .as_ref()
                .is_none_or(|node_id| {
                    fact.used_by()
                        .iter()
                        .any(|usage| usage.execution_unit().node_id() == node_id)
                })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFactsResult<'a> {
    facts: Vec<PathFactRef<'a>>,
}

impl<'a> PathFactsResult<'a> {
    pub fn facts(&self) -> &[PathFactRef<'a>] {
        self.facts.as_slice()
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

fn path_resolution_sort_key(resolution: &PathResolution) -> (u8, String) {
    match resolution {
        PathResolution::Concrete { path } => (0, path.clone()),
        PathResolution::ToolConvention { path, convention } => (1, format!("{convention}:{path}")),
        PathResolution::DerivedConcrete { path, basis, rule } => {
            (2, format!("{path}:{basis:?}:{rule:?}"))
        }
        PathResolution::DerivedUnresolved {
            basis,
            rule,
            reason,
        } => (3, format!("{basis:?}:{rule:?}:{reason:?}")),
        PathResolution::MissingBinding { variable_name } => (4, variable_name.clone()),
        PathResolution::UnsupportedDynamicBinding {
            variable_name,
            repr,
        } => (5, format!("{variable_name}:{repr}")),
        PathResolution::UnsupportedDynamicText { text } => (6, text.clone()),
        PathResolution::HomeUnavailable { text } => (7, text.clone()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFactRef<'a> {
    node_id: NodeId,
    resolution: PathResolution,
    role: ResolvedPathRole,
    purpose: Option<ResolvedPathPurpose>,
    slot_name: String,
    normalized_command_name: Option<String>,
    metadata_mutation: Option<caushell_types::PathMetadataMutation>,
    used_by: Vec<PathUsageRefIdentity<'a>>,
}

impl<'a> PathFactRef<'a> {
    fn from_node(node: &'a caushell_graph::GraphNode, session: QuerySession<'a>) -> Option<Self> {
        let NodeKind::PathFact {
            resolution,
            role,
            purpose,
            slot_name,
            normalized_command_name,
            metadata_mutation,
        } = &node.kind
        else {
            return None;
        };

        Some(Self {
            node_id: node.id.clone(),
            resolution: resolution.clone(),
            role: *role,
            purpose: *purpose,
            slot_name: slot_name.clone(),
            normalized_command_name: normalized_command_name.clone(),
            metadata_mutation: metadata_mutation.clone(),
            used_by: collect_path_usages_for_node(session, &node.id),
        })
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn resolution(&self) -> &PathResolution {
        &self.resolution
    }

    pub fn concrete_path(&self) -> Option<&str> {
        self.resolution.concrete_path()
    }

    pub fn role(&self) -> ResolvedPathRole {
        self.role
    }

    pub fn purpose(&self) -> Option<ResolvedPathPurpose> {
        self.purpose
    }

    pub fn slot_name(&self) -> &str {
        self.slot_name.as_str()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn metadata_mutation(&self) -> Option<&caushell_types::PathMetadataMutation> {
        self.metadata_mutation.as_ref()
    }

    pub fn used_by(&self) -> &[PathUsageRefIdentity<'a>] {
        self.used_by.as_slice()
    }

    pub fn to_path_fact(&self) -> PathFact {
        PathFact {
            node_id: self.node_id.0.clone(),
            resolution: self.resolution.clone(),
            role: self.role,
            purpose: self.purpose,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
            metadata_mutation: self.metadata_mutation.clone(),
            used_by: self
                .used_by
                .iter()
                .map(PathUsageRefIdentity::to_path_usage)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathUsageRefIdentity<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    relation: EdgeKind,
}

impl<'a> PathUsageRefIdentity<'a> {
    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn relation(&self) -> EdgeKind {
        self.relation
    }

    pub fn to_path_usage(&self) -> PathUsage {
        let execution_unit = self.execution_unit.to_execution_unit();

        PathUsage {
            source_node_id: execution_unit.node_id,
            execution_kind: execution_unit.execution_kind,
            root_sequence_no: execution_unit.root_sequence_no,
            depth: execution_unit.depth,
            raw_text: execution_unit.raw_text,
            relation: path_usage_relation(self.relation),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathUsageCandidateIdentity<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    relation: EdgeKind,
}

impl<'a> PathUsageCandidateIdentity<'a> {
    fn to_usage(self) -> PathUsageRefIdentity<'a> {
        PathUsageRefIdentity {
            execution_unit: self.execution_unit,
            relation: self.relation,
        }
    }
}

fn collect_path_usages_for_node<'a>(
    session: QuerySession<'a>,
    node_id: &NodeId,
) -> Vec<PathUsageRefIdentity<'a>> {
    let mut usages_by_key = BTreeMap::new();

    for edge in session.graph().incoming_edges(node_id) {
        let Some(source_node) = session.graph().get_node(&edge.from) else {
            continue;
        };
        let Some(execution_unit) = ExecutionUnitRef::from_node(source_node) else {
            continue;
        };
        if !matches!(
            edge.kind,
            EdgeKind::Reads | EdgeKind::Writes | EdgeKind::MutatesMetadata | EdgeKind::Targets
        ) {
            continue;
        }

        usages_by_key.insert(
            (
                execution_unit.node_id().0.clone(),
                path_usage_relation_rank(edge.kind),
            ),
            PathUsageCandidateIdentity {
                execution_unit,
                relation: edge.kind,
            },
        );
    }

    let mut usages: Vec<_> = usages_by_key
        .into_values()
        .map(PathUsageCandidateIdentity::to_usage)
        .collect();

    usages.sort_by(|left, right| {
        left.execution_unit()
            .root_command_sequence_no()
            .cmp(&right.execution_unit().root_command_sequence_no())
            .then_with(|| {
                left.execution_unit()
                    .depth()
                    .cmp(&right.execution_unit().depth())
            })
            .then_with(|| {
                left.execution_unit()
                    .node_id()
                    .0
                    .cmp(&right.execution_unit().node_id().0)
            })
            .then_with(|| {
                path_usage_relation_rank(left.relation())
                    .cmp(&path_usage_relation_rank(right.relation()))
            })
    });

    usages
}

fn path_usage_relation_rank(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Reads => 0,
        EdgeKind::Writes => 1,
        EdgeKind::MutatesMetadata => 2,
        EdgeKind::Targets => 3,
        other => unreachable!(
            "path_facts identity surface only supports Reads/Writes/MutatesMetadata/Targets, got {other:?}"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PathUsageClass {
    Read,
    Write,
    MetadataMutation,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathUsageCandidate<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    path_node_id: &'a NodeId,
    path: &'a str,
    relation: EdgeKind,
    class: PathUsageClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathUsageHistoryQuery {
    path: String,
    window: SequenceWindow,
}

impl PathUsageHistoryQuery {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            window: SequenceWindow::new(),
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathUsageHistoryResult<'a> {
        let mut usages = collect_path_usages(session, self.path(), self.window, |class| {
            matches!(
                class,
                PathUsageClass::Read
                    | PathUsageClass::Write
                    | PathUsageClass::MetadataMutation
                    | PathUsageClass::Target
            )
        });

        usages.sort_by(|left, right| {
            left.execution_unit()
                .root_command_sequence_no()
                .cmp(&right.execution_unit().root_command_sequence_no())
                .then_with(|| {
                    left.execution_unit()
                        .depth()
                        .cmp(&right.execution_unit().depth())
                })
                .then_with(|| {
                    left.execution_unit()
                        .node_id()
                        .0
                        .cmp(&right.execution_unit().node_id().0)
                })
                .then_with(|| left.path_node_id().0.cmp(&right.path_node_id().0))
        });

        PathUsageHistoryResult { usages }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWriteHistoryQuery {
    path: String,
    window: SequenceWindow,
}

impl PathWriteHistoryQuery {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            window: SequenceWindow::new(),
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
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

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathWriteHistoryResult<'a> {
        let writes = collect_path_usages(session, self.path(), self.window, |class| {
            class == PathUsageClass::Write
        })
        .into_iter()
        .map(PathWriteRef::from_usage)
        .collect();

        PathWriteHistoryResult { writes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathUsageHistoryResult<'a> {
    usages: Vec<PathUsageRef<'a>>,
}

impl<'a> PathUsageHistoryResult<'a> {
    pub fn usages(&self) -> &[PathUsageRef<'a>] {
        self.usages.as_slice()
    }

    pub fn len(&self) -> usize {
        self.usages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.usages.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWriteHistoryResult<'a> {
    writes: Vec<PathWriteRef<'a>>,
}

impl<'a> PathWriteHistoryResult<'a> {
    pub fn writes(&self) -> &[PathWriteRef<'a>] {
        self.writes.as_slice()
    }

    pub fn len(&self) -> usize {
        self.writes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathUsageRef<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    path_node_id: &'a NodeId,
    path: &'a str,
    relation: EdgeKind,
}

impl<'a> PathUsageRef<'a> {
    fn from_candidate(candidate: PathUsageCandidate<'a>) -> Self {
        Self {
            execution_unit: candidate.execution_unit,
            path_node_id: candidate.path_node_id,
            path: candidate.path,
            relation: candidate.relation,
        }
    }

    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn path_node_id(&self) -> &'a NodeId {
        self.path_node_id
    }

    pub fn path(&self) -> &'a str {
        self.path
    }

    pub fn relation(&self) -> EdgeKind {
        self.relation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathWriteRef<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    path_node_id: &'a NodeId,
    path: &'a str,
}

impl<'a> PathWriteRef<'a> {
    fn from_usage(usage: PathUsageRef<'a>) -> Self {
        Self {
            execution_unit: usage.execution_unit,
            path_node_id: usage.path_node_id,
            path: usage.path,
        }
    }

    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn path_node_id(&self) -> &'a NodeId {
        self.path_node_id
    }

    pub fn path(&self) -> &'a str {
        self.path
    }
}

fn path_usage_relation(relation: EdgeKind) -> PathUsageRelation {
    match relation {
        EdgeKind::Reads => PathUsageRelation::Reads,
        EdgeKind::Writes => PathUsageRelation::Writes,
        EdgeKind::MutatesMetadata => PathUsageRelation::MutatesMetadata,
        EdgeKind::Targets => PathUsageRelation::Targets,
        other => unreachable!(
            "path_facts identity surface only supports Reads/Writes/MutatesMetadata/Targets, got {other:?}"
        ),
    }
}

fn collect_path_usages<'a, F>(
    session: QuerySession<'a>,
    path_query: &str,
    window: SequenceWindow,
    mut usage_filter: F,
) -> Vec<PathUsageRef<'a>>
where
    F: FnMut(PathUsageClass) -> bool,
{
    let mut usages_by_key = BTreeMap::new();

    for path_node in session.graph().path_fact_nodes_by_concrete_path(path_query) {
        for edge in session.graph().incoming_edges(&path_node.id) {
            let Some(candidate) = path_usage_candidate(session, edge, path_node) else {
                continue;
            };

            if !window.contains(candidate.execution_unit.root_command_sequence_no()) {
                continue;
            }

            if !usage_filter(candidate.class) {
                continue;
            }

            let key = (
                candidate.execution_unit.node_id().0.as_str(),
                candidate.path_node_id.0.as_str(),
                path_usage_relation_rank(candidate.relation),
            );

            usages_by_key.insert(key, candidate);
        }
    }

    let mut usages: Vec<PathUsageRef<'a>> = usages_by_key
        .into_values()
        .map(PathUsageRef::from_candidate)
        .collect();

    usages.sort_by(|left, right| {
        left.execution_unit()
            .root_command_sequence_no()
            .cmp(&right.execution_unit().root_command_sequence_no())
            .then_with(|| {
                left.execution_unit()
                    .depth()
                    .cmp(&right.execution_unit().depth())
            })
            .then_with(|| {
                left.execution_unit()
                    .node_id()
                    .0
                    .cmp(&right.execution_unit().node_id().0)
            })
            .then_with(|| left.path_node_id().0.cmp(&right.path_node_id().0))
    });

    usages
}

fn path_usage_candidate<'a>(
    session: QuerySession<'a>,
    edge: &'a caushell_graph::Edge,
    path_node: &'a caushell_graph::GraphNode,
) -> Option<PathUsageCandidate<'a>> {
    let source_node = session.graph().get_node(&edge.from)?;
    let execution_unit = ExecutionUnitRef::from_node(source_node)?;

    match &path_node.kind {
        NodeKind::PathFact { resolution, .. } => {
            let path = resolution.concrete_path()?;
            let class = match edge.kind {
                EdgeKind::Reads => PathUsageClass::Read,
                EdgeKind::Writes => PathUsageClass::Write,
                EdgeKind::MutatesMetadata => PathUsageClass::MetadataMutation,
                EdgeKind::Targets => PathUsageClass::Target,
                _ => return None,
            };

            Some(PathUsageCandidate {
                execution_unit,
                path_node_id: &path_node.id,
                path,
                relation: edge.kind,
                class,
            })
        }
        _ => None,
    }
}

fn candidate_path_fact_nodes<'a>(
    session: QuerySession<'a>,
    query: &PathFactsQuery,
) -> Vec<&'a caushell_graph::GraphNode> {
    if let Some(node_id) = query.used_by_execution_unit_node_id.as_ref() {
        return collect_path_fact_nodes_for_execution_unit(session, node_id);
    }

    if let Some(sequence_no) = query.used_by_root_sequence {
        return collect_path_fact_nodes_for_root_sequence(session, sequence_no);
    }

    if let Some(path) = query.path.as_deref() {
        return session
            .graph()
            .path_fact_nodes_by_concrete_path(path)
            .collect();
    }

    session.graph().path_fact_nodes().collect()
}

fn collect_path_fact_nodes_for_root_sequence<'a>(
    session: QuerySession<'a>,
    sequence_no: CommandSequenceNo,
) -> Vec<&'a caushell_graph::GraphNode> {
    let mut nodes_by_id = BTreeMap::new();

    for execution_unit in ExecutionUnitHistoryQuery::new()
        .window(exact_sequence_window(sequence_no))
        .execute(session)
        .execution_units()
        .iter()
        .copied()
    {
        let execution_unit_node_id = execution_unit.node_id().clone();
        for node in collect_path_fact_nodes_for_execution_unit(session, &execution_unit_node_id) {
            nodes_by_id.insert(node.id.0.clone(), node);
        }
    }

    nodes_by_id.into_values().collect()
}

fn collect_path_fact_nodes_for_execution_unit<'a>(
    session: QuerySession<'a>,
    node_id: &NodeId,
) -> Vec<&'a caushell_graph::GraphNode> {
    let mut nodes_by_id = BTreeMap::new();

    for edge in session.graph().outgoing_edges(node_id) {
        if !is_path_usage_edge(edge.kind) {
            continue;
        }

        let Some(path_node) = session.graph().get_node(&edge.to) else {
            continue;
        };
        if !matches!(path_node.kind, NodeKind::PathFact { .. }) {
            continue;
        }

        nodes_by_id.insert(path_node.id.0.clone(), path_node);
    }

    nodes_by_id.into_values().collect()
}

fn exact_sequence_window(sequence_no: CommandSequenceNo) -> SequenceWindow {
    SequenceWindow::new()
        .after_sequence(CommandSequenceNo::new(sequence_no.0.saturating_sub(1)))
        .before_sequence(sequence_no.next())
}

fn is_path_usage_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Reads | EdgeKind::Writes | EdgeKind::MutatesMetadata | EdgeKind::Targets
    )
}

#[cfg(test)]
mod tests {
    use super::{PathFactsQuery, PathUsageHistoryQuery, PathWriteHistoryQuery};
    use crate::ExecutionUnitOrigin;
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocationOrigin, PathMetadataMutation, PathMetadataMutationKind,
        PathResolution, PathUsageRelation, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind, ResolvedPathPurpose,
        ResolvedPathRole, SessionId, SessionSummary, ShellKind,
    };

    fn graph_with_path_usage() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "cat README.md",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:8"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(8),
            "rm README.md",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:9"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(9),
            "echo ok > out.txt",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:10"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(10),
            "chmod +x README.md",
            "/tmp/project",
            ShellKind::Bash,
        );

        let _ = graph.add_path_fact(
            NodeId::new("path-readme"),
            PathResolution::Concrete {
                path: "/tmp/project/README.md".to_string(),
            },
            ResolvedPathRole::Read,
            Some(ResolvedPathPurpose::GenericOperand),
            "path",
            None,
        );
        let _ = graph.add_path_fact(
            NodeId::new("path-out"),
            PathResolution::Concrete {
                path: "/tmp/project/out.txt".to_string(),
            },
            ResolvedPathRole::Write,
            Some(ResolvedPathPurpose::GenericOperand),
            "redirect_target_0",
            None,
        );
        let _ = graph.add_path_fact_with_metadata_mutation(
            NodeId::new("path-readme-mode"),
            PathResolution::Concrete {
                path: "/tmp/project/README.md".to_string(),
            },
            ResolvedPathRole::MetadataMutation,
            Some(ResolvedPathPurpose::GenericOperand),
            "path_targets",
            Some("chmod".to_string()),
            Some(PathMetadataMutation {
                mutation_kinds: vec![PathMetadataMutationKind::ChangeMode],
                raw_operand: Some("+x".to_string()),
                owner_group: None,
                recursive: true,
            }),
        );

        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:8"),
            NodeId::new("path-readme"),
            EdgeKind::Targets,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:3"),
            NodeId::new("path-readme"),
            EdgeKind::Reads,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:10"),
            NodeId::new("path-readme-mode"),
            EdgeKind::MutatesMetadata,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:9"),
            NodeId::new("path-out"),
            EdgeKind::Writes,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/README.md"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/README.md".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/out.txt"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/out.txt".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:3"),
            NodeId::new("artifact:path-content:/tmp/project/README.md"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::PathRead,
                slot_name: Some("path".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:9"),
            NodeId::new("artifact:path-content:/tmp/project/out.txt"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: None,
                }),
            },
        ));

        graph
    }

    fn graph_with_path_writes() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "echo one > payload.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:7"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(7),
            "echo two > payload.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:9"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(9),
            "cat payload.sh",
            "/tmp/project",
            ShellKind::Bash,
        );

        let _ = graph.add_path_fact(
            NodeId::new("path-payload"),
            PathResolution::Concrete {
                path: "/tmp/project/payload.sh".to_string(),
            },
            ResolvedPathRole::Write,
            Some(ResolvedPathPurpose::GenericOperand),
            "redirect_target_0",
            None,
        );

        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:2"),
            NodeId::new("path-payload"),
            EdgeKind::Writes,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:7"),
            NodeId::new("path-payload"),
            EdgeKind::Writes,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:9"),
            NodeId::new("path-payload"),
            EdgeKind::Reads,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/payload.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:2"),
            NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:7"),
            NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:9"),
            NodeId::new("artifact:path-content:/tmp/project/payload.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::PathRead,
                slot_name: Some("path".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::GenericOperand),
                }),
            },
        ));

        graph
    }

    fn graph_with_derived_path_usage() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:5"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(5),
            "bash -c 'source ../shared/team.rc'",
            "/tmp/project/work",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:5:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(5),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "source ../shared/team.rc".to_string(),
                command_name: Some("source".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_path_fact(
            NodeId::new("path-team-rc"),
            PathResolution::Concrete {
                path: "/tmp/project/shared/team.rc".to_string(),
            },
            ResolvedPathRole::Config,
            Some(ResolvedPathPurpose::StartupConfig),
            "startup_config",
            Some("source".to_string()),
        );
        let _ = graph.add_edge(Edge::new(
            NodeId::new("derived:sess-1:5:0:0"),
            NodeId::new("path-team-rc"),
            EdgeKind::Reads,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/shared/team.rc".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("derived:sess-1:5:0:0"),
            NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::StartupConfigSource,
                slot_name: Some("startup_config".to_string()),
                normalized_command_name: Some("source".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Config,
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                }),
            },
        ));

        graph
    }

    fn graph_with_mixed_path_usage_same_root() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:5"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(5),
            "sudo bash --rcfile ../shared/team.rc -c 'echo ok'",
            "/tmp/project/work",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived-dispatch:sess-1:5:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(5),
                origin: DerivedInvocationOrigin::Dispatch {
                    source_command_index: 0,
                    dispatch_index: 0,
                    command_slot: "wrapped_command".to_string(),
                },
                derived_command_index: 0,
                raw_text: "bash --rcfile ../shared/team.rc -c echo ok".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_path_fact(
            NodeId::new("path-sudo-chdir"),
            PathResolution::Concrete {
                path: "/tmp/project/work".to_string(),
            },
            ResolvedPathRole::CwdAnchor,
            Some(ResolvedPathPurpose::WorkingDirectory),
            "working_directory",
            Some("sudo".to_string()),
        );
        let _ = graph.add_path_fact(
            NodeId::new("path-team-rc-derived"),
            PathResolution::Concrete {
                path: "/tmp/project/shared/team.rc".to_string(),
            },
            ResolvedPathRole::Config,
            Some(ResolvedPathPurpose::StartupConfig),
            "startup_config",
            Some("bash".to_string()),
        );
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:5"),
            NodeId::new("path-sudo-chdir"),
            EdgeKind::Targets,
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("derived-dispatch:sess-1:5:0:0"),
            NodeId::new("path-team-rc-derived"),
            EdgeKind::Reads,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/shared/team.rc".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("derived-dispatch:sess-1:5:0:0"),
            NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::StartupConfigSource,
                slot_name: Some("startup_config".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Config,
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                }),
            },
        ));

        graph
    }

    fn graph_with_purposeless_path_fact() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_path_fact(
            NodeId::new("path-redirect"),
            PathResolution::Concrete {
                path: "/tmp/project/out.log".to_string(),
            },
            ResolvedPathRole::Write,
            None,
            "redirect_target_0",
            None,
        );

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
            panic!("path query should not require graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("path query should not require graph.edges()");
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
    fn resolved_path_facts_query_returns_all_path_facts_sorted_by_path() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new().execute(session);

        assert_eq!(result.len(), 3);
        assert_eq!(result.facts()[0].node_id().0, "path-readme");
        assert_eq!(
            result.facts()[0].concrete_path(),
            Some("/tmp/project/README.md")
        );
        assert_eq!(result.facts()[0].role(), ResolvedPathRole::Read);
        assert_eq!(
            result.facts()[0].purpose(),
            Some(ResolvedPathPurpose::GenericOperand)
        );
        assert_eq!(result.facts()[0].slot_name(), "path");
        assert_eq!(result.facts()[0].normalized_command_name(), None);
        assert_eq!(result.facts()[1].node_id().0, "path-readme-mode");
        assert_eq!(result.facts()[1].role(), ResolvedPathRole::MetadataMutation);
        assert_eq!(result.facts()[1].normalized_command_name(), Some("chmod"));
        assert_eq!(
            result.facts()[1].metadata_mutation(),
            Some(&PathMetadataMutation {
                mutation_kinds: vec![PathMetadataMutationKind::ChangeMode],
                raw_operand: Some("+x".to_string()),
                owner_group: None,
                recursive: true,
            })
        );
        assert_eq!(result.facts()[2].node_id().0, "path-out");
    }

    #[test]
    fn resolved_path_facts_query_filters_by_path_role_and_purpose() {
        let graph = graph_with_derived_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new()
            .path("/tmp/project/shared/team.rc")
            .role(ResolvedPathRole::Config)
            .purpose(ResolvedPathPurpose::StartupConfig)
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.facts()[0].node_id().0, "path-team-rc");
        assert_eq!(result.facts()[0].slot_name(), "startup_config");
        assert_eq!(result.facts()[0].normalized_command_name(), Some("source"));
    }

    #[test]
    fn resolved_path_facts_query_exposes_usage_identity_edges() {
        let graph = graph_with_derived_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new()
            .path("/tmp/project/shared/team.rc")
            .execute(session);
        let usage = result.facts()[0].used_by()[0];

        assert_eq!(
            usage.execution_unit().origin(),
            ExecutionUnitOrigin::Derived
        );
        assert_eq!(usage.execution_unit().node_id().0, "derived:sess-1:5:0:0");
        assert_eq!(usage.execution_unit().root_command_sequence_no().0, 5);
        assert_eq!(usage.execution_unit().depth(), 1);
        assert_eq!(
            usage.execution_unit().raw_text(),
            "source ../shared/team.rc"
        );
        assert_eq!(usage.relation(), EdgeKind::Reads);
    }

    #[test]
    fn resolved_path_fact_ref_converts_to_contract_value() {
        let graph = graph_with_derived_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let fact = PathFactsQuery::new()
            .path("/tmp/project/shared/team.rc")
            .execute(session)
            .facts()[0]
            .clone();

        let resolved = fact.to_path_fact();

        assert_eq!(resolved.node_id, "path-team-rc");
        assert_eq!(
            resolved.resolution,
            PathResolution::Concrete {
                path: "/tmp/project/shared/team.rc".to_string()
            }
        );
        assert_eq!(resolved.role, ResolvedPathRole::Config);
        assert_eq!(resolved.purpose, Some(ResolvedPathPurpose::StartupConfig));
        assert_eq!(resolved.slot_name, "startup_config");
        assert_eq!(resolved.normalized_command_name, Some("source".to_string()));
        assert_eq!(resolved.used_by.len(), 1);
        assert_eq!(resolved.used_by[0].source_node_id, "derived:sess-1:5:0:0");
        assert_eq!(
            resolved.used_by[0].execution_kind,
            caushell_types::ExecutionUnitKind::Derived
        );
        assert_eq!(resolved.used_by[0].relation, PathUsageRelation::Reads);
    }

    #[test]
    fn resolved_path_facts_query_can_filter_purposeless_facts() {
        let graph = graph_with_purposeless_path_fact();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new().without_purpose().execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.facts()[0].concrete_path(),
            Some("/tmp/project/out.log")
        );
        assert_eq!(result.facts()[0].purpose(), None);
    }

    #[test]
    fn resolved_path_facts_query_can_filter_by_using_root_sequence() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new()
            .used_by_root_sequence(CommandSequenceNo::new(9))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.facts()[0].node_id().0, "path-out");
        assert_eq!(
            result.facts()[0].concrete_path(),
            Some("/tmp/project/out.txt")
        );
    }

    #[test]
    fn resolved_path_facts_query_can_filter_by_using_execution_unit_node_id() {
        let graph = graph_with_mixed_path_usage_same_root();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathFactsQuery::new()
            .used_by_root_sequence(CommandSequenceNo::new(5))
            .used_by_execution_unit_node_id(NodeId::new("derived-dispatch:sess-1:5:0:0"))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.facts()[0].node_id().0, "path-team-rc-derived");
        assert_eq!(
            result.facts()[0].concrete_path(),
            Some("/tmp/project/shared/team.rc")
        );
        assert_eq!(result.facts()[0].normalized_command_name(), Some("bash"));
    }

    #[test]
    fn path_usage_history_query_returns_empty_when_path_has_no_usage() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathUsageHistoryQuery::new("/tmp/project/missing.txt").execute(session);

        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn path_usage_history_query_returns_matching_command_path_edges_sorted_by_sequence() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathUsageHistoryQuery::new("/tmp/project/README.md").execute(session);

        assert_eq!(result.len(), 3);
        assert_eq!(
            result.usages()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            3
        );
        assert_eq!(
            result.usages()[0].execution_unit().raw_text(),
            "cat README.md"
        );
        assert_eq!(result.usages()[0].relation(), EdgeKind::Reads);
        assert_eq!(
            result.usages()[1]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            8
        );
        assert_eq!(
            result.usages()[1].execution_unit().raw_text(),
            "rm README.md"
        );
        assert_eq!(result.usages()[1].relation(), EdgeKind::Targets);
        assert_eq!(
            result.usages()[2]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            10
        );
        assert_eq!(
            result.usages()[2].execution_unit().raw_text(),
            "chmod +x README.md"
        );
        assert_eq!(result.usages()[2].relation(), EdgeKind::MutatesMetadata);
    }

    #[test]
    fn path_usage_history_query_filters_strictly_before_sequence() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathUsageHistoryQuery::new("/tmp/project/README.md")
            .before_sequence(CommandSequenceNo::new(8))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.usages()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            3
        );
    }

    #[test]
    fn path_usage_history_query_filters_strictly_after_sequence() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathUsageHistoryQuery::new("/tmp/project/README.md")
            .after_sequence(CommandSequenceNo::new(3))
            .execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.usages()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            8
        );
        assert_eq!(
            result.usages()[1]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            10
        );
        assert_eq!(result.usages()[1].relation(), EdgeKind::MutatesMetadata);
    }

    #[test]
    fn path_usage_history_query_can_use_shared_sequence_window() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathUsageHistoryQuery::new("/tmp/project/README.md")
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(3))
                    .before_sequence(CommandSequenceNo::new(9)),
            )
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.usages()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            8
        );
        assert_eq!(result.usages()[0].relation(), EdgeKind::Targets);
    }

    #[test]
    fn path_usage_history_query_exposes_typed_usage_fields() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let usage = PathUsageHistoryQuery::new("/tmp/project/out.txt")
            .execute(session)
            .usages()[0];

        assert_eq!(usage.execution_unit().node_id().0, "command:sess-1:9");
        assert_eq!(
            usage.execution_unit().origin(),
            ExecutionUnitOrigin::TopLevel
        );
        assert_eq!(usage.path_node_id().0, "path-out");
        assert_eq!(usage.path(), "/tmp/project/out.txt");
        assert_eq!(usage.relation(), EdgeKind::Writes);
    }

    #[test]
    fn path_usage_history_query_exposes_metadata_mutation_contract_relation() {
        let graph = graph_with_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let usage = PathUsageHistoryQuery::new("/tmp/project/README.md")
            .execute(session)
            .usages()
            .iter()
            .find(|usage| usage.relation() == EdgeKind::MutatesMetadata)
            .copied()
            .expect("expected metadata mutation usage");

        assert_eq!(usage.execution_unit().raw_text(), "chmod +x README.md");
        assert_eq!(
            super::path_usage_relation(usage.relation()),
            PathUsageRelation::MutatesMetadata
        );
    }

    #[test]
    fn path_usage_history_query_can_return_derived_execution_unit_sources() {
        let graph = graph_with_derived_path_usage();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let usage = PathUsageHistoryQuery::new("/tmp/project/shared/team.rc")
            .execute(session)
            .usages()[0];

        assert_eq!(
            usage.execution_unit().origin(),
            ExecutionUnitOrigin::Derived
        );
        assert_eq!(usage.execution_unit().node_id().0, "derived:sess-1:5:0:0");
        assert_eq!(usage.execution_unit().root_command_sequence_no().0, 5);
        assert_eq!(usage.execution_unit().depth(), 1);
        assert_eq!(
            usage.execution_unit().raw_text(),
            "source ../shared/team.rc"
        );
        assert_eq!(usage.relation(), EdgeKind::Reads);
    }

    #[test]
    fn path_write_history_query_returns_only_writes_sorted_by_sequence() {
        let graph = graph_with_path_writes();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathWriteHistoryQuery::new("/tmp/project/payload.sh").execute(session);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.writes()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            2
        );
        assert_eq!(
            result.writes()[0].execution_unit().raw_text(),
            "echo one > payload.sh"
        );
        assert_eq!(
            result.writes()[1]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            7
        );
        assert_eq!(
            result.writes()[1].execution_unit().raw_text(),
            "echo two > payload.sh"
        );
    }

    #[test]
    fn path_write_history_query_respects_sequence_window() {
        let graph = graph_with_path_writes();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathWriteHistoryQuery::new("/tmp/project/payload.sh")
            .window(
                SequenceWindow::new()
                    .after_sequence(CommandSequenceNo::new(2))
                    .before_sequence(CommandSequenceNo::new(9)),
            )
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.writes()[0]
                .execution_unit()
                .root_command_sequence_no()
                .0,
            7
        );
    }

    #[test]
    fn path_write_history_query_exposes_typed_write_fields() {
        let graph = graph_with_path_writes();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let write = PathWriteHistoryQuery::new("/tmp/project/payload.sh")
            .before_sequence(CommandSequenceNo::new(3))
            .execute(session)
            .writes()[0];

        assert_eq!(write.execution_unit().node_id().0, "command:sess-1:2");
        assert_eq!(
            write.execution_unit().origin(),
            ExecutionUnitOrigin::TopLevel
        );
        assert_eq!(write.path_node_id().0, "path-payload");
        assert_eq!(write.path(), "/tmp/project/payload.sh");
    }

    #[test]
    fn path_queries_do_not_require_full_graph_scan() {
        let graph = graph_with_path_usage();
        let wrapped = PanicOnFullScanGraph { inner: &graph };
        let summary = SessionSummary::new();
        let session = QuerySession::new(&wrapped, &summary);

        let facts = PathFactsQuery::new()
            .path("/tmp/project/README.md")
            .execute(session);
        assert!(!facts.is_empty());

        let usages = PathUsageHistoryQuery::new("/tmp/project/README.md").execute(session);
        assert!(!usages.is_empty());

        let writes = PathWriteHistoryQuery::new("/tmp/project/out.txt").execute(session);
        assert!(!writes.is_empty());
    }
}
