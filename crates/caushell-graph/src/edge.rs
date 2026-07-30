use caushell_types::{ProvenanceEdgeSemantics, SessionGraphEdgeKindSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
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

use crate::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub semantics: Option<ProvenanceEdgeSemantics>,
}

impl Edge {
    pub fn new(from: NodeId, to: NodeId, kind: EdgeKind) -> Self {
        Self {
            from,
            to,
            kind,
            semantics: None,
        }
    }

    pub fn with_semantics(
        from: NodeId,
        to: NodeId,
        kind: EdgeKind,
        semantics: ProvenanceEdgeSemantics,
    ) -> Self {
        Self {
            from,
            to,
            kind,
            semantics: Some(semantics),
        }
    }
}

impl From<EdgeKind> for SessionGraphEdgeKindSnapshot {
    fn from(value: EdgeKind) -> Self {
        match value {
            EdgeKind::Defines => Self::Defines,
            EdgeKind::Reads => Self::Reads,
            EdgeKind::Writes => Self::Writes,
            EdgeKind::MutatesMetadata => Self::MutatesMetadata,
            EdgeKind::Targets => Self::Targets,
            EdgeKind::Consumes => Self::Consumes,
            EdgeKind::Produces => Self::Produces,
            EdgeKind::Dispatches => Self::Dispatches,
            EdgeKind::ExpandsTo => Self::ExpandsTo,
            EdgeKind::DependsOn => Self::DependsOn,
            EdgeKind::FlowsTo => Self::FlowsTo,
            EdgeKind::ChangesCwdTo => Self::ChangesCwdTo,
            EdgeKind::InheritsFrom => Self::InheritsFrom,
            EdgeKind::TriggeredBy => Self::TriggeredBy,
        }
    }
}

impl From<SessionGraphEdgeKindSnapshot> for EdgeKind {
    fn from(value: SessionGraphEdgeKindSnapshot) -> Self {
        match value {
            SessionGraphEdgeKindSnapshot::Defines => Self::Defines,
            SessionGraphEdgeKindSnapshot::Reads => Self::Reads,
            SessionGraphEdgeKindSnapshot::Writes => Self::Writes,
            SessionGraphEdgeKindSnapshot::MutatesMetadata => Self::MutatesMetadata,
            SessionGraphEdgeKindSnapshot::Targets => Self::Targets,
            SessionGraphEdgeKindSnapshot::Consumes => Self::Consumes,
            SessionGraphEdgeKindSnapshot::Produces => Self::Produces,
            SessionGraphEdgeKindSnapshot::Dispatches => Self::Dispatches,
            SessionGraphEdgeKindSnapshot::ExpandsTo => Self::ExpandsTo,
            SessionGraphEdgeKindSnapshot::DependsOn => Self::DependsOn,
            SessionGraphEdgeKindSnapshot::FlowsTo => Self::FlowsTo,
            SessionGraphEdgeKindSnapshot::ChangesCwdTo => Self::ChangesCwdTo,
            SessionGraphEdgeKindSnapshot::InheritsFrom => Self::InheritsFrom,
            SessionGraphEdgeKindSnapshot::TriggeredBy => Self::TriggeredBy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Edge, EdgeKind};
    use crate::NodeId;

    #[test]
    fn edge_kind_can_be_compared() {
        assert_eq!(EdgeKind::Defines, EdgeKind::Defines);
        assert_ne!(EdgeKind::Reads, EdgeKind::Writes);
    }

    #[test]
    fn edge_can_connect_two_nodes() {
        let edge = Edge::new(NodeId::new("cmd-1"), NodeId::new("path-1"), EdgeKind::Reads);

        assert_eq!(edge.from.0, "cmd-1");
        assert_eq!(edge.to.0, "path-1");
        assert_eq!(edge.kind, EdgeKind::Reads);
        assert_eq!(edge.semantics, None);
    }
}
