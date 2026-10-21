use crate::{Edge, GraphNode, NodeId};
use caushell_types::CommandSequenceNo;

pub trait GraphRead {
    fn state_object_count(&self) -> usize {
        self.state_objects().len()
    }
    /// Compatibility implementation. Production graphs use a rebuildable index.
    fn state_candidate_nodes<'a>(
        &'a self,
        object: &caushell_types::SafetyObject,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        let object = object.clone();
        Box::new(self.nodes().filter(move |node| {
            matches!(&node.kind,
            crate::NodeKind::StateCandidate { fact } if fact.object == object)
        }))
    }

    fn state_objects(&self) -> std::collections::BTreeSet<caushell_types::SafetyObject> {
        self.nodes()
            .filter_map(|node| match &node.kind {
                crate::NodeKind::StateCandidate { fact } => Some(fact.object.clone()),
                _ => None,
            })
            .collect()
    }

    /// Reserved, fixed-size facts survive approval, compaction and recovery.
    fn incomplete_budgets(&self) -> Vec<caushell_types::AnalysisBudgetKind> {
        caushell_types::AnalysisBudgetKind::ALL
            .into_iter()
            .filter(|budget| {
                self.get_node(&NodeId::new(format!(
                    "analysis-incomplete:{}",
                    budget.key()
                )))
                .is_some_and(|node| matches!(node.kind, crate::NodeKind::AnalysisIncomplete { .. }))
            })
            .collect()
    }

    /// Compatibility fallback; production graph views use a directory index.
    fn path_family_artifact_nodes_for_path<'a>(
        &'a self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
        let path = path.to_owned();
        Box::new(self.path_content_artifact_nodes().filter(move |node| {
            matches!(&node.kind, crate::NodeKind::ProvenanceArtifact { artifact } if artifact.family_contains_path(&path))
        }))
    }
    fn get_node(&self, id: &NodeId) -> Option<&GraphNode>;
    fn node_count(&self) -> usize;
    fn edge_count(&self) -> usize;
    fn nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a>;
    fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a>;
    fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a>;
    fn command_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn derived_invocation_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn nested_payload_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn execution_semantics_nodes_in_window<'a>(
        &'a self,
        after_sequence: Option<CommandSequenceNo>,
        before_sequence: Option<CommandSequenceNo>,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn path_fact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn path_fact_nodes_by_concrete_path<'a>(
        &'a self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn path_content_artifact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
    fn path_content_artifact_nodes_by_path<'a>(
        &'a self,
        path: &str,
    ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a>;
}
