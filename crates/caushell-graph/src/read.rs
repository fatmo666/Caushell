use crate::{Edge, GraphNode, NodeId};
use caushell_types::CommandSequenceNo;

pub trait GraphRead {
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
