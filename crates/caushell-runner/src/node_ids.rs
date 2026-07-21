use caushell_graph::NodeId;
use caushell_types::{CheckRequest, CommandSequenceNo, SessionId};

pub fn request_anchor_node_id(request: &CheckRequest) -> NodeId {
    request_anchor_node_id_for(&request.session_id, request.sequence_no)
}

pub fn request_anchor_node_id_for(
    session_id: &SessionId,
    sequence_no: CommandSequenceNo,
) -> NodeId {
    NodeId::new(format!(
        "command-request:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
    ))
}

pub fn top_level_command_node_id(request: &CheckRequest, command_index: usize) -> NodeId {
    top_level_command_node_id_for(&request.session_id, request.sequence_no, command_index)
}

pub fn top_level_command_node_id_for(
    session_id: &SessionId,
    sequence_no: CommandSequenceNo,
    command_index: usize,
) -> NodeId {
    NodeId::new(format!(
        "command:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        command_index,
    ))
}

pub fn shell_state_reconciliation_anchor_node_id_for(
    session_id: &SessionId,
    sequence_no: CommandSequenceNo,
) -> NodeId {
    NodeId::new(format!(
        "shell-state-reconciliation:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
    ))
}

pub fn variable_value_artifact_node_id(name: &str, observed_at: CommandSequenceNo) -> NodeId {
    NodeId::new(format!("artifact:variable-value:{name}:{}", observed_at.0))
}
