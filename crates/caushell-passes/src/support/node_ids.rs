use caushell_graph::NodeId;
use caushell_parse::{CommandFact, ParsedCommandArtifact, RedirectionFact};
use caushell_runner::{request_anchor_node_id, top_level_command_node_id};
use caushell_types::{CheckRequest, CommandSequenceNo, SessionId};

use crate::support::{
    command_has_pipeline_execution_unit, top_level_unit_for_bare_redirection,
    top_level_unit_for_command,
};

pub(crate) fn pipeline_segment_node_id(
    session_id: &SessionId,
    sequence_no: CommandSequenceNo,
    command_index: usize,
) -> NodeId {
    NodeId::new(format!(
        "pipeline-segment:{}:{}:{}",
        session_id.0.as_str(),
        sequence_no.0,
        command_index,
    ))
}

pub(crate) fn pipeline_stream_artifact_node_id(
    scope_node_id: &NodeId,
    pipeline_group_index: usize,
    stream_index: usize,
) -> NodeId {
    NodeId::new(format!(
        "artifact:pipeline-stream:{}:{}:{}",
        scope_node_id.0, pipeline_group_index, stream_index,
    ))
}

pub(crate) fn transform_output_artifact_node_id(
    scope_node_id: &NodeId,
    pipeline_group_index: usize,
    stream_index: usize,
) -> NodeId {
    NodeId::new(format!(
        "artifact:transform-output:{}:{}:{}",
        scope_node_id.0, pipeline_group_index, stream_index,
    ))
}

pub(crate) fn execution_semantics_node_id(source_node_id: &NodeId) -> NodeId {
    NodeId::new(format!("execution-semantics:{}", source_node_id.0))
}

pub(crate) fn variable_binding_intent_node_id(
    source_node_id: &NodeId,
    variable_name: &str,
) -> NodeId {
    NodeId::new(format!(
        "variable-binding-intent:{}:{}",
        source_node_id.0, variable_name
    ))
}

pub(crate) fn source_node_id_for_command(
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    _command: &CommandFact,
) -> NodeId {
    if command_has_pipeline_execution_unit(parsed, command_index) {
        return pipeline_segment_node_id(&request.session_id, request.sequence_no, command_index);
    }

    top_level_unit_for_command(parsed, command_index)
        .map(|unit| unit.node_id(request))
        .unwrap_or_else(|| top_level_command_node_id(request, command_index))
}

pub(crate) fn source_node_id_for_redirection(
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    redirection: &RedirectionFact,
) -> NodeId {
    redirection_parent_command_index(parsed, redirection)
        .and_then(|command_index| {
            parsed
                .commands
                .get(command_index)
                .map(|command| source_node_id_for_command(request, parsed, command_index, command))
        })
        .or_else(|| {
            top_level_unit_for_bare_redirection(parsed, redirection)
                .map(|unit| unit.node_id(request))
        })
        .unwrap_or_else(|| request_anchor_node_id(request))
}

pub(crate) fn redirection_parent_command_index(
    parsed: &ParsedCommandArtifact,
    redirection: &RedirectionFact,
) -> Option<usize> {
    if let Some(parent_command_span) = redirection.parent_command_span.as_ref() {
        if let Some((command_index, _)) = parsed
            .commands
            .iter()
            .enumerate()
            .find(|(_, command)| &command.span == parent_command_span)
        {
            return Some(command_index);
        }
    }

    let Some(parent_command_name) = redirection.parent_command_name.as_deref() else {
        return nearest_preceding_command_index_for_redirection(parsed, redirection);
    };
    let mut matches = parsed
        .commands
        .iter()
        .enumerate()
        .filter(|(_, command)| command.command_name.as_deref() == Some(parent_command_name));
    let Some(first_match) = matches.next() else {
        return nearest_preceding_command_index_for_redirection(parsed, redirection);
    };

    if matches.next().is_some() {
        return nearest_preceding_command_index_for_redirection(parsed, redirection);
    }

    Some(first_match.0)
}

fn nearest_preceding_command_index_for_redirection(
    parsed: &ParsedCommandArtifact,
    redirection: &RedirectionFact,
) -> Option<usize> {
    parsed
        .commands
        .iter()
        .enumerate()
        .filter(|(_, command)| command_is_redirection_parent_fallback(parsed, command, redirection))
        .max_by_key(|(_, command)| command.span.start_byte)
        .map(|(command_index, _)| command_index)
}

fn command_is_redirection_parent_fallback(
    parsed: &ParsedCommandArtifact,
    command: &CommandFact,
    redirection: &RedirectionFact,
) -> bool {
    if spans_overlap(
        command.span.start_byte,
        command.span.end_byte,
        redirection.span.start_byte,
        redirection.span.end_byte,
    ) {
        return true;
    }

    if command.span.end_byte > redirection.span.start_byte {
        return false;
    }

    parsed
        .raw_command
        .get(command.span.end_byte..redirection.span.start_byte)
        .is_some_and(|between| {
            !between.contains('\n')
                && !between.contains('\r')
                && between.chars().all(|ch| ch == ' ' || ch == '\t')
        })
}

fn spans_overlap(left_start: usize, left_end: usize, right_start: usize, right_end: usize) -> bool {
    left_start < right_end && right_start < left_end
}
