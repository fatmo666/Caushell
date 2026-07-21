use std::collections::BTreeSet;

use caushell_graph::NodeId;
use caushell_parse::{
    AssignmentCommandFact, CommandFact, DeclarationCommandFact, FunctionDefinitionFact,
    ParsedCommandArtifact, RedirectionFact, SourceSpan, UnsetCommandFact,
};
use caushell_runner::top_level_command_node_id;
use caushell_types::CheckRequest;

use crate::support::collect_pipeline_groups;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopLevelUnitKind<'a> {
    Command(&'a CommandFact),
    PipelineRoot(&'a CommandFact),
    BareRedirection(&'a RedirectionFact),
    Declaration(&'a DeclarationCommandFact),
    Assignment(&'a AssignmentCommandFact),
    Unset(&'a UnsetCommandFact),
    FunctionDefinition(&'a FunctionDefinitionFact),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TopLevelUnit<'a> {
    pub(crate) unit_index: usize,
    pub(crate) kind: TopLevelUnitKind<'a>,
}

impl<'a> TopLevelUnit<'a> {
    pub(crate) fn node_id(&self, request: &CheckRequest) -> NodeId {
        top_level_command_node_id(request, self.unit_index)
    }

    pub(crate) fn raw_text(&self, parsed: &ParsedCommandArtifact) -> String {
        let span = self.top_level_span();
        parsed
            .raw_command
            .get(span.start_byte..span.end_byte)
            .unwrap_or_else(|| self.text())
            .to_string()
    }

    pub(crate) fn top_level_span(&self) -> &SourceSpan {
        match self.kind {
            TopLevelUnitKind::Command(command) | TopLevelUnitKind::PipelineRoot(command) => {
                &command.top_level_span
            }
            TopLevelUnitKind::BareRedirection(redirection) => &redirection.top_level_span,
            TopLevelUnitKind::Declaration(command) => &command.top_level_span,
            TopLevelUnitKind::Assignment(command) => &command.top_level_span,
            TopLevelUnitKind::Unset(command) => &command.top_level_span,
            TopLevelUnitKind::FunctionDefinition(command) => &command.top_level_span,
        }
    }

    pub(crate) fn text(&self) -> &str {
        match self.kind {
            TopLevelUnitKind::Command(command) | TopLevelUnitKind::PipelineRoot(command) => {
                command.text.as_str()
            }
            TopLevelUnitKind::BareRedirection(redirection) => redirection.text.as_str(),
            TopLevelUnitKind::Declaration(command) => command.text.as_str(),
            TopLevelUnitKind::Assignment(command) => command.text.as_str(),
            TopLevelUnitKind::Unset(command) => command.text.as_str(),
            TopLevelUnitKind::FunctionDefinition(command) => command.text.as_str(),
        }
    }

    pub(crate) fn command_index(&self, parsed: &ParsedCommandArtifact) -> Option<usize> {
        let target_top_level_span = match self.kind {
            TopLevelUnitKind::Command(command) | TopLevelUnitKind::PipelineRoot(command) => {
                &command.top_level_span
            }
            _ => return None,
        };

        parsed
            .commands
            .iter()
            .position(|command| &command.top_level_span == target_top_level_span)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTopLevelUnit<'a> {
    kind: TopLevelUnitKind<'a>,
    span: &'a SourceSpan,
    order_hint: usize,
}

pub(crate) fn collect_top_level_units(parsed: &ParsedCommandArtifact) -> Vec<TopLevelUnit<'_>> {
    let pipeline_groups = collect_pipeline_groups(parsed);
    let pipeline_root_indexes: BTreeSet<usize> = pipeline_groups
        .iter()
        .filter_map(|group| group.commands.first().map(|command| command.command_index))
        .collect();
    let pipeline_member_indexes: BTreeSet<usize> = pipeline_groups
        .iter()
        .flat_map(|group| {
            group
                .commands
                .iter()
                .skip(1)
                .map(|command| command.command_index)
        })
        .collect();

    let mut pending = Vec::new();

    for (command_index, command) in parsed.commands.iter().enumerate() {
        if pipeline_member_indexes.contains(&command_index) {
            continue;
        }

        pending.push(PendingTopLevelUnit {
            kind: if pipeline_root_indexes.contains(&command_index) {
                TopLevelUnitKind::PipelineRoot(command)
            } else {
                TopLevelUnitKind::Command(command)
            },
            span: &command.top_level_span,
            order_hint: command_index,
        });
    }

    for redirection in &parsed.redirections {
        if redirection.parent_command_span.is_some() {
            continue;
        }
        if pending
            .iter()
            .any(|candidate| *candidate.span == redirection.top_level_span)
        {
            continue;
        }

        pending.push(PendingTopLevelUnit {
            kind: TopLevelUnitKind::BareRedirection(redirection),
            span: &redirection.top_level_span,
            order_hint: redirection.span.start_byte,
        });
    }

    for declaration in &parsed.declaration_commands {
        pending.push(PendingTopLevelUnit {
            kind: TopLevelUnitKind::Declaration(declaration),
            span: &declaration.top_level_span,
            order_hint: declaration.span.start_byte,
        });
    }

    for assignment in &parsed.assignment_commands {
        pending.push(PendingTopLevelUnit {
            kind: TopLevelUnitKind::Assignment(assignment),
            span: &assignment.top_level_span,
            order_hint: assignment.span.start_byte,
        });
    }

    for unset in &parsed.unset_commands {
        pending.push(PendingTopLevelUnit {
            kind: TopLevelUnitKind::Unset(unset),
            span: &unset.top_level_span,
            order_hint: unset.span.start_byte,
        });
    }

    for definition in &parsed.function_definitions {
        pending.push(PendingTopLevelUnit {
            kind: TopLevelUnitKind::FunctionDefinition(definition),
            span: &definition.top_level_span,
            order_hint: definition.span.start_byte,
        });
    }

    pending.sort_by(|left, right| {
        left.span
            .start_byte
            .cmp(&right.span.start_byte)
            .then_with(|| left.span.end_byte.cmp(&right.span.end_byte))
            .then_with(|| left.order_hint.cmp(&right.order_hint))
    });

    pending
        .into_iter()
        .enumerate()
        .map(|(unit_index, unit)| TopLevelUnit {
            unit_index,
            kind: unit.kind,
        })
        .collect()
}

pub(crate) fn top_level_unit_for_command<'a>(
    parsed: &'a ParsedCommandArtifact,
    command_index: usize,
) -> Option<TopLevelUnit<'a>> {
    collect_top_level_units(parsed)
        .into_iter()
        .find(|unit| unit.command_index(parsed) == Some(command_index))
}

pub(crate) fn top_level_unit_for_span<'a>(
    parsed: &'a ParsedCommandArtifact,
    top_level_span: &SourceSpan,
) -> Option<TopLevelUnit<'a>> {
    collect_top_level_units(parsed)
        .into_iter()
        .find(|unit| unit.top_level_span() == top_level_span)
}

pub(crate) fn top_level_unit_for_bare_redirection<'a>(
    parsed: &'a ParsedCommandArtifact,
    redirection: &RedirectionFact,
) -> Option<TopLevelUnit<'a>> {
    collect_top_level_units(parsed).into_iter().find(|unit| {
        matches!(
            unit.kind,
            TopLevelUnitKind::BareRedirection(candidate) if candidate.span == redirection.span
        )
    })
}

pub(crate) fn top_level_node_id_for_command(
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
) -> Option<NodeId> {
    top_level_unit_for_command(parsed, command_index).map(|unit| unit.node_id(request))
}

pub(crate) fn top_level_node_id_for_span(
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    top_level_span: &SourceSpan,
) -> Option<NodeId> {
    top_level_unit_for_span(parsed, top_level_span).map(|unit| unit.node_id(request))
}
