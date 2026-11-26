use std::collections::BTreeMap;

use caushell_parse::{CommandFact, ParsedCommandArtifact, StatementTerminator};
use caushell_runner::{ExecutionUnitOriginKind, ExecutionUnitResolveRecord};
use caushell_types::PathNamespaceEffect;

use super::Input;
use crate::support::unzip;

pub(super) fn completes_before_unzip(
    target: &Input,
    writer: &Input,
    records: &BTreeMap<&str, &ExecutionUnitResolveRecord>,
    parsed: Option<&ParsedCommandArtifact>,
) -> bool {
    if !unzip::directory_write(&writer.fact) && !unzip::unknown_member_write(&writer.fact) {
        return false;
    }
    let Some(extraction) = records.get(writer.fact.source_node_id.as_str()) else {
        return false;
    };
    if !unzip::ordinary_extraction(extraction).is_some_and(unzip::has_explicit_directory) {
        return false;
    }
    if target.fact.source_node_id == writer.fact.source_node_id {
        // The native invocation establishes its output directory before
        // extracting members. Its overwrite effect refers to the same
        // directory operand, not a separate change during setup.
        return unzip::directory_write(&target.fact);
    }

    if target.namespace_effect != Some(PathNamespaceEffect::DirectoryCreate) {
        return false;
    }
    let Some(parsed) = parsed else { return false };
    let Some(setup) = records.get(target.fact.source_node_id.as_str()) else {
        return false;
    };
    let (Some(setup), Some(extraction)) = (
        foreground_command(parsed, setup),
        foreground_command(parsed, extraction),
    ) else {
        return false;
    };
    parsed.status_conditions.iter().any(|condition| {
        condition.success
            && condition.shell_scope_span.is_none()
            && condition.command_span == setup.span
            && setup.span.end_byte <= extraction.span.start_byte
            && condition.guarded_region.start_byte <= extraction.span.start_byte
            && extraction.span.end_byte <= condition.guarded_region.end_byte
    })
}

fn foreground_command<'a>(
    parsed: &'a ParsedCommandArtifact,
    record: &ExecutionUnitResolveRecord,
) -> Option<&'a CommandFact> {
    if record.origin_kind != ExecutionUnitOriginKind::TopLevel {
        return None;
    }
    parsed.commands.iter().find(|command| {
        command.span == record.command_ref.span
            && command.shell_scope_span.is_none()
            && command.control_flow_span.is_none()
            && !command.in_pipeline
            && command.terminator != Some(StatementTerminator::Background)
    })
}
