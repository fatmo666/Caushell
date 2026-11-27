use std::collections::BTreeMap;

use caushell_parse::ParsedCommandArtifact;
use caushell_runner::ExecutionUnitResolveRecord;
use caushell_types::PathNamespaceEffect;

use super::{Input, directory_setup::guarded_by_success};
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
    let Some(setup) = records.get(target.fact.source_node_id.as_str()) else {
        return false;
    };
    guarded_by_success(parsed, setup, extraction)
}
