mod host_target_catalog;
mod metadata_mutation_classifier;
mod resolved_sink;
mod semantic_rules;

pub(crate) use host_target_catalog::{
    HostTargetOperand, block_device_path_for_arg_with_optional_cwd,
    block_device_write_reason_for_redirection_with_optional_cwd,
    catastrophic_delete_target_for_arg,
};
pub(crate) use semantic_rules::{
    CommandSinkReasonBuckets, collect_command_sink_reason_buckets_with_optional_cwd,
    collect_execution_unit_scoped_reason_buckets,
};
