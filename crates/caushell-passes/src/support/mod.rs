mod alias;
pub(crate) mod config_tasks;
mod execution_records;
mod file_execution;
mod function_overlay;
pub(crate) mod git_hooks;
pub(crate) use file_execution::{file_execution_checks, file_reference_is_exempt};
mod hard_deny;
mod implicit_startup;
mod io_provenance;
mod io_target;
mod listener;
mod loop_overlay;
pub(crate) use io_provenance::stream_provenance_mutations;
pub(crate) use io_target::{
    bound_invocation, content_io_target, execution_content_io_target, slot_uses_content_open,
};
pub(crate) use listener::{environment_default, network_listeners, shell_variable_default};
mod native_template;
mod node_ids;
pub(crate) use native_template::{
    bind_symbolic_template_inputs, collect_native_template_input_mutations,
    forwarded_native_argument_inputs,
};
mod outside_workspace;
mod path_list;
pub(crate) use path_list::bind_path_list_targets;
pub(crate) mod parallel_jobs;
mod payload_hard_deny;
mod pipeline;
mod redirection;
mod runtime_variable_overlay;
pub(crate) use runtime_variable_overlay::{
    declaration_uses_nameref, function_variable_escapes, function_variable_escapes_in_frame,
    has_nameref_declaration, runtime_write_visible,
};
pub(crate) mod shell_evaluation;
mod shell_sink_hard_deny;
mod shell_state_options;
pub(crate) use shell_state_options::{
    ExportMode, UnsetMode, export_mode, scalar_identifier, state_visible, unset_mode,
};
mod shell_io_scope;
mod shell_redirections;
pub(crate) use shell_redirections::shell_syntax_redirections;
mod static_payload;
mod substitution_shape;
pub(crate) use substitution_shape::substitution_shapes;
mod stream_records;
mod stream_semantics;
pub(crate) use shell_io_scope::{collect_shell_io_scope_mutations, projected_shell_scope_parents};
pub(crate) use static_payload::scope_has_prior_directory_transition;
pub(crate) use stream_records::stdin_path_records;
pub(crate) use stream_semantics::{StreamSemanticsIndex, annotate_stream_output};
mod top_level_units;
mod variable_facts;
mod variable_overlay;

pub(crate) use runtime_variable_overlay::{
    RebasedBindingReplay, RuntimeBindingReplay, VariableBindingReplay,
    apply_runtime_variable_bindings_before_span, runtime_variable_overlay,
    runtime_visible_variable_bindings_before_span,
};

pub(crate) use alias::{
    AliasExpansionHop, alias_assignments, apply_alias_command, expand_alias_chain, unalias_names,
};
pub(crate) use execution_records::{
    ExecutionResolveRecordRef, graph_backed_execution_resolve_records,
    normalized_command_names_by_source_node, resolved_execution_records_for_local_analysis,
};
pub(crate) use function_overlay::{function_call_bindings, visible_function_bindings_before_span};
pub(crate) use hard_deny::{
    CommandSinkReasonBuckets, HostTargetOperand, block_device_path_for_arg_with_optional_cwd,
    block_device_write_reason_for_redirection_with_optional_cwd, bound_argument_operands_for_slot,
    catastrophic_delete_target_for_arg, collect_command_sink_reason_buckets_with_optional_cwd,
    collect_execution_unit_scoped_reason_buckets,
};
pub(crate) use implicit_startup::{
    ImplicitStartupEnvironmentSource, collect_implicit_startup_config_candidates,
    command_env_artifact_node_id, command_env_value_artifact, implicit_startup_path_fact_index,
    implicit_startup_slot_name, implicit_startup_source_node_ids, inherited_env_artifact_node_id,
    inherited_env_value_artifact,
};
pub(crate) use node_ids::{
    execution_semantics_node_id, nested_payload_node_id, pipeline_segment_node_id,
    pipeline_stream_artifact_node_id, redirection_parent_command_index, source_node_id_for_command,
    source_node_id_for_redirection, transform_output_artifact_node_id,
    variable_binding_intent_node_id,
};
pub(crate) use outside_workspace::{
    collect_outside_workspace_path_consumes, decision_for_rule_action, push_unique_reason,
};
pub(crate) use payload_hard_deny::{
    collect_block_device_destructive_reasons, collect_block_device_session_reasons,
};
pub(crate) use pipeline::command_has_pipeline_execution_unit;
pub(crate) use pipeline::{collect_pipeline_groups, pipeline_has_upstream};
pub(crate) use redirection::{
    EffectiveStdinSource, effective_stdin_source, redirection_targets_stdin_payload,
};
pub(crate) use shell_sink_hard_deny::{
    collect_bare_shell_sink_hard_deny_reasons, collect_shell_sink_hard_deny_reasons_for_command,
    is_file_write_redirection_operator,
};
pub(crate) use static_payload::{
    StaticFileContent, StaticStreamEvidence, known_literal_path_content_before_execution_unit,
    known_literal_path_content_before_scoped_command, known_literal_path_content_before_sequence,
    materialize_static_token_command_substitutions, materialize_static_token_text,
    process_substitution_evidence, static_file_content_before_scoped_command,
    static_io_target_evidence, static_stdin_evidence_for_scoped_command,
};
pub(crate) use top_level_units::{
    collect_top_level_units, top_level_node_id_for_command, top_level_node_id_for_span,
    top_level_unit_for_bare_redirection, top_level_unit_for_command, top_level_unit_for_span,
};
pub(crate) use variable_overlay::{
    PositionalParameterMutation, apply_visible_variable_bindings_before_span,
    command_environment_bindings, positional_parameter_mutation_for_command,
    request_variable_bindings, static_variable_overlay,
};
