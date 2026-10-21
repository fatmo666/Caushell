mod configured;
mod cwd;
pub(crate) use configured::resolve_configured_path;
pub(crate) use cwd::{effective_cwd_cases, project_path_at_cwd};
pub(crate) use extract::collect_invocation_mutation_targets;
mod expression;
mod extract;
mod glob;
pub(crate) use glob::resolve_glob_path_operand as iteration_glob_bounds;
mod normalize;
mod runtime;
mod target_match;

#[cfg(test)]
pub(crate) use expression::classify_path_operand_expression;

pub(crate) use expression::{
    PathExpression, classify_path_operand_expression_with_tilde, shell_pattern_matches_path,
};
pub(crate) use extract::{
    EXECUTABLE_FILE_SLOT, MutationTargetCandidate, RedirectionPathFactCandidate,
    collect_effect_mutation_targets, collect_mutation_scope_facts, collect_path_facts,
    collect_redirection_path_fact, collect_redirection_path_facts, derived_path_slot_name,
    edge_kind_for_mutation_scope_operation, edge_kind_for_path_role, mutation_scope_fact_node_id,
    path_fact_node_id, path_operand_depends_on_cwd, path_target_is_inapplicable,
    provenance_artifact_for_path, provenance_edge_for_path_fact, provenance_path_artifact_node_id,
    resolved_path_purpose_for_profile_purpose, resolved_path_role_for_profile_role,
    unmodeled_executable_path,
};
pub(crate) use normalize::{
    expand_home_path_spelling, join_shell_path, normalize_shell_path, resolve_path_operand,
    resolve_path_operand_with_tilde,
};
pub(crate) use target_match::match_path_expression_against_target_or_direct_children;
