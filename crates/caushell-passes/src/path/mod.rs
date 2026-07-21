mod expression;
mod extract;
mod normalize;
mod target_match;

pub(crate) use expression::{
    PathExpression, classify_path_operand_expression, shell_pattern_matches_path,
};
pub(crate) use extract::{
    collect_mutation_scope_facts, collect_path_facts, collect_redirection_path_facts,
    edge_kind_for_mutation_scope_operation, edge_kind_for_path_role, mutation_scope_fact_node_id,
    path_fact_node_id, provenance_artifact_for_path, provenance_edge_for_path_fact,
    provenance_path_artifact_node_id, resolved_path_purpose_for_profile_purpose,
    resolved_path_role_for_profile_role,
};
pub(crate) use normalize::{
    join_shell_path, normalize_shell_path, path_is_within_root, resolve_path_operand,
};
pub(crate) use target_match::match_path_expression_against_target_or_direct_children;
