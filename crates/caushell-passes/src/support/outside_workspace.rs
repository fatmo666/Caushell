use std::collections::BTreeMap;

use caushell_query::{PathContentOriginQuery, QuerySession, SequenceWindow};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathTrustScope, PathTrustSet, ProvenanceConsumeKind,
    RuleAction,
};

use crate::path::{join_shell_path, normalize_shell_path, path_is_within_root};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePathConsumeSet {
    pub normalized_workspace_root: String,
    pub consumes: Vec<OutsideWorkspacePathConsume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePathConsume {
    pub path: String,
    pub slot_name: Option<String>,
    pub normalized_command_name: Option<String>,
    pub latest_prior_write: Option<OutsideWorkspacePriorWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePriorWrite {
    pub sequence_no: CommandSequenceNo,
    pub raw_text: String,
}

pub(crate) fn collect_outside_workspace_path_consumes(
    query_session: QuerySession<'_>,
    request: &CheckRequest,
    trust_sets: &BTreeMap<String, PathTrustSet>,
    selected_trust_sets: &[String],
    consume_kind: ProvenanceConsumeKind,
    required_scope: PathTrustScope,
) -> Option<OutsideWorkspacePathConsumeSet> {
    let workspace_root = request.workspace_root.as_deref()?;
    let normalized_workspace_root = normalize_shell_path(workspace_root);
    let mut consumes = Vec::new();

    let path_facts = PathContentOriginQuery::new()
        .window(exact_sequence_window(request.sequence_no))
        .consume_kind(consume_kind)
        .used_by_root_sequence(request.sequence_no)
        .execute(query_session);

    for path in path_facts.origins() {
        let consume = path.consume();

        if path_is_within_root(consume.path(), &normalized_workspace_root) {
            continue;
        }

        if path_is_trusted_for_scope(
            consume.path(),
            trust_sets,
            selected_trust_sets,
            required_scope,
            request.home.as_deref(),
        ) {
            continue;
        }

        consumes.push(OutsideWorkspacePathConsume {
            path: consume.path().to_string(),
            slot_name: consume.slot_name().map(str::to_string),
            normalized_command_name: consume.normalized_command_name().map(str::to_string),
            latest_prior_write: path
                .latest_prior_write()
                .map(|write| OutsideWorkspacePriorWrite {
                    sequence_no: write.execution_unit().root_command_sequence_no(),
                    raw_text: write.execution_unit().raw_text().to_string(),
                }),
        });
    }

    Some(OutsideWorkspacePathConsumeSet {
        normalized_workspace_root,
        consumes,
    })
}

fn exact_sequence_window(sequence_no: CommandSequenceNo) -> SequenceWindow {
    SequenceWindow::new()
        .after_sequence(CommandSequenceNo::new(sequence_no.0.saturating_sub(1)))
        .before_sequence(sequence_no.next())
}

pub(crate) fn path_is_trusted_for_scope(
    path: &str,
    trust_sets: &BTreeMap<String, PathTrustSet>,
    selected_trust_sets: &[String],
    required_scope: PathTrustScope,
    home: Option<&str>,
) -> bool {
    for trust_set_name in selected_trust_sets {
        let Some(trust_set) = trust_sets.get(trust_set_name) else {
            continue;
        };

        if !trust_set.trusts_scope(required_scope) {
            continue;
        }

        for root in &trust_set.roots {
            let Some(normalized_root) = resolve_trust_root(root, home) else {
                continue;
            };

            if path_is_within_root(path, &normalized_root) {
                return true;
            }
        }
    }

    false
}

pub(crate) fn decision_for_rule_action(action: RuleAction) -> Option<Decision> {
    match action {
        RuleAction::Observe => None,
        RuleAction::NeedApproval => Some(Decision::NeedApproval),
        RuleAction::Deny => Some(Decision::Deny),
    }
}

pub(crate) fn push_unique_reason(reasons: &mut Vec<String>, reason: String) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn resolve_trust_root(root: &str, home: Option<&str>) -> Option<String> {
    if root == "~" {
        return home.map(normalize_shell_path);
    }

    if let Some(rest) = root.strip_prefix("~/") {
        return home.map(|home| join_shell_path(home, rest));
    }

    if root.starts_with('~') {
        return None;
    }

    // Policy roots are stable anchors, so relative paths are intentionally unsupported here.
    if !root.starts_with('/') {
        return None;
    }

    Some(normalize_shell_path(root))
}
