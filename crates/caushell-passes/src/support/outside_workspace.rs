use caushell_query::{PathContentOriginQuery, QuerySession, SequenceWindow};
use caushell_runner::{PathExemptionPolicy, PathOperation};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ProvenanceConsumeKind, RuleAction,
    RuleId,
};

use crate::path::normalize_shell_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePathConsumeSet {
    pub normalized_workspace_root: String,
    pub consumes: Vec<OutsideWorkspacePathConsume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePathConsume {
    pub source_node_id: caushell_graph::NodeId,
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
    policy: &PathExemptionPolicy,
    consume_kind: ProvenanceConsumeKind,
    operation: PathOperation,
    rule: RuleId,
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

        if policy
            .check(
                &PathResolution::Concrete {
                    path: consume.path().to_owned(),
                },
                operation,
                rule,
            )
            .is_exempt()
        {
            continue;
        }

        consumes.push(OutsideWorkspacePathConsume {
            source_node_id: consume.execution_unit().node_id().clone(),
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
