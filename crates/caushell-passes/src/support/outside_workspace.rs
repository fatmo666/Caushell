use caushell_query::{PathContentOriginQuery, PathTargetQuery, QuerySession, SequenceWindow};
use caushell_runner::{PathOperation, RunnerContext};
use caushell_types::{
    CommandSequenceNo, Decision, InProcessCodeLoadKind, PathResolution, PathTargetOperation,
    ProvenanceConsumeKind, RuleAction, RuleId, SemanticResolution,
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
    pub reason: String,
    pub resolution: SemanticResolution<PathResolution>,
}

pub(crate) struct DeclaredPathConsumption {
    pub source: caushell_graph::NodeId,
    pub slot: String,
    pub operation: PathTargetOperation,
}

pub(crate) fn declared_path_consumptions(ctx: &RunnerContext) -> Vec<DeclaredPathConsumption> {
    let mut declarations = Vec::new();
    for record in super::graph_backed_execution_resolve_records(ctx) {
        let Some(bound) = super::bound_invocation(record.result()) else {
            continue;
        };
        for parameter in &bound.bound_parameters {
            if parameter.values.is_empty() {
                continue;
            }
            let operation = match &parameter.semantic {
                caushell_profile::SemanticType::Path(path) => match path.purpose {
                    Some(caushell_profile::PathPurpose::ScriptSource) => Some(PathTargetOperation::ExecuteFile),
                    Some(caushell_profile::PathPurpose::InProcessCode) => Some(PathTargetOperation::LoadCode),
                    Some(caushell_profile::PathPurpose::StartupConfig) => Some(PathTargetOperation::StartupConfig),
                    _ => None,
                },
                caushell_profile::SemanticType::InProcessCodeLoad(load) if matches!(load.load_kind,
                    InProcessCodeLoadKind::Path | InProcessCodeLoadKind::LibraryPath | InProcessCodeLoadKind::AgentPath) => Some(PathTargetOperation::LoadCode),
                caushell_profile::SemanticType::InProcessCodeLoad(load) if load.load_kind == InProcessCodeLoadKind::Unknown && parameter.semantic_values().any(|value|
                    matches!(caushell_profile::project_semantic_value(&caushell_profile::ValueProjection::Identity, value),
                        Some(caushell_profile::SemanticValueResolution::Known(text)) if text.starts_with('/') || text.starts_with("./") || text.starts_with("../") || text.starts_with('~'))) => Some(PathTargetOperation::LoadCode),
                _ => None,
            };
            if let Some(operation) = operation {
                if operation == PathTargetOperation::LoadCode
                    && !bound.effects.iter().any(|effect| {
                        effect.kind == caushell_profile::EffectKind::LoadInProcessCode
                    })
                {
                    continue;
                }
                declarations.push(DeclaredPathConsumption {
                    source: record.source_node_id().clone(),
                    slot: parameter.name.as_str().into(),
                    operation,
                });
            }
        }
    }
    for candidate in super::collect_implicit_startup_config_candidates(ctx) {
        declarations.push(DeclaredPathConsumption {
            source: candidate.source_node_id,
            slot: super::implicit_startup_slot_name().into(),
            operation: PathTargetOperation::StartupConfig,
        });
    }
    declarations
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutsideWorkspacePriorWrite {
    pub sequence_no: CommandSequenceNo,
    pub raw_text: String,
}

pub(crate) fn collect_outside_workspace_path_consumes(
    query_session: QuerySession<'_>,
    ctx: &RunnerContext,
    consume_kind: ProvenanceConsumeKind,
    operation: PathOperation,
    rule: RuleId,
) -> OutsideWorkspacePathConsumeSet {
    let request = ctx.request();
    let normalized_workspace_root = request
        .workspace_root
        .as_deref()
        .map(normalize_shell_path)
        .unwrap_or_else(|| "<unavailable>".into());
    let mut consumes = Vec::new();

    let path_facts = PathContentOriginQuery::new()
        .window(exact_sequence_window(request.sequence_no))
        .consume_kind(consume_kind)
        .used_by_root_sequence(request.sequence_no)
        .execute(query_session);

    let target_operation = match operation {
        PathOperation::ExecuteFile => PathTargetOperation::ExecuteFile,
        PathOperation::LoadCodeFile => PathTargetOperation::LoadCode,
        PathOperation::StartupConfig => PathTargetOperation::StartupConfig,
        _ => unreachable!("file consumption operations only"),
    };
    let targets = PathTargetQuery::new(request.sequence_no).execute(query_session);
    for target in targets
        .iter()
        .filter(|target| target.operation == target_operation)
    {
        if matches!(&target.resolution, SemanticResolution::NotApplicable { .. })
            || ctx
                .target_path_policy()
                .is_some_and(|policy| policy.check_target(target, operation, rule).is_exempt())
        {
            continue;
        }
        let origin = path_facts.origins().iter().find(|origin| {
            let consume = origin.consume();
            consume.execution_unit().node_id().0 == target.source_node_id
                && consume.slot_name() == Some(target.slot_name.as_str())
                && target.lexical.concrete_path() == Some(consume.path())
        });
        let path = match &target.resolution {
            SemanticResolution::Resolved { value } => value
                .concrete_path()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{value:?}")),
            _ => target
                .lexical
                .concrete_path()
                .unwrap_or("<unresolved>")
                .into(),
        };
        let reason = match &target.resolution {
            SemanticResolution::Unresolved { gap } => format!(
                "file input {} for slot {} is unresolved ({:?}): {}",
                path, target.slot_name, gap.kind, gap.detail
            ),
            _ => format!(
                "file input {} for slot {} is outside the granted path scope or unproven",
                path, target.slot_name
            ),
        };
        consumes.push(OutsideWorkspacePathConsume {
            source_node_id: caushell_graph::NodeId::new(&target.source_node_id),
            path,
            slot_name: Some(target.slot_name.clone()),
            normalized_command_name: origin
                .and_then(|origin| origin.consume().normalized_command_name())
                .map(str::to_string),
            latest_prior_write: origin.and_then(|origin| origin.latest_prior_write()).map(
                |write| OutsideWorkspacePriorWrite {
                    sequence_no: write.execution_unit().root_command_sequence_no(),
                    raw_text: write.execution_unit().raw_text().to_string(),
                },
            ),
            reason,
            resolution: target.resolution.clone(),
        });
    }
    for declaration in declared_path_consumptions(ctx)
        .into_iter()
        .filter(|d| d.operation == target_operation)
    {
        if targets.iter().any(|target| {
            target.operation == target_operation
                && target.source_node_id == declaration.source.0
                && target.slot_name == declaration.slot
        }) {
            continue;
        }
        consumes.push(OutsideWorkspacePathConsume {
            source_node_id: declaration.source,
            path: "<unresolved>".into(),
            slot_name: Some(declaration.slot.clone()),
            normalized_command_name: None,
            latest_prior_write: None,
            reason: format!(
                "declared file input {} has no target-scope proof",
                declaration.slot
            ),
            resolution: SemanticResolution::Unresolved {
                gap: caushell_types::SemanticGap {
                    kind: caushell_types::SemanticGapKind::UnknownTarget,
                    detail: "missing target fact".into(),
                },
            },
        });
    }
    OutsideWorkspacePathConsumeSet {
        normalized_workspace_root,
        consumes,
    }
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
