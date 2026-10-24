use caushell_profile::{EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, EvidenceKind, ResourceAuthorizationEvidence, ResourceTargetEvidence, RuleId,
    StateOperationKind,
};

use crate::support::decision_for_rule_action;

/// Enforces declared external state classes, never names, live state or guessed
/// filesystem targets. The common path skips before querying the Graph.
pub struct StateOperationGuardPass;

impl SessionAnalysisPass for StateOperationGuardPass {
    fn name(&self) -> &'static str {
        "state_operation_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let candidate = ctx.execution_unit_resolve_records().iter().any(|record| {
            let bound = match &record.result {
                ResolveInvocationArtifactResult::Resolved(resolved) => &resolved.bound,
                ResolveInvocationArtifactResult::SelectionError {
                    partial_bound: Some(bound),
                    ..
                } => bound,
                _ => return false,
            };
            bound.effects.iter().any(|e| {
                e.kind == EffectKind::StateOperation
                    && e.state_operation
                        .is_some_and(|op| op.operation != StateOperationKind::Inspect)
            })
        });
        if !candidate {
            return;
        }

        let sequence = ctx.request().sequence_no;
        let mut query = caushell_query::ExecutionSemanticsQuery::new();
        if let Some(previous) = sequence.0.checked_sub(1) {
            query = query.after_sequence(caushell_types::CommandSequenceNo::new(previous));
        }
        if let Some(next) = sequence.0.checked_add(1) {
            query = query.before_sequence(caushell_types::CommandSequenceNo::new(next));
        }
        let facts = query.execute(caushell_query::QuerySession::from_session(&staged));
        for fact in facts.semantics() {
            for state in fact.state_operations() {
                let rule = match state.operation {
                    StateOperationKind::Inspect => continue,
                    StateOperationKind::Mutate => RuleId::StateMutation,
                    StateOperationKind::Control => RuleId::StateControl,
                    StateOperationKind::Opaque => RuleId::StateOpaqueOperation,
                };
                let reason = format!(
                    "{:?} {:?} state operation declared for {} ({}) at {}; filesystem workspace membership does not authorize this state operation",
                    state.domain,
                    state.operation,
                    fact.normalized_command_name(),
                    fact.form_id(),
                    fact.source().node_id().0
                );
                let source = fact.source().node_id();
                let mut proof = ResourceAuthorizationEvidence {
                    node_id: source.0.clone(),
                    operation: *state,
                    targets: Vec::new(),
                    binding: ctx.resource_authority().map(|s| s.binding().clone()),
                    registry_revision: ctx.resource_authority().map(|s| s.revision()),
                    authorized: false,
                    gap: None,
                };
                if let Some(selector) = state.resource {
                    let endpoints = caushell_query::NetworkEndpointQuery::for_execution_units(
                        staged.graph(),
                        std::slice::from_ref(source),
                        sequence,
                    );
                    for endpoint in endpoints.iter().filter(|e| selector.includes(e.usage)) {
                        let instance = endpoint
                            .endpoint
                            .and_then(|endpoint| ctx.resource_authority()?.resolve(endpoint));
                        let grant_id = instance
                            .as_ref()
                            .and_then(|i| ctx.resource_authority()?.permission(i, *state));
                        proof.targets.push(ResourceTargetEvidence {
                            slot_name: endpoint.slot_name.map(str::to_owned),
                            endpoint: endpoint.endpoint.map(str::to_owned),
                            resource_id: instance.as_ref().map(|i| i.resource_id.clone()),
                            instance_id: instance.as_ref().map(|i| i.instance_id.clone()),
                            generation: instance.as_ref().map(|i| i.generation),
                            grant_id,
                            namespace_id: instance.as_ref().map(|i| i.namespace_id.clone()),
                        });
                    }
                    proof.gap = if fact.operation_semantics_unresolved() {
                        Some("operation scope is incomplete".into())
                    } else if caushell_query::NetworkEndpointQuery::has_transport_target(
                        staged.graph(),
                        source,
                    ) {
                        Some(
                            "transport overrides do not prove an exact managed resource route"
                                .into(),
                        )
                    } else if proof.targets.is_empty() {
                        Some("declared resource target is unavailable".into())
                    } else if proof.targets.iter().any(|t| t.grant_id.is_none()) {
                        Some("resource instance or operation authorization is unproven".into())
                    } else if !owner_namespace_is_proved(ctx, source) {
                        Some(
                            "derived execution does not prove the owning resource namespace".into(),
                        )
                    } else if ctx.resource_authority().is_none_or(|snapshot| {
                        *snapshot.binding()
                            != caushell_types::ExecutionFrameBinding::for_request(
                                ctx.request(),
                                &snapshot.binding().executor_instance_id,
                            )
                    }) {
                        Some("resource authority does not match this check".into())
                    } else {
                        None
                    };
                    proof.authorized = proof.gap.is_none();
                } else {
                    proof.gap = Some("state operation has no complete resource binding".into());
                }
                let authorized = proof.authorized;
                ctx.add_evidence(Evidence {
                    rule_id: rule,
                    summary: proof.gap.clone().unwrap_or_else(|| {
                        "resource operation is covered by host authorization".into()
                    }),
                    kind: EvidenceKind::ResourceAuthorization(proof),
                });
                if !authorized
                    || ctx.policy().rule_policy.action_for(rule) == caushell_types::RuleAction::Deny
                {
                    ctx.add_finding(rule, reason.clone());
                }
                if let Some(decision) =
                    decision_for_rule_action(ctx.policy().rule_policy.action_for(rule))
                {
                    if !authorized || decision == caushell_types::Decision::Deny {
                        ctx.propose_decision(self.name(), rule, decision, reason);
                    }
                }
            }
        }
    }
}

fn owner_namespace_is_proved(ctx: &RunnerContext, source: &caushell_graph::NodeId) -> bool {
    use caushell_runner::ExecutionUnitOriginKind;
    let records = ctx.execution_unit_resolve_records();
    let mut current = source;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..64 {
        if !visited.insert(current) {
            return false;
        }
        let Some(record) = records
            .iter()
            .find(|record| record.source_node_id == *current)
        else {
            return false;
        };
        let bound = match &record.result {
            ResolveInvocationArtifactResult::Resolved(resolved) => Some(&resolved.bound),
            ResolveInvocationArtifactResult::SelectionError { partial_bound, .. } => {
                partial_bound.as_ref()
            }
            _ => None,
        };
        if bound.is_some_and(|bound| {
            bound.operation_semantics_unresolved
                || bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ExecuteRemoteCommand)
        }) {
            return false;
        }
        if record.origin_kind == ExecutionUnitOriginKind::TopLevel {
            return true;
        }
        let Some(parent) = records
            .iter()
            .find(|parent| parent.source_node_id == record.parent_execution_node_id)
        else {
            // A proved request-level shell function has no native invocation
            // record. Its body inherits the shell frame, not a tool namespace.
            return record.origin_kind == ExecutionUnitOriginKind::FunctionExpansion
                && record.depth == 1
                && ctx.parsed_command().is_some_and(|parsed| {
                    parsed.commands.iter().enumerate().any(|(index, command)| {
                        crate::support::source_node_id_for_command(
                            ctx.request(),
                            parsed,
                            index,
                            command,
                        ) == record.parent_execution_node_id
                    })
                });
        };
        if matches!(
            record.origin_kind,
            ExecutionUnitOriginKind::Dispatch | ExecutionUnitOriginKind::StaticXargs
        ) {
            let ResolveInvocationArtifactResult::Resolved(resolved) = &parent.result else {
                return false;
            };
            let dispatches: Vec<_> = resolved
                .bound
                .effects
                .iter()
                .filter(|effect| effect.kind == EffectKind::DispatchCommand)
                .collect();
            if resolved.bound.operation_semantics_unresolved
                || dispatches.is_empty()
                || dispatches.iter().any(|effect| {
                    effect.resource_namespace
                        != Some(caushell_profile::ResourceNamespaceTransfer::SameExecutor)
                })
            {
                return false;
            }
        }
        current = &parent.source_node_id;
    }
    false
}
