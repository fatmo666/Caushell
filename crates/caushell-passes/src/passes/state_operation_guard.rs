use caushell_graph::{GraphRead, NodeId};
use caushell_profile::{
    EffectKind, EnvironmentValueRef, ResolveInvocationArtifactResult, ResolvedInvocationArtifact,
    SessionValue, argument_structure,
};
use caushell_query::NetworkEndpointQuery;
use caushell_runner::{RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, EvidenceKind, ProvenanceEndpointKind, ProvenanceEndpointUsage, ResourceAuthorizationEvidence,
    ResourceTargetEvidence, RuleAction, RuleId, StateOperationDomain, StateOperationKind,
};

use crate::support::{decision_for_rule_action, graph_backed_execution_resolve_records};
use crate::support::resource::owner_namespace_is_proved;

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
                if ctx.assumes_protected_defaults()
                    && state.domain == StateOperationDomain::RemoteResource
                    && state.operation == StateOperationKind::Mutate
                    && fact.normalized_command_name() == "curl"
                    && matches!(fact.form_id(), "upload_to_url" | "upload_explicit_url")
                    && !fact.operation_semantics_unresolved()
                    && ctx.policy().rule_policy.action_for(rule) != RuleAction::Deny
                    && let Some(endpoints) = static_direct_loopback(ctx, staged.graph(), fact.source().node_id())
                {
                    ctx.add_evidence(Evidence {
                        rule_id: rule,
                        summary: "static policy classifies the declared direct loopback upload as local".into(),
                        kind: EvidenceKind::StaticLoopbackScope {
                            node_id: fact.source().node_id().0.clone(),
                            endpoints,
                        },
                    });
                    continue;
                }
                if ctx.assumes_protected_defaults()
                    && state.domain == StateOperationDomain::ConnectionVerification
                    && state.operation == StateOperationKind::Control
                    && fact.normalized_command_name() == "curl"
                    && fact.form_id() == "fetch_to_stdout"
                    && !fact.operation_semantics_unresolved()
                    && ctx.policy().rule_policy.action_for(rule) != RuleAction::Deny
                    && let Some(endpoints) = static_cleartext_fetch(ctx, staged.graph(), fact.source().node_id())
                {
                    ctx.add_evidence(Evidence {
                        rule_id: rule,
                        summary: "declared fetch and transport use cleartext HTTP; peer TLS verification is unused".into(),
                        kind: EvidenceKind::StaticCleartextScope {
                            node_id: fact.source().node_id().0.clone(),
                            endpoints,
                        },
                    });
                    continue;
                }
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
                        let resolution = endpoint.endpoint.and_then(|endpoint| {
                            ctx.resource_authority()?.resolve_target(endpoint)
                        });
                        let instance = resolution.as_ref().map(|r| &r.instance);
                        let grant_id =
                            instance.and_then(|i| ctx.resource_authority()?.permission(i, *state));
                        proof.targets.push(ResourceTargetEvidence {
                            slot_name: endpoint.slot_name.map(str::to_owned),
                            endpoint: endpoint.endpoint.map(str::to_owned),
                            resource_id: instance.as_ref().map(|i| i.resource_id.clone()),
                            instance_id: instance.as_ref().map(|i| i.instance_id.clone()),
                            generation: instance.as_ref().map(|i| i.generation),
                            grant_id,
                            namespace_id: instance.as_ref().map(|i| i.namespace_id.clone()),
                            route_id: resolution.as_ref().and_then(|r| r.route_id.clone()),
                            resolved_endpoint: resolution.map(|r| r.endpoint),
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

fn static_direct_loopback(
    ctx: &RunnerContext,
    graph: &dyn GraphRead,
    source: &NodeId,
) -> Option<Vec<String>> {
    let record = graph_backed_execution_resolve_records(ctx)
        .into_iter()
        .find(|record| record.source_node_id() == source)?;
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        return None;
    };
    if resolved.bound.applied_modifiers.iter().any(|modifier| {
        matches!(modifier.as_str(),
            "config_input" | "follow_redirects" | "request_target" | "socket_route"
            | "explicit_transport" | "explicit_route_override")
    }) || has_additional_transport_inputs(resolved)
        || NetworkEndpointQuery::has_transport_target(graph, source)
    {
        return None;
    }
    let environment = record.environment();
    for name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"] {
        match environment.value(name) {
            EnvironmentValueRef::Absent | EnvironmentValueRef::Unknown => {}
            EnvironmentValueRef::Present(SessionValue::ExactScalar(value)) if value.is_empty() => {}
            _ => return None,
        }
    }
    let endpoints = NetworkEndpointQuery::for_execution_units(
        graph, std::slice::from_ref(source), ctx.request().sequence_no,
    );
    if endpoints.is_empty() || endpoints.iter().any(|endpoint| {
        endpoint.kind != ProvenanceEndpointKind::Url || !endpoint.has_loopback_scope()
            || !endpoint.endpoint.is_some_and(|url| url.split_once("://").is_some_and(|(scheme, _)| {
                scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
            }))
    }) {
        return None;
    }
    Some(endpoints.into_iter().map(|endpoint| endpoint.description().to_owned()).collect())
}

fn static_cleartext_fetch(
    ctx: &RunnerContext,
    graph: &dyn GraphRead,
    source: &NodeId,
) -> Option<Vec<String>> {
    let record = graph_backed_execution_resolve_records(ctx)
        .into_iter()
        .find(|record| record.source_node_id() == source)?;
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        return None;
    };
    let modifiers = &resolved.bound.applied_modifiers;
    if !modifiers.iter().any(|id| id.as_str() == "peer_verification")
        || has_additional_transport_inputs(resolved)
        || modifiers.iter().any(|id| {
            matches!(id.as_str(), "config_input" | "follow_redirects" | "socket_route"
                | "explicit_route_override" | "proxy_peer_verification" | "doh_peer_verification")
        })
    {
        return None;
    }
    let endpoints = NetworkEndpointQuery::for_execution_units(
        graph, std::slice::from_ref(source), ctx.request().sequence_no,
    );
    if !endpoints.iter().any(|endpoint| endpoint.usage == ProvenanceEndpointUsage::FetchSource)
        || endpoints.iter().any(|endpoint| {
            endpoint.kind != ProvenanceEndpointKind::Url
                || !endpoint.endpoint.is_some_and(|url| url.split_once("://")
                    .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("http")))
        })
    {
        return None;
    }
    Some(endpoints.into_iter().map(|endpoint| endpoint.description().to_owned()).collect())
}

fn has_additional_transport_inputs(invocation: &ResolvedInvocationArtifact) -> bool {
    invocation.bound.applied_modifiers.iter().any(|id| {
        // State files can affect routing and the general option group includes DoH.
        matches!(id.as_str(), "state_file" | "common_value_option")
    }) || invocation.materialized_projection.invocation.args.iter().any(|arg| {
        matches!(argument_structure(arg).exact_value(), Some("--http3" | "--http3-only"))
    })
}
