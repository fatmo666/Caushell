use crate::support::{ExecutionResolveRecordRef, graph_backed_execution_resolve_records};
use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::{
    BoundParameter, BoundValue, EffectKind, EffectTarget, EndpointKind, EndpointUsage,
    ResolveInvocationArtifactResult, SemanticType,
};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, ProvenanceEndpointKind,
    ProvenanceEndpointUsage,
};

pub struct ExtractEndpointProvenancePass;

impl SessionTransformPass for ExtractEndpointProvenancePass {
    fn name(&self) -> &'static str {
        "extract_endpoint_provenance"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let mutations =
            collect_endpoint_provenance_mutations(&graph_backed_execution_resolve_records(ctx));

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_endpoint_provenance_mutations(
    records: &[ExecutionResolveRecordRef<'_>],
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        for effect in &resolved.bound.effects {
            if effect.kind != EffectKind::NetworkEndpoint {
                continue;
            }

            let EffectTarget::Slot(slot_name) = &effect.target else {
                continue;
            };

            let Some(parameter) = resolved
                .bound
                .bound_parameters
                .iter()
                .find(|parameter| parameter.name == *slot_name)
            else {
                continue;
            };

            let SemanticType::Endpoint(endpoint_semantic) = &parameter.semantic else {
                continue;
            };

            mutations.extend(parameter_endpoint_provenance_mutations(
                record.source_node_id(),
                &resolved.normalized_command_name,
                parameter,
                *endpoint_semantic,
            ));
        }
    }

    mutations
}

fn parameter_endpoint_provenance_mutations(
    source_node_id: &NodeId,
    normalized_command_name: &str,
    parameter: &BoundParameter,
    endpoint_semantic: caushell_profile::EndpointSemantic,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for value in &parameter.values {
        let BoundValue::Argument { text, .. } = value else {
            continue;
        };

        let endpoint_kind = provenance_endpoint_kind(endpoint_semantic.kind);
        let usage = provenance_endpoint_usage(endpoint_semantic.usage);

        mutations.push(PendingMutation::AddProvenanceArtifact {
            source_node_id: source_node_id.clone(),
            node_id: provenance_endpoint_artifact_node_id(text, endpoint_kind, usage),
            artifact: ProvenanceArtifact::NetworkEndpoint {
                endpoint: text.clone(),
                endpoint_kind,
                usage,
            },
            relation: EdgeKind::Consumes,
            semantics: ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                slot_name: Some(parameter.name.as_str().to_string()),
                normalized_command_name: Some(normalized_command_name.to_string()),
                domain_label: None,
            },
        });
    }

    mutations
}

fn provenance_endpoint_kind(kind: EndpointKind) -> ProvenanceEndpointKind {
    match kind {
        EndpointKind::Url => ProvenanceEndpointKind::Url,
        EndpointKind::HostPort => ProvenanceEndpointKind::HostPort,
        EndpointKind::SocketPath => ProvenanceEndpointKind::SocketPath,
        EndpointKind::RemoteSpec => ProvenanceEndpointKind::RemoteSpec,
    }
}

fn provenance_endpoint_usage(usage: EndpointUsage) -> ProvenanceEndpointUsage {
    match usage {
        EndpointUsage::FetchSource => ProvenanceEndpointUsage::FetchSource,
        EndpointUsage::UploadTarget => ProvenanceEndpointUsage::UploadTarget,
        EndpointUsage::ControlPlane => ProvenanceEndpointUsage::ControlPlane,
        EndpointUsage::GenericEndpoint => ProvenanceEndpointUsage::GenericEndpoint,
    }
}

fn endpoint_kind_slug(kind: ProvenanceEndpointKind) -> &'static str {
    match kind {
        ProvenanceEndpointKind::Url => "url",
        ProvenanceEndpointKind::HostPort => "host_port",
        ProvenanceEndpointKind::SocketPath => "socket_path",
        ProvenanceEndpointKind::RemoteSpec => "remote_spec",
    }
}

fn endpoint_usage_slug(usage: ProvenanceEndpointUsage) -> &'static str {
    match usage {
        ProvenanceEndpointUsage::FetchSource => "fetch_source",
        ProvenanceEndpointUsage::UploadTarget => "upload_target",
        ProvenanceEndpointUsage::ControlPlane => "control_plane",
        ProvenanceEndpointUsage::GenericEndpoint => "generic_endpoint",
    }
}

fn provenance_endpoint_artifact_node_id(
    endpoint: &str,
    endpoint_kind: ProvenanceEndpointKind,
    usage: ProvenanceEndpointUsage,
) -> NodeId {
    NodeId::new(format!(
        "artifact:network-endpoint:{}:{}:{endpoint}",
        endpoint_kind_slug(endpoint_kind),
        endpoint_usage_slug(usage),
    ))
}

#[cfg(test)]
mod tests {
    use super::ExtractEndpointProvenancePass;
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceEdgeSemantics, ProvenanceEndpointKind, ProvenanceEndpointUsage, RuntimeMetadata,
        SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(sequence_no: u64, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass(summary: &SessionSummary, sequence_no: u64, command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractEndpointProvenancePass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(sequence_no, command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_endpoint_provenance_stages_network_endpoint_artifact_for_curl_fetch() {
        let summary = SessionSummary::new();
        let ctx = run_pass(
            &summary,
            4,
            "curl -o ./payload.sh https://example.test/payload.sh",
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:4:0"),
                    node_id: NodeId::new(
                        "artifact:network-endpoint:url:fetch_source:https://example.test/payload.sh"
                    ),
                    artifact: ProvenanceArtifact::NetworkEndpoint {
                        endpoint: "https://example.test/payload.sh".to_string(),
                        endpoint_kind: ProvenanceEndpointKind::Url,
                        usage: ProvenanceEndpointUsage::FetchSource,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                        slot_name: Some("endpoint".to_string()),
                        normalized_command_name: Some("curl".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_endpoint_provenance_uses_materialized_exact_scalar_endpoint() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable(
            "URL",
            "https://example.test/payload.sh",
            true,
            CommandSequenceNo::new(2),
        );

        let ctx = run_pass(&summary, 3, r#"curl "$URL""#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:3:0"),
                    node_id: NodeId::new(
                        "artifact:network-endpoint:url:fetch_source:https://example.test/payload.sh"
                    ),
                    artifact: ProvenanceArtifact::NetworkEndpoint {
                        endpoint: "https://example.test/payload.sh".to_string(),
                        endpoint_kind: ProvenanceEndpointKind::Url,
                        usage: ProvenanceEndpointUsage::FetchSource,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                        slot_name: Some("endpoint".to_string()),
                        normalized_command_name: Some("curl".to_string()),
                        domain_label: None,
                    },
                })
        );
    }
}
