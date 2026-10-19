use crate::support::{ExecutionResolveRecordRef, graph_backed_execution_resolve_records};
use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::{
    BoundParameter, BoundValue, EffectKind, EffectTarget, EndpointKind, EndpointUsage, SemanticType,
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
        let Some(bound) = crate::support::bound_invocation(record.result()) else {
            continue;
        };

        for effect in &bound.effects {
            if effect.kind != EffectKind::NetworkEndpoint {
                continue;
            }

            let EffectTarget::Slot(slot_name) = &effect.target else {
                continue;
            };

            let Some(parameter) = bound
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
                bound.command_name.as_str(),
                parameter,
                *endpoint_semantic,
                effect.input_scope.as_ref().map(|scope| {
                    // The destination itself is always sent/resolved: URL or
                    // hostname expansion can carry data even with a fixed body.
                    let mut slots = scope.slots.clone();
                    let endpoint_slot = parameter.name.as_str().to_string();
                    if !slots.contains(&endpoint_slot) {
                        slots.push(endpoint_slot);
                    }
                    let stdin = scope.stdin && bound_consumes_stdin(bound, &slots);
                    caushell_types::ProvenanceDomainLabel::EndpointInputScope { slots, stdin }
                }),
            ));
        }
    }

    mutations
}

fn bound_consumes_stdin(
    bound: &caushell_profile::BoundInvocation,
    scoped_slots: &[String],
) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::ConsumeStdin
            && match &effect.target {
                EffectTarget::Slot(slot) => bound.bound_parameters.iter().any(|p| {
                    p.name == *slot
                        && !p.semantic_values_are_inapplicable()
                        && p.structured_source.as_ref().is_none_or(|source| {
                            scoped_slots
                                .iter()
                                .any(|name| name == p.name.as_str() || name == source.as_str())
                        })
                }),
                EffectTarget::ImplicitInput(source) => matches!(
                    source.to_runtime_input_source(),
                    Some(
                        caushell_types::RuntimeInputSource::StdinData
                            | caushell_types::RuntimeInputSource::StdinPayload
                    )
                ),
                _ => false,
            }
    })
}

fn parameter_endpoint_provenance_mutations(
    source_node_id: &NodeId,
    normalized_command_name: &str,
    parameter: &BoundParameter,
    endpoint_semantic: caushell_profile::EndpointSemantic,
    input_scope: Option<caushell_types::ProvenanceDomainLabel>,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for (index, value) in parameter.semantic_values().enumerate() {
        let endpoint = match value {
            caushell_profile::SemanticValueRef::Original(BoundValue::Argument { text, .. }) => {
                Some(text.clone())
            }
            caushell_profile::SemanticValueRef::Projected { value, source } => match &value
                .resolution
            {
                caushell_profile::SemanticValueResolution::Known(text) => Some(text.clone()),
                // Only identity projections may retain an address expression;
                // a source/container cannot stand in for its unknown value.
                caushell_profile::SemanticValueResolution::Unknown(_) if value.preserves_source => {
                    match source {
                        BoundValue::Argument { text, .. } => Some(text.clone()),
                        BoundValue::ImplicitInput { .. } => None,
                    }
                }
                caushell_profile::SemanticValueResolution::Unknown(_) => None,
            },
            caushell_profile::SemanticValueRef::Original(BoundValue::ImplicitInput { .. }) => None,
        };

        let endpoint_kind = provenance_endpoint_kind(endpoint_semantic.kind);
        let usage = provenance_endpoint_usage(endpoint_semantic.usage);

        mutations.push(PendingMutation::AddProvenanceArtifact {
            source_node_id: source_node_id.clone(),
            node_id: match &endpoint {
                Some(text) => provenance_endpoint_artifact_node_id(text, endpoint_kind, usage),
                None => NodeId::new(format!(
                    "artifact:unknown-network-endpoint:{}:{}:{}:{}:{index}",
                    endpoint_kind_slug(endpoint_kind),
                    endpoint_usage_slug(usage),
                    source_node_id.0,
                    parameter.name.as_str(),
                )),
            },
            artifact: ProvenanceArtifact::NetworkEndpoint {
                endpoint,
                endpoint_kind,
                usage,
            },
            relation: EdgeKind::Consumes,
            semantics: ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                slot_name: Some(parameter.name.as_str().to_string()),
                normalized_command_name: Some(normalized_command_name.to_string()),
                domain_label: input_scope.clone(),
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
        EndpointKind::EmailAddress => ProvenanceEndpointKind::EmailAddress,
    }
}

fn provenance_endpoint_usage(usage: EndpointUsage) -> ProvenanceEndpointUsage {
    match usage {
        EndpointUsage::FetchSource => ProvenanceEndpointUsage::FetchSource,
        EndpointUsage::TransportTarget => ProvenanceEndpointUsage::TransportTarget,
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
        ProvenanceEndpointKind::EmailAddress => "email_address",
    }
}

fn endpoint_usage_slug(usage: ProvenanceEndpointUsage) -> &'static str {
    match usage {
        ProvenanceEndpointUsage::FetchSource => "fetch_source",
        ProvenanceEndpointUsage::TransportTarget => "transport_target",
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
        ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceEndpointKind,
        ProvenanceEndpointUsage, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
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

    fn curl_fetch_request_scope() -> ProvenanceDomainLabel {
        ProvenanceDomainLabel::EndpointInputScope {
            slots: [
                "data_operand",
                "data_file",
                "literal_data",
                "urlencoded_operand",
                "urlencode_file",
                "form_operand",
                "form_file",
                "upload_payload",
                "binary_file_source",
                "upload_literal",
                "upload_file_operand",
                "upload_file_source",
                "cookie_operand",
                "cookie_file",
                "cookie_value",
                "request_header_operand",
                "request_header_file",
                "request_value",
                "request_method",
                "query_operand",
                "query_file",
                "netrc_file",
                "endpoint",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            stdin: false,
        }
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
                        endpoint: Some("https://example.test/payload.sh".to_string()),
                        endpoint_kind: ProvenanceEndpointKind::Url,
                        usage: ProvenanceEndpointUsage::FetchSource,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                        slot_name: Some("endpoint".to_string()),
                        normalized_command_name: Some("curl".to_string()),
                        domain_label: Some(curl_fetch_request_scope()),
                    },
                }),
            "{:#?}",
            ctx.pending_mutations()
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
                        endpoint: Some("https://example.test/payload.sh".to_string()),
                        endpoint_kind: ProvenanceEndpointKind::Url,
                        usage: ProvenanceEndpointUsage::FetchSource,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                        slot_name: Some("endpoint".to_string()),
                        normalized_command_name: Some("curl".to_string()),
                        domain_label: Some(curl_fetch_request_scope()),
                    },
                }),
            "{:#?}",
            ctx.pending_mutations()
        );
    }

    #[test]
    fn email_recipients_use_the_generic_upload_endpoint_path_without_url_coercion() {
        let ctx = run_pass(&SessionSummary::new(), 1, "mail receiver@example.test");
        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(mutation,
            PendingMutation::AddProvenanceArtifact { node_id, artifact: ProvenanceArtifact::NetworkEndpoint {
                endpoint, endpoint_kind: ProvenanceEndpointKind::EmailAddress,
                usage: ProvenanceEndpointUsage::UploadTarget,
            }, .. } if endpoint.as_deref() == Some("receiver@example.test")
                && node_id.0 == "artifact:network-endpoint:email_address:upload_target:receiver@example.test"
        )));
    }

    #[test]
    fn implicit_endpoint_is_unknown_not_absent_and_is_scoped_to_its_consumer() {
        use caushell_profile::{
            BoundParameter, BoundValue, EndpointKind, EndpointSemantic, EndpointUsage,
            ImplicitInputSource, SemanticType, SlotName,
        };
        let semantic = EndpointSemantic {
            kind: EndpointKind::Url,
            usage: EndpointUsage::FetchSource,
        };
        let mut parameter =
            BoundParameter::new(SlotName::new("addresses"), SemanticType::Endpoint(semantic))
                .with_value(BoundValue::implicit_input(ImplicitInputSource::StdinData));
        let first = super::parameter_endpoint_provenance_mutations(
            &NodeId::new("command:a:1:0"),
            "fetch-list",
            &parameter,
            semantic,
            None,
        );
        let second = super::parameter_endpoint_provenance_mutations(
            &NodeId::new("command:a:2:0"),
            "fetch-list",
            &parameter,
            semantic,
            None,
        );
        let node_id = |mutations: &[PendingMutation]| match &mutations[0] {
            PendingMutation::AddProvenanceArtifact {
                node_id,
                artifact: ProvenanceArtifact::NetworkEndpoint { endpoint: None, .. },
                ..
            } => node_id.clone(),
            other => panic!("{other:#?}"),
        };
        assert_eq!(first.len(), 1);
        assert_ne!(node_id(&first), node_id(&second));
        parameter.projected_values = Some(Vec::new());
        assert!(
            super::parameter_endpoint_provenance_mutations(
                &NodeId::new("command:a:3:0"),
                "fetch-list",
                &parameter,
                semantic,
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn only_identity_projections_can_retain_the_source_address_expression() {
        use caushell_profile::*;
        let semantic = EndpointSemantic {
            kind: EndpointKind::Url,
            usage: EndpointUsage::FetchSource,
        };
        let source = BoundValue::argument(
            "http://[::1]:8765/",
            false,
            caushell_parse::SourceSpan {
                start_byte: 0,
                end_byte: 0,
                start_row: 0,
                end_row: 0,
                start_column: 0,
                end_column: 0,
            },
            ArgumentBindingSource::RemainingArg,
        );
        let mut parameter =
            BoundParameter::new(SlotName::new("addresses"), SemanticType::Endpoint(semantic))
                .with_value(source);
        for preserves_source in [false, true] {
            parameter.projected_values = Some(vec![ProjectedSemanticValue {
                source_index: 0,
                preserves_source,
                resolution: SemanticValueResolution::Unknown(
                    ProjectionUnknownReason::DynamicArgument,
                ),
            }]);
            let mutations = super::parameter_endpoint_provenance_mutations(
                &NodeId::new("command:a:1:0"),
                "fetch-list",
                &parameter,
                semantic,
                None,
            );
            assert!(
                matches!(&mutations[0], PendingMutation::AddProvenanceArtifact {
                artifact: ProvenanceArtifact::NetworkEndpoint {endpoint, ..}, ..}
                if endpoint.as_deref() == preserves_source.then_some("http://[::1]:8765/"))
            );
        }
    }
}
