use caushell_graph::EdgeKind;
use caushell_profile::{PathPurpose, PathRole};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    ProvenanceConsumeKind, ProvenanceDomainLabel, ProvenanceEdgeSemantics, ProvenanceProduceKind,
    ResolvedPathPurpose, ResolvedPathRole,
};

use crate::path::{
    edge_kind_for_path_role, path_fact_node_id, provenance_artifact_for_path,
    provenance_edge_for_path_fact, provenance_path_artifact_node_id,
    resolved_path_purpose_for_profile_purpose, resolved_path_role_for_profile_role,
};
use crate::support::{
    ImplicitStartupEnvironmentSource, collect_implicit_startup_config_candidates,
    command_env_artifact_node_id, command_env_value_artifact, implicit_startup_path_fact_index,
    implicit_startup_slot_name, inherited_env_artifact_node_id, inherited_env_value_artifact,
};

pub struct ExtractImplicitStartupConfigPass;

impl SessionTransformPass for ExtractImplicitStartupConfigPass {
    fn name(&self) -> &'static str {
        "extract_implicit_startup_config"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let version = ctx.request().sequence_no.0;

        for candidate in collect_implicit_startup_config_candidates(ctx) {
            let slot_name = implicit_startup_slot_name().to_string();

            ctx.stage_mutation(PendingMutation::AddPathFact {
                source_node_id: candidate.source_node_id.clone(),
                node_id: path_fact_node_id(
                    &candidate.source_node_id,
                    implicit_startup_path_fact_index(
                        candidate.command_index,
                        &candidate.environment_name,
                    ),
                    &slot_name,
                    &candidate.resolution,
                ),
                resolution: candidate.resolution.clone(),
                role: resolved_path_role_for_profile_role(PathRole::Config),
                purpose: Some(resolved_path_purpose_for_profile_purpose(
                    PathPurpose::StartupConfig,
                )),
                slot_name: slot_name.clone(),
                normalized_command_name: Some(candidate.normalized_command_name.clone()),
                relation: edge_kind_for_path_role(PathRole::Config),
            });

            let env_artifact_node_id = match candidate.environment_source {
                ImplicitStartupEnvironmentSource::InheritedEnvironment => {
                    inherited_env_artifact_node_id(&candidate.environment_name, version)
                }
                ImplicitStartupEnvironmentSource::CommandPrefixAssignment => {
                    command_env_artifact_node_id(
                        &candidate.source_node_id,
                        &candidate.environment_name,
                    )
                }
            };
            let env_artifact = match candidate.environment_source {
                ImplicitStartupEnvironmentSource::InheritedEnvironment => {
                    inherited_env_value_artifact(
                        &candidate.environment_name,
                        candidate.environment_state.clone(),
                        version,
                    )
                }
                ImplicitStartupEnvironmentSource::CommandPrefixAssignment => {
                    command_env_value_artifact(
                        &candidate.environment_name,
                        candidate.environment_state.clone(),
                        version,
                    )
                }
            };

            ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                source_node_id: candidate.source_node_id.clone(),
                node_id: env_artifact_node_id.clone(),
                artifact: env_artifact,
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::VariableExpansion,
                    slot_name: Some(slot_name.clone()),
                    normalized_command_name: Some(candidate.normalized_command_name.clone()),
                    domain_label: None,
                },
            });

            let Some(path_string) = candidate.resolution.concrete_path() else {
                continue;
            };

            if let Some((relation, semantics)) = provenance_edge_for_path_fact(
                PathRole::Config,
                Some(PathPurpose::StartupConfig),
                &slot_name,
                Some(candidate.normalized_command_name.as_str()),
            ) {
                ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                    source_node_id: candidate.source_node_id.clone(),
                    node_id: provenance_path_artifact_node_id(path_string),
                    artifact: provenance_artifact_for_path(path_string),
                    relation,
                    semantics,
                });
            }

            ctx.stage_mutation(PendingMutation::AddProvenanceArtifact {
                source_node_id: env_artifact_node_id,
                node_id: provenance_path_artifact_node_id(path_string),
                artifact: provenance_artifact_for_path(path_string),
                relation: EdgeKind::Produces,
                semantics: ProvenanceEdgeSemantics::Produce {
                    produce_kind: ProvenanceProduceKind::MaterializedValue,
                    slot_name: Some(slot_name),
                    normalized_command_name: Some(candidate.normalized_command_name),
                    domain_label: Some(ProvenanceDomainLabel::Path {
                        role: ResolvedPathRole::Config,
                        purpose: Some(ResolvedPathPurpose::StartupConfig),
                    }),
                },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractImplicitStartupConfigPass;
    use crate::{ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass};
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, PathResolution, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceEdgeSemantics, ProvenanceProduceKind, ResolvedPathPurpose, ResolvedPathRole,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };
    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new(
                "/tmp/project/work".to_string(),
            )
            .with_exact_scalar_variable("BASH_ENV", "../shared/team.rc", true)
            .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project/work".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractImplicitStartupConfigPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_implicit_startup_config_stages_path_and_env_provenance_for_bash_env() {
        let ctx = run_pass(r#"bash -c 'echo ok'"#);

        assert!(ctx.pending_mutations().contains(&PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:2:0"),
            node_id: NodeId::new(
                "resolved-path:command:sess-1:2:0:1000000:startup_config:/tmp/project/shared/team.rc"
            ),
            resolution: PathResolution::Concrete {
                path: "/tmp/project/shared/team.rc".to_string(),
            },
            role: ResolvedPathRole::Config,
            purpose: Some(ResolvedPathPurpose::StartupConfig),
            slot_name: "startup_config".to_string(),
            normalized_command_name: Some("bash".to_string()),
            relation: EdgeKind::Reads,
        }));

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:inherited-env-value:BASH_ENV:2"),
                    artifact: ProvenanceArtifact::InheritedEnvValue {
                        name: "BASH_ENV".to_string(),
                        state: caushell_types::ProvenanceVariableValueState::ExactScalar {
                            value: "../shared/team.rc".to_string(),
                        },
                        version: 2,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("startup_config".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
                    artifact: ProvenanceArtifact::PathContent {
                        path: "/tmp/project/shared/team.rc".to_string(),
                        version: None,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::StartupConfigSource,
                        slot_name: Some("startup_config".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: Some(caushell_types::ProvenanceDomainLabel::Path {
                            role: ResolvedPathRole::Config,
                            purpose: Some(ResolvedPathPurpose::StartupConfig),
                        }),
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("artifact:inherited-env-value:BASH_ENV:2"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/shared/team.rc"),
                    artifact: ProvenanceArtifact::PathContent {
                        path: "/tmp/project/shared/team.rc".to_string(),
                        version: None,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::MaterializedValue,
                        slot_name: Some("startup_config".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: Some(caushell_types::ProvenanceDomainLabel::Path {
                            role: ResolvedPathRole::Config,
                            purpose: Some(ResolvedPathPurpose::StartupConfig),
                        }),
                    },
                })
        );
    }

    #[test]
    fn extract_implicit_startup_config_uses_command_prefix_bash_env_for_current_command() {
        let ctx = run_pass(r#"BASH_ENV=/tmp/shared/r3.env bash -c 'echo ok'"#);

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddPathFact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "resolved-path:command:sess-1:2:0:1000000:startup_config:/tmp/shared/r3.env"
                    ),
                    resolution: PathResolution::Concrete {
                        path: "/tmp/shared/r3.env".to_string(),
                    },
                    role: ResolvedPathRole::Config,
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                    slot_name: "startup_config".to_string(),
                    normalized_command_name: Some("bash".to_string()),
                    relation: EdgeKind::Reads,
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:command-env-value:command:sess-1:2:0:BASH_ENV"),
                    artifact: ProvenanceArtifact::VariableValue {
                        name: "BASH_ENV".to_string(),
                        state: caushell_types::ProvenanceVariableValueState::ExactScalar {
                            value: "/tmp/shared/r3.env".to_string(),
                        },
                        exported: true,
                        version: 2,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::VariableExpansion,
                        slot_name: Some("startup_config".to_string()),
                        normalized_command_name: Some("bash".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddProvenanceArtifact {
                source_node_id,
                node_id,
                artifact: ProvenanceArtifact::PathContent { path, version: None },
                relation: EdgeKind::Produces,
                semantics: ProvenanceEdgeSemantics::Produce {
                    produce_kind: ProvenanceProduceKind::MaterializedValue,
                    ..
                },
            } if source_node_id.0 == "artifact:command-env-value:command:sess-1:2:0:BASH_ENV"
                && node_id.0 == "artifact:path-content:/tmp/shared/r3.env"
                && path == "/tmp/shared/r3.env"
        )));
    }

    #[test]
    fn extract_implicit_startup_config_skips_when_environment_is_absent() {
        let mut request = sample_request(r#"bash -c 'echo ok'"#);
        request.shell_state_before.variables.clear();

        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractImplicitStartupConfigPass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(request);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        assert!(!ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddPathFact {
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                    ..
                }
            )
        }));
        assert!(!ctx.pending_mutations().iter().any(|mutation| {
            matches!(
                mutation,
                PendingMutation::AddProvenanceArtifact {
                    artifact: ProvenanceArtifact::InheritedEnvValue { name, .. },
                    ..
                } if name == "BASH_ENV"
            )
        }));
    }
}
