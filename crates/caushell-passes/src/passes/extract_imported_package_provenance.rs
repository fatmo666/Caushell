use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, PackageLocatorSemantic, ResolveInvocationArtifactResult,
    SemanticType,
};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    PackageLocatorKind, PackageManagerKind, ProvenanceArtifact, ProvenanceConsumeKind,
    ProvenanceEdgeSemantics, ProvenanceEndpointKind, ProvenanceEndpointUsage,
    ProvenanceProduceKind,
};

use crate::path::{
    provenance_artifact_for_path, provenance_path_artifact_node_id, resolve_path_operand,
};
use crate::support::{ExecutionResolveRecordRef, graph_backed_execution_resolve_records};

pub struct ExtractImportedPackageProvenancePass;

impl SessionTransformPass for ExtractImportedPackageProvenancePass {
    fn name(&self) -> &'static str {
        "extract_imported_package_provenance"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let cwd = ctx.request().shell_state_before.cwd.as_str();
        let home = ctx.request().home.as_deref();

        let mutations = collect_imported_package_provenance_mutations(
            &graph_backed_execution_resolve_records(ctx),
            cwd,
            home,
        );

        for mutation in mutations {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_imported_package_provenance_mutations(
    records: &[ExecutionResolveRecordRef<'_>],
    cwd: &str,
    home: Option<&str>,
) -> Vec<PendingMutation> {
    let mut mutations = Vec::new();

    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
            continue;
        };

        for effect in &resolved.bound.effects {
            if !matches!(
                effect.kind,
                EffectKind::ImportPackage | EffectKind::ExecuteImportedPackageLogic
            ) {
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

            let SemanticType::PackageLocator(locator_semantic) = &parameter.semantic else {
                continue;
            };

            for value in &parameter.values {
                let BoundValue::Argument {
                    text,
                    quoted,
                    node_kind,
                    ..
                } = value
                else {
                    continue;
                };

                let Some(locator_kind) =
                    classify_locator_kind(locator_semantic, text, *quoted, node_kind, cwd, home)
                else {
                    continue;
                };

                let manager = package_manager_kind(locator_semantic.manager);
                let artifact_node_id =
                    imported_package_artifact_node_id(manager, locator_kind, text);
                let artifact = imported_package_artifact(
                    manager,
                    locator_kind,
                    text,
                    *quoted,
                    node_kind,
                    cwd,
                    home,
                );

                mutations.push(PendingMutation::AddProvenanceArtifact {
                    source_node_id: record.source_node_id().clone(),
                    node_id: artifact_node_id.clone(),
                    artifact,
                    relation: effect_edge_kind(effect.kind),
                    semantics: effect_edge_semantics(
                        effect.kind,
                        parameter.name.as_str(),
                        resolved.normalized_command_name.as_str(),
                    ),
                });

                mutations.extend(source_provenance_mutations(
                    record.source_node_id(),
                    parameter.name.as_str(),
                    resolved.normalized_command_name.as_str(),
                    locator_kind,
                    text,
                    *quoted,
                    node_kind,
                    cwd,
                    home,
                ));
            }
        }
    }

    mutations
}

fn classify_locator_kind(
    semantic: &PackageLocatorSemantic,
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> Option<PackageLocatorKind> {
    let allowed: Vec<PackageLocatorKind> = semantic
        .locator_kinds
        .iter()
        .copied()
        .map(package_locator_kind)
        .collect();

    if allowed.is_empty() {
        return None;
    }

    if is_vcs_locator(text) {
        return first_allowed_kind(
            &allowed,
            &[PackageLocatorKind::VcsUrl, PackageLocatorKind::DirectUrl],
        );
    }

    if is_http_url(text) {
        return first_allowed_kind(&allowed, &[PackageLocatorKind::DirectUrl]);
    }

    if is_requirement_file_candidate(text, quoted, node_kind, cwd, home) {
        return first_allowed_kind(
            &allowed,
            &[
                PackageLocatorKind::RequirementFile,
                PackageLocatorKind::LocalPath,
            ],
        );
    }

    if is_explicit_local_path_candidate(text, quoted, node_kind, cwd, home) {
        return first_allowed_kind(&allowed, &[PackageLocatorKind::LocalPath]);
    }

    if is_dynamic_locator(text, node_kind) {
        return first_allowed_kind(
            &allowed,
            &[
                PackageLocatorKind::UnknownDynamic,
                PackageLocatorKind::RegistryRef,
            ],
        );
    }

    if is_ambiguous_local_path_candidate(text) {
        return first_allowed_kind(
            &allowed,
            manager_ambiguous_locator_precedence(semantic.manager),
        );
    }

    allowed_kind(&allowed, PackageLocatorKind::RegistryRef)
        .or_else(|| (allowed.len() == 1).then_some(allowed[0]))
        .or_else(|| allowed_kind(&allowed, PackageLocatorKind::UnknownDynamic))
}

fn allowed_kind(
    allowed: &[PackageLocatorKind],
    kind: PackageLocatorKind,
) -> Option<PackageLocatorKind> {
    allowed.contains(&kind).then_some(kind)
}

fn first_allowed_kind(
    allowed: &[PackageLocatorKind],
    precedence: &[PackageLocatorKind],
) -> Option<PackageLocatorKind> {
    precedence
        .iter()
        .find_map(|kind| allowed_kind(allowed, *kind))
}

fn manager_ambiguous_locator_precedence(
    manager: caushell_profile::PackageManagerKind,
) -> &'static [PackageLocatorKind] {
    match manager {
        caushell_profile::PackageManagerKind::Pip => &[
            PackageLocatorKind::LocalPath,
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::RequirementFile,
        ],
        caushell_profile::PackageManagerKind::Apt => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
            PackageLocatorKind::RequirementFile,
        ],
        caushell_profile::PackageManagerKind::Conan => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
        ],
        caushell_profile::PackageManagerKind::Npm => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
        ],
    }
}

fn imported_package_artifact(
    manager: PackageManagerKind,
    locator_kind: PackageLocatorKind,
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> ProvenanceArtifact {
    ProvenanceArtifact::ImportedPackage {
        manager,
        locator: text.to_string(),
        locator_kind,
        source_endpoint: match locator_kind {
            PackageLocatorKind::DirectUrl | PackageLocatorKind::VcsUrl => Some(text.to_string()),
            PackageLocatorKind::RegistryRef
            | PackageLocatorKind::LocalPath
            | PackageLocatorKind::RequirementFile
            | PackageLocatorKind::UnknownDynamic => None,
        },
        source_path: match locator_kind {
            PackageLocatorKind::LocalPath | PackageLocatorKind::RequirementFile => {
                resolve_path_operand(text, quoted, node_kind, cwd, home)
            }
            PackageLocatorKind::RegistryRef
            | PackageLocatorKind::DirectUrl
            | PackageLocatorKind::VcsUrl
            | PackageLocatorKind::UnknownDynamic => None,
        },
        version: 1,
    }
}

fn effect_edge_kind(kind: EffectKind) -> EdgeKind {
    match kind {
        EffectKind::ImportPackage => EdgeKind::Produces,
        EffectKind::ExecuteImportedPackageLogic => EdgeKind::Consumes,
        _ => unreachable!("caller must pre-filter imported-package effects"),
    }
}

fn effect_edge_semantics(
    kind: EffectKind,
    slot_name: &str,
    normalized_command_name: &str,
) -> ProvenanceEdgeSemantics {
    match kind {
        EffectKind::ImportPackage => ProvenanceEdgeSemantics::Produce {
            produce_kind: ProvenanceProduceKind::ImportedPackage,
            slot_name: Some(slot_name.to_string()),
            normalized_command_name: Some(normalized_command_name.to_string()),
            domain_label: None,
        },
        EffectKind::ExecuteImportedPackageLogic => ProvenanceEdgeSemantics::Consume {
            consume_kind: ProvenanceConsumeKind::ImportedPackageLogic,
            slot_name: Some(slot_name.to_string()),
            normalized_command_name: Some(normalized_command_name.to_string()),
            domain_label: None,
        },
        _ => unreachable!("caller must pre-filter imported-package effects"),
    }
}

fn source_provenance_mutations(
    source_node_id: &NodeId,
    slot_name: &str,
    normalized_command_name: &str,
    locator_kind: PackageLocatorKind,
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> Vec<PendingMutation> {
    match locator_kind {
        PackageLocatorKind::DirectUrl | PackageLocatorKind::VcsUrl => {
            vec![PendingMutation::AddProvenanceArtifact {
                source_node_id: source_node_id.clone(),
                node_id: network_endpoint_artifact_node_id(text),
                artifact: ProvenanceArtifact::NetworkEndpoint {
                    endpoint: text.to_string(),
                    endpoint_kind: ProvenanceEndpointKind::Url,
                    usage: ProvenanceEndpointUsage::FetchSource,
                },
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                    slot_name: Some(slot_name.to_string()),
                    normalized_command_name: Some(normalized_command_name.to_string()),
                    domain_label: None,
                },
            }]
        }
        PackageLocatorKind::LocalPath | PackageLocatorKind::RequirementFile => {
            resolve_path_operand(text, quoted, node_kind, cwd, home)
                .map(|path: String| {
                    vec![PendingMutation::AddProvenanceArtifact {
                        source_node_id: source_node_id.clone(),
                        node_id: provenance_path_artifact_node_id(path.as_str()),
                        artifact: provenance_artifact_for_path(path.as_str()),
                        relation: EdgeKind::Consumes,
                        semantics: ProvenanceEdgeSemantics::Consume {
                            consume_kind: ProvenanceConsumeKind::PackageLocator,
                            slot_name: Some(slot_name.to_string()),
                            normalized_command_name: Some(normalized_command_name.to_string()),
                            domain_label: None,
                        },
                    }]
                })
                .unwrap_or_default()
        }
        PackageLocatorKind::RegistryRef | PackageLocatorKind::UnknownDynamic => Vec::new(),
    }
}

fn package_manager_kind(kind: caushell_profile::PackageManagerKind) -> PackageManagerKind {
    match kind {
        caushell_profile::PackageManagerKind::Pip => PackageManagerKind::Pip,
        caushell_profile::PackageManagerKind::Apt => PackageManagerKind::Apt,
        caushell_profile::PackageManagerKind::Conan => PackageManagerKind::Conan,
        caushell_profile::PackageManagerKind::Npm => PackageManagerKind::Npm,
    }
}

fn package_locator_kind(kind: caushell_profile::PackageLocatorKind) -> PackageLocatorKind {
    match kind {
        caushell_profile::PackageLocatorKind::RegistryRef => PackageLocatorKind::RegistryRef,
        caushell_profile::PackageLocatorKind::LocalPath => PackageLocatorKind::LocalPath,
        caushell_profile::PackageLocatorKind::DirectUrl => PackageLocatorKind::DirectUrl,
        caushell_profile::PackageLocatorKind::VcsUrl => PackageLocatorKind::VcsUrl,
        caushell_profile::PackageLocatorKind::RequirementFile => {
            PackageLocatorKind::RequirementFile
        }
        caushell_profile::PackageLocatorKind::UnknownDynamic => PackageLocatorKind::UnknownDynamic,
    }
}

fn package_manager_slug(manager: PackageManagerKind) -> &'static str {
    match manager {
        PackageManagerKind::Pip => "pip",
        PackageManagerKind::Apt => "apt",
        PackageManagerKind::Conan => "conan",
        PackageManagerKind::Npm => "npm",
    }
}

fn package_locator_kind_slug(kind: PackageLocatorKind) -> &'static str {
    match kind {
        PackageLocatorKind::RegistryRef => "registry_ref",
        PackageLocatorKind::LocalPath => "local_path",
        PackageLocatorKind::DirectUrl => "direct_url",
        PackageLocatorKind::VcsUrl => "vcs_url",
        PackageLocatorKind::RequirementFile => "requirement_file",
        PackageLocatorKind::UnknownDynamic => "unknown_dynamic",
    }
}

fn imported_package_artifact_node_id(
    manager: PackageManagerKind,
    locator_kind: PackageLocatorKind,
    locator: &str,
) -> NodeId {
    NodeId::new(format!(
        "artifact:imported-package:{}:{}:{}",
        package_manager_slug(manager),
        package_locator_kind_slug(locator_kind),
        locator
    ))
}

fn network_endpoint_artifact_node_id(endpoint: &str) -> NodeId {
    NodeId::new(format!(
        "artifact:network-endpoint:url:fetch_source:{endpoint}"
    ))
}

fn is_dynamic_locator(text: &str, node_kind: &str) -> bool {
    matches!(
        node_kind,
        "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
    ) || text.contains('$')
        || text.contains('`')
}

fn is_http_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

fn is_vcs_locator(text: &str) -> bool {
    text.starts_with("git+")
        || text.starts_with("hg+")
        || text.starts_with("svn+")
        || text.starts_with("bzr+")
}

fn is_local_path_candidate(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    is_explicit_local_path_candidate(text, quoted, node_kind, cwd, home)
        || is_ambiguous_local_path_candidate(text)
}

fn is_explicit_local_path_candidate(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    if !has_explicit_local_path_syntax(text) {
        return false;
    }

    resolve_path_operand(text, quoted, node_kind, cwd, home).is_some()
}

fn has_explicit_local_path_syntax(text: &str) -> bool {
    text.starts_with('/')
        || text == "."
        || text == ".."
        || text == "~"
        || text.starts_with("~/")
        || text.starts_with("./")
        || text.starts_with("../")
}

fn is_ambiguous_local_path_candidate(text: &str) -> bool {
    text.contains('/') && !text.contains("://") && !has_explicit_local_path_syntax(text)
}

fn is_requirement_file_candidate(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
) -> bool {
    (text.ends_with(".txt")
        || text.ends_with(".in")
        || text.ends_with(".lock")
        || text.contains("requirements"))
        && !is_dynamic_locator(text, node_kind)
        && !is_http_url(text)
        && !is_vcs_locator(text)
        && !text.starts_with('-')
        && (is_local_path_candidate(text, quoted, node_kind, cwd, home) || !text.contains("://"))
}

#[cfg(test)]
mod tests {
    use super::ExtractImportedPackageProvenancePass;
    use crate::{
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
        path::provenance_artifact_for_path,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, ProvenanceArtifact, ProvenanceConsumeKind,
        ProvenanceEdgeSemantics, ProvenanceEndpointKind, ProvenanceEndpointUsage,
        ProvenanceProduceKind, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(2),
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

    fn run_pass(command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);

        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_imported_package_provenance_stages_registry_package_artifact_for_pip_install() {
        let ctx = run_pass("pip install requests");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:pip:registry_ref:requests"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: "requests".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:pip:registry_ref:requests"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: "requests".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ImportedPackageLogic,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_endpoint_source_for_vcs_package_locator() {
        let ctx = run_pass("pip install git+https://example.test/pkg.git");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "artifact:imported-package:pip:vcs_url:git+https://example.test/pkg.git"
                    ),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: "git+https://example.test/pkg.git".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::VcsUrl,
                        source_endpoint: Some("git+https://example.test/pkg.git".to_string()),
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(ctx
            .pending_mutations()
            .contains(&PendingMutation::AddProvenanceArtifact {
                source_node_id: NodeId::new("command:sess-1:2:0"),
                node_id: NodeId::new(
                    "artifact:network-endpoint:url:fetch_source:git+https://example.test/pkg.git"
                ),
                artifact: ProvenanceArtifact::NetworkEndpoint {
                    endpoint: "git+https://example.test/pkg.git".to_string(),
                    endpoint_kind: ProvenanceEndpointKind::Url,
                    usage: ProvenanceEndpointUsage::FetchSource,
                },
                relation: EdgeKind::Consumes,
                semantics: ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::NetworkEndpoint,
                    slot_name: Some("package_specs".to_string()),
                    normalized_command_name: Some("pip".to_string()),
                    domain_label: None,
                },
            }));
    }

    #[test]
    fn extract_imported_package_provenance_stages_requirement_file_locator_for_pip_install() {
        let ctx = run_pass("pip install -r requirements.txt");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new(
                        "artifact:imported-package:pip:requirement_file:requirements.txt"
                    ),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: "requirements.txt".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RequirementFile,
                        source_endpoint: None,
                        source_path: Some("/tmp/project/requirements.txt".to_string()),
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("requirement_files".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project/requirements.txt"),
                    artifact: provenance_artifact_for_path("/tmp/project/requirements.txt"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PackageLocator,
                        slot_name: Some("requirement_files".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_editable_dot_as_local_path() {
        let ctx = run_pass("pip install -e .");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:pip:local_path:."),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: ".".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::LocalPath,
                        source_endpoint: None,
                        source_path: Some("/tmp/project".to_string()),
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("editable_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:path-content:/tmp/project"),
                    artifact: provenance_artifact_for_path("/tmp/project"),
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::PackageLocator,
                        slot_name: Some("editable_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_unknown_dynamic_locator_for_pip_install() {
        let ctx = run_pass("pip install \"$PKG\"");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:pip:unknown_dynamic:$PKG"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Pip,
                        locator: "$PKG".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::UnknownDynamic,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("pip".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_registry_package_artifact_for_apt_get_install() {
        let ctx = run_pass("apt-get install curl");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:apt:registry_ref:curl"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Apt,
                        locator: "curl".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("apt-get".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_unknown_dynamic_locator_for_apt_get_install() {
        let ctx = run_pass("apt-get install \"$APT_PKG\"");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:apt:unknown_dynamic:$APT_PKG"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Apt,
                        locator: "$APT_PKG".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::UnknownDynamic,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("apt-get".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_registry_package_artifact_for_apt_get_install_with_yes_flag()
     {
        let ctx = run_pass("apt-get install -y curl");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:apt:registry_ref:curl"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Apt,
                        locator: "curl".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("package_specs".to_string()),
                        normalized_command_name: Some("apt-get".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_registry_package_artifact_for_conan_install() {
        let ctx = run_pass("conan install --requires zlib/1.3.1");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:conan:registry_ref:zlib/1.3.1"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Conan,
                        locator: "zlib/1.3.1".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("requires".to_string()),
                        normalized_command_name: Some("conan".to_string()),
                        domain_label: None,
                    },
                })
        );

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:conan:registry_ref:zlib/1.3.1"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Conan,
                        locator: "zlib/1.3.1".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Consumes,
                    semantics: ProvenanceEdgeSemantics::Consume {
                        consume_kind: ProvenanceConsumeKind::ImportedPackageLogic,
                        slot_name: Some("requires".to_string()),
                        normalized_command_name: Some("conan".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_registry_package_artifact_for_conan_positional_install()
     {
        let ctx = run_pass("conan install zlib/1.3.1");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:conan:registry_ref:zlib/1.3.1"),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Conan,
                        locator: "zlib/1.3.1".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::RegistryRef,
                        source_endpoint: None,
                        source_path: None,
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("requires".to_string()),
                        normalized_command_name: Some("conan".to_string()),
                        domain_label: None,
                    },
                })
        );
    }

    #[test]
    fn extract_imported_package_provenance_stages_conan_dot_as_local_path() {
        let ctx = run_pass("conan install .");

        assert!(
            ctx.pending_mutations()
                .contains(&PendingMutation::AddProvenanceArtifact {
                    source_node_id: NodeId::new("command:sess-1:2:0"),
                    node_id: NodeId::new("artifact:imported-package:conan:local_path:."),
                    artifact: ProvenanceArtifact::ImportedPackage {
                        manager: caushell_types::PackageManagerKind::Conan,
                        locator: ".".to_string(),
                        locator_kind: caushell_types::PackageLocatorKind::LocalPath,
                        source_endpoint: None,
                        source_path: Some("/tmp/project".to_string()),
                        version: 1,
                    },
                    relation: EdgeKind::Produces,
                    semantics: ProvenanceEdgeSemantics::Produce {
                        produce_kind: ProvenanceProduceKind::ImportedPackage,
                        slot_name: Some("requires".to_string()),
                        normalized_command_name: Some("conan".to_string()),
                        domain_label: None,
                    },
                })
        );
    }
}
