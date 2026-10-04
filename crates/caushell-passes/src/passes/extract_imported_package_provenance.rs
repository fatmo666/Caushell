use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::{
    BoundArgumentMaterialization, BoundValue, EffectKind, EffectTarget, PackageLocatorSemantic,
    ResolveInvocationArtifactResult, SemanticType, SemanticValueResolution, ValueProjection,
    project_value,
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

        for cwd_option in record.cwd_options(cwd) {
            let resolution_cwd = cwd_option.unwrap_or(cwd);
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

                for parameter in resolved
                    .bound
                    .bound_parameters
                    .iter()
                    .filter(|parameter| parameter.name == *slot_name)
                {
                    let SemanticType::PackageLocator(locator_semantic) = &parameter.semantic else {
                        continue;
                    };

                    for value in &parameter.values {
                        let (mut locator_kind, text) =
                            classify_locator_value(locator_semantic, value, resolution_cwd, home);
                        if cwd_option.is_none()
                            && matches!(
                                locator_kind,
                                PackageLocatorKind::LocalPath | PackageLocatorKind::RequirementFile
                            )
                            && !text.starts_with('/')
                        {
                            locator_kind = PackageLocatorKind::UnknownDynamic;
                        }

                        let manager = package_manager_kind(locator_semantic.manager);
                        let artifact =
                            imported_package_artifact(manager, locator_kind, &text, resolution_cwd);
                        // A relative spelling is not a session-wide identity: two
                        // invocations can refer to different files with the same
                        // argument. Absolute/remote/registry spellings remain stable.
                        let identity = match &artifact {
                            ProvenanceArtifact::ImportedPackage {
                                source_path: Some(path),
                                ..
                            } if !text.starts_with('/') => format!("{text}@{path}"),
                            _ => text.clone(),
                        };
                        let artifact_node_id =
                            imported_package_artifact_node_id(manager, locator_kind, &identity);

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
                            &text,
                            resolution_cwd,
                        ));
                    }
                }
            }
        }
    }

    mutations
}

fn classify_locator_value(
    semantic: &PackageLocatorSemantic,
    value: &BoundValue,
    cwd: &str,
    home: Option<&str>,
) -> (PackageLocatorKind, String) {
    if let Some(SemanticValueResolution::Known(text)) =
        project_value(&ValueProjection::Identity, value)
    {
        return (classify_static_locator_kind(semantic, &text), text);
    }

    // The shared argv view deliberately leaves shell tilde expansion unknown.
    // Its simple unquoted form can use the home already supplied in the request;
    // no filesystem lookup, named-user lookup or tool environment probing occurs.
    if let BoundValue::Argument {
        text,
        quoted: false,
        node_kind,
        materialization: BoundArgumentMaterialization::Literal,
        ..
    } = value
    {
        if node_kind == "word" && (text == "~" || text.starts_with("~/")) {
            if let Some(path) = resolve_path_operand(text, false, node_kind, cwd, home) {
                return (classify_static_locator_kind(semantic, &path), path);
            }
        }
    }

    let text = match value {
        BoundValue::Argument { text, .. } => text.clone(),
        BoundValue::ImplicitInput { source, .. } => {
            format!("<unresolved package argument from {source:?}>")
        }
    };
    // Unknown is an analysis result, not a valid-input alternative that a
    // profile can disable. Never discard an unresolved source or call it a
    // registry reference just because that is the only declared concrete kind.
    (PackageLocatorKind::UnknownDynamic, text)
}

fn classify_static_locator_kind(
    semantic: &PackageLocatorSemantic,
    text: &str,
) -> PackageLocatorKind {
    if text.is_empty() || text.starts_with('-') {
        return PackageLocatorKind::UnknownDynamic;
    }

    // A filesystem spelling still has to agree with the declared input role.
    // In particular, -r/-f definition inputs remain RequirementFile even when
    // absolute or extensionless. Conflicting local roles remain unresolved.
    if has_explicit_local_path_syntax(text) {
        return unique_local_kind(semantic).unwrap_or(PackageLocatorKind::UnknownDynamic);
    }

    if is_vcs_locator(text) && text.contains("://") {
        return first_allowed_kind(
            semantic,
            &[PackageLocatorKind::VcsUrl, PackageLocatorKind::DirectUrl],
        )
        .unwrap_or(PackageLocatorKind::UnknownDynamic);
    }

    if is_http_url(text) {
        return allowed_kind(semantic, PackageLocatorKind::DirectUrl)
            .unwrap_or(PackageLocatorKind::UnknownDynamic);
    }

    // Unsupported URI/composite URL syntax cannot fall through to a local
    // filename or a registry package. It requires its own declared grammar.
    if text.contains("://") || is_vcs_locator(text) {
        return PackageLocatorKind::UnknownDynamic;
    }

    if allowed_kind(semantic, PackageLocatorKind::RegistryRef).is_none() {
        return unique_local_kind(semantic).unwrap_or(PackageLocatorKind::UnknownDynamic);
    }

    if text.contains('/') {
        return first_allowed_kind(
            semantic,
            manager_ambiguous_locator_precedence(semantic.manager),
        )
        .unwrap_or(PackageLocatorKind::UnknownDynamic);
    }

    PackageLocatorKind::RegistryRef
}

fn allowed_kind(
    semantic: &PackageLocatorSemantic,
    kind: PackageLocatorKind,
) -> Option<PackageLocatorKind> {
    semantic
        .locator_kinds
        .iter()
        .any(|declared| package_locator_kind(*declared) == kind)
        .then_some(kind)
}

fn unique_local_kind(semantic: &PackageLocatorSemantic) -> Option<PackageLocatorKind> {
    match (
        allowed_kind(semantic, PackageLocatorKind::RequirementFile),
        allowed_kind(semantic, PackageLocatorKind::LocalPath),
    ) {
        (Some(kind), None) | (None, Some(kind)) => Some(kind),
        _ => None,
    }
}

fn first_allowed_kind(
    semantic: &PackageLocatorSemantic,
    precedence: &[PackageLocatorKind],
) -> Option<PackageLocatorKind> {
    precedence
        .iter()
        .find_map(|kind| allowed_kind(semantic, *kind))
}

fn manager_ambiguous_locator_precedence(
    manager: caushell_profile::PackageManagerKind,
) -> &'static [PackageLocatorKind] {
    match manager {
        caushell_profile::PackageManagerKind::Pip | caushell_profile::PackageManagerKind::Uv => &[
            PackageLocatorKind::LocalPath,
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::RequirementFile,
        ],
        caushell_profile::PackageManagerKind::Apt
        | caushell_profile::PackageManagerKind::Yum
        | caushell_profile::PackageManagerKind::Brew => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
            PackageLocatorKind::RequirementFile,
        ],
        caushell_profile::PackageManagerKind::Conan => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
        ],
        caushell_profile::PackageManagerKind::Conda => &[
            PackageLocatorKind::RegistryRef,
            PackageLocatorKind::LocalPath,
            PackageLocatorKind::RequirementFile,
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
    cwd: &str,
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
                resolve_path_operand(text, true, "raw_string", cwd, None)
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
    cwd: &str,
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
            resolve_path_operand(text, true, "raw_string", cwd, None)
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
        caushell_profile::PackageManagerKind::Uv => PackageManagerKind::Uv,
        caushell_profile::PackageManagerKind::Apt => PackageManagerKind::Apt,
        caushell_profile::PackageManagerKind::Conan => PackageManagerKind::Conan,
        caushell_profile::PackageManagerKind::Conda => PackageManagerKind::Conda,
        caushell_profile::PackageManagerKind::Npm => PackageManagerKind::Npm,
        caushell_profile::PackageManagerKind::Yum => PackageManagerKind::Yum,
        caushell_profile::PackageManagerKind::Brew => PackageManagerKind::Brew,
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
        PackageManagerKind::Uv => "uv",
        PackageManagerKind::Apt => "apt",
        PackageManagerKind::Conan => "conan",
        PackageManagerKind::Conda => "conda",
        PackageManagerKind::Npm => "npm",
        PackageManagerKind::Yum => "yum",
        PackageManagerKind::Brew => "brew",
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

fn is_http_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

fn is_vcs_locator(text: &str) -> bool {
    text.starts_with("git+")
        || text.starts_with("hg+")
        || text.starts_with("svn+")
        || text.starts_with("bzr+")
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

#[cfg(test)]
mod tests {
    use super::{
        ExtractImportedPackageProvenancePass, classify_locator_value, classify_static_locator_kind,
    };
    use crate::{
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
        path::provenance_artifact_for_path,
    };
    use caushell_graph::{EdgeKind, NodeId, SessionGraph};
    use caushell_profile::{
        BoundValue, ImplicitInputSource, PackageLocatorKind as DeclaredKind,
        PackageLocatorSemantic, PackageManagerKind as DeclaredManager, ProfileRegistry,
    };
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, PackageLocatorKind, ProvenanceArtifact,
        ProvenanceConsumeKind, ProvenanceEdgeSemantics, ProvenanceEndpointKind,
        ProvenanceEndpointUsage, ProvenanceProduceKind, RuntimeMetadata, SessionId, SessionSummary,
        ShellKind,
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

    fn assert_locator(
        command: &str,
        kind: PackageLocatorKind,
        path: Option<&str>,
        endpoint: Option<&str>,
    ) {
        let ctx = run_pass(command);
        let packages: Vec<_> = ctx
            .pending_mutations()
            .iter()
            .filter_map(|m| match m {
                PendingMutation::AddProvenanceArtifact {
                    artifact: artifact @ ProvenanceArtifact::ImportedPackage { .. },
                    relation: EdgeKind::Produces,
                    ..
                } => Some(artifact),
                _ => None,
            })
            .collect();
        assert_eq!(packages.len(), 1, "{command}: {packages:?}");
        let ProvenanceArtifact::ImportedPackage {
            locator_kind,
            source_path,
            source_endpoint,
            ..
        } = packages[0]
        else {
            unreachable!()
        };
        assert_eq!(*locator_kind, kind, "{command}: {packages:?}");
        assert_eq!(source_path.as_deref(), path, "{command}");
        assert_eq!(source_endpoint.as_deref(), endpoint, "{command}");
    }

    #[test]
    fn definition_role_is_independent_of_filename_and_suffix() {
        for name in [
            "input",
            "environment.yml",
            "dependencies.toml",
            "packages.lock",
            "requirements.txt",
            "config/custom.spec",
        ] {
            for prefix in ["pip install -r", "conda env create -p env -f"] {
                assert_locator(
                    &format!("{prefix} {name}"),
                    PackageLocatorKind::RequirementFile,
                    Some(&format!("/tmp/project/{name}")),
                    None,
                );
            }
        }
    }

    #[test]
    fn explicit_definition_paths_keep_the_definition_role() {
        for (name, path) in [
            ("./input", "/tmp/project/input"),
            ("/etc/custom", "/etc/custom"),
            ("../deps", "/tmp/deps"),
        ] {
            for prefix in ["pip install -r", "conda install -p env --file"] {
                assert_locator(
                    &format!("{prefix} {name}"),
                    PackageLocatorKind::RequirementFile,
                    Some(path),
                    None,
                );
            }
        }
    }

    #[test]
    fn the_same_name_uses_the_declared_parameter_role() {
        assert_locator(
            "pip install requests.txt",
            PackageLocatorKind::RegistryRef,
            None,
            None,
        );
        assert_locator(
            "pip install -r requests.txt",
            PackageLocatorKind::RequirementFile,
            Some("/tmp/project/requests.txt"),
            None,
        );
        assert_locator(
            "pip install -e requests.txt",
            PackageLocatorKind::LocalPath,
            Some("/tmp/project/requests.txt"),
            None,
        );
        for name in ["foo.in", "foo.lock", "requirements-helper"] {
            for prefix in ["pip install", "npm install", "conda install -p env"] {
                assert_locator(
                    &format!("{prefix} {name}"),
                    PackageLocatorKind::RegistryRef,
                    None,
                    None,
                );
            }
        }
    }

    #[test]
    fn definition_urls_have_network_provenance_not_fake_filesystem_paths() {
        for prefix in ["pip install -r", "conda env create -p env -f"] {
            assert_locator(
                &format!("{prefix} https://example.test/input"),
                PackageLocatorKind::DirectUrl,
                None,
                Some("https://example.test/input"),
            );
        }
    }

    #[test]
    fn unsupported_source_forms_are_retained_as_unknown_artifacts() {
        for command in [
            "pip install -r s3://bucket/input",
            "pip install -r file:///tmp/input",
            "conan install --requires https://example.test/pkg",
            "apt-get install ./pkg",
            "pip install 'pkg @ https://example.test/archive'",
        ] {
            assert_locator(command, PackageLocatorKind::UnknownDynamic, None, None);
        }
    }

    #[test]
    fn unresolved_shell_values_cannot_be_classified_from_their_static_prefix_or_suffix() {
        for command in [
            "pip install -r \"$FILE\"",
            "pip install -r \"$ROOT/requirements.txt\"",
            "conda env create -p env -f \"$ROOT/environment.yml\"",
            "pip install -r \"https://example.test/$FILE\"",
            "pip install -r *.txt",
        ] {
            assert_locator(command, PackageLocatorKind::UnknownDynamic, None, None);
        }
    }

    #[test]
    fn quoted_literals_are_not_reinterpreted_as_shell_expansion() {
        for (argument, expected) in [
            ("'input$NAME'", "input$NAME"),
            ("'*.txt'", "*.txt"),
            ("'`input`'", "`input`"),
            ("input\\$NAME", "input$NAME"),
        ] {
            assert_locator(
                &format!("pip install -r {argument}"),
                PackageLocatorKind::RequirementFile,
                Some(&format!("/tmp/project/{expected}")),
                None,
            );
        }
    }

    #[test]
    fn simple_shell_home_expansion_preserves_local_definition_provenance() {
        assert_locator(
            "pip install -r ~/input",
            PackageLocatorKind::RequirementFile,
            Some("/home/alice/input"),
            None,
        );
        assert_locator(
            "pip install -r ~missing/input",
            PackageLocatorKind::UnknownDynamic,
            None,
            None,
        );
    }

    #[test]
    fn definition_resolution_uses_metadata_for_every_manager() {
        for manager in [
            DeclaredManager::Pip,
            DeclaredManager::Apt,
            DeclaredManager::Conan,
            DeclaredManager::Conda,
            DeclaredManager::Npm,
        ] {
            let semantic = PackageLocatorSemantic {
                manager,
                locator_kinds: vec![
                    DeclaredKind::RequirementFile,
                    DeclaredKind::DirectUrl,
                    DeclaredKind::UnknownDynamic,
                ],
            };
            for name in ["input", "arbitrary.ext", "/etc/no-extension"] {
                assert_eq!(
                    classify_static_locator_kind(&semantic, name),
                    PackageLocatorKind::RequirementFile
                );
            }
        }
    }

    #[test]
    fn ambiguous_or_url_only_declarations_do_not_invent_a_file_role() {
        for kinds in [
            vec![DeclaredKind::RequirementFile, DeclaredKind::LocalPath],
            vec![DeclaredKind::DirectUrl],
            vec![],
        ] {
            let semantic = PackageLocatorSemantic {
                manager: DeclaredManager::Pip,
                locator_kinds: kinds,
            };
            for name in ["input", "requirements.txt", "./environment.yml"] {
                assert_eq!(
                    classify_static_locator_kind(&semantic, name),
                    PackageLocatorKind::UnknownDynamic
                );
            }
        }
    }

    #[test]
    fn runtime_input_does_not_disappear_when_only_a_concrete_kind_is_declared() {
        let semantic = PackageLocatorSemantic {
            manager: DeclaredManager::Apt,
            locator_kinds: vec![DeclaredKind::RegistryRef],
        };
        let (kind, text) = classify_locator_value(
            &semantic,
            &BoundValue::implicit_input(ImplicitInputSource::StdinData),
            "/tmp/project",
            None,
        );
        assert_eq!(kind, PackageLocatorKind::UnknownDynamic);
        assert!(text.contains("StdinData"));
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
                        "artifact:imported-package:pip:requirement_file:requirements.txt@/tmp/project/requirements.txt"
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
                    node_id: NodeId::new("artifact:imported-package:pip:local_path:.@/tmp/project"),
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
                    node_id: NodeId::new(
                        "artifact:imported-package:conan:local_path:.@/tmp/project"
                    ),
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
