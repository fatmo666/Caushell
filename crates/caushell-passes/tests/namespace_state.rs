//! A synthetic producer proves the namespace engine does not depend on GCC.
use caushell_graph::SessionGraph;
use caushell_passes::*;
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{FilesystemView, PassRunner, PendingMutation, RunnerContext, SessionView};
use caushell_types::*;
use std::sync::Arc;

struct Namespace;
impl FilesystemView for Namespace {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if path == "/workspace" || path == "/tmp" {
            FilesystemEntry::Directory
        } else {
            FilesystemEntry::Missing
        }
    }
}

#[test]
fn any_declared_regular_file_producer_can_supply_a_request_local_scope_proof() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: materializer}\nforms:\n  - id: emit\n    parameters: [{name: destination, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}]\n    effects: [{kind: write_path, namespace_effect: regular_file_write, target: {kind: slot, name: destination}}]\n";
    for configured in [false, true] {
        for declared in [true, false] {
            let yaml = if declared {
                source.to_owned()
            } else {
                source.replace("namespace_effect: regular_file_write, ", "")
            };
            let yaml = if configured {
                yaml.replace("target: {kind: slot, name: destination}", "target: {kind: configured_path, sources: [{slot: destination, projection: {kind: identity}}], missing: unknown}")
            } else {
                yaml
            };
            let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
            profiles.push(load_command_profile_from_str(&yaml).unwrap());
            let mut runner = PassRunner::new();
            runner.register_request_transform_pass(ParseCommandPass);
            runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
            runner.register_session_transform_pass(ResolveInvocationPass::new(
                ProfileRegistry::from_profiles(profiles).unwrap(),
            ));
            runner.register_session_transform_pass(ComputeEffectiveCwdPass);
            runner.register_session_transform_pass(ExtractPathFactsPass);
            runner.register_session_transform_pass(ResolvePathTargetsPass);
            let req = CheckRequest {
                session_id: SessionId::new("abstract-namespace"),
                sequence_no: CommandSequenceNo(1),
                command: "materializer ./product && ./product".into(),
                shell_state_before: ShellStateSnapshot::new("/workspace"),
                shell_kind: ShellKind::Bash,
                home: None,
                workspace_root: Some("/workspace".into()),
                runtime: RuntimeMetadata {
                    runtime_name: "static".into(),
                    tool_name: None,
                    shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
                },
            };
            let mut ctx = RunnerContext::with_policy(req, PolicyConfig::default());
            ctx.set_filesystem_view(Arc::new(Namespace));
            runner.run(
                SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
                &mut ctx,
            );
            let facts: Vec<_> = ctx
                .pending_mutations()
                .iter()
                .filter_map(|m| match m {
                    PendingMutation::AddPathTargetFact { fact, .. }
                        if fact.operation == PathTargetOperation::ExecuteFile =>
                    {
                        Some(fact)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(facts.len(), 1);
            assert_eq!(
                !facts[0].namespace_proofs.is_empty(),
                declared,
                "{facts:#?}"
            );
            assert_eq!(
                matches!(facts[0].resolution, SemanticResolution::Resolved { .. }),
                declared,
                "{facts:#?}"
            );
        }
    }
}

struct FamilyNamespace;
impl FilesystemView for FamilyNamespace {
    fn entry(&self, path: &str) -> FilesystemEntry {
        match path {
            "/" | "/workspace" | "/workspace/config" | "/outside" => FilesystemEntry::Directory,
            "/workspace/program" => FilesystemEntry::File,
            _ => FilesystemEntry::Missing,
        }
    }
    fn read_directory(
        &self,
        path: &str,
        limits: DirectoryReadLimits,
    ) -> caushell_runner::DirectoryRead {
        caushell_runner::DirectoryRead::complete(
            self.source(),
            path,
            limits,
            FileContentIdentity {
                device: 1,
                inode: 1,
                size: 0,
                modified_seconds: 0,
                modified_nanos: 0,
                changed_seconds: 0,
                changed_nanos: 0,
            },
            vec![],
        )
    }
}

#[test]
fn family_proofs_close_over_unobserved_children_and_opaque_siblings() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: family_materializer}\nforms:\n  - id: emit\n    parameters: [{name: directory, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}]\n    effects: [{kind: write_path, namespace_effect: directory_tree_write, target: {kind: configured_path, sources: [{slot: directory, projection: {kind: identity}}], missing: unknown}}]\n";
    let opaque = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: opaque_native_action}\nforms:\n  - id: run\n    effects: [{kind: state_operation, state_operation: {domain: service_manager, operation: opaque}, target: {kind: none}}]\n";
    for (command, expected) in [
        ("family_materializer /workspace/config", true),
        (
            "ln -s /outside /workspace/config/future; family_materializer /workspace/config",
            false,
        ),
        ("./program; family_materializer /workspace/config", false),
        (
            "opaque_native_action; family_materializer /workspace/config",
            false,
        ),
    ] {
        let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
        profiles.extend([
            load_command_profile_from_str(source).unwrap(),
            load_command_profile_from_str(opaque).unwrap(),
        ]);
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(profiles).unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_transform_pass(ResolvePathTargetsPass);
        let request = CheckRequest {
            session_id: SessionId::new("closed-output-family"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        };
        let mut ctx = RunnerContext::with_policy(request, PolicyConfig::default());
        ctx.set_filesystem_view(Arc::new(FamilyNamespace));
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        let target = ctx
            .pending_mutations()
            .iter()
            .find_map(|m| match m {
                PendingMutation::AddPathTargetFact { fact, .. }
                    if fact.slot_name.starts_with("configured_path")
                        && fact.operation == PathTargetOperation::Write =>
                {
                    Some(fact)
                }
                _ => None,
            })
            .expect("the declared output family retains its target");
        assert_eq!(
            matches!(&target.resolution, SemanticResolution::Resolved { .. }),
            expected,
            "{command}: {target:#?}"
        );
        if !expected {
            assert!(target.namespace_proofs.is_empty());
        }
    }
}

#[test]
fn directory_creation_proofs_follow_generic_contracts_without_fabricating_entries() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: directory_materializer}\nforms:\n  - id: emit\n    parameters: [{name: destination, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}]\n    effects: [{kind: write_path, namespace_effect: directory_create, target: {kind: slot, name: destination}}]\n";
    for declared in [true, false] {
        let yaml = if declared {
            source.to_owned()
        } else {
            source.replace("namespace_effect: directory_create, ", "")
        };
        let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
        profiles.push(load_command_profile_from_str(&yaml).unwrap());
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(profiles).unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_transform_pass(ResolvePathTargetsPass);
        let req = CheckRequest {
            session_id: SessionId::new("abstract-directory-namespace"),
            sequence_no: CommandSequenceNo(1),
            command: "directory_materializer ./new; printf x > ./new/product".into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        };
        let mut ctx = RunnerContext::with_policy(req, PolicyConfig::default());
        ctx.set_filesystem_view(Arc::new(Namespace));
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        let target = ctx
            .pending_mutations()
            .iter()
            .find_map(|m| match m {
                PendingMutation::AddPathTargetFact { fact, .. }
                    if fact.lexical.concrete_path() == Some("/workspace/new/product") =>
                {
                    Some(fact)
                }
                _ => None,
            })
            .expect("the consuming write retains its target fact");
        assert_eq!(!target.namespace_proofs.is_empty(), declared, "{target:#?}");
        assert_eq!(
            matches!(target.resolution, SemanticResolution::Resolved { .. }),
            declared
        );
        assert!(
            target
                .observations
                .iter()
                .any(|o| o.path == "/workspace/new" && o.entry == FilesystemEntry::Missing)
        );
        assert!(
            target
                .namespace_proofs
                .iter()
                .all(|p| p.effect == PathNamespaceEffect::DirectoryCreate)
        );
    }
}

#[test]
fn removal_invariant_comes_from_effect_semantics_instead_of_tool_names() {
    for kind in ["move_path", "delete_path", "write_path"] {
        let yaml = format!(
            "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: retiring_fixture}}\nforms:\n - id: run\n   parameters: [{{name: source, semantic: {{kind: path, role: target}}, binding: {{kind: next_positional}}, cardinality: required_one}}]\n   effects: [{{kind: {kind}, target: {{kind: slot, name: source}}}}]\n"
        );
        let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
        profiles.push(load_command_profile_from_str(&yaml).unwrap());
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(profiles).unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_transform_pass(ResolvePathTargetsPass);
        let request = CheckRequest {
            session_id: SessionId::new("generic-removal"),
            sequence_no: CommandSequenceNo(1),
            command: "retiring_fixture ./product; printf x > ./product".into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        };
        let mut ctx = RunnerContext::new(request);
        ctx.set_filesystem_view(Arc::new(Namespace));
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        let target = ctx
            .pending_mutations()
            .iter()
            .find_map(|m| match m {
                PendingMutation::AddPathTargetFact { fact, .. }
                    if fact.effect_key.starts_with("redirect:") =>
                {
                    Some(fact)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            target
                .namespace_proofs
                .iter()
                .any(|p| p.effect == PathNamespaceEffect::EntryRemoval),
            kind != "write_path",
            "{kind}: {target:#?}"
        );
    }
}
