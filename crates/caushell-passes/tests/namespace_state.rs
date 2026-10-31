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
