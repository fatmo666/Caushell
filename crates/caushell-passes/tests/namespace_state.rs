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
    for declared in [true, false] {
        let yaml = if declared {
            source.to_owned()
        } else {
            source.replace("namespace_effect: regular_file_write, ", "")
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
