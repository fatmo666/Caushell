use caushell_profile::{ResolveInvocationArtifactResult, runtime_variable_writes};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::RuntimeInputSource;

use crate::support::{
    ExecutionResolveRecordRef, graph_backed_execution_resolve_records,
    variable_binding_intent_node_id,
};

pub struct ExtractVariableBindingIntentPass;

impl SessionTransformPass for ExtractVariableBindingIntentPass {
    fn name(&self) -> &'static str {
        "extract_variable_binding_intent"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        for mutation in collect_variable_binding_intent_mutations(ctx) {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_variable_binding_intent_mutations(ctx: &RunnerContext) -> Vec<PendingMutation> {
    graph_backed_execution_resolve_records(ctx)
        .into_iter()
        .flat_map(project_variable_binding_intent_mutations)
        .collect()
}

fn project_variable_binding_intent_mutations(
    record: ExecutionResolveRecordRef<'_>,
) -> Vec<PendingMutation> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        return Vec::new();
    };

    runtime_variable_writes(&resolved.bound)
        .names
        .into_iter()
        .map(|variable_name| PendingMutation::AddVariableBindingIntent {
            source_node_id: record.source_node_id().clone(),
            node_id: variable_binding_intent_node_id(record.source_node_id(), &variable_name),
            variable_name,
            runtime_input_source: runtime_input_source(&resolved.bound),
        })
        .collect()
}

fn runtime_input_source(
    invocation: &caushell_profile::BoundInvocation,
) -> Option<RuntimeInputSource> {
    invocation
        .bound_implicit_inputs
        .iter()
        .find_map(|input| input.source.to_runtime_input_source())
}

#[cfg(test)]
mod tests {
    use super::ExtractVariableBindingIntentPass;
    use crate::{
        ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
        support::variable_binding_intent_node_id,
    };
    use caushell_graph::NodeId;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeInputSource, RuntimeMetadata, SessionId, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
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
        runner.register_session_transform_pass(ExtractVariableBindingIntentPass);

        let graph = caushell_graph::SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(
            SessionView::new(&graph, &caushell_types::SessionSummary::new()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn extract_variable_binding_intent_stages_read_target_before_commit() {
        let ctx = run_pass("read USER_CMD");
        let node_id =
            variable_binding_intent_node_id(&NodeId::new("command:sess-1:1:0"), "USER_CMD");

        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddVariableBindingIntent {
                source_node_id,
                node_id: mutation_node_id,
                variable_name,
                runtime_input_source: Some(RuntimeInputSource::StdinData),
            } if source_node_id == &NodeId::new("command:sess-1:1:0")
                && mutation_node_id == &node_id
                && variable_name == "USER_CMD"
        )));
    }

    #[test]
    fn extract_variable_binding_intent_skips_non_runtime_input_bindings() {
        let ctx = run_pass("export USER_CMD=echo");

        assert!(
            !ctx.pending_mutations().iter().any(|mutation| matches!(
                mutation,
                PendingMutation::AddVariableBindingIntent { .. }
            ))
        );
    }
}
