use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};

pub struct ExtractCurrentWorkingDirectoryPass;

impl SessionTransformPass for ExtractCurrentWorkingDirectoryPass {
    fn name(&self) -> &'static str {
        "extract_current_working_directory"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let Some(path) = ctx.known_request_exit_cwd() else {
            return;
        };

        let entry_cwd = ctx.request().shell_state_before.cwd();

        if path == entry_cwd {
            return;
        }

        ctx.stage_mutation(PendingMutation::SetCurrentWorkingDirectory {
            path: path.to_string(),
            observed_at: ctx.request().sequence_no,
            source: caushell_types::SessionCurrentWorkingDirectorySource::StaticAnalysis,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractCurrentWorkingDirectoryPass;
    use crate::{
        ComputeEffectiveCwdPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{EffectiveCwd, PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str, cwd: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(7),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new(cwd.to_string()),
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

    fn run_pass(command: &str, summary: &SessionSummary) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().expect("expected built-in registry"),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractCurrentWorkingDirectoryPass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(command, "/tmp/project"));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    fn cwd_mutations(ctx: &RunnerContext) -> Vec<&PendingMutation> {
        ctx.pending_mutations()
            .iter()
            .filter(|mutation| {
                matches!(mutation, PendingMutation::SetCurrentWorkingDirectory { .. })
            })
            .collect()
    }

    #[test]
    fn extract_current_working_directory_stages_static_cd_exit() {
        let summary = SessionSummary::new();

        let ctx = run_pass("cd /", &summary);

        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
        assert_eq!(
            cwd_mutations(&ctx),
            vec![&PendingMutation::SetCurrentWorkingDirectory {
                path: "/".to_string(),
                observed_at: CommandSequenceNo::new(7),
                source: caushell_types::SessionCurrentWorkingDirectorySource::StaticAnalysis,
            }]
        );
    }

    #[test]
    fn extract_current_working_directory_uses_request_snapshot_cwd_as_entry() {
        let mut summary = SessionSummary::new();
        summary.set_current_working_directory("/", CommandSequenceNo::new(6));

        let ctx = run_pass("pwd", &summary);

        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/tmp/project".to_string()))
        );
        assert!(cwd_mutations(&ctx).is_empty());
    }

    #[test]
    fn extract_current_working_directory_skips_uncertain_exit() {
        let summary = SessionSummary::new();

        let ctx = run_pass("cd /no-such", &summary);

        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::KnownOneOf(vec![
                "/no-such".to_string(),
                "/tmp/project".to_string(),
            ]))
        );
        assert!(cwd_mutations(&ctx).is_empty());
    }
}
