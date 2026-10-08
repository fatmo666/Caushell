use caushell_parse::ParsedCommandArtifact;
use caushell_profile::EnvironmentValueRef;
use caushell_query::QuerySession;
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{CheckRequest, CommandSequenceNo, SessionVariableBinding};

use crate::support::{PositionalParameterMutation, request_variable_bindings};

pub struct ExtractVariableBindingsPass;

impl SessionTransformPass for ExtractVariableBindingsPass {
    fn name(&self) -> &'static str {
        "extract_variable_bindings"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        // Invocation resolution already computed the complete ordered final
        // state. Reuse it instead of replaying static mutations a second time.
        // Standalone pass use still has the shared static fallback below.
        if !ctx.runtime_variable_final_mutations().is_empty() {
            for mutation in ctx.runtime_variable_final_mutations().to_vec() {
                ctx.stage_mutation(mutation);
            }
            return;
        }
        let observed_at = ctx.request().sequence_no;
        let Some(parsed) = ctx.parsed_command() else {
            return;
        };
        // The audit artifact is untouched. Only the state-propagation view is fenced.
        let filtered;
        let parsed = if ctx.has_shell_state_fences() {
            filtered = {
                let mut p = parsed.clone();
                p.assignment_commands
                    .retain(|a| ctx.shell_state_at_is_reachable(a.span.start_byte));
                p.declaration_commands
                    .retain(|a| ctx.shell_state_at_is_reachable(a.span.start_byte));
                p.unset_commands
                    .retain(|a| ctx.shell_state_at_is_reachable(a.span.start_byte));
                p.commands
                    .retain(|a| ctx.shell_state_at_is_reachable(a.span.start_byte));
                p
            };
            &filtered
        } else {
            parsed
        };

        let query_session = QuerySession::from_session(&session);
        let mutations =
            collect_variable_mutations(parsed, query_session, ctx.request(), observed_at);

        for mutation in mutations {
            if matches!(
                mutation,
                PendingMutation::SetPositionalParameters { .. }
                    | PendingMutation::ForgetPositionalParameters { .. }
            ) && ctx.runtime_variable_final_mutations().iter().any(|m| {
                matches!(
                    m,
                    PendingMutation::SetPositionalParameters { .. }
                        | PendingMutation::ForgetPositionalParameters { .. }
                )
            }) {
                continue;
            }
            let name = match &mutation {
                PendingMutation::UpsertVariableBinding { binding } => Some(binding.name.as_str()),
                PendingMutation::UnsetVariable { name, .. } => Some(name.as_str()),
                _ => None,
            };
            if name.is_some_and(|name| {
                ctx.runtime_variable_final_mutations()
                    .iter()
                    .any(|m| match m {
                        PendingMutation::UpsertVariableBinding { binding } => binding.name == name,
                        PendingMutation::UnsetVariable {
                            name: final_name, ..
                        } => final_name == name,
                        _ => false,
                    })
            }) {
                continue;
            }
            ctx.stage_mutation(mutation);
        }
        // Kept for contexts that provide no final replay mutations.
        for mutation in ctx.runtime_variable_final_mutations().to_vec() {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_variable_mutations(
    parsed: &ParsedCommandArtifact,
    session: QuerySession<'_>,
    request: &CheckRequest,
    observed_at: CommandSequenceNo,
) -> Vec<PendingMutation> {
    let overlay = crate::support::static_variable_overlay(
        request_variable_bindings(session.summary(), request),
        parsed,
        observed_at,
    );
    let mut mutations = overlay
        .assigned
        .into_iter()
        .map(|name| match overlay.bindings.get(&name) {
            Some(value) => PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    &name,
                    value.value.to_session_variable_value(),
                    matches!(
                        overlay.bindings.environment_value(&name),
                        EnvironmentValueRef::Present(_)
                    ),
                    observed_at,
                ),
            },
            None => PendingMutation::UnsetVariable { name, observed_at },
        })
        .collect::<Vec<_>>();
    if let Some(result) = overlay.positional_state {
        match result {
            PositionalParameterMutation::Replace(values) => {
                mutations.push(PendingMutation::SetPositionalParameters {
                    values: values
                        .iter()
                        .map(caushell_profile::SessionValue::to_session_variable_value)
                        .collect(),
                    observed_at,
                });
            }
            PositionalParameterMutation::Forget => {
                mutations.push(PendingMutation::ForgetPositionalParameters { observed_at });
            }
            PositionalParameterMutation::Shift(_) => {
                unreachable!("overlay returns final positional state")
            }
        }
    }

    mutations
}

#[cfg(test)]
mod tests {
    use super::ExtractVariableBindingsPass;
    use crate::ParseCommandPass;
    use caushell_graph::SessionGraph;
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, RuntimeMetadata, SessionId, SessionSummary,
        SessionVariableBinding, SessionVariableValue, ShellKind,
    };

    fn sample_request(sequence_no: u64, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(sequence_no),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "claude_code".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn run_pass(summary: &SessionSummary, sequence_no: u64, command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ExtractVariableBindingsPass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(sequence_no, command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    #[test]
    fn extract_variable_bindings_stages_export_assignment_with_exact_scalar() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 3, "export SCRIPT=build.sh");

        assert_eq!(
            ctx.executed_passes,
            vec![
                "parse_command".to_string(),
                "extract_variable_bindings".to_string(),
            ]
        );
        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "SCRIPT",
                    SessionVariableValue::exact_scalar("build.sh"),
                    true,
                    CommandSequenceNo::new(3),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_treats_raw_string_as_exact_scalar() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 4, "export SCRIPT='$BAR'");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "SCRIPT",
                    SessionVariableValue::exact_scalar("$BAR"),
                    true,
                    CommandSequenceNo::new(4),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_treats_ansi_c_string_as_exact_scalar() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 5, r#"export SCRIPT=$'line1\nline2'"#);

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "SCRIPT",
                    SessionVariableValue::exact_scalar("line1\nline2"),
                    true,
                    CommandSequenceNo::new(5),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_treats_interpolated_string_as_opaque_dynamic() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 6, r#"export USER_CMD="$payload""#);

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "USER_CMD",
                    SessionVariableValue::opaque_dynamic("$payload"),
                    true,
                    CommandSequenceNo::new(6),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_stages_plain_assignment_without_export() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 7, r#"TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)""#);

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "TMP_SCRIPT",
                    SessionVariableValue::opaque_dynamic("$(mktemp /tmp/tmp.XXXXXX.sh)"),
                    false,
                    CommandSequenceNo::new(7),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_ignores_plain_append_assignment_in_first_version() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 8, "PATH+=:/tmp/bin");

        assert!(ctx.pending_mutations().is_empty());
    }

    #[test]
    fn extract_variable_bindings_can_export_existing_binding_without_new_assignment() {
        let mut summary = SessionSummary::new();
        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(1));

        let ctx = run_pass(&summary, 2, "export SCRIPT");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    "SCRIPT",
                    SessionVariableValue::exact_scalar("build.sh"),
                    true,
                    CommandSequenceNo::new(2),
                ),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_ignores_export_name_when_binding_is_unknown() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 2, "export MISSING");

        assert!(ctx.pending_mutations().is_empty());
    }

    #[test]
    fn extract_variable_bindings_stages_final_unsets_in_stable_name_order() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 6, "unset SCRIPT OTHER");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UnsetVariable {
                    name: "OTHER".to_string(),
                    observed_at: CommandSequenceNo::new(6),
                },
                PendingMutation::UnsetVariable {
                    name: "SCRIPT".to_string(),
                    observed_at: CommandSequenceNo::new(6),
                },
            ]
        );
    }

    #[test]
    fn extract_variable_bindings_ignores_optionful_unset_in_first_version() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 7, "unset -f FUNC VAR");

        assert!(ctx.pending_mutations().is_empty());
    }

    #[test]
    fn extract_variable_bindings_stages_static_positional_parameters() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 8, "set -- / /dev/sda");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::SetPositionalParameters {
                values: vec![
                    SessionVariableValue::exact_scalar("/"),
                    SessionVariableValue::exact_scalar("/dev/sda"),
                ],
                observed_at: CommandSequenceNo::new(8),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_materializes_prior_assignment_into_positional_parameters() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 9, r#"PAYLOAD=/; set -- "$PAYLOAD""#);

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UpsertVariableBinding {
                    binding: SessionVariableBinding::new(
                        "PAYLOAD",
                        SessionVariableValue::exact_scalar("/"),
                        false,
                        CommandSequenceNo::new(9),
                    ),
                },
                PendingMutation::SetPositionalParameters {
                    values: vec![SessionVariableValue::exact_scalar("/")],
                    observed_at: CommandSequenceNo::new(9),
                },
            ]
        );
    }

    #[test]
    fn extract_variable_bindings_materializes_all_positional_parameters() {
        let mut summary = SessionSummary::new();
        summary.set_positional_parameters(
            [
                SessionVariableValue::exact_scalar("/"),
                SessionVariableValue::exact_scalar("/dev/sda"),
            ],
            CommandSequenceNo::new(8),
        );

        let ctx = run_pass(&summary, 9, r#"set -- "$@""#);

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::SetPositionalParameters {
                values: vec![
                    SessionVariableValue::exact_scalar("/"),
                    SessionVariableValue::exact_scalar("/dev/sda"),
                ],
                observed_at: CommandSequenceNo::new(9),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_stages_shifted_positional_parameters() {
        let mut summary = SessionSummary::new();
        summary.set_positional_parameters(
            [
                SessionVariableValue::exact_scalar("/tmp"),
                SessionVariableValue::exact_scalar("/"),
            ],
            CommandSequenceNo::new(8),
        );

        let ctx = run_pass(&summary, 9, "shift");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::SetPositionalParameters {
                values: vec![SessionVariableValue::exact_scalar("/")],
                observed_at: CommandSequenceNo::new(9),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_stages_opaque_quoted_dynamic_positional_parameter() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 10, r#"set -- "$USER_INPUT""#);

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::SetPositionalParameters {
                values: vec![SessionVariableValue::opaque_dynamic("$USER_INPUT")],
                observed_at: CommandSequenceNo::new(10),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_forgets_unquoted_dynamic_positional_parameters() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 11, "set -- $USER_INPUT");

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::ForgetPositionalParameters {
                observed_at: CommandSequenceNo::new(11),
            }]
        );
    }

    #[test]
    fn extract_variable_bindings_does_not_persist_background_positional_mutation() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 12, "set -- / &");

        assert!(ctx.pending_mutations().is_empty());
    }
}
