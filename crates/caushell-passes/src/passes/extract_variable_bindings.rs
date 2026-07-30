use caushell_parse::{
    AssignmentOperator, AssignmentValueFact, DeclarationCommandKind, ParsedCommandArtifact,
};
use caushell_profile::SessionValue;
use caushell_query::{QuerySession, VariableBindingQuery};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    CheckRequest, CommandSequenceNo, SessionVariableBinding, SessionVariableValue,
};

use crate::support::{
    PositionalParameterMutation, apply_positional_parameter_mutation,
    positional_parameter_mutation_for_command, visible_variable_bindings_before_span,
};

pub struct ExtractVariableBindingsPass;

impl SessionTransformPass for ExtractVariableBindingsPass {
    fn name(&self) -> &'static str {
        "extract_variable_bindings"
    }

    fn run(&self, session: SessionView<'_>, ctx: &mut RunnerContext) {
        let observed_at = ctx.request().sequence_no;
        let Some(parsed) = ctx.parsed_command() else {
            return;
        };

        let query_session = QuerySession::from_session(&session);
        let mutations =
            collect_variable_mutations(parsed, query_session, ctx.request(), observed_at);

        for mutation in mutations {
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
    let mut mutations = Vec::new();

    for declaration in &parsed.declaration_commands {
        if declaration.kind != DeclarationCommandKind::Export || !declaration.options.is_empty() {
            continue;
        }

        for assignment in &declaration.assignments {
            mutations.push(PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    assignment.name.clone(),
                    classify_assignment_value(&assignment.value),
                    true,
                    observed_at,
                ),
            });
        }

        for name in &declaration.names {
            if declaration
                .assignments
                .iter()
                .any(|assignment| assignment.name == *name)
            {
                continue;
            }

            let Some(existing) = VariableBindingQuery::new(name).execute(session) else {
                continue;
            };

            mutations.push(PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    name.clone(),
                    existing.value().clone(),
                    true,
                    observed_at,
                ),
            });
        }
    }

    for assignment_command in &parsed.assignment_commands {
        for assignment in &assignment_command.assignments {
            if assignment.operator != AssignmentOperator::Assign {
                continue;
            }

            mutations.push(PendingMutation::UpsertVariableBinding {
                binding: SessionVariableBinding::new(
                    assignment.name.clone(),
                    classify_assignment_value(&assignment.value),
                    false,
                    observed_at,
                ),
            });
        }
    }

    for unset in &parsed.unset_commands {
        if !unset.options.is_empty() {
            continue;
        }

        for name in &unset.names {
            mutations.push(PendingMutation::UnsetVariable {
                name: name.clone(),
                observed_at,
            });
        }
    }

    if let Some(result) =
        final_positional_parameters_after_static_mutations(parsed, session, request, observed_at)
    {
        match result {
            PositionalParameterMutationResult::Known(values) => {
                mutations.push(PendingMutation::SetPositionalParameters {
                    values: values
                        .iter()
                        .map(SessionValue::to_session_variable_value)
                        .collect(),
                    observed_at,
                });
            }
            PositionalParameterMutationResult::Unknown => {
                mutations.push(PendingMutation::ForgetPositionalParameters { observed_at });
            }
        }
    }

    mutations
}

enum PositionalParameterMutationResult {
    Known(Vec<SessionValue>),
    Unknown,
}

fn final_positional_parameters_after_static_mutations(
    parsed: &ParsedCommandArtifact,
    session: QuerySession<'_>,
    request: &CheckRequest,
    observed_at: CommandSequenceNo,
) -> Option<PositionalParameterMutationResult> {
    let mut final_values = None;

    for command in &parsed.commands {
        if !matches!(command.command_name.as_deref(), Some("set" | "shift")) {
            continue;
        }

        let mut bindings = visible_variable_bindings_before_span(
            session.summary(),
            request,
            parsed,
            command.span.start_byte,
            observed_at,
        );

        let Some(mutation) = positional_parameter_mutation_for_command(command, &bindings) else {
            continue;
        };
        let unknown = matches!(mutation, PositionalParameterMutation::Forget);
        apply_positional_parameter_mutation(&mut bindings, mutation);
        final_values = Some(if unknown {
            PositionalParameterMutationResult::Unknown
        } else {
            PositionalParameterMutationResult::Known(bindings.positional_parameters().to_vec())
        });
    }

    final_values
}

fn classify_assignment_value(value: &AssignmentValueFact) -> SessionVariableValue {
    match value.node_kind.as_str() {
        "empty" => SessionVariableValue::exact_scalar(String::new()),
        "raw_string" | "ansi_c_string" | "number" => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        "string" if is_plain_quoted_literal(&value.text) => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        "word" if is_plain_unquoted_literal(&value.text) => {
            SessionVariableValue::exact_scalar(value.text.clone())
        }
        _ => SessionVariableValue::opaque_dynamic(value.text.clone()),
    }
}

fn is_plain_quoted_literal(text: &str) -> bool {
    !text.contains('\\') && !contains_unescaped_dynamic_syntax(text)
}

fn is_plain_unquoted_literal(text: &str) -> bool {
    !text.contains('\\') && !text.contains('~') && !contains_unescaped_dynamic_syntax(text)
}

fn contains_unescaped_dynamic_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }

        if bytes[index] == b'$' || bytes[index] == b'`' {
            return true;
        }

        index += 1;
    }

    false
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
    fn extract_variable_bindings_stages_unset_for_each_name_without_options() {
        let summary = SessionSummary::new();
        let ctx = run_pass(&summary, 6, "unset SCRIPT OTHER");

        assert_eq!(
            ctx.pending_mutations(),
            &[
                PendingMutation::UnsetVariable {
                    name: "SCRIPT".to_string(),
                    observed_at: CommandSequenceNo::new(6),
                },
                PendingMutation::UnsetVariable {
                    name: "OTHER".to_string(),
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
