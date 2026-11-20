//! Static pg_dump checks. The requests never connect to a database.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("pg-dump-connection-effects"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn plain_dump_keeps_database_read_and_unknown_connection_write_separate() {
    for command in [
        "pg_dump -U demo fixture_db",
        "pg_dump --username demo fixture_db | gzip > fixture.sql.gz",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        let dump = response
            .decision_trace
            .execution_semantics
            .iter()
            .find(|item| item.normalized_command_name == "pg_dump")
            .expect("expected pg_dump effects in the decision trace");
        assert_eq!(dump.form_id, "plain_stdout");
        assert_eq!(dump.database_operations, [DatabaseOperationKind::Read]);
        assert!(dump.loads_tool_config && !dump.executes_payload);
        assert!(response.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Write
                && matches!(target.resolution, SemanticResolution::Unresolved { .. })
        }));
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| { finding.rule_id == RuleId::OutsideWorkspaceMutation })
        );
    }
}

#[test]
fn unproved_options_cannot_be_classified_as_plain_stdout() {
    for command in [
        "pg_dump --file /outside/report fixture_db",
        "pg_dump fixture_db --format=directory",
        "pg_dump -U demo \"$unobserved\"",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|item| {
                    item.normalized_command_name == "pg_dump"
                        && item.form_id == "plain_stdout"
                        && !item.operation_semantics_unresolved
                })
        );
    }
}
