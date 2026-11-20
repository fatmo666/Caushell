//! Static checks only. No archive is opened and no database is contacted.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("pg-restore-stdout"),
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
fn plain_archive_input_does_not_perform_database_operations() {
    for (command, form) in [
        (
            "gzip -cd fixture.gz | pg_restore fixture.dump",
            "archive_to_stdout",
        ),
        ("pg_restore < fixture.dump", "stdin_archive_to_stdout"),
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        let restore = response
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "pg_restore")
            .expect("pg_restore form in the decision trace");
        assert_eq!(restore.form_id, form);
        assert!(!restore.operation_semantics_unresolved && !restore.executes_payload);
        assert!(restore.database_operations.is_empty());
    }
}

#[test]
fn script_output_depends_on_the_selected_archive_input() {
    let profiles = ProfileRegistry::built_in().unwrap();
    for (command, stdin_mode, kinds) in [
        (
            "pg_restore fixture.dump",
            StreamInputMode::Ignored,
            &[EffectKind::ReadPath, EffectKind::ReadPath][..],
        ),
        (
            "pg_restore",
            StreamInputMode::DataRequired,
            &[EffectKind::ConsumeStdin][..],
        ),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let artifact = resolve_invocation_artifact_with_bindings(
            &profiles,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        let ResolveInvocationArtifactResult::Resolved(result) = artifact else {
            panic!("{command}: expected archive input and script output");
        };
        let streams = result.proven_stream_contract().unwrap();
        assert_eq!(streams.stdin_mode, stdin_mode);
        assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
        assert!(result.bound.stdout_scalar.is_none() && result.bound.stdout_records.is_none());
        assert_eq!(
            result
                .bound
                .effects
                .iter()
                .map(|effect| effect.kind)
                .collect::<Vec<_>>(),
            kinds
        );
    }
}

#[test]
fn database_file_and_unknown_control_surfaces_keep_approval() {
    for command in [
        "pg_restore --dbname=fixture_db fixture.dump",
        "pg_restore fixture.dump --file=/outside/script.sql",
        "pg_restore \"$unobserved\"",
        "pg_restore fixture.dump > /outside/script.sql",
        "pg_restore fixture.dump | psql",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
    }
}
