//! Docker-only static checks; command strings below are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphRead, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("sqlite-profile-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn check(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(
        result.decision, expected,
        "{command}: {:?}",
        result.decision_trace.findings
    );
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
}

fn inspect(command: &str, verify: impl FnOnce(&dyn GraphRead)) {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    verify(staged.graph());
}

#[test]
fn normal_sql_and_readonly_are_opaque_execution() {
    for command in [
        "sqlite3 db.sqlite 'SELECT 1;'",
        "sqlite3 --readonly db.sqlite 'SELECT 1;'",
        "sqlite3 :memory: 'SELECT 1;'",
        "sqlite3 --noinit :memory: 'SELECT 1;'",
        "sqlite3 db.sqlite '.output /opt/example'",
        "sqlite3 db.sqlite '.shell rm -f /opt/example'",
        "sqlite3 db.sqlite 'SELECT writefile(\"/opt/example\", \"x\");'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn constrained_sql_respects_database_scope() {
    for (command, decision) in [
        (
            "sqlite3 --safe --noinit db.sqlite 'CREATE TABLE t(x);'",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit :memory: 'SELECT 1;'",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 db.sqlite 'SELECT 1;' --noinit --safe --csv",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit /opt/db.sqlite 'SELECT 1;'",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit --readonly /opt/db.sqlite 'SELECT 1;'",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit '../db.sqlite' 'SELECT 1;'",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit \"$DB\" 'SELECT 1;'",
            Decision::NeedApproval,
        ),
    ] {
        check(command, decision);
    }
}

#[test]
fn safe_batch_stdin_is_native_constrained_not_recursively_bash() {
    for (command, decision) in [
        ("sqlite3 --safe --noinit --batch", Decision::NeedApproval),
        (
            "sqlite3 --safe --noinit --batch db.sqlite",
            Decision::NeedApproval,
        ),
        (
            "printf 'SELECT 1;' | sqlite3 --safe --noinit --batch db.sqlite",
            Decision::NeedApproval,
        ),
        (
            "sqlite3 --safe --noinit --batch /opt/db.sqlite",
            Decision::NeedApproval,
        ),
        ("sqlite3 --safe --noinit", Decision::NeedApproval),
        ("sqlite3 --safe --noinit db.sqlite", Decision::NeedApproval),
        (
            "sqlite3 --safe --noinit --batch --interactive db.sqlite",
            Decision::NeedApproval,
        ),
    ] {
        check(command, decision);
    }
}

#[test]
fn startup_and_nonce_prevent_false_safe_admission() {
    for command in [
        "sqlite3 --safe db.sqlite 'SELECT 1;'",
        "sqlite3 --cmd '.shell true' --safe --noinit db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit --cmd '.shell true' db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit --nonce abc db.sqlite '.nonce abc' '.shell true'",
        "sqlite3 --safe --noinit --init init.sql db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit --vfs unix db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit --unsafe-testing db.sqlite 'SELECT 1;'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn archive_options_are_not_lost_among_known_arguments() {
    for command in [
        "sqlite3 -Acr --safe --noinit archive.sqlite 'SELECT 1;'",
        "sqlite3 --safe -Acr --noinit archive.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit archive.sqlite -Acr 'SELECT 1;'",
        "sqlite3 --safe --noinit archive.sqlite 'SELECT 1;' -Acr",
        "sqlite3 -Acr --noinit --version",
        "sqlite3 --safe --noinit --append db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit --zip archive.zip 'SELECT 1;'",
        "sqlite3 --safe --noinit --deserialize db.sqlite 'SELECT 1;'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn implicit_script_database_dispatch_cannot_hide_later_external_database() {
    for command in [
        "sqlite3 --safe --noinit input.sql /opt/db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit input.TXT /opt/db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit file:db.sqlite?mode=ro 'SELECT 1;'",
        "sqlite3 --safe --noinit '' 'SELECT 1;'",
    ] {
        check(command, Decision::NeedApproval);
    }
    check(
        "sqlite3 --safe --noinit db.unusual 'SELECT 1;'",
        Decision::NeedApproval,
    );
}

#[test]
fn dynamic_sql_and_option_values_cannot_smuggle_cli_options() {
    for command in [
        "sqlite3 --safe --noinit :memory: \"$INPUT\"",
        "sqlite3 --safe --noinit --separator \"$INPUT\" :memory: 'SELECT 1;'",
        "sqlite3 --safe --noinit --threadsafe 0 :memory: 'SELECT 1;'",
        "sqlite3 --safe --noinit --pagecache 4096 2 :memory: 'SELECT 1;'",
        "sqlite3 --safe --noinit --separator , :memory: 'SELECT 1;'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn informational_calls_only_skip_execution_when_startup_is_disabled() {
    for command in ["sqlite3 --noinit --version", "sqlite3 -noinit -help"] {
        check(command, Decision::Allow);
    }
    for command in [
        "sqlite3 --version",
        "sqlite3 --init init.sql --version",
        "sqlite3 --cmd '.shell true' --noinit --version",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn flags_after_terminator_and_flag_shaped_values_are_not_options() {
    for command in [
        "sqlite3 --noinit -- db.sqlite --safe",
        "sqlite3 --noinit --separator --safe db.sqlite 'SELECT 1;'",
        "sqlite3 --safe=true --noinit db.sqlite 'SELECT 1;'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn graph_keeps_database_and_sidecars_without_fabricating_sql_paths() {
    inspect(
        "sqlite3 --safe --noinit db.sqlite 'CREATE TABLE t(x);'",
        |graph| {
            for path in [
                "/tmp/project/db.sqlite",
                "/tmp/project/db.sqlite-journal",
                "/tmp/project/db.sqlite-wal",
                "/tmp/project/db.sqlite-shm",
            ] {
                assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..} if resolution.concrete_path()==Some(path))), "{path}");
            }
            assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution, ..} if resolution.concrete_path().is_some_and(|p| p.contains("CREATE TABLE")))));
        },
    );
}

#[test]
fn sql_language_survives_graph_and_never_creates_shell_calls() {
    inspect(
        "sqlite3 --safe --noinit :memory: '.shell rm -f /opt/example'",
        |graph| {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::NestedPayload {language, ..} if language=="sqlite_cli")));
            assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::DerivedInvocation {command_name, ..} if command_name.as_deref()==Some("rm"))));
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics {semantics} if semantics.normalized_command_name=="sqlite3" && semantics.executes_payload)));
            assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution, ..} if resolution.concrete_path().is_some_and(|p| p.contains(":memory:")))));
        },
    );
}

#[test]
fn opaque_proposals_keep_execution_and_known_file_facts_in_staged_graph() {
    inspect("sqlite3 --init init.sql db.sqlite 'SELECT 1;'", |graph| {
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution, ..} if resolution.concrete_path()==Some("/tmp/project/db.sqlite"))));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Config, resolution, ..} if resolution.concrete_path()==Some("/tmp/project/init.sql"))));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics {semantics} if semantics.normalized_command_name=="sqlite3" && semantics.executes_payload && semantics.loads_startup_config)));
    });
}

#[test]
fn noinit_does_not_invent_startup_loading_or_default_database_paths() {
    inspect("sqlite3 --noinit --init ignored.sql --batch", |graph| {
        assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution, ..} if resolution.concrete_path().is_some())));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics {semantics} if semantics.normalized_command_name=="sqlite3" && !semantics.loads_startup_config && semantics.executes_payload)));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::NestedPayload {language, source, ..} if language=="sqlite_cli" && source=="stdin")));
    });
}

#[test]
fn implicit_startup_is_unknown_not_guessed_from_home() {
    inspect("sqlite3 db.sqlite 'SELECT 1;'", |graph| {
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics {semantics} if semantics.normalized_command_name=="sqlite3" && semantics.loads_startup_config)));
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Config, purpose: Some(ResolvedPathPurpose::StartupConfig), resolution, ..} if resolution.concrete_path().is_none())));
        assert!(
            !graph.nodes().any(
                |n| matches!(&n.kind, NodeKind::NestedPayload {source, ..} if source=="stdin")
            )
        );
    });
}

#[test]
fn clean_information_does_not_claim_sql_execution() {
    inspect("sqlite3 --noinit --version", |graph| {
        assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics {semantics} if semantics.executes_payload || semantics.loads_startup_config)));
        assert!(!graph.nodes().any(|n| matches!(
            n.kind,
            NodeKind::NestedPayload { .. } | NodeKind::PathFact { .. }
        )));
    });
    check("sqlite3 -Acr --noinit --version", Decision::NeedApproval);
}

#[test]
fn temporary_storage_pragmas_and_redirections_keep_independent_approvals() {
    for command in [
        "sqlite3 --safe --noinit :memory: 'PRAGMA temp_store_directory=\"/opt/spill\";'",
        "sqlite3 --noinit db.sqlite 'SELECT 1;' >/opt/query-results",
        "sqlite3 --noinit --version >/opt/version-output",
        "sqlite3 --safe --noinit db.sqlite '.load extension.so'",
        "sqlite3 --noinit --cmd",
        "sqlite3 --noinit --vfs",
        "sqlite3 --noinit --init",
        "sqlite3 --noinit --pagecache 4096",
    ] {
        check(command, Decision::NeedApproval);
    }
}
