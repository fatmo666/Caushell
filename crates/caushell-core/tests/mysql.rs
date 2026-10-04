//! Docker-only static guard/Graph checks. Never execute SQL or client commands.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphRead, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractEndpointProvenancePass,
    ExtractExecutionSemanticsPass, ExtractPathFactsPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("mysql-static"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
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
fn rule(r: &CheckResponse, id: RuleId) -> bool {
    r.decision_trace.findings.iter().any(|f| f.rule_id == id)
        || r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == id)
}
fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    assert!(!rule(&r, RuleId::NoProfile), "{command}");
    r
}
fn database_approval(command: &str) -> CheckResponse {
    let r = check(command, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::DatabaseOpaqueExecution
                && p.source_pass == "database_operation_guard"),
        "{command}: {:?}",
        r.decision_trace
    );
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "mysql"
                && s.database_operations
                    .contains(&DatabaseOperationKind::Opaque)),
        "{command}"
    );
    r
}
fn inspect(command: &str, verify: impl FnOnce(&dyn GraphRead)) {
    // Inspect staged semantics, not a claimed approved/default execution.
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractEndpointProvenancePass);
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
fn sql_queries_and_mutations_use_existing_database_guard() {
    for c in [
        "mysql -e 'SELECT 1;'",
        "mysql db -e 'DROP TABLE lab;'",
        "mysql --execute='SHOW TABLES;'",
        "mysql -e 'SELECT 1; DELETE FROM lab;'",
        "mysql -e 'SELECT 1 INTO OUTFILE \"/etc/sql-output\";'",
        "mysql --no-defaults --no-login-paths -e 'SELECT 1;'",
    ] {
        let r = database_approval(c);
        assert!(
            !rule(&r, RuleId::OutsideWorkspaceMutation),
            "{c}: {:?}",
            r.decision_trace
        );
        assert!(
            !rule(&r, RuleId::SelectionError),
            "{c}: {:?}",
            r.decision_trace
        );
    }
}
#[test]
fn disabling_client_commands_or_restricting_updates_is_not_a_sql_exemption() {
    for c in [
        "mysql --safe-updates -e 'SELECT 1;'",
        "mysql -U -e 'DELETE FROM lab WHERE id=1;'",
        "mysql --binary-mode -e 'DROP TABLE lab;'",
        "mysql --commands=OFF --system-command=OFF -e 'SELECT 1;'",
        "mysql --skip-commands --skip-system-command -B db",
    ] {
        database_approval(c);
    }
}
#[test]
fn local_connections_do_not_prove_database_workspace_ownership() {
    for c in [
        "mysql -h localhost -e 'SELECT 1;'",
        "mysql -h127.0.0.1 -P3306 db -e 'DELETE FROM lab;'",
        "mysql --socket=/tmp/project/db.sock -e 'UPDATE lab SET x=1;'",
        "mysql -S./db.sock -e 'SELECT 1;'",
        "mysql --protocol=SOCKET --database=/etc/not-a-path -e 'SELECT 1;'",
    ] {
        let r = database_approval(c);
        assert!(!rule(&r, RuleId::OutsideWorkspaceMutation));
    }
}
#[test]
fn init_sql_is_opaque_even_without_an_execute_option() {
    for c in [
        "mysql --init-command='SELECT 1;' -B db",
        "mysql --init-command-add='SET @x=1;' -q db",
        "mysql --init-command='DROP TABLE lab;' --reconnect -e 'SELECT 1;'",
    ] {
        let r = database_approval(c);
        assert!(
            r.decision_trace
                .nested_payloads
                .iter()
                .any(|p| p.language == NestedPayloadLanguage::MysqlCli)
        );
    }
}
#[test]
fn stdin_pipe_heredoc_file_and_interactive_protocol_all_require_approval() {
    for c in [
        "mysql",
        "mysql -B db",
        "printf 'SELECT 1;\\n' | mysql -B db",
        "mysql db < fixture.sql",
        "mysql --binary-mode db <<'SQL'\nSELECT 1;\nSQL",
    ] {
        database_approval(c);
    }
}
#[test]
fn mysql_client_commands_and_sql_literals_do_not_become_bash_children() {
    for c in [
        "mysql -e 'system rm -rf /'",
        "mysql -e 'source /etc/example.sql'",
        "mysql -e 'pager cat > /etc/log'",
        "mysql -e 'tee /etc/log'",
        "printf 'system rm -rf /\\n' | mysql -B db",
        "mysql -e 'SELECT \"rm -rf /\";'",
        "mysql --init-command='system rm -rf /' -B db",
    ] {
        let r = database_approval(c);
        assert!(
            !r.decision_trace.derived_invocations.iter().any(|d| [
                Some("rm"),
                Some("cat"),
                Some("tee")
            ]
            .contains(&d.command_name.as_deref())),
            "{c}"
        );
        assert!(
            r.decision_trace
                .nested_payloads
                .iter()
                .all(|p| p.language == NestedPayloadLanguage::MysqlCli),
            "{c}: {:?}",
            r.decision_trace.nested_payloads
        );
    }
}
#[test]
fn an_outer_bash_substitution_or_following_action_is_still_checked() {
    check("mysql -e \"SELECT '$(rm -rf /)'\"", Decision::Deny);
    check("mysql -e 'SELECT 1;'; rm -rf /", Decision::Deny);
}
#[test]
fn explicit_tee_and_outer_redirections_keep_independent_mutation_approval() {
    for c in [
        "mysql --tee=/etc/log -e 'SELECT 1;'",
        "mysql -B --tee=/etc/log db",
        "mysql --tee=/etc/log --help",
        "mysql --tee=/etc/log --skip-tee --version",
        "mysql --tee=local --tee=/etc/log -e 'SELECT 1;'",
        "mysql -e 'SELECT 1;' > /etc/out",
        "mysql -e 'SELECT 1;' | tee /etc/out",
    ] {
        let r = database_approval(c);
        assert!(
            rule(&r, RuleId::OutsideWorkspaceMutation),
            "{c}: {:?}",
            r.decision_trace
        );
    }
}
#[test]
fn explicit_raw_device_tee_denial_survives_opaque_approval() {
    for c in [
        "mysql --tee=/dev/sda -e 'SELECT 1;'",
        "mysql --tee='/dev/sda' --help",
        "mysql --tee=local --tee=/dev/sda --skip-tee --version",
    ] {
        check(c, Decision::Deny);
    }
}
#[test]
fn dynamic_inputs_and_paths_are_not_guessed() {
    for c in [
        "mysql -e \"$SQL\"",
        "mysql --init-command=\"$INIT\" -B db",
        "mysql --tee=\"$LOG\" -e 'SELECT 1;'",
        "mysql -h \"$HOST\" -e 'SELECT 1;'",
    ] {
        let mut req = request(c);
        req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        let r = ShellQueryCore::new().check(req);
        assert_eq!(r.decision, Decision::NeedApproval, "{c}");
        assert!(rule(&r, RuleId::DatabaseOpaqueExecution), "{c}");
        if c.contains("$LOG") {
            assert!(rule(&r, RuleId::OutsideWorkspaceMutation));
        }
    }
}
#[test]
fn help_shaped_operands_and_terminator_do_not_trigger_information_exit() {
    for c in [
        "mysql -e --help",
        "mysql -h --version -e 'SELECT 1;'",
        "mysql -u --help -e 'SELECT 1;'",
        "mysql -- --help --tee=/etc/log",
    ] {
        database_approval(c);
    }
}
#[test]
fn startup_config_and_debug_information_are_not_certified_side_effect_free() {
    for c in [
        "mysql --help",
        "mysql --version",
        "mysql --defaults-file=/etc/my.cnf --help",
        "mysql --debug --version",
        "mysql --no-defaults --help --no-login-paths",
    ] {
        database_approval(c);
    }
}

#[test]
fn proven_config_free_pure_information_is_allowed_by_unchanged_policy() {
    for c in [
        "mysql --no-defaults --no-login-paths --help",
        "mysql --no-defaults --no-login-paths --version",
        "mysql --no-defaults --no-login-paths -I",
        "mysql '--no-defaults' '--no-login-paths' --help",
    ] {
        let r = check(c, Decision::Allow);
        assert!(!rule(&r, RuleId::DatabaseOpaqueExecution), "{c}");
        assert!(!rule(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        assert!(r.decision_trace.nested_payloads.is_empty());
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.database_operations.is_empty())
        );
    }
}

#[test]
fn malformed_prefixes_and_mixed_info_keep_existing_approval_or_denial() {
    for c in [
        "mysql --no-login-paths --no-defaults --help",
        "mysql --help --no-defaults --no-login-paths",
        "mysql --no-defaults --no-login-paths --help --future",
        "mysql --no-defaults --no-login-paths --help --debug",
        "mysql --no-defaults --no-login-paths --help -pfixture",
        "mysql --no-defaults --no-login-paths -e 'SELECT 1;' --help",
        "mysql --no-defaults --no-login-paths --tee=/etc/log --help",
    ] {
        database_approval(c);
    }
    check(
        "mysql --no-defaults --no-login-paths --tee=/dev/sda --help",
        Decision::Deny,
    );
}
#[test]
fn default_resolve_gap_observe_cannot_bypass_declared_database_opaque_fallback() {
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .resolve_gap
        .defaults
        .insert(ResolveGapKind::OpaqueInvocation, RuleAction::Observe);
    for c in [
        "mysql --future --help",
        "mysql --loose-tee=/etc/log --version",
        "mysql -e",
        "mysql --defaults-file config.cnf --help",
        "mysql -pfixture -e 'SELECT 1;'",
    ] {
        let r = ShellQueryCore::with_policy(policy.clone()).check(request(c));
        assert_eq!(r.decision, Decision::NeedApproval, "{c}");
        assert!(rule(&r, RuleId::DatabaseOpaqueExecution));
    }
}
#[test]
fn database_policy_override_does_not_override_filesystem_rules() {
    // Explicit test-only isolation, not a new product default or SQL proof.
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::DatabaseOpaqueExecution,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    for (c, decision) in [
        ("mysql --tee=local -e 'SELECT 1;'", Decision::Allow),
        (
            "mysql --tee=/etc/log -e 'SELECT 1;'",
            Decision::NeedApproval,
        ),
        ("mysql --tee=/dev/sda -e 'SELECT 1;'", Decision::Deny),
    ] {
        let r = ShellQueryCore::with_policy(policy.clone()).check(request(c));
        assert_eq!(r.decision, decision, "{c}: {:?}", r.decision_trace);
        assert!(rule(&r, RuleId::DatabaseOpaqueExecution));
        if decision == Decision::NeedApproval {
            assert!(rule(&r, RuleId::OutsideWorkspaceMutation));
        }
    }
}
#[test]
fn staged_graph_retains_paths_endpoints_and_database_semantics_without_sql_paths() {
    inspect(
        "mysql -h 127.0.0.1 -S db.sock --ssl-ca='/etc/cert one.pem' --tee='./log one' --tee=/etc/log --defaults-file=cfg.cnf -e 'SELECT 1 INTO OUTFILE \"/etc/sql-only\";' /etc/database-name",
        |g| {
            for (path, role) in [
                ("/etc/cert one.pem", ResolvedPathRole::Read),
                ("/tmp/project/log one", ResolvedPathRole::Write),
                ("/etc/log", ResolvedPathRole::Write),
            ] {
                assert!(g.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { resolution, role: actual, .. } if actual == &role && resolution.concrete_path() == Some(path))), "{path}: {:?}", g.nodes().filter(|n| matches!(&n.kind, NodeKind::PathFact { .. })).collect::<Vec<_>>());
            }
            assert!(g.nodes().any(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, endpoint_kind: ProvenanceEndpointKind::HostPort, .. } } if endpoint == "127.0.0.1")));
            assert!(g.nodes().any(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, endpoint_kind: ProvenanceEndpointKind::SocketPath, .. } } if endpoint == "db.sock")));
            assert!(g.nodes().any(|n| matches!(&n.kind, NodeKind::ExecutionSemantics { semantics } if semantics.database_operations == [DatabaseOperationKind::Opaque])));
            assert!(!g.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { resolution, .. } if [Some("/etc/database-name"), Some("/etc/sql-only")].contains(&resolution.concrete_path()))));
        },
    );
}
#[test]
fn staged_graph_keeps_mysql_language_and_source_text_without_bash_parsing() {
    inspect(
        "mysql -e 'system rm -rf /' --init-command='SET @x=1;'",
        |g| {
            for text in ["system rm -rf /", "SET @x=1;"] {
                assert!(g.nodes().any(|n| matches!(&n.kind, NodeKind::NestedPayload { language, input_text, .. } if language == "mysql_cli" && input_text.as_deref() == Some(text))), "{text}");
            }
            assert!(!g.nodes().any(|n| matches!(&n.kind, NodeKind::DerivedInvocation { command_name, .. } if command_name.as_deref() == Some("rm"))));
        },
    );
}
