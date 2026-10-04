//! Static guard inputs only; no database operation is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("redis-cli-scope"),
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
fn check(command: &str, decision: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(
        response.decision, decision,
        "{command}: {:?}",
        response.decision_trace
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
    response
}
fn assert_operation(command: &str, operation: DatabaseOperationKind, rule: Option<RuleId>) {
    let r = check(
        command,
        if rule.is_some() {
            Decision::NeedApproval
        } else {
            Decision::Allow
        },
    );
    let semantics: Vec<_> = r
        .decision_trace
        .execution_semantics
        .iter()
        .filter(|s| s.normalized_command_name == "redis-cli")
        .collect();
    assert_eq!(semantics.len(), 1, "{command}: {semantics:?}");
    assert_eq!(semantics[0].database_operations, [operation]);
    if let Some(rule) = rule {
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == rule && p.source_pass == "database_operation_guard"),
            "{command}"
        );
    }
}
#[test]
fn explicit_queries_and_diagnostics_are_allowed_and_recorded() {
    for command in [
        "redis-cli GET key",
        "redis-cli GeT /etc/not-a-path",
        "redis-cli EXISTS key",
        "redis-cli DBSIZE",
        "redis-cli CONFIG GET dir",
        "redis-cli CLIENT LIST",
        "redis-cli --scan --pattern 'test:*'",
        "redis-cli --latency",
        "redis-cli --json -r 1 -i 0 -n 2 GET key",
    ] {
        assert_operation(command, DatabaseOperationKind::Read, None);
    }
}
#[test]
fn localhost_and_workspace_socket_do_not_authorize_mutation() {
    for command in [
        "redis-cli SET key value",
        "redis-cli -h 127.0.0.1 DEL key",
        "redis-cli -u redis://localhost:6379/0 FLUSHALL",
        "redis-cli -s /tmp/project/db.sock SET key value",
        "redis-cli GETDEL key",
        "redis-cli --lru-test 10",
    ] {
        assert_operation(
            command,
            DatabaseOperationKind::Write,
            Some(RuleId::DatabaseStateMutation),
        );
    }
}
#[test]
fn server_administration_requires_approval_not_process_or_path_surrogates() {
    for command in [
        "redis-cli CONFIG SET dir /etc",
        "redis-cli SHUTDOWN NOSAVE",
        "redis-cli CLIENT KILL ID 2",
        "redis-cli ACL SETUSER user on",
        "redis-cli --cluster fix localhost:6379",
        "redis-cli --replica",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::DatabaseAdministration)
        );
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .filter(|s| s.normalized_command_name == "redis-cli")
                .all(|s| !s.controls_process)
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
}
#[test]
fn opaque_execution_and_command_streams_require_approval() {
    for command in [
        "redis-cli",
        "printf 'GET key\nFLUSHALL\n' | redis-cli",
        "redis-cli --pipe < input.resp",
        "redis-cli -x SET key < input",
        "redis-cli -X CMD CMD key < input",
        "redis-cli --quoted-input GET key",
        "redis-cli EVAL 'return 1' 0",
        "redis-cli EVALSHA abc 0",
        "redis-cli FCALL f 0",
        "redis-cli FCALL_RO f 0",
        "redis-cli CUSTOM.OP key",
        "redis-cli \"$CMD\" key",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::DatabaseOpaqueExecution),
            "{command}"
        );
    }
}
#[test]
fn lua_and_protocol_input_never_generate_bash_child_commands() {
    for command in [
        "redis-cli --eval /etc/script.lua key , value",
        "redis-cli EVAL 'rm -f /etc/a; return 1' 0",
        "printf 'rm -f /etc/a\n' | redis-cli --pipe",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            !r.decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("rm"))
        );
        assert!(
            !r.decision_trace
                .nested_payloads
                .iter()
                .any(|p| p.language == NestedPayloadLanguage::Bash)
        );
    }
}
#[test]
fn backups_and_redirections_follow_independent_filesystem_rules() {
    for command in [
        "redis-cli --rdb dump.rdb",
        "redis-cli --functions-rdb local.rdb",
        "redis-cli --rdb -",
        "redis-cli GET key > result.txt",
        "redis-cli GET --rdb",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "redis-cli --rdb /backup/dump.rdb",
        "redis-cli --rdb \"$OUTPUT\"",
        "redis-cli --functions-rdb ../outside.rdb",
        "redis-cli GET key > /backup/result.txt",
        "redis-cli GET key | tee /backup/result.txt",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}"
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::DatabaseStateMutation)
        );
    }
}
#[test]
fn query_words_cannot_mask_options_or_other_commands() {
    for command in [
        "redis-cli --eval local.lua GET key",
        "redis-cli --pipe GET key",
        "redis-cli -X GET GET key",
        "redis-cli CONFIG SET GET value",
        "redis-cli GET key; redis-cli FLUSHALL",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "redis-cli GET --help",
        "redis-cli -a --help GET key",
        "redis-cli GET --eval",
        "redis-cli GET /etc/key",
        "redis-cli --help --eval nonexistent.lua",
        "redis-cli --version FLUSHALL",
    ] {
        check(command, Decision::Allow);
    }
}
#[test]
fn incomplete_option_boundary_is_opaque_even_when_gap_policy_observes() {
    for command in [
        "redis-cli --unknown GET key",
        "redis-cli -h",
        "redis-cli -p6379 GET key",
        "redis-cli --rdb",
        "redis-cli --eval",
    ] {
        assert_operation(
            command,
            DatabaseOperationKind::Opaque,
            Some(RuleId::DatabaseOpaqueExecution),
        );
    }
}
#[test]
fn nested_execution_uses_the_same_guard_and_canonical_source() {
    for command in [
        "env redis-cli FLUSHALL",
        "bash -c 'redis-cli SET key v'",
        "f() { redis-cli DEL key; }; f",
        "find . -exec redis-cli SET key v \\;",
        "printf key | xargs redis-cli DEL",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::DatabaseStateMutation),
            "{command}"
        );
        let proposals: Vec<_> = r
            .decision_trace
            .decision_proposals
            .iter()
            .filter(|p| p.rule_id == RuleId::DatabaseStateMutation)
            .collect();
        assert_eq!(proposals.len(), 1, "{command}: {proposals:?}");
    }
}
#[test]
fn database_rule_configuration_does_not_override_file_safety() {
    let mut policy = PolicyConfig::default();
    for rule in [
        RuleId::DatabaseStateMutation,
        RuleId::DatabaseAdministration,
        RuleId::DatabaseOpaqueExecution,
    ] {
        assert_eq!(
            policy.rule_policy.action_for(rule),
            RuleAction::NeedApproval
        );
        assert_eq!(rule.family(), RuleFamily::DatabaseSafety);
        policy
            .rule_policy
            .rules
            .insert(rule, RulePolicyEntry::new(RuleAction::Observe));
    }
    for command in [
        "redis-cli SET key v",
        "redis-cli SHUTDOWN",
        "redis-cli EVAL 'return 1' 0",
    ] {
        let r = ShellQueryCore::try_with_policy(policy.clone())
            .unwrap()
            .check(request(command));
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:?}");
    }
    let r = ShellQueryCore::try_with_policy(policy)
        .unwrap()
        .check(request("redis-cli GET key > /etc/result"));
    assert_eq!(r.decision, Decision::NeedApproval);
    let mut deny = PolicyConfig::default();
    deny.rule_policy.rules.insert(
        RuleId::DatabaseStateMutation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    assert_eq!(
        ShellQueryCore::try_with_policy(deny)
            .unwrap()
            .check(request("redis-cli SET key v"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn database_facts_survive_snapshot_without_retriggering_history() {
    for (command, rule, operation) in [
        (
            "redis-cli SET key v",
            RuleId::DatabaseStateMutation,
            DatabaseOperationKind::Write,
        ),
        (
            "redis-cli SHUTDOWN",
            RuleId::DatabaseAdministration,
            DatabaseOperationKind::Administration,
        ),
        (
            "redis-cli --unknown GET key",
            RuleId::DatabaseOpaqueExecution,
            DatabaseOperationKind::Opaque,
        ),
    ] {
        // Observe permits committing each effect so persistence can be tested.
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(rule, RulePolicyEntry::new(RuleAction::Observe));
        let mut core = ShellQueryCore::try_with_policy(policy).unwrap();
        let req = request(command);
        assert_eq!(core.check(req.clone()).decision, Decision::Allow);
        let snapshot = core.session_snapshot(&req.session_id, 1).unwrap();
        assert!(snapshot.graph.nodes.iter().any(|node| matches!(&node.kind,
            SessionGraphNodeKindSnapshot::ExecutionSemantics {semantics}
                if semantics.database_operations == [operation])));
        core.replace_policy(PolicyConfig::default());
        let mut next = request("echo done");
        next.sequence_no = CommandSequenceNo::new(2);
        let r = core.check(next);
        assert_eq!(r.decision, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id.family() == RuleFamily::DatabaseSafety)
        );
    }
}
