//! Only static guard inputs; no session is launched or injected into.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("screen-scope"),
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
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, decision, "{command}: {:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{command}"
    );
    r
}
fn assert_operation(command: &str, operation: TerminalSessionOperationKind) {
    let r = check(
        command,
        if operation == TerminalSessionOperationKind::Inspect {
            Decision::Allow
        } else {
            Decision::NeedApproval
        },
    );
    let semantics: Vec<_> = r
        .decision_trace
        .execution_semantics
        .iter()
        .filter(|s| s.normalized_command_name == "screen")
        .collect();
    assert_eq!(semantics.len(), 1, "{command}: {semantics:?}");
    assert_eq!(
        semantics[0].terminal_session_operations,
        [operation],
        "{command}"
    );
    let proposals: Vec<_> = r
        .decision_trace
        .decision_proposals
        .iter()
        .filter(|p| p.rule_id == RuleId::TerminalSessionOperation)
        .collect();
    assert_eq!(
        proposals.len(),
        usize::from(operation != TerminalSessionOperationKind::Inspect),
        "{command}: {proposals:?}"
    );
    assert!(
        proposals
            .iter()
            .all(|p| p.source_pass == "interactive_escape_guard")
    );
}
#[test]
fn explicit_version_list_and_argumentless_queries_allow() {
    for c in [
        "screen -v",
        "screen -ls",
        "screen -list build",
        "screen -q -ls build",
        "screen -S build -p 0 -Q windows",
        "screen -Q info",
        "screen -Q title",
        "screen -Q number",
        "screen -Q lastmsg",
    ] {
        assert_operation(c, TerminalSessionOperationKind::Inspect);
    }
}
#[test]
fn creation_attachment_control_and_input_injection_need_approval() {
    for (c, op) in [
        ("screen", TerminalSessionOperationKind::Create),
        (
            "screen -dmS build sleep 1",
            TerminalSessionOperationKind::Create,
        ),
        ("screen -r build", TerminalSessionOperationKind::Attach),
        ("screen -RR", TerminalSessionOperationKind::Attach),
        ("screen -D -RR build", TerminalSessionOperationKind::Attach),
        ("screen -d build", TerminalSessionOperationKind::Control),
        ("screen -wipe build", TerminalSessionOperationKind::Control),
        (
            "screen -S build -X stuff 'echo hi'",
            TerminalSessionOperationKind::Control,
        ),
        (
            "screen -X source local.screenrc",
            TerminalSessionOperationKind::Control,
        ),
        (
            "screen -X hardcopy /etc/output",
            TerminalSessionOperationKind::Control,
        ),
    ] {
        assert_operation(c, op);
    }
}
#[test]
fn arbitrary_queries_and_option_gaps_are_opaque_under_default_gap_policy() {
    for c in [
        "screen -Q title renamed",
        "screen -Q number 1",
        "screen -Q select 1",
        "screen -Q echo hi",
        "screen -Q Info",
        "screen -Q time",
        "screen -Q",
        "screen -L -ls",
        "screen -ls build -wipe",
        "screen -ls -wipe",
        "screen --future -ls",
        "screen -S",
        "screen -c",
        "screen -Logfile",
        "screen -dmS",
        "screen -lsS build",
    ] {
        assert_operation(c, TerminalSessionOperationKind::Opaque);
    }
}
#[test]
fn terminal_protocol_and_child_argv_never_become_bash_payloads() {
    for c in [
        "screen -X stuff 'cd /etc; rm -f a\n'",
        "screen -X eval 'stuff rm -f /etc/a'",
        "screen -X screen bash -c 'rm -f /etc/a'",
        "screen bash -c 'rm -f /etc/a'",
        "screen -X stuff 'apply_patch *** Delete File: /etc/a'",
        "printf 'rm -f /etc/a\n' | screen",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            !r.decision_trace
                .derived_invocations
                .iter()
                .any(|d| matches!(
                    d.command_name.as_deref(),
                    Some("rm" | "bash" | "apply_patch")
                )),
            "{c}"
        );
        assert!(
            !r.decision_trace
                .nested_payloads
                .iter()
                .any(|p| p.language == NestedPayloadLanguage::Bash),
            "{c}"
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{c}: {:?}",
            r.decision_trace
        );
    }
}
#[test]
fn caller_state_and_session_names_do_not_authorize_terminal_control() {
    for c in [
        "STY=build screen",
        "STY=build screen -X quit",
        "STY=build screen -m sleep 1",
        "env STY=build screen -dmS build sleep 1",
        "screen -S /tmp/project/build -X stuff 'echo hi'",
        "screen -S /etc/name -Q info",
    ] {
        check(
            c,
            if c.ends_with("-Q info") {
                Decision::Allow
            } else {
                Decision::NeedApproval
            },
        );
    }
}
#[test]
fn wrapper_payload_function_and_dispatch_share_canonical_terminal_guard() {
    for c in [
        "env screen -X quit",
        "bash -c 'screen -dmS build sleep 1'",
        "f() { screen -X quit; }; f",
        "find . -exec screen -X stuff {} \\;",
        "printf hi | xargs screen -X stuff",
    ] {
        let r = check(c, Decision::NeedApproval);
        let proposals: Vec<_> = r
            .decision_trace
            .decision_proposals
            .iter()
            .filter(|p| p.rule_id == RuleId::TerminalSessionOperation)
            .collect();
        assert_eq!(proposals.len(), 1, "{c}: {proposals:?}");
    }
    let r = check("screen -X quit; screen -dm sleep 1", Decision::NeedApproval);
    assert_eq!(
        r.decision_trace
            .decision_proposals
            .iter()
            .filter(|p| p.rule_id == RuleId::TerminalSessionOperation)
            .count(),
        2
    );
}
#[test]
fn terminal_rule_is_configurable_without_changing_old_escape_or_file_rules() {
    let mut policy = PolicyConfig::default();
    assert_eq!(
        RuleId::TerminalSessionOperation.family(),
        RuleFamily::InteractiveControl
    );
    assert_eq!(
        policy
            .rule_policy
            .action_for(RuleId::TerminalSessionOperation),
        RuleAction::NeedApproval
    );
    assert_eq!(
        policy
            .rule_policy
            .action_for(RuleId::InteractiveEscapeSurface),
        RuleAction::Observe
    );
    policy.rule_policy.rules.insert(
        RuleId::TerminalSessionOperation,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    for c in ["screen", "screen -X stuff hi", "screen --future -ls"] {
        assert_eq!(
            ShellQueryCore::try_with_policy(policy.clone())
                .unwrap()
                .check(request(c))
                .decision,
            Decision::Allow,
            "{c}"
        );
    }
    let r = ShellQueryCore::try_with_policy(policy.clone())
        .unwrap()
        .check(request("screen -ls > /etc/output"));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    policy.rule_policy.rules.insert(
        RuleId::TerminalSessionOperation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    assert_eq!(
        ShellQueryCore::try_with_policy(policy)
            .unwrap()
            .check(request("screen -X quit"))
            .decision,
        Decision::Deny
    );
}
#[test]
fn unrelated_tools_and_inspection_do_not_emit_terminal_guard_findings() {
    for c in [
        "echo hi",
        "less README.md",
        "top -b",
        "tmux list-sessions",
        "screen -ls",
    ] {
        let r = check(c, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::TerminalSessionOperation),
            "{c}"
        );
    }
}
#[test]
fn terminal_facts_survive_snapshots_without_retriggering_history() {
    for (c, op) in [
        ("screen -dm sleep 1", TerminalSessionOperationKind::Create),
        ("screen -r build", TerminalSessionOperationKind::Attach),
        ("screen -X quit", TerminalSessionOperationKind::Control),
        ("screen --future", TerminalSessionOperationKind::Opaque),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::TerminalSessionOperation,
            RulePolicyEntry::new(RuleAction::Observe),
        );
        let mut core = ShellQueryCore::try_with_policy(policy).unwrap();
        let req = request(c);
        assert_eq!(core.check(req.clone()).decision, Decision::Allow);
        let snapshot = core.session_snapshot(&req.session_id, 1).unwrap();
        assert!(snapshot.graph.nodes.iter().any(|n| matches!(&n.kind, SessionGraphNodeKindSnapshot::ExecutionSemantics {semantics} if semantics.terminal_session_operations == [op])));
        core.replace_policy(PolicyConfig::default());
        let mut next = request("echo done");
        next.sequence_no = CommandSequenceNo::new(2);
        let r = core.check(next);
        assert_eq!(r.decision, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::TerminalSessionOperation)
        );
    }
}

#[test]
fn unresolved_or_multiword_inspection_operands_are_not_safe_argv_proofs() {
    for command in [
        "screen -ls $PATTERN",
        "screen -ls *",
        "screen -S $SESSION -Q info",
        "screen -S \"$SESSION\" -Q info",
        "screen -p $WINDOW -Q title",
        "screen -S first -S second -Q windows",
        "PATTERN='build -wipe'; screen -ls $PATTERN",
        "SESSION='build /bin/echo'; screen -S $SESSION -Q info",
    ] {
        assert_operation(command, TerminalSessionOperationKind::Opaque);
    }
}
