//! Static checks only. No target process is launched, queried or signalled.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("process-static"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

#[test]
fn default_rule_covers_direct_unknown_and_nested_targets() {
    for command in [
        "kill 123",
        "kill -9 123",
        "kill --signal TERM 123",
        "kill \"$PID\"",
        "killall service",
        "pkill -f service",
        "fg",
        "bg",
        "fg %1",
        "bg %1",
        "env kill 123",
        "bash -c 'kill 123'",
        "printf '123\\n' | xargs kill",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl),
            "{command}"
        );
    }
}

#[test]
fn zero_signal_and_information_forms_do_not_control_processes() {
    for command in [
        "echo ok",
        "kill -0 123",
        "kill -s 0 123",
        "kill -n 0 123",
        "kill --signal=0 123",
        "kill -l",
        "kill -l TERM",
        "killall -0 service",
        "killall --signal=0 service",
        "pkill -0 -f service",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::Allow,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl)
        );
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.controls_process)
        );
    }
}

#[test]
fn configuration_preserves_findings_and_other_guards() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::ProcessControl, RulePolicyEntry::new(action));
        let r = ShellQueryCore::with_policy(policy.clone()).check(request("kill 123"));
        assert_eq!(r.decision, expected);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ProcessControl)
        );
        if action == RuleAction::Observe {
            assert_eq!(
                ShellQueryCore::with_policy(policy.clone())
                    .check(request("kill 123 > /opt/log"))
                    .decision,
                Decision::NeedApproval
            );
            assert_eq!(
                ShellQueryCore::with_policy(policy)
                    .check(request("kill 123; rm -rf /"))
                    .decision,
                Decision::Deny
            );
        }
    }
}

#[test]
fn default_job_target_is_unknown_not_a_fabricated_pid() {
    for command in ["fg", "bg"] {
        let r = ShellQueryCore::new().check(request(command));
        let s = r
            .decision_trace
            .execution_semantics
            .iter()
            .find(|s| s.normalized_command_name == command)
            .unwrap();
        assert!(s.controls_process);
        assert_eq!(
            s.process_control_target_kind,
            Some(ProcessControlTargetKind::Unknown)
        );
    }
}

#[test]
fn unknown_control_options_cannot_be_mistaken_for_probes() {
    for command in [
        "kill -0 --timeout 1000 TERM 123",
        "pkill -0 --unknown service",
        "killall -0 --unknown service",
        "kill -SIGRTMIN 123",
        "fg %1 %2",
        "bg %1 %2",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError)
        );
    }
}
