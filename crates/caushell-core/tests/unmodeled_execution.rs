//! Guard-only regressions: none of the submitted shell commands are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("unmodeled-execution"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-unmodeled-execution-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn expect(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.reasons
    );
    response
}

#[test]
fn bare_unprofiled_execution_requires_approval_even_in_a_workspace() {
    for command in [
        "rq1_unmodeled_tool --help",
        "shutdown -r now",
        "auditctl -e 0",
        "osascript -e 'display dialog \"example\"'",
    ] {
        let result = expect(command, Decision::NeedApproval);
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::NoProfile),
            "{command}"
        );
    }
}

#[test]
fn nested_unprofiled_execution_keeps_its_own_approval_requirement() {
    for command in [
        "printf data | rq1_unmodeled_tool",
        "bash -c 'rq1_unmodeled_tool'",
        "env rq1_unmodeled_tool",
        "timeout 1 rq1_unmodeled_tool",
        "printf '%s\\n' item | xargs rq1_unmodeled_tool",
        "value=$(rq1_unmodeled_tool); printf '%s' \"$value\"",
        "cat <(rq1_unmodeled_tool)",
        "bash -c 'enable -f /outside/code.so fixture'",
        "busybox httpd -f -p 12345 -h .",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn proved_local_file_authority_and_modeled_operations_remain_allowed() {
    for command in [
        "printf '%s' safe",
        "ls .",
        "true",
        ": literal",
        "set -- first second; shift; printf '%s' \"$1\"",
        "bash -c 'f() { printf safe; }; f'",
        "bash -c 'f() { value=safe; }; f'",
        "./rq1_unmodeled_tool",
        "/workspace/rq1_unmodeled_tool",
        "/tmp/rq1_unmodeled_tool",
        "/private/tmp/rq1_unmodeled_tool",
        "env ./rq1_unmodeled_tool",
        "bash -c './rq1_unmodeled_tool'",
        "printf '%s\\n' item | xargs ./rq1_unmodeled_tool",
        "python3 ./local.py",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn a_local_file_grant_does_not_cover_an_unmodeled_sibling_or_other_risks() {
    for command in [
        "./local_tool; rq1_unmodeled_tool",
        "bash -c './local_tool; rq1_unmodeled_tool'",
        "./local_tool | rq1_unmodeled_tool",
        "/outside/rq1_unmodeled_tool",
        "./local_tool > /outside/output",
        "./local_tool; rm ./victim",
        "./local_tool; python3 -c pass",
        "bash -c 'f() { rq1_unmodeled_tool; }; f'",
        "bash -c 'f() { > /outside/output; }; f'",
        ": \"$(rq1_unmodeled_tool)\"",
        "shift \"$(rq1_unmodeled_tool)\"",
        "let 'a[$(touch /outside/output)]'",
        "let 'value=1+2'",
    ] {
        expect(command, Decision::NeedApproval);
    }
    for command in [
        "./local_tool; rm -rf /",
        "rq1_unmodeled_tool; rm -rf /",
        "let 'a[$(rm -rf /)]'",
    ] {
        expect(command, Decision::Deny);
    }
}

#[test]
fn explicit_no_profile_decisions_are_not_erased_by_file_authority() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .no_profile
            .commands
            .insert("rq1_unmodeled_tool".into(), action);
        policy
            .rule_policy
            .no_profile
            .commands
            .insert("./rq1_unmodeled_tool".into(), action);
        for command in ["rq1_unmodeled_tool", "./rq1_unmodeled_tool"] {
            let result = ShellQueryCore::with_policy(policy.clone()).check(request(command, 1));
            assert_eq!(
                result.decision, expected,
                "{command} {action:?}: {:?}",
                result.reasons
            );
        }
    }
}

#[test]
fn explicit_resolve_gap_configuration_remains_effective() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .resolve_gap
            .defaults
            .insert(ResolveGapKind::NoProfile, action);
        let result = ShellQueryCore::with_policy(policy).check(request("rq1_unmodeled_tool", 1));
        assert_eq!(
            result.decision, expected,
            "{action:?}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn an_explicit_unknown_command_deny_survives_gap_and_file_authority() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.no_profile.action = RuleAction::Deny;
    policy
        .rule_policy
        .resolve_gap
        .defaults
        .insert(ResolveGapKind::NoProfile, RuleAction::Observe);
    for command in [
        "rq1_unmodeled_tool",
        "./rq1_unmodeled_tool",
        "/tmp/rq1_unmodeled_tool",
    ] {
        let result = ShellQueryCore::with_policy(policy.clone()).check(request(command, 1));
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn loaded_configuration_uses_the_same_defaults_and_explicit_overrides() {
    for (text, expected) in [
        ("", Decision::NeedApproval),
        ("{}", Decision::NeedApproval),
        (
            "policy:\n  unknown_commands:\n    default: allow",
            Decision::Allow,
        ),
        (
            "policy:\n  unknown_commands:\n    default: deny",
            Decision::Deny,
        ),
        (
            "policy:\n  resolve_gaps:\n    no_profile: allow",
            Decision::Allow,
        ),
        (
            "policy:\n  unknown_commands:\n    overrides:\n      rq1_unmodeled_tool: deny\n  resolve_gaps:\n    no_profile: allow",
            Decision::Deny,
        ),
    ] {
        let config = caushell_config::load_config_from_str(text).unwrap();
        let result =
            ShellQueryCore::with_policy(config.policy).check(request("rq1_unmodeled_tool", 1));
        assert_eq!(result.decision, expected, "{text}: {:?}", result.reasons);
    }
}

#[test]
fn downloaded_local_files_still_require_approval() {
    let mut core = ShellQueryCore::new();
    let download = core.check(request(
        "curl -q -o ./downloaded https://example.test/code",
        1,
    ));
    assert_eq!(download.decision, Decision::Allow, "{:?}", download.reasons);
    let result = core.check(request("./downloaded", 2));
    assert_eq!(
        result.decision,
        Decision::NeedApproval,
        "{:?}",
        result.reasons
    );
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::TaintedExecution)
    );
}

#[test]
fn builtin_contracts_do_not_erase_nested_execution_guards_in_other_shells() {
    for shell in [
        ShellKind::Bash,
        ShellKind::Sh,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::Powershell,
    ] {
        for command in [
            "let 'a[$(touch /outside/output)]'",
            ": \"$(rq1_unmodeled_tool)\"",
            "shift \"$(rq1_unmodeled_tool)\"",
        ] {
            let mut req = request(command, 1);
            req.shell_kind = shell;
            let response = ShellQueryCore::new().check(req);
            assert_ne!(
                response.decision,
                Decision::Allow,
                "{shell:?} {command}: {:?}",
                response.reasons
            );
        }
    }
}

#[test]
fn unprofiled_arithmetic_builtin_keeps_unknown_expression_bytes_under_approval() {
    let mut req = request("let \"$EXPR\"", 1);
    req.shell_state_before =
        req.shell_state_before
            .with_opaque_dynamic_variable("EXPR", "unobserved", false);
    let response = ShellQueryCore::new().check(req);
    assert_eq!(
        response.decision,
        Decision::NeedApproval,
        "{:?}",
        response.reasons
    );
}
