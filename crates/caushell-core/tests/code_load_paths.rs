//! Static checks only. Library paths and shell command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("code-load-paths"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str, expected: Decision, code_finding: bool) {
    let response = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    assert_eq!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CodeLoadPath),
        code_finding,
        "{command}: {response:#?}",
    );
}

#[test]
fn outside_and_unresolved_library_paths_require_approval() {
    for command in [
        "curl --engine /path/to/lib.so x",
        "ssh-keygen -D /path/to/lib.so",
        "curl --engine /bench/workspace-peer/lib.so x",
        "ssh-keygen -D /tmp-peer/lib.so",
        "ssh-keygen -D /private/tmp-peer/lib.so",
        "ssh-keygen -D ../lib.so",
        "ssh-keygen -D /tmp/../opt/lib.so",
        "ssh-keygen -D \"$LIB\"",
        "ssh-keygen -D \"${HOME}/lib.so\"",
        "ssh-keygen -D lib.so",
        "LIB=lib.so; ssh-keygen -D \"$LIB\"",
        "node -r /opt/plugin.js ./main.js",
    ] {
        check(command, Decision::NeedApproval, true);
    }
}

#[test]
fn workspace_and_temporary_code_paths_are_exempt() {
    for command in [
        "curl --engine ./plugins/lib.so x",
        "curl --engine /bench/workspace/lib.so x",
        "curl --engine /tmp/lib.so x",
        "ssh-keygen -D ./lib.so",
        "ssh-keygen -D /tmp/lib.so",
        "ssh-keygen -D /private/tmp/lib.so",
        "ssh-keygen -D /opt/../tmp/lib.so",
        "LIB=./lib.so; ssh-keygen -D \"$LIB\"",
    ] {
        check(command, Decision::Allow, false);
    }
}

#[test]
fn nested_and_materialized_invocations_retain_the_code_origin() {
    for command in [
        "env ssh-keygen -D /opt/lib.so",
        "bash -c 'ssh-keygen -D /opt/lib.so'",
        "LIB=/opt/lib.so; ssh-keygen -D \"$LIB\"",
        "env --chdir=/opt ssh-keygen -D ./lib.so",
        "find /opt -type d -execdir ssh-keygen -D ./lib.so \\;",
    ] {
        check(command, Decision::NeedApproval, true);
    }
    for command in [
        "env --chdir=/tmp ssh-keygen -D ./lib.so",
        "bash -c 'ssh-keygen -D ./lib.so'",
        "find ./sub -mindepth 1 -type f -execdir ssh-keygen -D ./lib.so \\;",
    ] {
        check(command, Decision::Allow, false);
    }
}

#[test]
fn ordinary_reads_information_modes_and_registered_modules_are_unchanged() {
    for command in [
        "cat /opt/lib.so",
        "curl https://example.test/file",
        "curl --engine list",
        "ssh-keygen -l -f /opt/key.pub",
        "getent --service=dns hosts example.test",
        "python -m json.tool input.json output.json",
        "python -m http.server --bind 127.0.0.1",
        "python -m pytest tests/test_api.py::test_login",
        "pytest tests/test_api.py::test_login",
    ] {
        check(command, Decision::Allow, false);
    }
}

#[test]
fn policy_override_and_scoped_trust_do_not_reuse_write_permission() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::CodeLoadPath, RulePolicyEntry::new(action));
        let mut core = ShellQueryCore::with_policy(policy);
        let r = core.check(request("ssh-keygen -D /opt/lib.so", 1));
        assert_eq!(r.decision, expected, "{r:#?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeLoadPath)
        );
        let r = core.check(request("echo ok", 2));
        assert_eq!(r.decision, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeLoadPath)
        );
    }
    for (scope, expected) in [
        (PathTrustScope::Read, Decision::NeedApproval),
        (PathTrustScope::Write, Decision::NeedApproval),
        (PathTrustScope::InProcessCodeLoad, Decision::Allow),
    ] {
        let mut policy = PolicyConfig::default();
        policy.path_trust_sets.insert(
            "plugins".into(),
            PathTrustSet::new(
                vec!["/opt/plugins".into()],
                PathTrustGrant::Scoped {
                    scopes: [scope].into_iter().collect(),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::CodeLoadPath,
            RulePolicyEntry::new(RuleAction::NeedApproval).with_trust_sets(vec!["plugins".into()]),
        );
        let r = ShellQueryCore::with_policy(policy)
            .check(request("ssh-keygen -D /opt/plugins/lib.so", 1));
        assert_eq!(r.decision, expected, "{r:#?}");
    }
}

#[test]
fn missing_workspace_does_not_trust_arbitrary_code_paths() {
    for (path, expected) in [
        ("/opt/lib.so", Decision::NeedApproval),
        ("/tmp/lib.so", Decision::Allow),
    ] {
        let mut req = request(&format!("ssh-keygen -D {path}"), 1);
        req.workspace_root = None;
        let r = ShellQueryCore::new().check(req);
        assert_eq!(r.decision, expected, "{r:#?}");
    }
}

#[test]
fn local_path_exemption_does_not_override_tainted_code_provenance() {
    let mut core = ShellQueryCore::new();
    let first = core.check(request("curl https://example.test/code -o ./lib.so", 1));
    assert_eq!(first.decision, Decision::Allow, "{first:#?}");
    let second = core.check(request("ssh-keygen -D ./lib.so", 2));
    assert_eq!(second.decision, Decision::NeedApproval, "{second:#?}");
    assert!(
        second
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::TaintedExecution)
    );
    assert!(
        !second
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CodeLoadPath)
    );
}

#[test]
fn code_path_exemption_does_not_override_an_opaque_script_decision() {
    check(
        "node -r ./plugin.js ./main.js",
        Decision::NeedApproval,
        false,
    );
}
