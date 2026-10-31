use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("native-query-modes"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
    })
}

#[test]
fn script_information_does_not_create_a_terminal_or_log_write() {
    for command in [
        "script --help",
        "script --version",
        "script --help -c 'rm -rf /' -O /outside/log",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
    for command in [
        "script -- --help",
        "script -c '--help'",
        "script --unknown",
        "script /outside/log --help",
        "script --help > /outside/log",
    ] {
        assert_ne!(check(command).decision, Decision::Allow, "{command}");
    }
    for command in [
        "script --help; rm -rf /",
        "script --help -c \"$(rm -rf /)\"",
    ] {
        assert_eq!(check(command).decision, Decision::Deny, "{command}");
    }
}

#[test]
fn query_coverage_keeps_independent_policy_floors() {
    assert_eq!(
        check("dpkg --no-pager -L arbitrary-package").decision,
        Decision::Allow
    );
    let pager = check("dpkg -L arbitrary-package");
    assert!(
        pager
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::InteractiveEscapeSurface),
        "{pager:#?}"
    );
    for command in [
        "dpkg --no-pager -L arbitrary-package; dpkg -i package.deb",
        "git describe --tags; rm victim",
        "git ls-remote --tags https://example.test/repo.git; rm victim",
        "git ls-remote --upload-pack='sh -c id' https://example.test/repo.git",
    ] {
        assert_ne!(check(command).decision, Decision::Allow, "{command}");
    }
    for command in [
        "git describe --tags; rm -rf /",
        "dpkg --no-pager -L arbitrary-package; rm -rf /",
    ] {
        assert_eq!(check(command).decision, Decision::Deny, "{command}");
    }
    assert_ne!(
        check("git grep -h --open-files-in-pager=sh needle").decision,
        Decision::Allow
    );
}
