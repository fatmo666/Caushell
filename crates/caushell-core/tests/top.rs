//! Decision and execution-semantic checks only, never native top execution.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn check(command: &str, decision: Decision) -> CheckResponse {
    let req = CheckRequest {
        session_id: SessionId::new("top-profile"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    let r = ShellQueryCore::new().check(req);
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
    r
}
#[test]
fn explicit_batch_and_logging_queries_allow_without_interactive_findings() {
    for c in [
        "top -bn1 | grep zombie",
        "top -bn1 | sed -n '/Cpu/p'",
        "top -bn1 | grep zombie | awk '{print $4\" \"$6\" \"$8\" \"$10}'",
        "top -bn1 | sed -n '/Cpu/p' | awk '{print $2}' | sed 's/..,//'",
        "top -l1 | grep \"$APP\"",
        "top -l1 -s0 -stats mem -pid \"$PID\"",
        "top -l1 -s0 -i1 -stats vprvt -pid \"$PID\"",
        "top -l1 -s0 -stats vprvt -pid 8631",
        "top --batch-mode --iterations=1",
        "top -h",
        "top --version",
    ] {
        let r = check(c, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "top" && !s.opens_interactive_escape_surface)
        );
    }
}
#[test]
fn interaction_unknown_ownership_and_incomplete_options_still_ask() {
    for c in [
        "top",
        "top -n1",
        "top -n 1 | grep cpu",
        "top -l1 -L",
        "top -L -l1",
        "top -o -b",
        "top -pid -l",
        "top -n -b",
        "top -bn",
        "top -l",
        "top -l1 -stats",
        "top -b --future-option",
        "top -- -b",
        "top -l1 unexpected",
        "top \"$OPTIONS\"",
        "top -b $OPTIONS",
        "top -l1 -pid $PID",
    ] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn wrappers_and_nested_queries_keep_noninteractive_semantics() {
    for c in [
        "env top -bn1",
        "timeout 2s top -bn1",
        "watch -x top -bn1",
        "watch 'top -bn1 | grep cpu'",
        "sh -c 'top -l1 -stats mem'",
    ] {
        check(c, Decision::Allow);
    }
    check("watch -x top -n1", Decision::NeedApproval);
}
#[test]
fn noninteractive_modes_do_not_suppress_independent_shell_effects() {
    for c in [
        "top -bn1 > /opt/shared/top.log",
        "top -l1 > /opt/shared/top.log",
        "top -bn1; rm ./file",
        "top -h; rm ./file",
    ] {
        check(c, Decision::NeedApproval);
    }
    check("top -bn1 > ./top.log", Decision::Allow);
    check("top -bn1 > /tmp/top.log", Decision::Allow);
    check("top -bn1; rm -rf /", Decision::Deny);
}
