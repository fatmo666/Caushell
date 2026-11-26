//! Decision and execution-semantic checks only, never native top execution.
use caushell_core::ShellQueryCore;
use caushell_types::*;
use std::collections::BTreeMap;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
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
    }
}

fn check(command: &str, decision: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
    r
}

#[test]
fn protected_procps_lookup_enables_only_proven_single_frame_queries() {
    use Decision::{Allow, NeedApproval};

    for (command, variant, expected) in [
        ("top -n 1", Some("procps_ng"), Allow),
        ("watch -d 'top -n1 | grep fixture'", Some("procps_ng"), Allow),
        ("top -n 2", Some("procps_ng"), NeedApproval),
        ("top -n \"$FRAMES\"", Some("procps_ng"), NeedApproval),
        ("top -n1 -n2", Some("procps_ng"), NeedApproval),
        ("PATH=./bin:$PATH top -n1", Some("procps_ng"), NeedApproval),
        ("top -n1", Some("busybox"), NeedApproval),
        ("top -n1", None, NeedApproval),
    ] {
        let mut req = request(command);
        req.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::request_only();
        let inventory: BTreeMap<_, _> = variant
            .map(|variant| ("top".into(), variant.into()))
            .into_iter()
            .collect();
        let response = ShellQueryCore::new()
            .try_judge_static_shell_with_native_variants(req, &inventory)
            .unwrap();
        assert_eq!(response.decision, expected, "{command} [{variant:?}]");
    }
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
fn batch_process_query_accepts_split_decimal_pid_output() {
    for command in [
        "top -b -p $(pidof fixture)",
        "top -b -p `pidof fixture` -n 2",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "top -p $(pidof fixture)",
        "top -b -p $(pidof --help)",
        "top -b -p $(pidof -S text fixture)",
        "top -b -p $(seq -1 1)",
        "top -b -p $(pidof fixture) --unknown",
        "top -b -p $(pidof fixture) > /opt/fixture.log",
        "top -b -p $(pidof fixture) > /tmp/fixture.log",
        "XDG_CONFIG_HOME=/opt/fixture top -b -p $(pidof fixture)",
    ] {
        check(command, Decision::NeedApproval);
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
