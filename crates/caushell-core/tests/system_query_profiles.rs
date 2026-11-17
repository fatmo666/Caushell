//! Judge only. Never execute original benchmark command strings.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("system-query-profiles"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn reviewed_queries_use_registered_native_semantics() {
    for command in [
        "uptime", "uptime --pretty", "uptime -s", "free", "free -h", "free --bytes --total",
        "vmstat", "vmstat --stats", "vmstat -S M", "netstat", "netstat --statistics",
        "netstat -i", "netstat -nr", "netstat -rn", "netstat -an", "locale", "locale -a",
        "locale -ck LC_TIME", "ipcs -mb", "ipcs -a", "ipcs -m -i 42", "lsmod", "lsmod --help",
        "lscpu", "lscpu --json", "command uptime", "/usr/bin/free -m",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn unsupported_modes_do_not_inherit_query_effects() {
    for command in [
        "uptime /opt/shared/utmp", "free --output=/opt/shared/out", "vmstat 1", "vmstat 1 2",
        "netstat -M /opt/shared/core", "netstat -N /opt/shared/kernel", "lsmod -s",
        "lscpu --sysroot=/opt/shared/root", "ipcs -C /opt/shared/core",
        "locale --output=/opt/shared/out", "free $OPTIONS", "netstat $OPTIONS", "lsmod load module",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
}

#[test]
fn query_profiles_do_not_weaken_write_delete_or_execution_guards() {
    for command in [
        "uptime > /opt/shared/out", "free > /opt/shared/out", "vmstat > /opt/shared/out",
        "netstat -rn > /opt/shared/out", "locale > /opt/shared/out", "ipcs > /opt/shared/out",
        "lsmod > /opt/shared/out", "lscpu > /opt/shared/out", "locale | sh",
        "netstat -rn | sh", "uptime; rm -f /workspace/cache", "free; eval \"$PAYLOAD\"",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
}

#[test]
fn repeated_queries_preserve_unbounded_output_guard() {
    for command in ["free -s 1 > memory.log", "netstat --continuous > network.log"] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
    for command in ["free -s 1 -c 2 > memory.log", "free > memory.log", "vmstat > memory.log"] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn query_output_does_not_claim_unproved_variable_or_argv_shapes() {
    for command in ["unset $(locale | cut -d= -f1)", "find $(lscpu) -delete", "locale | xargs sh -c"] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
}
