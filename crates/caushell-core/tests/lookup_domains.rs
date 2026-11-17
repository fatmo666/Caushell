//! Static checks: none of the command strings under test is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("lookup-domain"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/work/project")
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/work/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.reasons
    );
    response
}
#[test]
fn argv_launchers_do_not_borrow_builtin_profiles() {
    for command in [
        "env command",
        "env exit 0",
        "env cd .",
        "env return 0",
        "env read X",
        "env shift 0",
        "timeout 2 command",
        "timeout 2 exit 0",
        "nohup command",
        "nice command",
        "\\time -o time.log command",
        "command env command",
        "exec command",
        "f() { printf SAFE; }; env f",
        "env env command",
    ] {
        check(command, Decision::NeedApproval);
    }
}
#[test]
fn external_names_never_prune_the_callers_dangerous_tail() {
    for command in [
        "env exit 0; rm -rf /",
        "timeout 2 exit 0; rm -rf /",
        "exec exit 0; rm -rf /",
    ] {
        check(command, Decision::Deny);
    }
}
#[test]
fn shell_dispatch_and_real_shell_bodies_restore_builtin_lookup() {
    for command in [
        "command",
        "command command",
        "shift 0",
        "command exit 0",
        "f() { return 0; }; f",
        "env bash -c command",
        "env bash -c 'exit 0'",
        "timeout 2 bash -c command",
        "env env bash -c command",
        "command env bash -c command",
        "exec bash -c command",
        "find . -exec bash -c command \\;",
        "env parallel 'command; printf %s' ::: x",
    ] {
        check(command, Decision::Allow);
    }
}
#[test]
fn shared_and_native_profiles_remain_usable_as_external_programs() {
    for command in [
        "env printf SAFE",
        "env echo SAFE",
        "timeout 2 true",
        "env pwd",
        "env env printf SAFE",
    ] {
        check(command, Decision::Allow);
    }
}
#[test]
fn native_argv_templates_use_the_same_external_boundary() {
    for command in [
        "printf 'x\\0' | xargs -0 command",
        "find . -exec command \\;",
    ] {
        check(command, Decision::NeedApproval);
    }
    check("printf 'x\\0' | xargs -0 printf '%s'", Decision::Allow);
}

#[test]
fn shell_entry_does_not_bypass_native_argument_provenance() {
    let response = check(
        "printf 'x\\0' | xargs -0 bash -c command",
        Decision::NeedApproval,
    );
    assert!(
        response
            .reasons
            .iter()
            .any(|r| r.contains("native interpreter argument provenance is unproven"))
    );
}

#[test]
fn executable_normalization_does_not_turn_a_path_name_into_a_shell_builtin() {
    for command in [r"'C:\Windows\command.exe'", r"'C:\Windows\exit.exe' 0"] {
        check(command, Decision::NeedApproval);
    }
    check(r"'C:\Windows\exit.exe' 0; rm -rf /", Decision::Deny);
    check(r"\command", Decision::Allow);
}
