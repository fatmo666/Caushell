//! JudgeOnly checks for Bash arithmetic passed to let.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("bash-let-arithmetic"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn direct_let_uses_existing_arithmetic_analysis() {
    for command in [
        "index=0; let index=index+2",
        "index=1; let 'index=index*2'",
        "work() { local index=0; let index=index+2; }; work",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|entry| {
                    entry.normalized_command_name == "let"
                        && entry.form_id == "evaluate_arithmetic"
                        && !entry.operation_semantics_unresolved
                })
        );
    }
}

#[test]
fn unknown_arguments_and_unproved_lookup_routes_still_require_approval() {
    for command in [
        "let \"$unobserved\"",
        "builtin let \"$unobserved\"",
        "command let \"$unobserved\"",
        "env let index=index+2",
        "name=let; \"$name\" index=index+2",
        "/usr/local/bin/let index=index+2",
        "index=0 let index=index+2",
        "index=0; let index=index+2 > /outside/fixture.txt",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn matching_function_keeps_its_own_body() {
    let result = check("let() { printf '%s' \"$1\"; }; let fixture");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    assert!(
        result
            .decision_trace
            .execution_semantics
            .iter()
            .any(|entry| { entry.normalized_command_name == "printf" })
    );
}
