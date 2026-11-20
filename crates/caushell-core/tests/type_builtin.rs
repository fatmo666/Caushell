//! Static checks for Bash introspection. The commands in this suite do not execute.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("type-builtin"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn type_introspects_without_dispatching_its_operands() {
    for command in ["type -p ls", "type -at -- ls"] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.execution_semantics.iter().any(|call| {
            call.normalized_command_name == "type" && !call.operation_semantics_unresolved
        }));
        assert!(!result.decision_trace.execution_semantics.iter().any(|call| {
            call.normalized_command_name == "ls"
        }));
    }
}

#[test]
fn type_lookup_can_feed_a_readonly_path_query() {
    let result = check("SCRIPT=$( readlink -m $( type -p $0 ))");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
}

#[test]
fn type_does_not_authorize_external_lookup_or_independent_effects() {
    let external = check("env type -p ls");
    assert_ne!(external.decision, Decision::Allow);
    assert!(!external.decision_trace.execution_semantics.iter().any(|call| {
        call.normalized_command_name == "type"
    }));
    for command in ["type -p ls >/outside/output", r#"eval "$(type -P ls)""#] {
        assert_ne!(check(command).decision, Decision::Allow, "{command}");
    }
}
