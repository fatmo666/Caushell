//! Static admission only; no submitted Shell text is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    check_with_knowledge(command, ShellStateKnowledge::Complete)
}

fn check_with_knowledge(command: &str, knowledge: ShellStateKnowledge) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("arithmetic-for-ternary"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(knowledge),
        home: Some("/home/tester".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn native_ternary_loops_are_not_parse_failures() {
    for command in [
        "for ((i=0; i<(2>1?3:1); i++)); do echo \"$i\"; done",
        "show(){ for ((i=0; i<(2>1?3:1); i++)); do echo \"$i\"; done; }; show",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn unknown_values_and_incomplete_input_keep_approval() {
    for command in [
        "for ((i=0; i<($UNKNOWN?3:1); i++)); do echo ok; done",
        "for ((i=0; i<(flag?3:); i++)); do echo ok; done",
        "for ((i=0; i<(1?3:1); i++)); do rm /workspace/old; done",
    ] {
        let result = check_with_knowledge(command, ShellStateKnowledge::Unknown);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn branch_substitutions_function_bodies_and_independent_denies_survive() {
    for command in [
        "for ((i=0; i<(flag ? $(rm -rf /) : 3); i++)); do echo ok; done",
        "f(){ for ((i=0; i<(flag?3:4); i++)); do rm -rf /; done; }; f",
        "for ((i=0; i<(flag?3:); i++)); do echo ok; done; rm -rf /",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
    }
}
