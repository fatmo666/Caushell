//! Static loop-value proofs. Submitted shell text is never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("loop-numeric-state"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/user".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn numeric_iteration_and_assignment_shapes_flow_without_choosing_one_value() {
    for command in [
        "for item in 2 4 8; do printf '%s\\n' \"$((item+9))\"; done",
        "for item in {2..4}; do printf '%s\\n' \"$((item*3))\"; done",
        "for item in $(seq 2 4); do printf '%s\\n' \"$((item+9))\"; done",
        "for item in 2 4; do next=$((item+1)); copied=$next; printf '%s\\n' \"$((copied*2))\"; done",
        "for left in 2 4; do for right in 3 5; do printf '%s\\n' \"$((left+right))\"; done; done",
        "bash -c 'for item; do printf \"%s\\n\" \"$((item+9))\"; done' _ 2 4 8",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(response.decision_trace.derived_invocations.iter().all(|d| {
            !d.raw_text
                .contains("shell arithmetic/index expression is unresolved")
        }));
    }
}

#[test]
fn unknown_mutated_and_post_loop_values_do_not_inherit_numeric_proofs() {
    for command in [
        "for item in $UNKNOWN; do echo $((item+1)); done",
        "for item in $(cat input); do echo $((item+1)); done",
        "for item in 2 4; do read item; echo $((item+1)); done",
        "for item in 2 4; do item=$UNKNOWN; echo $((item+1)); done",
        "for item in 2 4; do :; done; echo $((item+1))",
        "for item in 2 4; do for item in $UNKNOWN; do :; done; echo $((item+1)); done",
        "for item in 2 4; do for item in x y; do echo $((item+1)); done; done",
        "seq() { cat input; }; for item in $(seq 2 4); do echo $((item+1)); done",
        "for item in $(seq -f 'x%g' 2 4); do echo $((item+1)); done",
        "for item in $(seq -s x 2 4); do echo $((item+1)); done",
        "for item in $(seq 2.5 4.5); do echo $((item+1)); done",
        "for item in 2 4; do read -a item; echo $((item+1)); done",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn numeric_loop_proofs_never_authorize_deletion_or_hide_deny() {
    for command in [
        "for item in 2 4; do echo $((item+1)); rm /workspace/out; done",
        "for item in 2 4; do echo $((item+1)); python3 -c pass; done",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::NeedApproval
        );
    }
    for command in [
        "for item in 2 4; do echo $((item+1)); rm -rf /; done",
        "for item in $(seq 2 4); do read item; echo $((item)); rm -rf /; done",
        "for item in 2 4; do item=$(rm -rf /); echo $((item)); done",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::Deny
        );
    }
}
