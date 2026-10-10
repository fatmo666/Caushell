//! Decision and Graph checks for grammar compatibility; never execute samples.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("shell-parameter-forms"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn benign_substring_and_implicit_loop_payloads_are_not_sent_for_approval() {
    for command in [
        "data=abc; i=0; char=$(printf \"%d\" \"'${data:$i:1}\"); echo \"$char\"",
        "f() { local data=$1; i=0; char=${data:$i:1}; echo \"$char\"; }; f abc",
        "f() { local data=$1; for ((i=0; i<${#data}; i++)); do if [ \"${data:$i:1}\" = a ]; then echo yes; fi; done; }; f abc",
        "bash -c 'for f do echo \"$f\"; done' _ a b",
        "find . -name '*.text' -exec sh -c 'for i do if [ ! -f \"${i%.text}\" ]; then echo == $i; fi;done' sh {} +",
        "bash -c 'for f do for g do echo \"$f $g\"; done; done' _ a b",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.normalized_command_name != "done")
        );
    }
}

#[test]
fn embedded_mutations_still_reach_the_existing_guard() {
    for command in [
        "echo \"${data:$i:$(touch /opt/shared/marker)}\"",
        "echo \"${data:$i + $(touch /opt/shared/marker):1}\"",
        "f() { x=${data:$i:$(touch /opt/shared/marker)}; }; f",
        "bash -c 'for f do touch /opt/shared/marker; done' _ a",
        "find . -exec sh -c 'for f do touch /opt/shared/marker; done' _ {} +",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "touch"),
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.source_pass == "outside_workspace_mutation_guard"),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn projection_is_not_an_evaluator_or_a_source_of_known_payload_bytes() {
    let response = ShellQueryCore::new().check(request(
        "f() { local data=$1; char=${data:$i:1}; eval \"$char\"; }; f abc",
    ));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    for command in [
        "echo '${data:$i:$(touch /opt/shared/marker)} for f do touch /opt/shared/marker; done'",
        "echo okay # ${data:$i:$(touch /opt/shared/marker)} for f do touch /opt/shared/marker; done",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "touch")
        );
    }
}
