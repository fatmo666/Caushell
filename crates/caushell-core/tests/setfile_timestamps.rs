//! Static judge checks only. No SetFile command is executed by these tests.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("setfile-timestamps"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn timestamp_modes_bind_each_target_as_metadata_mutation() {
    for command in [
        "SetFile -m 06/07/2016 ./fixture-a ./fixture-b",
        "SetFile -d '09/10/2012 14:20:08' ./fixture-a ./fixture-b",
        "/usr/bin/SetFile -m 06/07/2016 -d 09/10/2012 ./fixture-a ./fixture-b",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|entry| {
                    entry.normalized_command_name == "SetFile"
                        && entry.form_id == "update_timestamps"
                        && !entry.operation_semantics_unresolved
                }),
            "{command}: {:?}",
            response.reasons
        );
        let targets = response
            .decision_trace
            .path_targets
            .iter()
            .filter_map(|fact| {
                (fact.operation == PathTargetOperation::Metadata
                    && fact.access == PathTargetAccess::Either
                    && fact.slot_name == "path_targets")
                    .then_some(fact.lexical.concrete_path())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            targets,
            [Some("/workspace/fixture-a"), Some("/workspace/fixture-b")],
            "{command}"
        );
        assert!(response.decision_trace.path_targets.iter().all(|fact| {
            !matches!(
                fact.operation,
                PathTargetOperation::Write | PathTargetOperation::Delete
            )
        }));
    }
}

#[test]
fn unknown_modes_or_operands_never_bypass_approval() {
    for command in [
        "SetFile -m 06/07/2016 /outside/fixture",
        "SetFile -m 06/07/2016 /tmp/fixture",
        "SetFile -m \"$unknown\" ./fixture",
        "SetFile -m 06/07/2016 \"$unknown\"",
        "SetFile -a v ./fixture",
        "SetFile -P -m 06/07/2016 ./fixture",
        "SetFile -m 06/07/2016 ./fixture -a v",
        "SetFile -m 06/07/2016 -- '-fixture'",
        "SetFile -m 06/07/2016",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}
