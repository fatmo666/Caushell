//! Static checks for the execution identity of a mode-modified file.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("set-id-execution"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/fixture".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

fn has_privilege_boundary(result: &CheckResponse) -> bool {
    result
        .decision_trace
        .findings
        .iter()
        .any(|finding| finding.rule_id == RuleId::PrivilegeBoundary)
}

#[test]
fn explicit_set_id_then_execution_of_same_file_requires_approval() {
    for command in [
        "chmod u+s ./fixture-note\n./fixture-note",
        "chmod 2600 ./fixture-note; /bench/workspace/fixture-note",
        "chmod a=rs,g-s ./fixture-note; ./fixture-note",
    ] {
        let result = check(command);
        assert!(
            has_privilege_boundary(&result),
            "{command}: {:?}",
            result.reasons
        );
        assert_ne!(result.decision, Decision::Allow, "{command}");
        assert!(result.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Metadata
                && target.metadata_mutation.as_ref().is_some_and(|mutation| {
                    mutation
                        .mutation_kinds
                        .contains(&PathMetadataMutationKind::ChangeMode)
                })
        }));
    }
}

#[test]
fn other_modes_and_unpaired_file_effects_do_not_create_a_privilege_finding() {
    for command in [
        "chmod u+s ./fixture-note",
        "chmod 1600 ./fixture-note; ./fixture-note",
        "chmod g-s ./fixture-note; ./fixture-note",
        "chmod u+s,u-s ./fixture-note; ./fixture-note",
        "chmod u+s,u=rw ./fixture-note; ./fixture-note",
        "chmod o+s ./fixture-note; ./fixture-note",
        "chmod u+s ./fixture-note; ./other-note",
        "./fixture-note; chmod u+s ./fixture-note",
        "chmod u+s ./fixture-note; chmod u-s ./fixture-note; ./fixture-note",
        "chmod u+s ./fixture-note & ./fixture-note",
    ] {
        let result = check(command);
        assert!(
            !has_privilege_boundary(&result),
            "{command}: {:?}",
            result.reasons
        );
    }
}
