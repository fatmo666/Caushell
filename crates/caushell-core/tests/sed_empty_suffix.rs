//! Judge-only checks of the native sed separate empty suffix.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("sed-empty-suffix"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/fixture".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "judge-only".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn separate_empty_suffix_does_not_treat_slash_terminated_script_as_a_file_write() {
    let result = check("find . -name '*.fixture' -exec sed -i '' 's/old/new/' '{}' +");
    assert_eq!(result.decision, Decision::NeedApproval);
    let edit = result
        .decision_trace
        .execution_semantics
        .iter()
        .find(|entry| entry.normalized_command_name == "sed")
        .expect("sed child semantics must be preserved");
    assert_eq!(edit.form_id, "positional_in_place_split_empty_suffix");
    assert!(edit.operation_semantics_unresolved);
    let writes: Vec<_> = result
        .decision_trace
        .path_targets
        .iter()
        .filter(|path| path.operation == PathTargetOperation::Write)
        .collect();
    assert_eq!(writes.len(), 1, "{:?}", writes);
    assert_eq!(writes[0].slot_name, "input_paths");
    assert!(matches!(
        writes[0].lexical,
        PathResolution::BoundedPathSet { .. }
    ));
}

#[test]
fn existing_gnu_or_unproved_forms_keep_their_own_operand_contract() {
    for command in [
        "sed -i 's/old/new/' fixture.txt",
        "sed -i.bak 's/old/new/' fixture.txt",
        "sed -i '' 's/old/new/g' fixture.txt",
        "sed -i '' 's/old/new/' -e 's/x/y/' fixture.txt",
        "sed -i '' \"$script\" fixture.txt",
        "sed -i '' 's/old/new/' -- fixture.txt",
        "sed -i '' 's/old/new/'",
    ] {
        let result = check(command);
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| entry.form_id != "positional_in_place_split_empty_suffix"),
            "{command}: {:?}",
            result.reasons
        );
    }
}
