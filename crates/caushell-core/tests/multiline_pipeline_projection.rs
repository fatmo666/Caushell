//! Judge shell source only; no submitted deletion, program, or pipe runs.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    let shell = ShellStateSnapshot::new("/workspace")
        .with_variable_knowledge(ShellStateKnowledge::Complete)
        .with_alias_knowledge(ShellStateKnowledge::Complete)
        .with_function_knowledge(ShellStateKnowledge::Complete)
        .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
        .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("multiline-pipeline"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-regression".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

fn deletion_is_covered(result: &CheckResponse, expected: Decision) {
    assert_eq!(result.decision, expected, "{result:#?}");
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::FileDeletion)
    );
    let deletion = result
        .decision_trace
        .execution_units
        .iter()
        .find(|u| u.raw_text == "rm -f victim")
        .expect("independent rm execution unit");
    assert!(
        result
            .decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation == PathTargetOperation::Delete
                && p.source_node_id == deletion.node_id)
    );
    assert!(
        !result
            .decision_trace
            .execution_unit_flows
            .iter()
            .any(
                |flow| flow.from.node_id == deletion.node_id || flow.to.node_id == deletion.node_id
            )
    );
}

#[test]
fn deletion_after_multistage_pipes_is_a_separate_effect_in_every_shell_carrier() {
    for pipe in [
        "printf x | cat | head -3",
        "printf x | cat | cat | cat",
        "printf x |& cat | cat",
    ] {
        for redirect in [">out", "2>err", "2>&1"] {
            let source = format!("{pipe}\nrm -f victim\nprintf done {redirect}");
            for command in [
                source.clone(),
                format!("bash -c '{source}'"),
                format!("sh -c '{source}'"),
            ] {
                let result = check(&command);
                deletion_is_covered(&result, Decision::NeedApproval);
            }
        }
    }
}

#[test]
fn hard_deny_and_incomplete_analysis_survive_boundary_projection() {
    for body in [
        "printf x | cat | cat\nrm -rf /\nprintf done >out",
        "printf x | cat | cat\nrm -rf /\nunknown_program >out",
        "rm -rf /; printf x | cat | cat\nrm -f victim\nprintf done >out",
        "printf x | cat | cat\nrm -rf /\nprintf done >out; echo \"unterminated",
    ] {
        for command in [body.into(), format!("bash -c '{body}'")] {
            assert_eq!(check(&command).decision, Decision::Deny, "{command}");
        }
    }
    for source in [
        "printf x | cat | cat\npython3 -c pass\nprintf done >out",
        "printf x | cat | cat\nrm -f \"$UNKNOWN\"\nprintf done >out",
        "printf x | cat | cat\nprintf done >out; echo \"unterminated",
    ] {
        let result = check(source);
        assert_eq!(result.decision, Decision::NeedApproval, "{source}");
        if source.contains("unterminated") {
            assert!(
                result
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::CommandParseFailure)
            );
        }
    }
}

#[test]
fn literal_data_does_not_become_a_deletion_and_benign_pipelines_stay_allowed() {
    for source in [
        "printf x | cat | cat\nprintf done >out",
        "printf '%s' 'one\nrm -f victim' | cat | cat\nprintf done >out",
        "cat <<'EOF' | cat | cat\nrm -f victim\nEOF\nprintf done >out",
    ] {
        let result = check(source);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{source}: {:?}",
            result.reasons
        );
        assert!(
            !result
                .decision_trace
                .path_targets
                .iter()
                .any(|p| p.operation == PathTargetOperation::Delete)
        );
    }
}
