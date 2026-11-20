//! Static judgments for the two documented samefile modes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("samefile-stdin-contract"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

#[test]
fn known_modes_read_newline_filename_records_and_leave_spill_unresolved() {
    for option in ["-r", "-g 10"] {
        let command = format!(r"printf './alpha b\n./beta\n' | samefile {option}");
        let mut core = ShellQueryCore::new();
        let outcome = core.check_with_outcome(request(&command));
        let result = outcome.response;
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        let semantics = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "samefile")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(semantics.form_id, "compare_stdin_filename_records");
        assert!(!semantics.executes_payload);
        for operation in [PathTargetOperation::Write, PathTargetOperation::Delete] {
            assert!(result.decision_trace.path_targets.iter().any(|fact| {
                fact.operation == operation
                    && matches!(fact.resolution, SemanticResolution::Unresolved { .. })
            }));
        }
        // An approval-required action never commits its planned read facts.
        let SessionStateEffect::PendingApproval(plan) = outcome.state_effect else {
            panic!("{command}: missing pending effects");
        };
        for fixture in ["/bench/workspace/alpha b", "/bench/workspace/beta"] {
            assert!(
                plan.mutations.iter().any(|mutation| matches!(
                    mutation,
                    SessionMutation::AddPathFact {
                        resolution: PathResolution::Concrete { path },
                        role: ResolvedPathRole::Read,
                        normalized_command_name: Some(name),
                        relation: SessionGraphEdgeKindSnapshot::Reads,
                        ..
                    } if path == fixture && name == "samefile"
                )),
                "{command}: missing planned read for {fixture}"
            );
        }
    }
}

#[test]
fn other_modes_and_unknown_thresholds_remain_unresolved() {
    for command in [
        "samefile",
        "samefile -g",
        "samefile -g \"$UNOBSERVED\"",
        "samefile -g -r",
        "samefile -r -g 10",
        "samefile -r --",
        "samefile -r extra",
        "samefile -0",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            !result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| { fact.form_id == "compare_stdin_filename_records" })
        );
    }
}
