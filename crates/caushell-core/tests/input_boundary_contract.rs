//! Static analysis only; none of the submitted shell text is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("input-boundaries"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn record_framing_changes_native_targets_not_the_producer_path_spelling() {
    let split = ShellQueryCore::new().check(request(
        "printf '%s\\n' './input/part\n/outside/result' | xargs -n1 cp -- source",
    ));
    assert_eq!(split.decision, Decision::NeedApproval, "{split:#?}");
    assert!(
        split.decision_trace.path_targets.iter().any(|p| {
            matches!(&p.lexical, PathResolution::Concrete { path } if path == "/outside/result")
                && p.operation == PathTargetOperation::Write
        }),
        "{split:#?}"
    );
    let preserved = ShellQueryCore::new().check(request(
        "printf '%s\\0' './input/part\n/outside/result' | xargs -0 -n1 cp -- source",
    ));
    assert_eq!(preserved.decision, Decision::Allow, "{preserved:#?}");
    assert!(preserved.decision_trace.path_targets.iter().any(|p| {
        matches!(&p.lexical, PathResolution::Concrete { path } if path == "/workspace/input/part\n/outside/result")
            && p.operation == PathTargetOperation::Write
    }), "{preserved:#?}");
}

#[test]
fn unknown_directory_output_remains_incomplete_without_an_output_proof() {
    let r = ShellQueryCore::new().check(request("find ./input -name result | xargs -n1 cp source"));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "cp" && s.operation_semantics_unresolved)
    );
}

#[test]
fn named_option_environment_evidence_does_not_clear_glob_uncertainty() {
    let mut r = request("tar -cf output.tar *");
    r.shell_state_before = r
        .shell_state_before
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    let r = ShellQueryCore::new().check(r);
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.reason.contains("argument region ownership is unresolved"))
    );
    assert!(!r.decision_trace.decision_proposals.iter().any(|p| {
        p.reason
            .contains("TAR_OPTIONS option environment is not observed")
    }));
}

#[test]
fn missing_named_environment_evidence_remains_unknown() {
    let r = ShellQueryCore::new().check(request("tar -cf output.tar -- input"));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(r.decision_trace.decision_proposals.iter().any(|p| {
        p.reason
            .contains("TAR_OPTIONS option environment is not observed")
    }));
    let mut r = request("tar -cf output.tar -- input");
    r.shell_state_before = r
        .shell_state_before
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    let r = ShellQueryCore::new().check(r);
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
}

fn runtime(command: &str) -> RuntimeCheckRequest {
    let r = request(command);
    RuntimeCheckRequest {
        intent: CheckIntent::ProposeForExecution,
        session_id: r.session_id,
        command: r.command,
        shell_state_before: r.shell_state_before,
        shell_kind: r.shell_kind,
        runtime: r.runtime,
        home: r.home,
        workspace_root: r.workspace_root,
    }
}

#[test]
fn later_missing_observation_cannot_resurrect_a_conflicting_environment_value() {
    for value in [
        ShellEnvironmentValue::Absent,
        ShellEnvironmentValue::Unknown,
        ShellEnvironmentValue::Present {
            value: "--checkpoint=1".into(),
        },
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(
            core.check_runtime(runtime("export TAR_OPTIONS=--verbose"))
                .decision,
            Decision::Allow
        );
        let mut r = runtime("true");
        r.intent = CheckIntent::JudgeOnly;
        r.shell_state_before = r
            .shell_state_before
            .with_environment_observation("TAR_OPTIONS", value);
        core.check_runtime(r);
        let snapshot = core
            .session_snapshot(&SessionId::new("input-boundaries"), 0)
            .unwrap();
        assert!(matches!(
            snapshot
                .summary
                .variable_binding("TAR_OPTIONS")
                .unwrap()
                .value,
            SessionVariableValue::OpaqueDynamic { .. }
        ));
        let mut restored = ShellQueryCore::new();
        restored.insert_session_state(
            SessionId::new("input-boundaries"),
            caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
        );
        let after_restore = restored.check_runtime(runtime("tar -cf output.tar -- input"));
        assert_eq!(
            after_restore.decision,
            Decision::NeedApproval,
            "{after_restore:#?}"
        );
        let r = core.check_runtime(runtime("tar -cf output.tar -- input"));
        assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    }
}

#[test]
fn explicit_sequence_api_reconciles_named_observations_too() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request("export TAR_OPTIONS=--verbose")).decision,
        Decision::Allow
    );
    let mut observed = request("true");
    observed.sequence_no = CommandSequenceNo(2);
    observed.shell_state_before = observed
        .shell_state_before
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    core.try_check_with_intent(observed, CheckIntent::JudgeOnly)
        .unwrap();
    let snapshot = core
        .session_snapshot(&SessionId::new("input-boundaries"), 0)
        .unwrap();
    assert!(matches!(
        snapshot
            .summary
            .variable_binding("TAR_OPTIONS")
            .unwrap()
            .value,
        SessionVariableValue::OpaqueDynamic { .. }
    ));
    let mut next = request("tar -cf output.tar -- input");
    next.sequence_no = CommandSequenceNo(3);
    assert_eq!(core.check(next).decision, Decision::NeedApproval);
}
