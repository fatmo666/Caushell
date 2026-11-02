//! Static checking only; none of the submitted commands is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("time-numeric-argv"),
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
fn observed(
    command: &str,
    integer: bool,
    variant: Option<&str>,
    ifs: ShellEnvironmentValue,
) -> CheckRequest {
    let mut r = request(command);
    r.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding: ExecutionFrameBinding::for_request(&r, "owner"),
        environment: vec![],
        pathname: None,
        variables: vec![
            ShellEnvironmentSnapshot {
                name: "SECONDS".into(),
                value: ShellEnvironmentValue::Unknown,
            },
            ShellEnvironmentSnapshot {
                name: "IFS".into(),
                value: ifs,
            },
        ],
        variable_values: Vec::new(),
        integer_variables: if integer {
            ["SECONDS".into()].into()
        } else {
            Default::default()
        },
        native_variants: variant
            .map(|v| [("date".into(), v.into())].into())
            .unwrap_or_default(),
    });
    r
}
fn check(r: CheckRequest, expected: Decision) -> CheckResponse {
    let source = r.command.clone();
    let result = ShellQueryCore::new().check(r);
    assert_eq!(result.decision, expected, "{source}: {:?}", result.reasons);
    result
}

#[test]
fn volatile_integer_proof_flows_without_a_concrete_value() {
    for command in [
        "start=$SECONDS; echo $((SECONDS-start))",
        "snapshot=$SECONDS; copied=$snapshot; printf '%s' \"$((copied+1))\"",
    ] {
        check(
            observed(command, true, None, ShellEnvironmentValue::Absent),
            Decision::Allow,
        );
        check(
            observed(command, false, None, ShellEnvironmentValue::Absent),
            Decision::NeedApproval,
        );
    }
    for command in [
        "unset SECONDS; SECONDS=$untrusted; echo $((SECONDS))",
        "read SECONDS; echo $((SECONDS))",
        "SECONDS=$untrusted; echo $((SECONDS))",
        "start=$SECONDS; bash -c 'echo $((start))'",
    ] {
        check(
            observed(command, true, None, ShellEnvironmentValue::Absent),
            Decision::NeedApproval,
        );
    }
}

#[test]
fn native_nanosecond_shape_requires_a_matching_current_executor_contract() {
    for command in [
        "start=$(date +%s%N); echo $((start+1))",
        "start=$(date +%s%N); end=$(date +%s%N); echo $((end-start))",
    ] {
        check(
            observed(
                command,
                false,
                Some("gnu_coreutils"),
                ShellEnvironmentValue::Absent,
            ),
            Decision::Allow,
        );
        for variant in [None, Some("bsd")] {
            check(
                observed(command, false, variant, ShellEnvironmentValue::Absent),
                Decision::NeedApproval,
            );
        }
    }
    for command in [
        "start=$(PATH=/unknown date +%s%N); echo $((start))",
        "start=$(/outside/date +%s%N); echo $((start))",
        "date() { echo \"$unknown\"; }; start=$(date +%s%N); echo $((start))",
        "PATH=/unknown; start=$(date +%s%N); echo $((start))",
        "cd /outside; start=$(date +%s%N); echo $((start))",
        "ignored=$(touch /workspace/date); start=$(date +%s%N); echo $((start))",
        "ignored=1 >/workspace/date; start=$(date +%s%N); echo $((start))",
        "arbitrary_unknown_command; start=$(date +%s%N); echo $((start))",
    ] {
        check(
            observed(
                command,
                false,
                Some("gnu_coreutils"),
                ShellEnvironmentValue::Absent,
            ),
            Decision::NeedApproval,
        );
    }
}

#[test]
fn integer_loop_members_prove_awk_assignment_width_with_observed_ifs() {
    for command in [
        "for member in 2 4 8; do awk -v R=$member 'BEGIN { print R }'; done",
        "for member in 3 9; do copied=$member; awk -v R=$copied 'BEGIN { print R }'; done",
        "for member in 3 9; do next=$((member+1)); awk -v R=$next 'BEGIN { print R }'; done",
    ] {
        check(
            observed(command, false, None, ShellEnvironmentValue::Absent),
            Decision::Allow,
        );
        check(
            observed(
                command,
                false,
                None,
                ShellEnvironmentValue::Present { value: "3".into() },
            ),
            Decision::NeedApproval,
        );
        check(
            observed(command, false, None, ShellEnvironmentValue::Unknown),
            Decision::NeedApproval,
        );
    }
    for command in [
        "for member in 2 4; do read member; awk -v R=$member 'BEGIN { print R }'; done",
        "for member in 2 4; do member=$unknown; awk -v R=$member 'BEGIN { print R }'; done",
        "for member in 2 4; do :; done; awk -v R=$member 'BEGIN { print R }'",
    ] {
        check(
            observed(command, false, None, ShellEnvironmentValue::Absent),
            Decision::NeedApproval,
        );
    }
}

#[test]
fn facts_and_entry_coverage_never_supply_authority() {
    for command in [
        "start=$SECONDS; echo $((start)); rm /workspace/out",
        "pip download package-a -d /workspace/dist --no-deps",
        "pip wheel /workspace -w /workspace/dist",
        "pip config set global.timeout 10",
        "pip config unset global.timeout",
        "for member in 2 4; do awk -v R=$member 'BEGIN {system(R)}'; done",
    ] {
        check(
            observed(
                command,
                true,
                Some("gnu_coreutils"),
                ShellEnvironmentValue::Absent,
            ),
            Decision::NeedApproval,
        );
    }
    for command in [
        "start=$SECONDS; rm -rf /",
        "pip download package-a --unknown; rm -rf /",
        "for member in 2 4; do awk -v R=$member 'BEGIN {print R}'; rm -rf /; done",
    ] {
        check(
            observed(
                command,
                true,
                Some("gnu_coreutils"),
                ShellEnvironmentValue::Absent,
            ),
            Decision::Deny,
        );
    }
}
