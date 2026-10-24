#![cfg(target_os = "linux")]
#[path = "../../caushell/tests/support/frame_adapter_roundtrip.rs"]
mod support;
use caushell_types::{Decision, EvidenceKind};

fn run(
    command: &str,
    attach: bool,
    model_only: bool,
    invalid: bool,
) -> caushell_types::CheckResponse {
    support::roundtrip(
        "codex",
        command,
        attach,
        model_only,
        invalid,
        |socket, input, output| {
            caushell_adapter_codex::run_pretooluse(
                socket,
                caushell_adapter_codex::CodexNeedApprovalMode::Block,
                input,
                output,
            )
            .unwrap()
        },
    )
}

#[test]
fn real_executor_observations_cross_adapter_socket_runtime_and_profiles() {
    for command in [
        "find . -iname '*.DATA' | xargs -n1 cat",
        "tar -cf out.tar -- *",
    ] {
        assert_eq!(
            run(command, false, false, false).decision,
            Decision::NeedApproval
        );
        let r = run(command, true, false, false);
        assert_eq!(r.decision, Decision::Allow, "{r:#?}");
        assert!(r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::ExecutionFrame(frame) if frame.accepted)));
    }
}

#[test]
fn tool_input_cannot_supply_observations_and_invalid_frames_do_not_authorize() {
    assert_eq!(
        run("tar -cf out.tar -- *", false, true, false).decision,
        Decision::NeedApproval
    );
    assert_eq!(
        run("printf ok", true, false, true).decision,
        Decision::NeedApproval
    );
}

#[test]
fn script_approval_and_deny_survive_the_complete_observation_path() {
    for command in [
        "python3 -c pass",
        "tar -cf out.tar --checkpoint=1 --checkpoint-action='exec=python3 -c pass' -- report.data",
    ] {
        assert_eq!(
            run(command, true, false, false).decision,
            Decision::NeedApproval
        );
    }
    for invalid in [false, true] {
        assert_eq!(
            run("rm -rf /", true, false, invalid).decision,
            Decision::Deny
        );
    }
}
