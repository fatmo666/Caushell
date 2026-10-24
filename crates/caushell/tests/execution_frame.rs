#![cfg(target_os = "linux")]
#[path = "support/owned_bash_frame.rs"]
mod owned_bash_frame;
use caushell_types::*;
use owned_bash_frame::OwnedBashFrame;
use std::{fs, io::Cursor};

#[test]
fn stdio_persistence_and_restore_do_not_extend_frame_fact_lifetimes() {
    let root = std::env::temp_dir().join(format!("caushell-frame-store-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("input"), "unchanged\n").unwrap();
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let requirements = caushell_profile::execution_frame_requirements(registry.profiles());
    let owner = OwnedBashFrame::start(&work, &requirements);
    let check = |sequence: u64, attach: bool| {
        let mut request = RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("frame-restore"),
            command: "tar -cf output.tar -- input".into(),
            shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "owned-executor".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some(work.to_str().unwrap().into()),
        };
        if attach {
            request.shell_state_before.execution_frame = Some(
                ExecutionFrameObservation::collect(
                    ExecutionFrameBinding::for_request(
                        &request
                            .clone()
                            .into_check_request(CommandSequenceNo(sequence)),
                        owner.instance_id(),
                    ),
                    &requirements,
                    &owner,
                )
                .unwrap(),
            );
        }
        RuntimeTransportRequest::Check(request)
    };
    let round = |request: RuntimeTransportRequest| {
        let mut runtime =
            caushell::create_runtime(Some(&root.join("defaults.yaml")), Some(&root.join("store")))
                .unwrap();
        let input = serde_json::to_string(&request).unwrap() + "\n";
        let mut output = Vec::new();
        caushell::serve_stdio(&mut runtime, Cursor::new(input), &mut output).unwrap();
        let result: RuntimeTransportResponse = serde_json::from_slice(&output).unwrap();
        match result {
            RuntimeTransportResponse::Check(r) => r.response,
            _ => panic!(),
        }
    };
    assert_eq!(round(check(1, true)).decision, Decision::Allow);
    let stale = round(check(1, true));
    assert_eq!(stale.decision, Decision::NeedApproval);
    assert!(
        stale
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,
        EvidenceKind::ExecutionFrame(frame) if !frame.accepted))
    );
    assert_eq!(round(check(3, false)).decision, Decision::NeedApproval);
    assert_eq!(round(check(4, true)).decision, Decision::Allow);
    assert!(!work.join("output.tar").exists());
    assert_eq!(
        fs::read_to_string(work.join("input")).unwrap(),
        "unchanged\n"
    );
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejected_frame_preserves_the_proposal_receipt_and_replays_after_restart() {
    let root = std::env::temp_dir().join(format!("caushell-frame-proposal-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("input"), "unchanged\n").unwrap();
    let request = RuntimeCheckRequest {
        intent: CheckIntent::ProposeForExecution,
        session_id: SessionId::new("frame-proposal"),
        command: "tar -cf output.tar -- input".into(),
        shell_state_before: ShellStateSnapshot::new(work.to_str().unwrap()),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "owned-executor".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: None,
        workspace_root: Some(work.to_str().unwrap().into()),
    };
    let mut invalid = request.clone();
    let mut binding = ExecutionFrameBinding::for_request(
        &request.clone().into_check_request(CommandSequenceNo(1)),
        "rejected-executor",
    );
    binding.protocol = 2;
    invalid.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding,
        environment: vec![ShellEnvironmentSnapshot {
            name: "TAR_OPTIONS".into(),
            value: ShellEnvironmentValue::Absent,
        }],
        pathname: None,
    });
    let open = || {
        caushell::create_runtime(Some(&root.join("defaults.yaml")), Some(&root.join("store")))
            .unwrap()
    };
    let receipt = {
        let mut runtime = open();
        let checked = runtime
            .handle_runtime_request_with_receipt(invalid.clone())
            .unwrap();
        assert_eq!(checked.response.decision, Decision::NeedApproval);
        let receipt = checked.check_receipt.unwrap();
        assert_eq!(
            receipt.check_id,
            CheckId::for_request(&invalid.into_check_request(CommandSequenceNo(1)),)
        );
        receipt
    };
    {
        let mut runtime = open();
        let authorized = runtime
            .handle_runtime_transport_request(RuntimeTransportRequest::Authorize(ApprovalRequest {
                check_id: receipt.check_id,
                state_revision: receipt.state_revision,
                approved: false,
                authority: ApprovalAuthority::SimulatedUser,
            }))
            .unwrap();
        assert!(matches!(
            authorized,
            RuntimeTransportResponse::Authorize(ApprovalResponse {
                approved: false,
                ..
            })
        ));
    }
    assert_eq!(
        open()
            .handle_runtime_request(request.clone())
            .unwrap()
            .decision,
        Decision::NeedApproval
    );
    let mut fresh = request;
    fresh.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding: ExecutionFrameBinding::for_request(
            &fresh.clone().into_check_request(CommandSequenceNo(3)),
            "fresh-executor",
        ),
        environment: vec![ShellEnvironmentSnapshot {
            name: "TAR_OPTIONS".into(),
            value: ShellEnvironmentValue::Absent,
        }],
        pathname: None,
    });
    assert_eq!(
        open().handle_runtime_request(fresh).unwrap().decision,
        Decision::Allow
    );
    assert!(!work.join("output.tar").exists());
    fs::remove_dir_all(root).unwrap();
}
