//! Static policy checks. These fixtures never query the machine's registry.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("ioreg-properties"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn ioreg_property_listing_is_a_host_inspection() {
    for command in [
        "ioreg -l",
        "/usr/sbin/ioreg -l",
        "if (ioreg -l | grep fixture) then printf ok; fi;",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let inspection = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "ioreg")
            .expect("expected I/O Registry inspection");
        assert_eq!(inspection.form_id, "list_properties");
        assert_eq!(inspection.state_operations.len(), 1);
        assert_eq!(
            inspection.state_operations[0].domain,
            StateOperationDomain::HostIdentity
        );
        assert_eq!(
            inspection.state_operations[0].operation,
            StateOperationKind::Inspect
        );
        assert!(!inspection.executes_payload);
    }
}

#[test]
fn listing_preserves_shell_writes_and_execution_boundaries() {
    let output = check("ioreg -l > ./fixture.txt");
    assert_eq!(output.decision, Decision::Allow);
    assert!(output.decision_trace.path_targets.iter().any(|target| {
        target.operation == PathTargetOperation::Write
            && target.lexical.concrete_path() == Some("/bench/workspace/fixture.txt")
    }));
    for command in [
        "ioreg",
        "ioreg -l -p IOService",
        "ioreg -l --",
        "ioreg -l ./operand",
        "ioreg -l > /opt/shared/fixture.txt",
        "ioreg -l | sh",
        "sudo ioreg -l",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}
