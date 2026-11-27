//! Judge the parsed commands only. The files and tools are never invoked.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn judge(command: &str, native_grep: bool) -> CheckResponse {
    let mut request = CheckRequest {
        session_id: SessionId::new("sed-decimal-addresses"),
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
    };
    if native_grep {
        request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
            binding: ExecutionFrameBinding::for_request(&request, "owner"),
            environment: Vec::new(),
            pathname: None,
            variables: Vec::new(),
            variable_values: Vec::new(),
            integer_variables: Default::default(),
            native_variants: [("grep".into(), "gnu_grep_3_5_or_newer".into())].into(),
        });
    }
    ShellQueryCore::new().check(request)
}

#[test]
fn decimal_records_only_change_the_print_address() {
    for command in [
        "sed -n \"$(grep -n marker input | head -1 | cut -d: -f1),+6p\" input",
        "sed -n \"$(grep -n marker input | cut --delimiter : --fields 1),20p\" input",
    ] {
        let result = judge(command, true);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let result = judge(command, false);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn field_and_consumer_checks_stay_separate() {
    for command in [
        "sed -n \"$(grep -H -n marker input | cut -d: -f1),+6p\" input",
        "sed -n \"$(grep -n marker input | cut -d: -f2),+6p\" input",
        "sed -n \"$(grep -n marker input | cut -d: -f1),+6p\" $file",
        "sed -i \"$(grep -n marker input | cut -d: -f1),+6p\" input",
    ] {
        let result = judge(command, true);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}
