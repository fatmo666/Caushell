//! Guard-only checks. Never open, create, format or write a real device.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("raw-device-regression"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "raw-device-regression".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
}
fn floor(result: &CheckResponse) -> bool {
    result
        .decision_trace
        .findings
        .iter()
        .any(|p| p.enforcement_class == FindingEnforcementClass::HardDenyFloor)
}

#[test]
fn raw_storage_write_sinks_share_the_device_family_classifier() {
    for command in [
        "dd if=payload.img of=/dev/fd0",
        "dd of=/dev/rfd0a if=payload.img",
        "cp payload.img /dev/fd6",
        "tee /dev/rfd1a",
        "mkfs.ext4 /dev/fd0u1440",
        "wipefs -a /dev/rfd0a",
        "shred /dev/fd1",
        "printf data > /dev/fd0",
        "printf data >> /dev/rfd0",
        "printf data > /dev/../dev/fd0",
        "cd /dev; printf data > fd0",
        "env dd if=payload of=/dev/fd0",
        "bash -c 'printf data > /dev/rfd0a'",
        "tee /dev/fd/3 3<>/dev/fd0",
        "dd of=/dev/fd/3 if=payload 3<>/dev/rfd0",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
        assert!(floor(&result), "{command}");
    }
}

#[test]
fn original_archive_cases_retain_a_raw_device_denial_despite_other_uncertainty() {
    for command in [
        "find . -cpio /dev/fd0 -print | tee /tmp/BACKUP.LOG",
        "find / -user edwarda -print | cpio -ovBc > /dev/rfd0",
        "find . -name nameoffile -print | cpio -iv > /dev/fd0",
        "find . -depth -print | cpio -ov > /dev/fd0",
    ] {
        let mut req = request(command);
        req.shell_state_before.observability = ShellStateObservability::default();
        let result = ShellQueryCore::new().check(req);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
        assert!(floor(&result));
    }
}

#[test]
fn patterns_and_brace_alternatives_preserve_a_dangerous_member() {
    for command in [
        "printf data > /dev/fd[4-7]",
        "wipefs -a /dev/rfd[1-3]a",
        "tee /dev/fd{0,6}",
        "printf data > /dev/fd0u14??",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
        assert!(floor(&result));
    }
}

#[test]
fn device_reads_and_informational_data_do_not_become_raw_writes() {
    for command in [
        "cat /dev/fd0",
        "dd if=/dev/rfd0a",
        "cat < /dev/fd0",
        "fdisk -l /dev/fd0",
        "wipefs /dev/fd0",
        "printf '%s' /dev/fd0",
        "cat /dev/fd/3 3<>/dev/fd0",
    ] {
        let result = check(command);
        assert!(!floor(&result), "{command}: {:?}", result.reasons);
    }
}

#[test]
fn descriptor_channels_and_regular_filename_shapes_keep_their_other_guards() {
    for command in [
        "printf data > /dev/stdout",
        "printf data > /dev/fd/1",
        "dd if=payload of=/dev/fd0.img",
        "tee /dev/rfd0.backup",
        "printf data > fd0.img",
        "printf data > /dev/fd0u9999",
        "printf data > '/dev/fd[4-7]'",
        "touch /dev/fd0",
        "chmod 600 /dev/fd0",
        "wipefs /dev/fd/3 3<>/dev/fd0",
    ] {
        let result = check(command);
        assert!(!floor(&result), "{command}: {:?}", result.reasons);
    }
    let result = check("tee /dev/rfd0.backup; rm -rf /");
    assert_eq!(result.decision, Decision::Deny);
    assert!(floor(&result));
}

#[test]
fn dynamic_targets_keep_uncertainty_and_observed_device_names_keep_denial() {
    let mut req = request("printf data > \"$target\"");
    req.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let result = ShellQueryCore::new().check(req);
    assert_eq!(result.decision, Decision::NeedApproval);
    assert!(!floor(&result));
    for command in [
        "target=/dev/fd0; printf data > \"$target\"",
        "target=/dev/rfd0a; printf data >> \"$target\"",
        "target=/dev/sda; printf data > \"$target\"",
        "target=/dev/fd0; tee \"$target\"",
        "target=/dev/fd0; dd if=payload of=\"$target\"",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "{command}: {:?}",
            result.reasons
        );
        assert!(floor(&result));
    }
    for command in [
        "target=/dev/fd0; cat < \"$target\"",
        "target=/dev/fd0; cat <> \"$target\"",
        "target=/dev/fd/3; printf data > \"$target\"",
        "target=out; printf data > \"$target\"",
        "target=/dev/fd0.img; printf data > \"$target\"",
        "target=/dev/fd0; target=out; printf data > \"$target\"",
        "target='/dev/fd[4-7]'; printf data > \"$target\"",
        "target=/dev/fd0; cat \"$target\"; printf data > out",
    ] {
        let result = check(command);
        assert!(!floor(&result), "{command}: {:?}", result.reasons);
    }
}
