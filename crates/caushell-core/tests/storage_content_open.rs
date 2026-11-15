//! Guard-only checks. No formatter or device command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("storage-content-open"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/auditor".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "storage-content-open".into(),
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
        .any(|f| f.enforcement_class == FindingEnforcementClass::HardDenyFloor)
}
fn resolved_target(result: &CheckResponse, path: &str) -> bool {
    result.decision_trace.path_targets.iter().any(|f| f.effect_key.starts_with("effect:")
        && matches!(&f.resolution, SemanticResolution::Resolved { value } if value.concrete_path()==Some(path)))
}

#[test]
fn proven_storage_writes_follow_descriptor_backing_targets() {
    for command in [
        "mke2fs /dev/fd/3 3<>/dev/fd0",
        "mkfs.ext2 /dev/fd/3 3<>/dev/fd0",
        "mkfs.ext3 /dev/fd/3 3<>/dev/rfd0a",
        "mkfs.ext4 /dev/fd/3 3<>/dev/fd0",
        "wipefs -a /dev/fd/3 3<>/dev/fd0",
        "wipefs --offset 0 /dev/fd/3 3<>/dev/rfd0a",
        "target=/dev/fd/3; wipefs -a \"$target\" 3<>/dev/fd0",
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
fn sfdisk_resolved_device_uses_the_existing_partition_policy() {
    for command in [
        "sfdisk --delete /dev/fd0",
        "sfdisk --delete /dev/fd/3 3<>/dev/fd0",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!floor(&result));
        assert!(
            resolved_target(&result, "/dev/fd0"),
            "{command}: {:?}",
            result.decision_trace.path_targets
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CatastrophicPartitionLayoutMutation
                    && f.message.contains("/dev/fd0")),
            "{command}: {:?}",
            result.reasons
        );
    }
    for (action, expected) in [
        (RuleAction::Deny, Decision::Deny),
        (RuleAction::Observe, Decision::Allow),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceMutation,
            RulePolicyEntry::new(RuleAction::Observe),
        );
        policy.rule_policy.rules.insert(
            RuleId::CatastrophicPartitionLayoutMutation,
            RulePolicyEntry::new(action),
        );
        for command in [
            "sfdisk --delete /dev/fd0",
            "sfdisk --delete /dev/fd/3 3<>/dev/fd0",
        ] {
            let result = ShellQueryCore::with_policy(policy.clone()).check(request(command));
            assert_eq!(result.decision, expected, "{command}: {:?}", result.reasons);
            assert!(
                !floor(&result),
                "policy decisions must not become hard floors"
            );
        }
    }
}

#[test]
fn read_only_and_preview_modes_never_acquire_a_device_destruction_floor() {
    for command in [
        "mkfs.ext4 -n /dev/fd/3 3</dev/fd0",
        "mkfs.ext4 -V /dev/fd0",
        "wipefs /dev/fd/3 3</dev/fd0",
        "wipefs -n -a /dev/fd/3 3<>/dev/fd0",
        "sfdisk --list /dev/fd/3 3</dev/fd0",
        "sfdisk --dump /dev/fd/3 3</dev/fd0",
        "sfdisk --no-act /dev/fd/3 3<>/dev/fd0",
    ] {
        let result = check(command);
        assert!(!floor(&result), "{command}: {:?}", result.reasons);
        assert_ne!(result.decision, Decision::Deny, "{command}");
    }
}

#[test]
fn regular_files_keep_workspace_scope_and_unknown_descriptors_remain_unknown() {
    for command in ["wipefs -a image", "wipefs -a /dev/fd/3 3<>image"] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!floor(&result));
    }
    for command in [
        "wipefs -a /outside/image",
        "wipefs -a /dev/fd/3",
        "mkfs.ext4 /dev/fd/3",
        "sfdisk --delete /dev/fd/3",
        "mkfs.ext4 /dev/fd/3 3<>image",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!floor(&result));
    }
}

#[test]
fn auxiliary_outputs_and_helpers_cannot_borrow_the_main_target_scope() {
    for command in [
        "mkfs.ext4 image",
        "mkfs.ext4 -n image",
        "mkfs.ext4 -c /dev/fd/3 3<>image",
        "mkfs.ext4 -J device=/outside/journal /dev/fd/3 3<>image",
        "mkfs.ext4 -z /outside/undo /dev/fd/3 3<>image",
        "mkfs.ext4 -n -z /outside/undo /dev/fd/3 3<>image",
        "wipefs -a -b /dev/fd/3 3<>image",
        "wipefs -n -a -b /dev/fd/3 3<>image",
        "sfdisk --delete -b /dev/fd/3 3<>image",
        "sfdisk --backup-pt-sectors /dev/fd/3 3<image",
        "sfdisk --delete -O /outside/prefix /dev/fd/3 3<>image",
        "sfdisk --backup-pt-sectors -O prefix image",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!floor(&result));
    }
}

#[test]
fn generic_backends_literal_data_and_independent_denials_keep_their_boundaries() {
    for command in [
        "mkfs -t ext4 /dev/fd/3 3<>image",
        "mkfs.unreviewed /dev/fd/3 3<>image",
        "mkfs.ext4 --unreviewed-control /dev/fd/3 3<>image",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!floor(&result));
    }
    assert!(!floor(&check("mkfs.ext4 -M /dev/fd0 image")));
    let result = check("mkfs.ext4 -n image; rm -rf /");
    assert_eq!(result.decision, Decision::Deny);
    assert!(floor(&result));
}
