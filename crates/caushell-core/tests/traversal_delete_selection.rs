//! Static requests only; no fixture shell string is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, decision: Decision) {
    let request = CheckRequest {
        session_id: SessionId::new("selection-proof"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    };
    let response = ShellQueryCore::new().check(request);
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
}

#[test]
fn selected_deletion_is_approval_not_a_whole_tree_deny() {
    for command in [
        "find / -name '*.core' -exec rm {} \\;",
        "find / -name '*.old' -delete",
        "find / -user alice -exec rm {} +",
        "find / -size +100M -exec rm -rf {} +",
        "find / -name core -exec sh -c 'rm \"$1\"' _ {} \\;",
        "find /etc -path '/etc/*' -exec sh -c 'rm -rf $1' sh {} \\;",
        "find . -name '*.old' -delete",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn unrelated_fixed_and_nested_targets_do_not_inherit_root_destruction() {
    for command in [
        "find / -name core -exec rm ./cache/local \\;",
        "find / -exec rm ./cache/local \\;",
        "find / -exec sh -c 'rm ./cache/local' _ {} \\;",
        "find / -exec sh -c 'find ./cache -type f -exec rm {} +' \\;",
        "find / -exec rm '{}.bak' \\;",
        "find / -execdir rm ./cache/local \\;",
        "fd . / -x rm -rf {}",
        "fd . / -X rm -rf {}",
        "fd . / -x rm ./cache/local",
        "find /etc -type f -exec rename foo bar {} \\;",
        "rename foo bar /opt/shared/file",
        "rename 's/foo/bar/' ./cache/file",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn whole_tree_and_explicit_catastrophic_targets_keep_hard_deny() {
    for command in [
        "rm -rf /",
        "find / -delete",
        "find / -type f -exec rm {} +",
        "find / -exec rm {} +",
        "find / -type f -execdir rm {} +",
        "find /etc/* -type f -exec rm {} +",
        "fd . / -x rm -rf /",
        "find . -name core -exec rm -rf / \\;",
        "find / -name core -exec rm -rf /etc \\;",
        "bash -c 'find / -type f -exec rm {} +'",
        "find / -type f -exec sh -c 'rm \"$1\"' _ {} \\;",
        "find /dev -maxdepth 1 -type b -name 'sd?' -exec mkfs.ext4 -F {} +",
    ] {
        check(command, Decision::Deny);
    }
}
