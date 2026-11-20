//! Judgment-only checks for stdout creation without a member list.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    StreamInputMode, resolve_invocation,
};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuntimeMetadata, SessionId, ShellEnvironmentValue,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str, options: Option<ShellEnvironmentValue>) -> caushell_types::CheckResponse {
    let mut state = ShellStateSnapshot::new("/workspace/project");
    if let Some(options) = options {
        state = state.with_environment_observation("TAR_OPTIONS", options);
    }
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("tar-stdout-no-members"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: state,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-tar-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn stdout_creation_without_members_has_no_implicit_input_list() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["tar cf -", "tar -cf -", "tar --create --file=-"] {
        let result = check(command, Some(ShellEnvironmentValue::Absent));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}");
        };
        assert_eq!(
            resolved.bound.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DeclaredEffects,
        );
        assert!(
            !resolved
                .bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ConsumeStdin)
        );
    }
}

#[test]
fn unobserved_tar_options_remain_an_approval_reason() {
    for command in ["tar cf -", "tar -cf -", "tar --create --file=-"] {
        let result = check(command, None);
        assert_eq!(result.decision, Decision::NeedApproval);
        assert!(
            result.reasons.iter().any(|reason| {
                reason.contains("TAR_OPTIONS option environment is not observed")
            }),
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn files_from_and_non_stdout_modes_keep_their_existing_boundaries() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("tar -cf - -T -", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!("explicit member list must bind");
    };
    assert!(
        resolved
            .bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ConsumeStdin)
    );
    for command in ["tar -cf /opt/fixture/archive.tar", "tar -c"] {
        let result = check(command, Some(ShellEnvironmentValue::Absent));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}
