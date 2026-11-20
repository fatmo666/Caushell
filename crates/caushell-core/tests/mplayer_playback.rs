//! Static checks for MPlayer playback with configuration-dependent effects.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    ConfiguredPathMissing, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("mplayer-playback"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
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
fn local_playback_reports_config_and_keeps_approval() {
    for command in [
        "mplayer './fixture audio.mp3'",
        "find . -name '*.fixture' -exec mplayer {} ';'",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let fact = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "mplayer")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(fact.form_id, "play_media");
        assert!(fact.loads_tool_config);
        assert!(fact.operation_semantics_unresolved);
    }
}

#[test]
fn plain_media_has_file_reads_and_no_static_output_destination() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("mplayer './fixture audio.mp3' disc.wav", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("expected a playback profile");
    };
    let bound = resolved.bound;
    assert!(bound.stream_contract.is_none());
    assert!(bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::ReadPath
            && matches!(&effect.target, EffectTarget::Slot(slot) if slot.as_str() == "local_media")
    }));
    assert!(bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::WritePath
            && matches!(
                &effect.target,
                EffectTarget::ConfiguredPath(target)
                    if target.sources.is_empty() && target.missing == ConfiguredPathMissing::Unknown
            )
    }));
}

#[test]
fn other_sources_and_control_options_remain_under_approval() {
    for command in [
        "mplayer",
        "mplayer -",
        "mplayer https://fixture.invalid/audio.mp3",
        "mplayer -playlist fixture-list",
        "mplayer ./fixture.mp3 -ao null",
        "mplayer -- ./fixture.mp3",
        "mplayer \"$UNOBSERVED\"",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "play_media" || fact.operation_semantics_unresolved),
            "{command}"
        );
        if command.contains("fixture.invalid") {
            assert!(!result.decision_trace.path_targets.iter().any(|target| {
                target.slot_name == "local_media"
                    && target
                        .spelling
                        .as_deref()
                        .is_some_and(|literal| literal.starts_with("https://"))
            }));
        }
    }
}
