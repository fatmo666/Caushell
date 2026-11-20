//! Static judgments for PulseAudio's raw capture form.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, StreamInputMode, StreamOutputMode,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("parec-record-stdout"),
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
fn raw_stdout_capture_needs_an_observed_server_and_source() {
    for command in [
        "parec",
        "parec --raw --channels=2 --latency=64 | wc -c",
        "parec --latency 64 --channels 2 --raw",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let fact = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "parec")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(fact.form_id, "record_raw_stdout");
        assert!(fact.loads_tool_config && fact.executes_payload);
        assert!(fact.operation_semantics_unresolved);
    }
}

#[test]
fn capture_contract_keeps_the_source_outside_stdin() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("parec --raw --channels=2", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("expected the raw stdout capture form");
    };
    let bound = resolved.bound;
    let contract = bound.stream_contract.expect("capture stream contract");
    assert_eq!(contract.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(contract.stdout_mode, StreamOutputMode::Opaque);
    assert!(bound.bound_implicit_inputs.is_empty());
    assert!(bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::NetworkEndpoint && matches!(&effect.target, EffectTarget::None)
    }));
    assert!(
        !bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
}

#[test]
fn other_endpoints_modes_and_file_operands_remain_under_approval() {
    for command in [
        "parec --raw ./local.pcm",
        "parec --raw -- ./local.pcm",
        "parec --raw --file-format=wav",
        "parec --raw --playback",
        "parec --raw --server=fixture.invalid",
        "parec --raw --channels=unknown",
        "parec --raw \"$UNOBSERVED\"",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "record_raw_stdout"
                    || fact.operation_semantics_unresolved),
            "{command}"
        );
    }
}
