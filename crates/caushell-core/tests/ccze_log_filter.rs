//! Static checks for the ccze log filter and its unobserved plugin loader.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    ConfiguredPathMissing, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, StreamInputMode, StreamOutputMode,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("ccze-log-filter"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn log_filter_exposes_plugin_loading_in_pipelines_and_watch() {
    for command in [
        "printf '%s\\n' 'fixture message' | ccze",
        "watch -n 5 -c 'printf fixture | ccze'",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let fact = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "ccze")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(fact.form_id, "colorize_stdin");
        assert!(fact.loads_tool_config && fact.loads_in_process_code);
        assert!(fact.operation_semantics_unresolved);
    }
}

#[test]
fn ansi_output_uses_stdin_but_does_not_resolve_plugins() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["ccze -A", "ccze --raw-ansi"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
                &SessionBindings::new(),
            )
        else {
            panic!("expected ccze stream form for {command}");
        };
        let bound = resolved.bound;
        let stream = bound.stream_contract.expect("log coloring stream");
        assert_eq!(stream.stdin_mode, StreamInputMode::DataRequired);
        assert_eq!(stream.stdout_mode, StreamOutputMode::Opaque);
        assert!(bound.effects.iter().any(|effect| {
            effect.kind == EffectKind::LoadConfig
                && matches!(
                    &effect.target,
                    EffectTarget::ConfiguredPath(target)
                        if target.sources.is_empty() && target.missing == ConfiguredPathMissing::Unknown
                )
        }));
        assert!(bound.effects.iter().any(|effect| {
            effect.kind == EffectKind::LoadInProcessCode
                && matches!(effect.target, EffectTarget::None)
        }));
        assert!(bound.operation_semantics_unresolved);
    }
}

#[test]
fn unsupported_modes_and_operands_keep_approval() {
    for command in [
        "ccze --html",
        "ccze --rcfile=fixture.cfg",
        "ccze --list-plugins",
        "ccze --plugin=fixture",
        "ccze -A fixture.log",
        "ccze -A --",
        "ccze \"$unobserved\"",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "colorize_stdin"),
            "{command}"
        );
    }
}
