//! JudgeOnly coverage for SMART report options. No storage device is opened.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    ConfiguredPathMissing, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, StreamOutputMode,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("smartctl-fixture"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/fixture".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn smart_report_keeps_device_and_database_inputs_in_the_analysis() {
    for command in [
        "/usr/sbin/smartctl -a /dev/fixture | wc -l",
        "smartctl --all -- /dev/fixture",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval);
        let fact = response
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "smartctl")
            .unwrap_or_else(|| panic!("{:?}", response.reasons));
        assert_eq!(fact.form_id, "report_device_health");
        assert!(fact.loads_tool_config && fact.operation_semantics_unresolved);
    }
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("smartctl -a /dev/fixture", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("missing SMART health report form");
    };
    let stream = resolved.bound.stream_contract.expect("SMART report stream");
    assert_eq!(stream.stdout_mode, StreamOutputMode::Opaque);
    assert_eq!(stream.stdout_dependency, StreamDataDependency::Inputs);
    assert!(resolved.bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::ReadPath
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == "device")
    }));
    assert!(resolved.bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::LoadConfig
            && matches!(&effect.target, EffectTarget::ConfiguredPath(path)
                if path.sources.is_empty() && path.missing == ConfiguredPathMissing::Unknown)
    }));
}

#[test]
fn incomplete_or_different_requests_do_not_select_the_smart_report() {
    for command in [
        "smartctl -a",
        "smartctl -a -",
        "smartctl -a ''",
        "smartctl -a /dev/one /dev/two",
        "smartctl -a --test=short /dev/fixture",
        "smartctl -a --device=ata /dev/fixture",
        "smartctl --scan-open",
        "smartctl -- -a /dev/fixture",
        "smartctl -a \"$UNOBSERVED\"",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "report_device_health"),
            "{command}"
        );
    }
}
