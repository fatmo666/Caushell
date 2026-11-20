//! Static judgments for the default JSON stream conversion.
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
        session_id: SessionId::new("json-xs-stdin"),
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
fn default_json_conversion_retains_unverified_perl_startup() {
    for command in [
        r#"printf '%s\n' '{"fixture":42}' | json_xs"#,
        r#"printf '%s\n' '{"fixture":42}' | json_xs -v"#,
        r#"json_xs < ./fixture.json"#,
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let fact = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "json_xs")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(fact.form_id, "format_standard_json");
        assert!(fact.executes_payload && fact.loads_tool_config);
        assert!(fact.operation_semantics_unresolved);
        assert!(result.reasons.iter().any(|reason| {
            reason.contains("json_xs") && reason.contains("unresolved operation semantics")
        }));
    }
}

#[test]
fn profile_declares_input_dependent_standard_output_and_unknown_startup_sources() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["json_xs", "json_xs -v"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}: expected the default JSON format");
        };
        let bound = resolved.bound;
        let contract = bound.stream_contract.expect("standard stream contract");
        assert_eq!(contract.stdin_mode, StreamInputMode::DataRequired);
        assert_eq!(contract.stdout_mode, StreamOutputMode::Opaque);
        assert_eq!(contract.stdout_dependency, StreamDataDependency::Inputs);
        assert_eq!(bound.bound_implicit_inputs.len(), 1);
        for kind in [EffectKind::LoadConfig, EffectKind::ExecutePayload] {
            assert!(bound.effects.iter().any(|effect| {
                effect.kind == kind && matches!(&effect.target, EffectTarget::ConfiguredPath(_))
            }));
        }
    }
}

#[test]
fn unmodeled_arguments_remain_subject_to_approval() {
    for command in [
        "json_xs --",
        "json_xs -vv",
        "json_xs -t yaml",
        "json_xs -e 0",
        "json_xs ./fixture.json",
        "json_xs \"$UNOBSERVED\"",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "format_standard_json"),
            "{command}"
        );
    }
}
