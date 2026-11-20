//! Static checks for the configuration-dependent qstat XML form.
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
        session_id: SessionId::new("qstat-xml"),
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
fn xml_query_preserves_approval_and_reports_unresolved_configuration() {
    let response = check("qstat -xml | wc -l");
    assert_eq!(response.decision, Decision::NeedApproval);
    let fact = response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|fact| fact.normalized_command_name == "qstat")
        .unwrap_or_else(|| panic!("{:?}", response.reasons));
    assert_eq!(fact.form_id, "query_xml");
    assert!(fact.loads_tool_config && fact.operation_semantics_unresolved);
    assert!(!fact.executes_payload);
}

#[test]
fn xml_contract_keeps_configuration_and_endpoint_unresolved() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("qstat -xml", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("expected the XML query form");
    };
    let bound = resolved.bound;
    assert_eq!(
        bound
            .stream_contract
            .expect("XML stream contract")
            .stdout_mode,
        StreamOutputMode::Opaque
    );
    assert!(bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::LoadConfig
            && matches!(
                &effect.target,
                EffectTarget::ConfiguredPath(target)
                    if target.sources.is_empty() && target.missing == ConfiguredPathMissing::Unknown
            )
    }));
    assert!(bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::NetworkEndpoint && matches!(&effect.target, EffectTarget::None)
    }));
}

#[test]
fn other_arguments_are_not_bound_as_the_xml_only_form() {
    for command in [
        "qstat",
        "qstat -x",
        "qstat -xml --",
        "qstat -- -xml",
        "qstat -xml fixture.invalid",
        "qstat -xml -f",
        "qstat -xml -xml",
        "qstat -xml ''",
        "qstat -xml \"$UNOBSERVED\"",
        "qstat \"$UNOBSERVED\"",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "query_xml"),
            "{command}"
        );
    }
}
