use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("xmllint-xpath"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/fixture"),
        shell_kind: ShellKind::Bash,
        home: Some("/fixture".into()),
        workspace_root: Some("/fixture".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn xpath_file_and_expression_ownership_follow_the_native_argv() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "xmllint --xpath '/root/item' ./fixture.xml",
        "xmllint ./fixture.xml --xpath '/root/item'",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let artifact = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        let ResolveInvocationArtifactResult::Resolved(result) = artifact else {
            panic!("{command}: {artifact:?}");
        };
        assert_eq!(result.bound.form_id.as_str(), "xpath_file_with_catalog");
        assert!(result.bound.operation_semantics_unresolved);
        assert!(result.proven_stream_contract().is_none());
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath)
        );
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadConfig)
        );
        assert!(
            !result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
}

#[test]
fn a_pipeline_keeps_the_catalog_source_gap() {
    let response = check("xmllint fixture.xml --xpath '/root/item' | wc -l");
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response.decision_trace.execution_semantics.iter().any(|e| {
            e.normalized_command_name == "xmllint"
                && e.form_id == "xpath_file_with_catalog"
                && e.loads_tool_config
                && e.operation_semantics_unresolved
        }),
        "{:?}",
        response.reasons
    );
}

#[test]
fn other_sources_modes_and_unbound_arguments_do_not_become_local_xpath() {
    for command in [
        "xmllint --xpath '/root/item' file:///fixture.xml",
        "xmllint --xpath '/root/item' -",
        "xmllint --xpath '/root/item' one.xml two.xml",
        "xmllint --xpath '/root/item' \"$unknown\"",
        "xmllint fixture.xml --xpath",
        "xmllint --xpath '/root/item' --noent fixture.xml",
        "xmllint --xpath '/root/item' --output out.xml fixture.xml",
        "xmllint --nonet --nocatalogs --xpath '/root/item' fixture.xml",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|e| { e.form_id != "xpath_file_with_catalog" }),
            "{command}"
        );
    }
}
