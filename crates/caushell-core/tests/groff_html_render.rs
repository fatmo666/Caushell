//! Offline judgments and profile bindings for the GNU roff HTML pipeline.
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
        session_id: SessionId::new("groff-html-render"),
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
fn html_rendering_keeps_helper_configuration_and_temporary_paths_unresolved() {
    for command in [
        r#"printf '%s\n' '.TH EXAMPLE 1' | groff -mandoc -Thtml"#,
        "groff -T html -m andoc < ./fixture.roff",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let fact = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|fact| fact.normalized_command_name == "groff")
            .unwrap_or_else(|| panic!("{command}: {:?}", result.reasons));
        assert_eq!(fact.form_id, "render_andoc_html_from_stdin");
        assert!(fact.loads_tool_config && fact.executes_payload);
        assert!(fact.operation_semantics_unresolved);
        for operation in [PathTargetOperation::Write, PathTargetOperation::Delete] {
            assert!(result.decision_trace.path_targets.iter().any(|target| {
                target.source_node_id == fact.source.node_id
                    && target.operation == operation
                    && matches!(target.resolution, SemanticResolution::Unresolved { .. })
            }));
        }
    }
}

#[test]
fn html_is_an_input_dependent_stream_with_opaque_helpers() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("groff -mandoc -Thtml", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("expected the HTML standard-input form");
    };
    let bound = resolved.bound;
    let contract = bound
        .stream_contract
        .expect("HTML standard stream contract");
    assert_eq!(contract.stdin_mode, StreamInputMode::DataRequired);
    assert_eq!(contract.stdout_mode, StreamOutputMode::Opaque);
    assert_eq!(contract.stdout_dependency, StreamDataDependency::Inputs);
    assert_eq!(bound.bound_implicit_inputs.len(), 1);
    for kind in [
        EffectKind::LoadConfig,
        EffectKind::ExecutePayload,
        EffectKind::WritePath,
        EffectKind::DeletePath,
    ] {
        assert!(bound.effects.iter().any(|effect| {
            effect.kind == kind && matches!(&effect.target, EffectTarget::ConfiguredPath(_))
        }));
    }
}

#[test]
fn other_source_and_driver_options_stay_conservative() {
    for command in [
        "groff",
        "groff -mandoc -Txhtml",
        "groff -man -Thtml",
        "groff -mandoc -Thtml ./fixture.roff",
        "groff -mandoc -Thtml -- ./fixture.roff",
        "groff -mandoc -Thtml -U",
        "groff -m \"$UNOBSERVED\" -Thtml",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "render_andoc_html_from_stdin"),
            "{command}"
        );
    }
}
