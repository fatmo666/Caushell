//! Static checks for cpp with a single, literal standard-input operand.
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
        session_id: SessionId::new("cpp-stdin"),
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
fn stdin_form_preserves_config_and_unproved_file_effects() {
    let result = check("printf '%s\\n' 'int fixture;' | cpp - | wc -c");
    assert_eq!(result.decision, Decision::NeedApproval);
    let fact = result
        .decision_trace
        .execution_semantics
        .iter()
        .find(|fact| fact.normalized_command_name == "cpp")
        .unwrap_or_else(|| panic!("{:?}", result.reasons));
    assert_eq!(fact.form_id, "preprocess_stdin");
    assert!(fact.loads_tool_config && fact.operation_semantics_unresolved);
    assert!(result.decision_trace.path_targets.iter().any(|path| {
        path.source_node_id == fact.source.node_id
            && path.operation == PathTargetOperation::Write
            && matches!(path.resolution, SemanticResolution::Unresolved { .. })
    }));
}

#[test]
fn preprocessor_output_has_no_certified_shape() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("cpp -", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        )
    else {
        panic!("expected the standard-input preprocessor form");
    };
    let bound = resolved.bound;
    let stream = bound.stream_contract.expect("preprocess stream");
    assert_eq!(stream.stdin_mode, StreamInputMode::DataOptional);
    assert_eq!(stream.stdout_mode, StreamOutputMode::Opaque);
    for kind in [
        EffectKind::LoadConfig,
        EffectKind::ReadPath,
        EffectKind::WritePath,
    ] {
        assert!(bound.effects.iter().any(|effect| {
            effect.kind == kind
                && matches!(
                    &effect.target,
                    EffectTarget::ConfiguredPath(target)
                        if target.sources.is_empty() && target.missing == ConfiguredPathMissing::Unknown
                )
        }));
    }
}

#[test]
fn alternate_argv_does_not_inherit_the_single_dash_form() {
    for command in [
        "cpp",
        "cpp - fixture.i",
        "cpp - -o fixture.i",
        "cpp -- -",
        "cpp @fixture-options",
        "cpp fixture.c",
        "cpp \"$unobserved\"",
        "cpp - ''",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| {
                    fact.normalized_command_name != "cpp" || fact.form_id != "preprocess_stdin"
                }),
            "{command}"
        );
    }
}
