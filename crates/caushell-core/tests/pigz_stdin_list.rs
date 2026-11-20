//! Static judge and profile checks. The command text is never executed.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("pigz-stdin-list"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
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
fn lists_pipeline_stdin_in_original_and_equivalent_spellings() {
    for command in [
        "echo -n teststring | gzip -1 | pigz -lv",
        "printf payload | pigz --list --verbose",
        "pigz -vl",
        "pigz -l -",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effect| {
                    effect.normalized_command_name == "pigz"
                        && effect.form_id == "list_stdin"
                        && !effect.operation_semantics_unresolved
                })
        );
    }
}

#[test]
fn list_metadata_retains_stdin_data_dependency_without_file_effects() {
    let parsed = parse_command("pigz --list", ShellKind::Bash).unwrap();
    let artifacts = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = artifacts else {
        panic!("expected a resolved stdin listing: {artifacts:#?}");
    };
    let streams = result.proven_stream_contract().unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::DataRequired);
    assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
    assert_eq!(streams.stderr_dependency, StreamDataDependency::Inputs);
    assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
    assert!(
        result
            .bound
            .effects
            .iter()
            .all(|effect| effect.kind == EffectKind::TransformData)
    );
}

#[test]
fn stdin_transform_has_no_native_file_effect_or_typed_output() {
    for command in ["printf fixture | pigz", "pigz -", "pigz --quiet -"] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effect| {
                    effect.normalized_command_name == "pigz"
                        && effect.form_id == "transform_stdin"
                        && !effect.operation_semantics_unresolved
                })
        );
    }

    let parsed = parse_command("pigz -", ShellKind::Bash).unwrap();
    let artifacts = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = artifacts else {
        panic!("expected a resolved stdin transform: {artifacts:#?}");
    };
    let streams = result.proven_stream_contract().unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::DataRequired);
    assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
    assert_eq!(streams.stderr_dependency, StreamDataDependency::Inputs);
    assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
    let [effect] = result.bound.effects.as_slice() else {
        panic!("expected one stream effect: {:?}", result.bound.effects);
    };
    assert_eq!(effect.kind, EffectKind::TransformData);
}

#[test]
fn tar_resolves_the_compressor_without_dropping_its_own_approval() {
    let result = check("tar -c --use-compress-program=pigz -f ./fixture.tar ./fixture.txt");
    assert_eq!(result.decision, Decision::NeedApproval);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("TAR_OPTIONS")),
        "{:?}",
        result.reasons
    );
    assert!(
        result
            .decision_trace
            .execution_semantics
            .iter()
            .any(|effect| {
                effect.normalized_command_name == "pigz"
                    && effect.form_id == "transform_stdin"
                    && !effect.operation_semantics_unresolved
            })
    );
}

#[test]
fn other_modes_and_independent_effects_still_require_approval() {
    for command in [
        "pigz input",
        "pigz -df archive.gz",
        "pigz -l archive.gz",
        "pigz -l -r dir",
        "pigz -l -- archive.gz",
        "pigz -- -l",
        "pigz -l -- -",
        "pigz -l \"$unknown\"",
        "pigz -- -",
        "pigz - \"$unknown\"",
        "pigz - named",
        "pigz --recursive .",
        "pigz - >/outside/output",
        "pigz | sh",
        "pigz -lv >/outside/output",
        "pigz -lv | sh",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}
