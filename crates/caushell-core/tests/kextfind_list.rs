//! Static classification of the default kernel-extension inventory.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, StreamInputMode,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("kextfind-list"),
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
fn default_query_is_classified_without_any_mutation() {
    for command in ["kextfind", "/usr/sbin/kextfind | grep fixture"] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        let native = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "kextfind")
            .unwrap();
        assert_eq!(native.form_id, "list_default_repositories");
        assert!(!native.operation_semantics_unresolved && !native.executes_payload);
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .all(|target| !target.operation.is_mutation())
        );
    }
}

#[test]
fn default_inventory_reads_both_native_repositories() {
    let parsed = parse_command("kextfind", ShellKind::Bash).unwrap();
    let artifact = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = artifact else {
        panic!("expected a resolved inventory query: {artifact:#?}");
    };
    let paths: Vec<_> = result
        .bound
        .effects
        .iter()
        .map(|effect| {
            assert_eq!(effect.kind, EffectKind::ReadPath);
            let EffectTarget::ToolConventionPath(target) = &effect.target else {
                panic!("expected a native repository read: {effect:?}");
            };
            target.path.as_str()
        })
        .collect();
    assert_eq!(paths, ["/System/Library/Extensions", "/Library/Extensions"]);
    assert_eq!(
        result.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
    assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
}

#[test]
fn query_arguments_and_independent_shell_effects_stay_guarded() {
    for command in [
        "kextfind --",
        "kextfind ./fixture",
        "kextfind -name fixture",
        "kextfind -report -print",
        "kextfind \"$unobserved\"",
        "kextfind $unobserved",
        "kextfind ''",
        "kextfind >/outside/inventory",
        "kextfind | sh",
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
