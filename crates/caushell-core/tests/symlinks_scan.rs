//! Static checks. The command text is never executed.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("symlinks-scan"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
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
fn named_roots_and_reporting_flags_are_supported() {
    for command in [
        "symlinks ./fixture",
        "symlinks -rsv ./fixture ./other",
        "symlinks ./fixture -r",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|entry| {
                    entry.normalized_command_name == "symlinks"
                        && entry.form_id == "report_links"
                        && !entry.operation_semantics_unresolved
                })
        );
    }
}

#[test]
fn metadata_output_does_not_supply_a_path_list_contract() {
    let parsed = parse_command("symlinks ./fixture", ShellKind::Bash).unwrap();
    let binding = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(resolved) = binding else {
        panic!("expected a bound symlink scan");
    };
    let streams = resolved.proven_stream_contract().unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
    assert!(resolved.bound.stdout_records.is_none() && resolved.bound.stdout_scalar.is_none());
    assert_eq!(resolved.bound.effects.len(), 1);
    assert_eq!(resolved.bound.effects[0].kind, EffectKind::TargetPath);
}

#[test]
fn mutation_and_uncertain_argv_do_not_fall_into_reporting() {
    for command in [
        "symlinks -d ./fixture",
        "symlinks ./fixture -c ./other",
        "symlinks -td ./fixture",
        "symlinks -rvd ./fixture",
        "symlinks -- -d ./fixture",
        "symlinks \"$unobserved\"",
        "symlinks ./fixture > /outside/output",
    ] {
        assert_eq!(check(command).decision, Decision::NeedApproval, "{command}");
    }
}
