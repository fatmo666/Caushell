use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("jar-listing"),
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
fn table_mode_models_the_archive_read_and_retains_unknown_jvm_startup() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["jar -tf ./sample.jar", "jar -tvf ./sample.jar"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        let ResolveInvocationArtifactResult::Resolved(result) = result else {
            panic!("{command}: {result:?}");
        };
        assert_eq!(result.bound.form_id.as_str(), "list_archive_members");
        assert!(result.bound.operation_semantics_unresolved);
        assert!(result.proven_stream_contract().is_none());
        for name in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"] {
            assert!(
                result
                    .bound
                    .residuals
                    .iter()
                    .any(|residual| residual.reason.contains(name)),
                "{name} must remain unobserved"
            );
        }
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ReadPath)
        );
        assert!(
            !result
                .bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::WritePath)
        );
    }
}

#[test]
fn nested_listing_is_traced_without_approving_jvm_startup() {
    let response = check("find . -name '*.jar' -exec jar -tf {} \\; | grep manifest");
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|effect| {
                effect.normalized_command_name == "jar" && effect.form_id == "list_archive_members"
            }),
        "{:?}",
        response.reasons
    );
    assert!(
        response
            .reasons
            .iter()
            .any(|reason| reason.contains("jar") && reason.contains("unresolved"))
    );
}

#[test]
fn a_supplied_jvm_option_is_an_opaque_startup_input() {
    let command = "JAVA_TOOL_OPTIONS=-Dfixture=true jar -tf ./sample.jar";
    let response = check(command);
    assert_eq!(response.decision, Decision::NeedApproval);
    let jar = response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|effect| effect.normalized_command_name == "jar")
        .expect("jar should be present in the execution trace");
    assert!(jar.executes_payload && jar.operation_semantics_unresolved);
}

#[test]
fn other_operation_modes_and_indirect_options_remain_unresolved() {
    for command in [
        "jar -xf ./sample.jar",
        "jar -uf ./sample.jar note.txt",
        "jar -tf @options",
        "jar -J-version -tf ./sample.jar",
        "jar -tf -J-version",
        "jar -tf -tvf ./sample.jar",
        "jar -tf",
        "jar -tf ./sample.jar members.txt",
    ] {
        let response = check(command);
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|effect| effect.form_id != "list_archive_members"),
            "{command}"
        );
    }
}
