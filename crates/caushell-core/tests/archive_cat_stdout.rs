//! Static checks of archive-to-stdout entry points. No command is executed.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, StreamInputMode, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("archive-cat-stdout"),
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
fn named_archives_can_feed_process_substitution() {
    let response = check("md5sum <(bzcat fixture.bz2) <(lzcat fixture.lzma) <(xzcat fixture.xz)");
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    for tool in ["bzcat", "lzcat", "xzcat"] {
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effect| {
                    effect.form_id == "archive_stdout_files"
                        && !effect.operation_semantics_unresolved
                        && effect.source.raw_text.split_whitespace().next() == Some(tool)
                }),
            "{tool} did not select the archive stdout form"
        );
    }
}

#[test]
fn unknown_environment_does_not_prove_a_fixed_output_encoding() {
    let profiles = ProfileRegistry::built_in().unwrap();
    for name in ["bzcat", "lzcat", "xzcat"] {
        let parsed = parse_command(&format!("{name} fixture.archive"), ShellKind::Bash).unwrap();
        let artifact = resolve_invocation_artifact_with_bindings(
            &profiles,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        let ResolveInvocationArtifactResult::Resolved(result) = artifact else {
            panic!("{name}: expected an archive stdout form");
        };
        let streams = result.proven_stream_contract().unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::DataOptional);
        assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
        assert!(result.bound.stdout_records.is_none() && result.bound.stdout_scalar.is_none());
        assert_eq!(result.bound.effects.len(), 2);
        assert!(
            result
                .bound
                .effects
                .iter()
                .all(|effect| effect.kind == EffectKind::ReadPath)
        );
    }
}

#[test]
fn options_dash_operands_and_outside_redirections_remain_guarded() {
    for name in ["bzcat", "lzcat", "xzcat"] {
        for args in [
            "",
            "fixture.archive --files",
            "-- -",
            "fixture.archive > /outside/result",
        ] {
            let command = format!("{name} {args}");
            let response = check(&command);
            assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        }
    }
}
