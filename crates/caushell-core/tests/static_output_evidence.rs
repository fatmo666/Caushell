//! Static checks only: sample commands and their substitutions are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("static-output-evidence"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

fn materializations(response: &CheckResponse) -> Vec<&DerivedInvocation> {
    response
        .decision_trace
        .derived_invocations
        .iter()
        .filter(|invocation| {
            matches!(
                invocation.origin,
                DerivedInvocationOrigin::CommandSubstitutionMaterialization { .. }
            )
        })
        .collect()
}

#[test]
fn command_substitution_materializes_pipeline_output_once() {
    for command in [
        r#"touch "$(printf /bench/workspace/cache/file | cat)""#,
        r#"touch "$(printf '/bench/workspace/cache/file\n\n' | cat | cat)""#,
    ] {
        let response = check(command);
        let derived = materializations(&response);
        assert_eq!(derived.len(), 1, "{command}: {response:#?}");
        assert_eq!(
            derived[0].raw_text, "touch '/bench/workspace/cache/file'",
            "{response:#?}"
        );
    }
}

#[test]
fn unknown_transform_or_partial_output_does_not_invent_exact_arguments() {
    for command in [
        r#"basename "$(printf a:b:c | tr : /)""#,
        r#"printf %s "$(printf abc | base64)""#,
        r#"touch "$(printf safe; cat /unknown)""#,
        r#"touch "$(printf safe > /tmp/output)""#,
    ] {
        let response = check(command);
        assert!(
            materializations(&response).is_empty(),
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|invocation| {
                    matches!(
                        invocation.origin,
                        DerivedInvocationOrigin::CommandSubstitutionBody { .. }
                    )
                }),
            "the original body must still be analyzed: {response:#?}"
        );
    }
}

#[test]
fn existing_base64_decode_reaches_both_substitution_and_script_consumers() {
    let response = check(r#"echo "$(printf ZWNobyBzYWZlCg== | base64 -d | cat)""#);
    let derived = materializations(&response);
    assert_eq!(derived.len(), 1, "{response:#?}");
    assert_eq!(derived[0].raw_text, "echo 'echo safe'", "{response:#?}");

    for command in [
        "printf cm0gLXJmIC8K | base64 -d | sh",
        "source <(printf cm0gLXJmIC8K | base64 -d | cat)",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Deny,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| { semantics.normalized_command_name == "rm" }),
            "{command}: {response:#?}"
        );
    }
}
