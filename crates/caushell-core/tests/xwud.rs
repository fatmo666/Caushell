//! Judge-only checks for the file input of an X Window dump viewer.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, EffectTarget, InvocationRuntimeContext, PathAccessKind, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("xwud-file-input"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/fixture".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn explicit_xwd_file_is_a_read_with_unresolved_display_effects() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (command, expected_path) in [
        ("xwud -in fixture.xwd", "fixture.xwd"),
        ("/usr/bin/xwud -in 'fixture image.xwd'", "fixture image.xwd"),
        ("xwud -in -", "-"),
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let viewer = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "xwud")
            .expect("xwud file input should be represented in execution semantics");
        assert_eq!(viewer.form_id, "display_dump_from_file");
        assert!(viewer.operation_semantics_unresolved);
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .all(|target| !target.operation.is_mutation())
        );

        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let resolved = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        let ResolveInvocationArtifactResult::Resolved(resolved) = resolved else {
            panic!("{command}: {resolved:?}");
        };
        let [input] = resolved.bound.bound_parameters.as_slice() else {
            panic!("{command}: expected one input parameter");
        };
        assert_eq!(input.name.as_str(), "dump_file");
        assert!(matches!(input.values.as_slice(),
            [caushell_profile::BoundValue::Argument {text, ..}] if text == expected_path));
        let [effect] = resolved.bound.effects.as_slice() else {
            panic!("{command}: expected one effect");
        };
        assert_eq!(effect.kind, EffectKind::ReadPath);
        assert_eq!(effect.target, EffectTarget::Slot(input.name.clone()));
        assert_eq!(effect.path_access, Some(PathAccessKind::ContentOpen));
    }
}

#[test]
fn unsupported_viewer_argv_does_not_claim_a_file_input() {
    for command in [
        "xwud",
        "xwud -in",
        "xwud -in ''",
        "xwud -in \"$name\"",
        "xwud -- -in fixture.xwd",
        "xwud -in fixture.xwd -dumpheader",
        "xwud -in first.xwd -in second.xwd",
        "xwud -display display.test:1 -in fixture.xwd",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| entry.form_id != "display_dump_from_file"),
            "{command}"
        );
    }
}
