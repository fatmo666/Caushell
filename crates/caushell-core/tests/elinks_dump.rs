//! Static checks for ELinks output mode and its unobserved startup hooks.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, resolve_invocation,
};
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("elinks-dump"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-elinks-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn dump_preserves_config_and_code_loading_inside_watch() {
    let response = check("watch -n 2 elinks -dump fixture.html");
    assert_eq!(response.decision, Decision::NeedApproval);
    let dump = response
        .decision_trace
        .execution_semantics
        .iter()
        .find(|fact| fact.normalized_command_name == "elinks")
        .unwrap_or_else(|| panic!("{:?}", response.reasons));
    assert_eq!(dump.form_id, "dump_document");
    assert!(dump.loads_tool_config && dump.loads_in_process_code);
    assert!(dump.operation_semantics_unresolved);
}

#[test]
fn explicit_document_path_is_recorded_but_a_bare_name_is_not_a_read_proof() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (path, explicit) in [("./fixture.html", true), ("fixture.html", false)] {
        let command = format!("elinks -dump {path}");
        assert_eq!(check(&command).decision, Decision::NeedApproval);
        let parsed = parse_command(&command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}");
        };
        let bound = resolved.bound;
        let file = bound
            .bound_parameters
            .iter()
            .find(|slot| slot.name.as_str() == "file_operand");
        let populated = file.filter(|slot| !slot.values.is_empty());
        assert_eq!(populated.is_some(), explicit, "{command}");
        if let Some(file) = populated {
            assert!(
                matches!(&file.values[..], [BoundValue::Argument { text, .. }] if text == path)
            );
            assert!(bound.effects.iter().any(|effect| {
                effect.kind == EffectKind::ReadPath
                    && matches!(&effect.target, EffectTarget::Slot(slot) if slot == &file.name)
            }));
        }
        assert!(bound.operation_semantics_unresolved);
    }
}

#[test]
fn other_forms_and_boolean_arguments_keep_approval() {
    for command in [
        "elinks",
        "elinks -dump",
        "elinks -dump 0",
        "elinks -dump 0 fixture.html",
        "elinks -dump 1 fixture.html",
        "elinks -dump ./one.html ./two.html",
        "elinks -dump -",
        "elinks -dump https://example.invalid/fixture",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|fact| fact.form_id != "dump_document")
        );
    }
}
