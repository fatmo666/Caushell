//! Judge-only checks. No command in this suite is executed.
use caushell_core::ShellQueryCore;
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, StreamInputMode,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("xattr-read"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
    })
}

#[test]
fn nonrecursive_reads_use_only_the_bounded_read_forms() {
    for (command, form) in [
        ("xattr ./sample", "list_attributes"),
        ("xattr -l ./sample", "list_attributes"),
        ("POSIXLY_CORRECT=1 xattr -l ./sample", "list_attributes"),
        ("xattr -p com.caushell.fixture ./sample", "print_attribute"),
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
                .any(|semantics| {
                    semantics.normalized_command_name == "xattr"
                        && semantics.form_id == form
                        && !semantics.operation_semantics_unresolved
                        && !semantics.executes_payload
                }),
            "{command}"
        );
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
fn attribute_name_and_files_have_distinct_bindings() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(
        "xattr -p com.caushell.fixture ./first ./second",
        ShellKind::Bash,
    )
    .unwrap();
    let resolved = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = resolved else {
        panic!("{resolved:?}");
    };
    let [attribute, paths] = result.bound.bound_parameters.as_slice() else {
        panic!(
            "unexpected parameter bindings: {:?}",
            result.bound.bound_parameters
        );
    };
    assert_eq!(attribute.name.as_str(), "attribute");
    assert_eq!(attribute.values.len(), 1);
    assert_eq!(paths.name.as_str(), "input_paths");
    assert_eq!(paths.values.len(), 2);
    let [effect] = result.bound.effects.as_slice() else {
        panic!("unexpected effects: {:?}", result.bound.effects);
    };
    assert_eq!(effect.kind, EffectKind::ReadPath);
    assert_eq!(effect.target, EffectTarget::Slot(paths.name.clone()));
    assert_eq!(
        result.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
    assert!(result.bound.stdout_scalar.is_none() && result.bound.stdout_records.is_none());
}

#[test]
fn recursive_listing_keeps_its_descendant_scope_unresolved() {
    for command in ["xattr -lr ./tree", "xattr -r -l ./tree"] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| {
                    semantics.form_id == "list_attributes_recursively"
                        && semantics.operation_semantics_unresolved
                }),
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn mutations_and_unverified_operands_do_not_inherit_the_read_form() {
    for command in [
        "xattr -w com.caushell.fixture value ./sample",
        "xattr -d com.caushell.fixture ./sample",
        "xattr -c ./sample",
        "xattr -lrw com.caushell.fixture value ./tree",
        "xattr -l \"$ARG\"",
        "xattr ./sample -l",
        "POSIXLY_CORRECT=1 xattr ./sample -l",
        "xattr ./sample -- ./other",
        "xattr -l ./sample -w com.caushell.fixture value",
        "xattr -p com.caushell.fixture",
        "xattr -p com.caushell.fixture -p ./sample",
        "xattr -l ./sample > /opt/shared/attributes.txt",
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
