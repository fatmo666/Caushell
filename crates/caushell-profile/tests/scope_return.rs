use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{CommandSequenceNo, ShellKind};

#[test]
fn return_declares_scope_transfer_without_a_shell_exit_capability() {
    let registry = ProfileRegistry::built_in().unwrap();
    assert!(!registry.may_terminate_shell("return"));
    for command in [
        "return",
        "return 0",
        "return -1",
        "return --",
        "return -- 7",
        "return \"$status\"",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}");
        };
        assert!(
            resolved
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReturnFromShellScope),
            "{command}"
        );
        assert!(
            !resolved
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::TerminateCurrentShell)
        );
    }
    let parsed = parse_command("return --help", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!();
    };
    assert!(
        resolved
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReturnFromShellScope)
    );
    assert!(
        !resolved
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TerminateCurrentShell)
    );
}

#[test]
fn path_qualified_return_does_not_acquire_owning_shell_authority() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("/custom/return 0", ShellKind::Bash).unwrap();
    if let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
    ) {
        assert!(resolved.bound.operation_semantics_unresolved);
    }
}

#[test]
fn control_path_join_preserves_common_facts_and_forgets_divergent_facts() {
    let mut left = SessionBindings::new()
        .with_exact_scalar("same", "common")
        .with_exact_scalar("slot", "/opt/shared/out");
    let mut right = left.clone();
    right.insert_exact_scalar("slot", "inside");
    right.insert_exact_scalar("new", "inside");
    left.join_control_path(&right, CommandSequenceNo::new(1));
    assert_eq!(
        left.get("same").unwrap().value,
        &SessionValue::exact_scalar("common")
    );
    assert!(matches!(
        left.get("slot").unwrap().value,
        SessionValue::OpaqueDynamic { .. }
    ));
    assert!(matches!(
        left.get("new").unwrap().value,
        SessionValue::OpaqueDynamic { .. }
    ));
    assert_eq!(left.variable_presence("new"), VariablePresence::Unknown);
}

#[test]
fn unrepresentable_export_membership_uses_frame_uncertainty() {
    let mut left = SessionBindings::new();
    let mut right = left.clone();
    right.set_environment_value("CONFIG", SessionValue::exact_scalar("/opt/shared/config"));
    left.join_control_path(&right, CommandSequenceNo::new(1));
    assert!(matches!(
        left.environment_value("CONFIG"),
        EnvironmentValueRef::Unknown
    ));
    assert!(left.shell_state_uncertainty().is_some());
}
