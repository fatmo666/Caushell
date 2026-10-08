use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

#[test]
fn exit_declares_enclosing_shell_termination_not_process_control() {
    let registry = ProfileRegistry::built_in().unwrap();
    assert!(registry.may_terminate_shell("exit"));
    assert!(!registry.may_terminate_shell("kill"));
    for c in ["exit", "exit 0", "exit -1", "exit --", "exit -- 0"] {
        let p = parse_command(c, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &p.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{c}")
        };
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{c}: {:?}",
            r.bound.residuals
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::TerminateCurrentShell)
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ControlProcess)
        );
    }
}
#[test]
fn help_is_not_termination_and_unknown_shape_is_not_proved() {
    let registry = ProfileRegistry::built_in().unwrap();
    let p = parse_command("exit --help", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        &registry,
        &p.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!()
    };
    assert!(r.bound.effects.is_empty());
    for c in ["exit 0 1", "exit \"$status\""] {
        let p = parse_command(c, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &p.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!()
        };
        assert!(r.bound.operation_semantics_unresolved, "{c}");
    }
}
