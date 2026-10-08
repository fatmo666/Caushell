use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

#[test]
fn wait_declares_only_runtime_assignment_not_control_effect() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "wait",
        "wait -n",
        "wait -f 123",
        "wait -n -p target",
        "wait -np target",
        "wait -ptarget",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}");
        };
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ControlProcess)
        );
        let writes = runtime_variable_writes(&r.bound);
        assert!(!writes.unresolved);
        assert_eq!(
            writes.names,
            if command.contains("-p") || command.contains("np") {
                vec!["target"]
            } else {
                vec![]
            },
            "{command}"
        );
    }
}
#[test]
fn runtime_destinations_use_materialized_semantics() {
    let registry = ProfileRegistry::built_in().unwrap();
    let bindings = SessionBindings::new().with_exact_scalar("name", "target");
    for (command, unresolved) in [
        ("wait -p \"$name\"", false),
        ("wait -p \"$unknown\"", true),
        ("wait -p 'a[0]'", true),
        ("wait -p 'bad-name'", true),
    ] {
        let p = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
            &registry,
            &p.commands[0],
            InvocationRuntimeContext::default(),
            &bindings,
        ) else {
            panic!("{command}");
        };
        assert_eq!(
            r.bound.operation_semantics_unresolved, unresolved,
            "{command}"
        );
        assert_eq!(
            runtime_variable_writes(&r.bound).unresolved,
            unresolved,
            "{command}"
        );
    }
}
