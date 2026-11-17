use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolved_in(command: &str, domain: CommandLookupDomain) -> bool {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    matches!(
        resolve_invocation_in_lookup_domain_with_stdout_proofs(
            &ProfileRegistry::built_in().unwrap(),
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
            &domain,
            &[],
        ),
        ResolveInvocationResult::Resolved(_)
    )
}
#[test]
fn availability_is_declared_by_profiles_not_executable_names() {
    for command in [
        "command", "exit 0", "cd .", "read X", "return 0", "jobs", "set -e", "shift 0",
    ] {
        assert!(
            resolved_in(command, CommandLookupDomain::Shell),
            "{command}"
        );
        assert!(
            resolved_in(command, CommandLookupDomain::Builtin),
            "{command}"
        );
        assert!(
            !resolved_in(command, CommandLookupDomain::External),
            "{command}"
        );
    }
    for command in ["printf SAFE", "echo SAFE", "true", "pwd"] {
        assert!(
            resolved_in(command, CommandLookupDomain::Shell),
            "{command}"
        );
        assert!(
            resolved_in(command, CommandLookupDomain::Builtin),
            "{command}"
        );
        assert!(
            resolved_in(command, CommandLookupDomain::External),
            "{command}"
        );
    }
    assert!(!resolved_in("cat data", CommandLookupDomain::Builtin));
    assert!(!resolved_in(
        "/usr/bin/exit 0",
        CommandLookupDomain::Builtin
    ));
    assert!(!resolved_in("/usr/bin/exit 0", CommandLookupDomain::Shell));
    assert!(!resolved_in("printf SAFE", CommandLookupDomain::Unknown));
}
#[test]
fn dispatch_domains_are_projected_without_losing_the_contract() {
    for (command, expected) in [
        ("env command", CommandLookupDomain::External),
        ("timeout 2 command", CommandLookupDomain::External),
        ("exec command", CommandLookupDomain::External),
        ("command command", CommandLookupDomain::Shell),
        (
            "python -m pytest",
            CommandLookupDomain::Module("python".into()),
        ),
    ] {
        let registry = ProfileRegistry::built_in().unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!("{command}")
        };
        let children = collect_dispatch_command_candidates(&r.bound);
        assert_eq!(children.len(), 1, "{command}");
        assert_eq!(children[0].lookup_domain, expected, "{command}");
    }
}
fn fixture(domain: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: launcher}}
forms:
  - id: launch
    parameters:
      - {{name: child, semantic: {{kind: command_ref, dispatch: wrapper_command}}, binding: {{kind: next_positional}}, cardinality: required_one}}
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          command: child
          {domain}
"#
    )
}
#[test]
fn dsl_defaults_to_external_and_rejects_conflicting_domains() {
    for (syntax, expected) in [
        ("", CommandLookupDomain::External),
        ("lookup_domain: builtin", CommandLookupDomain::Builtin),
        ("lookup_domain: shell", CommandLookupDomain::Shell),
        (
            "module_runtime: python",
            CommandLookupDomain::Module("python".into()),
        ),
    ] {
        let profile = load_command_profile_from_str(&fixture(syntax)).unwrap();
        assert_eq!(
            profile.identity.execution_domain,
            ProfileExecutionDomain::External
        );
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let parsed = parse_command("launcher command", ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!("{syntax}")
        };
        assert_eq!(
            collect_dispatch_command_candidates(&r.bound)[0].lookup_domain,
            expected
        );
    }
    assert!(
        load_command_profile_from_str(&fixture(
            "lookup_domain: external\n          module_runtime: python"
        ))
        .is_err()
    );
}
#[test]
fn modules_never_fall_back_to_same_named_executables() {
    assert!(!resolved_in(
        "printf SAFE",
        CommandLookupDomain::Module("python".into())
    ));
    assert!(resolved_in(
        "pytest --help",
        CommandLookupDomain::Module("python".into())
    ));
}
#[test]
fn entering_a_real_shell_resets_its_command_lookup_domain() {
    let mut bindings = SessionBindings::new();
    bindings.set_command_lookup_domain(CommandLookupDomain::External);
    bindings.enter_child_shell_environment();
    assert_eq!(
        bindings.command_lookup_domain(),
        &CommandLookupDomain::Shell
    );
}

#[test]
fn executable_path_normalization_cannot_manufacture_a_builtin_identity() {
    for command in [r"'C:\Windows\command.exe'", r"'C:\Windows\exit.exe' 0"] {
        assert!(
            !resolved_in(command, CommandLookupDomain::Shell),
            "{command}"
        );
    }
}
