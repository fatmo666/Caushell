//! procps-ng watch argv contracts; no sample command is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn bind(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!("{command}")
    };
    assert!(
        !r.bound.operation_semantics_unresolved,
        "{command}: {:?}",
        r.bound
    );
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    r.bound
}

#[test]
fn shell_mode_joins_all_command_arguments_with_native_quote_removal() {
    for (command, program) in [
        ("watch -n 1 date", "date"),
        (
            "watch -n10 cat /tmp/iostat.running",
            "cat /tmp/iostat.running",
        ),
        ("watch -tdn0.5 ps -mo pid,tid", "ps -mo pid,tid"),
        (
            "watch --interval=0.5 --differences=permanent ls -l",
            "ls -l",
        ),
        ("watch -d -q3 -p -b -c -e -g -t -w ls -l", "ls -l"),
        ("watch -d ls -l", "ls -l"),
        ("watch -dx ls -l", "ls -l"),
        ("watch 'ls -l | grep foo'", "ls -l | grep foo"),
        ("watch printf '%s' 'a b'", "printf %s a b"),
        (
            "watch -- printf -- --exec --help",
            "printf -- --exec --help",
        ),
        ("watch ls --version", "ls --version"),
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "repeat_shell_command", "{command}");
        let p = collect_dispatch_command_projection(&b);
        assert!(p.unresolved.is_empty(), "{command}: {p:?}");
        assert_eq!(p.resolved.len(), 1, "{command}");
        assert_eq!(p.resolved[0].command.text, "/bin/sh");
        assert_eq!(
            p.resolved[0]
                .argv
                .iter()
                .map(|a| a.text.as_str())
                .collect::<Vec<_>>(),
            ["-c", program]
        );
        assert!(p.resolved[0].stdin_from_parent);
        assert!(p.resolved[0].stdout_to_parent);
    }
}

#[test]
fn exec_mode_preserves_argv_instead_of_parsing_shell_operators() {
    for command in [
        "watch -x printf '%s' 'a b' '; rm /opt/file'",
        "watch --exec -n1 -- printf '%s' 'a b' '; rm /opt/file'",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "repeat_exec_command");
        let p = collect_dispatch_command_projection(&b);
        assert!(p.unresolved.is_empty());
        assert_eq!(p.resolved.len(), 1);
        assert_eq!(p.resolved[0].command.text, "printf");
        assert_eq!(
            p.resolved[0]
                .argv
                .iter()
                .map(|a| a.text.as_str())
                .collect::<Vec<_>>(),
            ["%s", "a b", "; rm /opt/file"]
        );
    }
    let b = bind("watch -x printf -- '%s' '--exec'");
    let p = collect_dispatch_command_projection(&b);
    assert_eq!(
        p.resolved[0]
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["--", "%s", "--exec"]
    );
}

#[test]
fn help_and_version_do_not_dispatch_the_displayed_tail() {
    for command in [
        "watch --help",
        "watch -v",
        "watch -h rm /opt/file",
        "watch --version --exec rm /opt/file",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "information");
        assert!(collect_dispatch_command_candidates(&b).is_empty());
    }
}
