use caushell_parse::parse_command;
use caushell_profile::{
    bind_invocation, load_command_profile_from_str, project_invocation, select_invocation,
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext,
};
use caushell_types::ShellKind;

fn profile(name: &str) -> caushell_profile::CommandProfile {
    let source = match name {
        "aa-exec" => include_str!("../profiles/aa-exec.yaml"),
        "aoss" => include_str!("../profiles/aoss.yaml"),
        "choom" => include_str!("../profiles/choom.yaml"),
        "cpulimit" => include_str!("../profiles/cpulimit.yaml"),
        "multitime" => include_str!("../profiles/multitime.yaml"),
        "setarch" => include_str!("../profiles/setarch.yaml"),
        "softlimit" => include_str!("../profiles/softlimit.yaml"),
        "torify" => include_str!("../profiles/torify.yaml"),
        "torsocks" => include_str!("../profiles/torsocks.yaml"),
        "logsave" => include_str!("../profiles/logsave.yaml"),
        other => panic!("unknown fixture profile: {other}"),
    };
    load_command_profile_from_str(source).unwrap()
}

fn bind(name: &str, command: &str) -> Option<BoundInvocation> {
    let profile = profile(name);
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected).ok()?;
    Some(bind_invocation(&profile, &projected, &selected))
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("unexpected {slot} binding: {other:?}"),
        })
        .collect()
}

#[test]
fn all_gtfobins_shell_forms_bind_the_real_child_argv() {
    let cases = [
        (
            "aa-exec",
            "aa-exec -- /bin/sh -p",
            "execute_command",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "aoss",
            "aoss /bin/sh -p",
            "execute_oss_command",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "choom",
            "choom -n 0 -- /bin/sh -p",
            "adjust_and_execute",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "cpulimit",
            "cpulimit -l 100 -f -- /bin/sh -p",
            "limit_and_execute",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "multitime",
            "multitime /bin/sh -p",
            "time_command",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "setarch",
            "setarch -3 -- /bin/sh -p",
            "set_personality_and_execute",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "softlimit",
            "softlimit /bin/sh -p",
            "set_limits_and_execute",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "torify",
            "torify /bin/sh -p",
            "run_application",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "torsocks",
            "torsocks /bin/sh -p",
            "run_application",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-p"][..],
        ),
        (
            "logsave",
            "logsave /dev/null /bin/sh -i -p",
            "log_command_output",
            "child_command",
            "/bin/sh",
            "child_argv",
            &["-i", "-p"][..],
        ),
    ];

    for (name, command, form, command_slot, child, args_slot, args) in cases {
        let bound = bind(name, command).unwrap_or_else(|| panic!("{command}: no selected form"));
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:?}");
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
        assert_eq!(
            values(&bound, command_slot),
            [child],
            "{command}: {bound:?}"
        );
        assert_eq!(values(&bound, args_slot), args, "{command}: {bound:?}");
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::DispatchCommand),
            "{command}: {bound:?}"
        );
        if name == "cpulimit" {
            assert!(
                bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ControlProcess),
                "{command}: {bound:?}"
            );
        }
        if name == "logsave" {
            assert!(
                bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::WritePath),
                "{command}: {bound:?}"
            );
            assert_eq!(values(&bound, "logfile"), ["/dev/null"]);
        }
    }
}

#[test]
fn parent_options_and_delimiters_do_not_consume_child_options_or_data() {
    for (name, command, args_slot, expected) in [
        (
            "aa-exec",
            "aa-exec --profile unconfined -- printf --profile -p",
            "child_argv",
            &["--profile", "-p"][..],
        ),
        (
            "choom",
            "choom --adjust=0 -- printf --adjust -n",
            "child_argv",
            &["--adjust", "-n"][..],
        ),
        (
            "cpulimit",
            "cpulimit --limit=100 -- printf --limit -l",
            "child_argv",
            &["--limit", "-l"][..],
        ),
        (
            "setarch",
            "setarch -3 -- printf -3 --",
            "child_argv",
            &["-3", "--"][..],
        ),
        (
            "logsave",
            "logsave -av /tmp/safe.log printf -a -v",
            "child_argv",
            &["-a", "-v"][..],
        ),
    ] {
        let bound = bind(name, command).unwrap_or_else(|| panic!("{command}: no selected form"));
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
        assert_eq!(values(&bound, args_slot), expected, "{command}: {bound:?}");
    }

    let repeated = bind("multitime", "multitime -n 5 /usr/bin/printf SAFE").unwrap();
    assert_eq!(repeated.form_id.as_str(), "time_command");
    assert!(!repeated.operation_semantics_unresolved, "{repeated:?}");
    assert_eq!(values(&repeated, "child_command"), ["/usr/bin/printf"]);
    assert_eq!(values(&repeated, "child_argv"), ["SAFE"]);
    assert_eq!(values(&repeated, "run_count"), ["5"]);
}

#[test]
fn unknown_parent_options_missing_operands_and_unsupported_shapes_stay_unresolved() {
    for (name, command) in [
        ("aa-exec", "aa-exec --mystery /bin/true"),
        ("aa-exec", "aa-exec --profile"),
        ("aoss", "aoss"),
        ("choom", "choom -n"),
        ("choom", "choom -p 1"),
        ("cpulimit", "cpulimit -l"),
        ("cpulimit", "cpulimit -p 1 -l 50"),
        ("multitime", "multitime -o 'cat > /tmp/out' /usr/bin/true"),
        ("multitime", "multitime -q /usr/bin/printf SAFE"),
        ("setarch", "setarch"),
        ("setarch", "setarch --list"),
        ("softlimit", "softlimit"),
        ("torify", "torify"),
        ("torsocks", "torsocks --shell"),
        ("logsave", "logsave /tmp/only-logfile"),
        ("logsave", "logsave /tmp/log -"),
    ] {
        if let Some(bound) = bind(name, command) {
            assert!(
                bound.operation_semantics_unresolved || !bound.residuals.is_empty(),
                "{command}: {bound:?}"
            );
        }
    }
}
