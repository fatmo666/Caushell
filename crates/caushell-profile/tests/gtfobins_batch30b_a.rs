//! Static wrapper argv and effect tests for the fixed GTFOBins snapshot.
//! Commands are parsed and projected only; none of the child commands run.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const SSH_AGENT: &str = include_str!("../profiles/ssh-agent.yaml");
const DISTCC: &str = include_str!("../profiles/distcc.yaml");
const PKEXEC: &str = include_str!("../profiles/pkexec.yaml");
const PEXEC: &str = include_str!("../profiles/pexec.yaml");
const GRC: &str = include_str!("../profiles/grc.yaml");
const CAPSH: &str = include_str!("../profiles/capsh.yaml");
const CHROOT: &str = include_str!("../profiles/chroot.yaml");
const OPENVT: &str = include_str!("../profiles/openvt.yaml");
const KSU: &str = include_str!("../profiles/ksu.yaml");
const SG: &str = include_str!("../profiles/sg.yaml");

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("unexpected {name} value: {other:?}"),
        })
        .collect()
}

fn assert_form(source: &str, command: &str, form_id: &str) -> BoundInvocation {
    let bound = bind(source, command);
    assert_eq!(bound.form_id.as_str(), form_id, "{command}: {bound:#?}");
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    bound
}

#[test]
fn all_profiles_load_with_snapshot_provenance_and_explicit_boundaries() {
    for (name, source) in [
        ("ssh-agent", SSH_AGENT),
        ("distcc", DISTCC),
        ("pkexec", PKEXEC),
        ("pexec", PEXEC),
        ("grc", GRC),
        ("capsh", CAPSH),
        ("chroot", CHROOT),
        ("openvt", OPENVT),
        ("ksu", KSU),
        ("sg", SG),
    ] {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile.extensions.contains_key("caushell.profile/sources"),
            "{name}"
        );
        assert!(
            profile.extensions.contains_key("caushell.profile/scope"),
            "{name}"
        );
    }
}

#[test]
fn ksu_execute_owns_child_options_and_grc_binds_its_color_value() {
    let bound = assert_form(
        KSU,
        "ksu -q -e sh -c 'touch /opt/shared/out'",
        "execute_command",
    );
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "touch /opt/shared/out"]
    );
    let bound = assert_form(GRC, "grc --pty --colour=off cat .env", "pty_child");
    assert_eq!(values(&bound, "color_mode"), ["off"]);
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "cat");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        [".env"]
    );
}

#[test]
fn daemon_modes_and_remote_compiler_forms_do_not_fake_local_dispatch() {
    for command in [
        "ssh-agent -c touch /opt/shared/out",
        "ssh-agent -s touch /opt/shared/out",
        "ssh-agent -d touch /opt/shared/out",
        "ssh-agent -D touch /opt/shared/out",
    ] {
        let profile = load_command_profile_from_str(SSH_AGENT).unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&profile, &projected).is_err(),
            "{command}"
        );
    }
    for command in [
        "distcc gcc -c file.c",
        "distcc /usr/bin/x86_64-linux-gnu-gcc -c file.c",
        "distcc clang++ file.cpp",
    ] {
        let profile = load_command_profile_from_str(DISTCC).unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&profile, &projected).is_err(),
            "{command}"
        );
    }
    let info = assert_form(DISTCC, "distcc --help touch /opt/shared/out", "information");
    assert!(collect_dispatch_command_candidates(&info).is_empty());
}

#[test]
fn command_wrappers_preserve_child_argv_and_shell_entrypoints() {
    for (source, command, expected_child, args) in [
        (SSH_AGENT, "ssh-agent /bin/sh -p", "/bin/sh", vec!["-p"]),
        (DISTCC, "distcc /bin/sh -p", "/bin/sh", vec!["-p"]),
        (PKEXEC, "pkexec /bin/sh -p", "/bin/sh", vec!["-p"]),
        (PEXEC, "pexec /bin/sh -p", "/bin/sh", vec!["-p"]),
        (GRC, "grc --pty /bin/sh -p", "/bin/sh", vec!["-p"]),
    ] {
        let bound = assert_form(
            source,
            command,
            if source == GRC {
                "pty_child"
            } else if source == PKEXEC {
                "authorized_child"
            } else if source == PEXEC {
                "child_command"
            } else if source == DISTCC {
                "compiler_or_command_child"
            } else {
                "agent_child"
            },
        );
        let child = collect_dispatch_command_candidates(&bound).remove(0);
        assert_eq!(child.command.text, expected_child, "{command}");
        assert_eq!(
            child
                .argv
                .iter()
                .map(|v| v.text.as_str())
                .collect::<Vec<_>>(),
            args,
            "{command}"
        );
    }
}

#[test]
fn environment_and_cwd_changes_are_not_reused_from_the_parent() {
    let default = assert_form(PKEXEC, "pkexec /usr/bin/touch relative", "authorized_child");
    assert!(
        default
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::SetExecutionWorkingDirectory)
    );
    let kept = assert_form(
        PKEXEC,
        "pkexec --keep-cwd /usr/bin/touch relative",
        "authorized_child_keep_cwd",
    );
    assert!(
        !kept
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::SetExecutionWorkingDirectory)
    );

    let agent = assert_form(SSH_AGENT, "ssh-agent /bin/sh", "agent_child");
    let EffectTarget::Dispatch(dispatch) = &agent
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::DispatchCommand)
        .unwrap()
        .target
    else {
        panic!("{agent:#?}")
    };
    assert!(
        dispatch
            .unknown_environment_names
            .iter()
            .any(|n| n == "SSH_AUTH_SOCK")
    );
    assert!(
        dispatch
            .unknown_environment_names
            .iter()
            .any(|n| n == "SSH_AGENT_PID")
    );
}

#[test]
fn source_modes_and_benign_children_are_classified_without_running_them() {
    for (source, command, form) in [
        (SSH_AGENT, "ssh-agent /usr/bin/true", "agent_child"),
        (
            DISTCC,
            "distcc /usr/bin/printf SAFE",
            "compiler_or_command_child",
        ),
        (
            PKEXEC,
            "pkexec --user nobody /usr/bin/true",
            "authorized_child",
        ),
        (PEXEC, "pexec /usr/bin/printf SAFE", "child_command"),
        (GRC, "grc --pty /usr/bin/printf SAFE", "pty_child"),
        (
            OPENVT,
            "openvt -- /usr/bin/printf SAFE",
            "virtual_terminal_child",
        ),
        (KSU, "ksu -q -e /usr/bin/printf SAFE", "execute_command"),
    ] {
        assert_form(source, command, form);
    }
}

#[test]
fn capsh_and_chroot_model_the_implicit_shell_and_namespace_boundary() {
    let shell = assert_form(CAPSH, "capsh --", "bash_after_options");
    let child = collect_dispatch_command_candidates(&shell).remove(0);
    assert_eq!(child.command.text, "/bin/bash");
    assert!(child.argv.is_empty());

    let shell_command = assert_form(CAPSH, "capsh -- -c 'printf SAFE'", "bash_after_options");
    let child = collect_dispatch_command_candidates(&shell_command).remove(0);
    assert_eq!(child.command.text, "/bin/bash");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|v| v.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "printf SAFE"]
    );

    let default = assert_form(CHROOT, "chroot /", "default_shell_at_host_root");
    assert!(
        default
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::SetExecutionWorkingDirectory)
    );
    assert!(
        default
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    let nested = assert_form(CHROOT, "chroot / /bin/sh -p", "execute_at_host_root");
    assert_eq!(values(&nested, "new_root"), ["/"]);
    let child = collect_dispatch_command_candidates(&nested).remove(0);
    assert_eq!(child.command.text, "/bin/sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|v| v.text.as_str())
            .collect::<Vec<_>>(),
        ["-p"]
    );

    let chroot = load_command_profile_from_str(CHROOT).unwrap();
    let parsed = parse_command(
        "chroot /tmp/root /bin/sh -c 'touch relative'",
        ShellKind::Bash,
    )
    .unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(&chroot, &projected).is_err());
}

#[test]
fn group_shell_and_shell_command_have_distinct_semantics() {
    let interactive = assert_form(SG, "sg staff", "interactive_group_shell");
    assert!(
        interactive
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    let command = assert_form(
        SG,
        "sg staff 'printf SAFE'",
        "shell_command_string_without_c",
    );
    assert_eq!(values(&command, "command_string"), ["printf SAFE"]);
    assert!(
        command
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );

    let command_with_c = assert_form(SG, "sg staff -c 'printf SAFE'", "shell_command_string");
    assert_eq!(values(&command_with_c, "command_string"), ["printf SAFE"]);
}

#[test]
fn tty_and_agent_stream_contracts_do_not_overstate_parent_forwarding() {
    let grc = assert_form(GRC, "grc --pty /bin/sh", "pty_child");
    let dispatch = grc
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::DispatchCommand)
        .unwrap();
    let EffectTarget::Dispatch(dispatch) = &dispatch.target else {
        panic!("{dispatch:?}")
    };
    assert!(dispatch.stdin_from_parent);
    assert!(dispatch.stdout_to_parent);
    let no_color = assert_form(GRC, "grc --pty --colour=off /bin/cat", "pty_child");
    assert_eq!(values(&no_color, "color_mode"), ["off"]);

    let vt = assert_form(OPENVT, "openvt -- /bin/sh", "virtual_terminal_child");
    let dispatch = vt
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::DispatchCommand)
        .unwrap();
    let EffectTarget::Dispatch(dispatch) = &dispatch.target else {
        panic!("{dispatch:?}")
    };
    assert!(!dispatch.stdin_from_parent);
    assert!(!dispatch.stdout_to_parent);
}

#[test]
fn incomplete_or_unsupported_invocations_do_not_select_a_shell_form() {
    for (source, command) in [
        (SSH_AGENT, "ssh-agent"),
        (DISTCC, "distcc"),
        (PKEXEC, "pkexec"),
        (PEXEC, "pexec"),
        (GRC, "grc --pty"),
        (OPENVT, "openvt"),
        (KSU, "ksu -q"),
        (KSU, "ksu -q -e"),
        (SSH_AGENT, "ssh-agent -k"),
        (CAPSH, "capsh --chroot=/tmp/root --"),
        (SG, "sg"),
    ] {
        let profile = load_command_profile_from_str(source).unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&profile, &projected).is_err(),
            "{command}"
        );
    }
    let capsh = load_command_profile_from_str(CAPSH).unwrap();
    let parsed = parse_command("capsh --print", ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(&capsh, &projected).is_err());
}
