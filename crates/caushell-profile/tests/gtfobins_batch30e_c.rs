//! Static profile acceptance for GTFOBins batch 30e group C.
//! Payloads and recipes are strings; none are executed.
use caushell_parse::parse_command;
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    collect_dispatch_command_candidates, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [&str; 10] = [
    include_str!("../profiles/acr.yaml"),
    include_str!("../profiles/agetty.yaml"),
    include_str!("../profiles/task.yaml"),
    include_str!("../profiles/tasksh.yaml"),
    include_str!("../profiles/xdotool.yaml"),
    include_str!("../profiles/at.yaml"),
    include_str!("../profiles/zic.yaml"),
    include_str!("../profiles/runscript.yaml"),
    include_str!("../profiles/gtester.yaml"),
    include_str!("../profiles/zip.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .map(|source| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> caushell_profile::BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn every_profile_loads_and_known_entry_forms_resolve() {
    for source in PROFILES {
        load_command_profile_from_str(source).unwrap();
    }
    for (command, expected_form) in [
        ("acr -r ./relative/script", "recovery_mode_source"),
        ("agetty -l /bin/sh tty", "custom_login_program"),
        ("task execute /bin/sh", "execute_command"),
        ("tasksh", "interactive_tasksh"),
        ("xdotool exec --sync /bin/sh", "exec_program"),
        ("at now", "submit_job"),
        (
            "zic -y /tmp/callback /tmp/zones",
            "legacy_year_type_callback",
        ),
        ("runscript /tmp/script", "run_script_file"),
        ("gtester /tmp/test", "run_test_binary"),
        (
            "zip /tmp/archive.zip /etc/hosts -T -TT '/bin/sh #'",
            "test_archive",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(
            bound.form_id.as_str(),
            expected_form,
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn explicit_command_dispatch_keeps_child_identity_and_argv_boundaries() {
    for (command, child, argv) in [
        ("task execute /bin/sh -c 'id'", "/bin/sh", vec!["-c", "id"]),
        ("xdotool exec --sync /bin/sh -p", "/bin/sh", vec!["-p"]),
    ] {
        let bound = bind(command);
        assert!(
            collect_dispatch_command_candidates(&bound)
                .iter()
                .any(|candidate| {
                    candidate.command.text == child
                        && candidate
                            .argv
                            .iter()
                            .map(|arg| arg.text.as_str())
                            .eq(argv.iter().copied())
                }),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn interactive_and_tool_languages_remain_opaque_instead_of_being_reparsed_as_bash() {
    for command in ["agetty -l /bin/sh tty", "zic -y /tmp/callback /tmp/zones"] {
        // Their children receive generated argv; an empty child argv would be
        // invented completeness. Keep the code reference opaque instead.
        assert!(collect_dispatch_command_candidates(&bind(command)).is_empty());
    }
    let tasksh = bind("tasksh");
    assert_eq!(tasksh.form_id.as_str(), "interactive_tasksh");
    assert!(collect_dispatch_command_candidates(&tasksh).is_empty());

    let runscript = bind("runscript /tmp/minicom.script");
    assert_eq!(runscript.form_id.as_str(), "run_script_file");
    assert!(collect_dispatch_command_candidates(&runscript).is_empty());

    let zip = bind("zip /tmp/archive.zip /etc/hosts -T -TT '/bin/sh #'");
    assert_eq!(zip.form_id.as_str(), "test_archive", "{zip:#?}");
    assert!(collect_dispatch_command_candidates(&zip).is_empty());
}
