//! Static profile acceptance for GTFOBins batch 30d group C. Recipes are only
//! parsed as data; no command, listener, or nested payload is executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, collect_dispatch_command_candidates, load_command_profile_from_str,
    resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [&str; 9] = [
    include_str!("../profiles/arch-nspawn.yaml"),
    include_str!("../profiles/genie.yaml"),
    include_str!("../profiles/rustup.yaml"),
    include_str!("../profiles/fzf.yaml"),
    include_str!("../profiles/scrot.yaml"),
    include_str!("../profiles/pidstat.yaml"),
    include_str!("../profiles/sshuttle.yaml"),
    include_str!("../profiles/xdg-user-dir.yaml"),
    include_str!("../profiles/cowsay.yaml"),
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

fn bind(command: &str) -> BoundInvocation {
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

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

#[test]
fn every_group_c_profile_loads_and_cowthink_is_a_native_alias() {
    let registry = registry();
    assert_eq!(
        registry.lookup("cowthink").profile.unwrap().primary_name(),
        "cowsay"
    );
    for source in PROFILES {
        load_command_profile_from_str(source).unwrap();
    }
}

#[test]
fn arch_nspawn_reads_rootfs_configuration_as_opaque_executable_data() {
    let bound = bind("arch-nspawn .");
    assert_eq!(bound.form_id.as_str(), "run_rootfs");
    assert!(has_effect(&bound, EffectKind::ReadPath));
    assert!(has_effect(&bound, EffectKind::ExecutePayload));
    assert!(
        bound
            .effects
            .iter()
            .any(|effect| { matches!(effect.target, EffectTarget::ConfiguredPath(_)) })
    );
}

#[test]
fn explicit_wrapper_commands_keep_the_real_child_and_argv() {
    for (command, child, args) in [
        ("genie -c /usr/bin/id -u", "/usr/bin/id", vec!["-u"]),
        ("rustup run x rustc --version", "rustc", vec!["--version"]),
        ("pidstat -e /bin/sh -p", "/bin/sh", vec!["-p"]),
    ] {
        let bound = bind(command);
        let projected = collect_dispatch_command_candidates(&bound);
        assert!(
            projected.iter().any(|candidate| {
                candidate.command.text == child
                    && candidate
                        .argv
                        .iter()
                        .map(|arg| arg.text.as_str())
                        .eq(args.iter().copied())
            }),
            "{command}: {projected:#?}"
        );
    }
}

#[test]
fn tool_shell_templates_keep_their_declared_string_grammars() {
    let scrot = bind("scrot -e /bin/sh");
    assert_eq!(scrot.form_id.as_str(), "execute_shell_template");
    let scrot_child = collect_dispatch_command_candidates(&scrot);
    assert!(
        scrot_child
            .iter()
            .any(|candidate| candidate.command.text == "/bin/sh")
    );

    let sshuttle = bind("sshuttle -r x --ssh-cmd 'sh -c \"echo SAFE\"' localhost");
    assert_eq!(sshuttle.form_id.as_str(), "proxy_with_ssh_command");
    let ssh_child = collect_dispatch_command_candidates(&sshuttle);
    assert!(
        ssh_child.iter().any(|candidate| {
            candidate.command.text == "sh"
                && candidate
                    .argv
                    .iter()
                    .map(|arg| arg.text.as_str())
                    .eq(["-c", "echo SAFE"])
        }),
        "{ssh_child:#?}"
    );
}

#[test]
fn fzf_bind_payload_is_opaque_and_listener_form_is_separate() {
    let bind_payload = bind("fzf --bind 'enter:execute(/bin/sh)'");
    assert_eq!(bind_payload.form_id.as_str(), "opaque_bind_actions");
    assert!(has_effect(&bind_payload, EffectKind::ExecutePayload));

    let listener = bind("fzf --listen=12345");
    assert_eq!(listener.form_id.as_str(), "listen_tcp");
    assert!(has_effect(&listener, EffectKind::NetworkEndpoint));
}

#[test]
fn xdg_eval_argument_is_not_reparsed_as_a_standalone_shell_program() {
    let bound = bind("xdg-user-dir '}; /bin/sh #'");
    assert_eq!(bound.form_id.as_str(), "eval_argument");
    assert!(has_effect(&bound, EffectKind::ExecutePayload));
    assert!(collect_dispatch_command_candidates(&bound).is_empty());
}

#[test]
fn perl_cowfiles_are_read_and_executed_through_the_alias() {
    for command in [
        "cowsay -f /tmp/custom.cow hello",
        "cowthink -f /tmp/custom.cow hello",
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), "execute_cowfile", "{command}");
        assert!(has_effect(&bound, EffectKind::ReadPath), "{command}");
        assert!(has_effect(&bound, EffectKind::ExecutePayload), "{command}");
    }
}

#[test]
fn scrot_does_not_claim_a_concrete_output_from_format_strings() {
    let capture = bind("scrot '%Y-%m-%d.png'");
    assert_eq!(capture.form_id.as_str(), "capture_to_formatted_filename");
    assert!(has_effect(&capture, EffectKind::WritePath));
    let default_capture = bind("scrot");
    assert_eq!(default_capture.form_id.as_str(), "capture_image");
    assert!(has_effect(&default_capture, EffectKind::WritePath));
    let explicit_capture = bind("scrot /opt/shared/capture.png");
    assert_eq!(
        explicit_capture.form_id.as_str(),
        "capture_to_stable_filename"
    );
    assert!(has_effect(&explicit_capture, EffectKind::WritePath));
}
