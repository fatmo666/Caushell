//! Static profile acceptance for group B of the pinned GTFOBins snapshot.
//! Recipes are parsed and inspected as data; none is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("aria2c", include_str!("../profiles/aria2c.yaml")),
    ("tcpdump", include_str!("../profiles/tcpdump.yaml")),
    ("restic", include_str!("../profiles/restic.yaml")),
    ("borg", include_str!("../profiles/borg.yaml")),
    ("logrotate", include_str!("../profiles/logrotate.yaml")),
    ("dmidecode", include_str!("../profiles/dmidecode.yaml")),
    ("ldconfig", include_str!("../profiles/ldconfig.yaml")),
    (
        "update-alternatives",
        include_str!("../profiles/update-alternatives.yaml"),
    ),
    ("varnishncsa", include_str!("../profiles/varnishncsa.yaml")),
    ("hashcat", include_str!("../profiles/hashcat.yaml")),
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

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

fn has_slot_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && match &effect.target {
                EffectTarget::Slot(name) => name.as_str() == slot,
                EffectTarget::ConfiguredPath(target) => target
                    .sources
                    .iter()
                    .any(|source| source.slot.as_str() == slot),
                _ => false,
            }
    })
}

#[test]
fn all_profiles_load_with_primary_research_and_limitations() {
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/source_research")
        );
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/known_limitations")
        );
    }
}

#[test]
fn hooks_and_external_commands_keep_their_native_opaque_boundary() {
    let aria = bind(
        PROFILES[0].1,
        "aria2c --on-download-error=/bin/sh https://download.example/file",
    );
    assert_eq!(aria.form_id.as_str(), "download_with_hook");
    assert_eq!(values(&aria, "hook"), ["/bin/sh"]);
    assert!(has_effect(&aria, EffectKind::ExecutePayload), "{aria:#?}");
    assert!(has_effect(&aria, EffectKind::NetworkEndpoint), "{aria:#?}");
    assert!(has_effect(&aria, EffectKind::WritePath), "{aria:#?}");
    assert!(!has_effect(&aria, EffectKind::DispatchCommand));

    let aria_list = bind(PROFILES[0].1, "aria2c -i /tmp/project/uris");
    assert_eq!(aria_list.form_id.as_str(), "read_input_list");
    assert!(has_slot_effect(
        &aria_list,
        EffectKind::ReadPath,
        "input_list"
    ));
    assert!(has_effect(&aria_list, EffectKind::WritePath));

    let tcpdump = bind(
        PROFILES[1].1,
        "tcpdump -l -n -i lo -w /tmp/project/cap -W 1 -G 1 -z /tmp/project/postrotate",
    );
    assert_eq!(tcpdump.form_id.as_str(), "capture_with_postrotate");
    assert_eq!(
        values(&tcpdump, "postrotate_payload"),
        ["/tmp/project/postrotate"]
    );
    assert!(
        has_effect(&tcpdump, EffectKind::ExecutePayload),
        "{tcpdump:#?}"
    );
    assert!(has_effect(&tcpdump, EffectKind::WritePath), "{tcpdump:#?}");
    assert!(!has_effect(&tcpdump, EffectKind::DispatchCommand));

    let tcpdump_file = bind(
        PROFILES[1].1,
        "tcpdump -l -n -i lo -w /tmp/project/output.pcap -c 1 -Z user",
    );
    assert_eq!(tcpdump_file.form_id.as_str(), "write_capture");
    assert_eq!(
        values(&tcpdump_file, "capture_output"),
        ["/tmp/project/output.pcap"]
    );
    assert!(has_effect(&tcpdump_file, EffectKind::WritePath));

    let restic = bind(
        PROFILES[2].1,
        "restic --password-command='/bin/sh -c \"/bin/sh 0<&2 1<&2\"' backup -r rest:http://backup.example:12345/x /tmp/project/data",
    );
    assert_eq!(restic.form_id.as_str(), "backup_remote_repository");
    assert_eq!(
        values(&restic, "password_command"),
        ["'/bin/sh -c \"/bin/sh 0<&2 1<&2\"'"]
    );
    assert_eq!(values(&restic, "backup_inputs"), ["/tmp/project/data"]);
    assert!(
        has_effect(&restic, EffectKind::ExecutePayload),
        "{restic:#?}"
    );
    // Backend URI projection is an explicit partial: do not fabricate an HTTP
    // endpoint from the raw rest:http://... repository locator.
    assert!(
        !has_effect(&restic, EffectKind::NetworkEndpoint),
        "{restic:#?}"
    );
    assert!(has_effect(&restic, EffectKind::WritePath), "{restic:#?}");
    assert!(!has_effect(&restic, EffectKind::DispatchCommand));

    let restic_environment = bind(
        PROFILES[2].1,
        "RESTIC_PASSWORD_COMMAND='/path/to/command' restic backup",
    );
    assert_eq!(
        restic_environment.form_id.as_str(),
        "backup_local_repository"
    );
    assert!(!has_effect(&restic_environment, EffectKind::ExecutePayload));
    assert!(has_effect(&restic_environment, EffectKind::WritePath));
    // This environment-only source remains an explicit, uncovered limitation.

    let borg = bind(
        PROFILES[3].1,
        "borg extract @:/::: --rsh \"/bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\"",
    );
    assert_eq!(borg.form_id.as_str(), "extract_with_rsh");
    assert!(has_effect(&borg, EffectKind::ExecutePayload), "{borg:#?}");
    assert!(has_effect(&borg, EffectKind::WritePath), "{borg:#?}");
    assert!(!has_effect(&borg, EffectKind::DispatchCommand));

    let logrotate = bind(
        PROFILES[4].1,
        "logrotate -m /tmp/project/mailer -f /tmp/project/logrotate.conf",
    );
    assert_eq!(logrotate.form_id.as_str(), "run_mailer_from_config");
    assert_eq!(
        values(&logrotate, "mailer_command"),
        ["/tmp/project/mailer"]
    );
    assert_eq!(
        values(&logrotate, "config"),
        ["/tmp/project/logrotate.conf"]
    );
    assert!(
        has_effect(&logrotate, EffectKind::ReadPath),
        "{logrotate:#?}"
    );
    assert!(
        has_effect(&logrotate, EffectKind::ExecutePayload),
        "{logrotate:#?}"
    );
    assert!(
        has_effect(&logrotate, EffectKind::WritePath),
        "{logrotate:#?}"
    );

    let log_file = bind(PROFILES[4].1, "logrotate -l /tmp/project/run.log DATA");
    assert_eq!(log_file.form_id.as_str(), "write_log");
    assert_eq!(values(&log_file, "config"), ["DATA"]);
    assert!(has_slot_effect(
        &log_file,
        EffectKind::WritePath,
        "log_file"
    ));
    assert!(has_effect(&log_file, EffectKind::ReadPath));
}

#[test]
fn explicit_path_roles_and_read_only_boundaries_remain_distinct() {
    let dmi = bind(
        PROFILES[5].1,
        "dmidecode --no-sysfs -d /tmp/project/input.dmi --dump-bin /tmp/project/dump.bin",
    );
    assert_eq!(dmi.form_id.as_str(), "dump_binary");
    assert!(has_slot_effect(&dmi, EffectKind::ReadPath, "dmi_source"));
    assert!(has_slot_effect(&dmi, EffectKind::WritePath, "dump_output"));

    let cache = bind(PROFILES[6].1, "ldconfig -p");
    assert_eq!(cache.form_id.as_str(), "list_cache");
    assert!(has_effect(&cache, EffectKind::ReadPath));
    assert!(!has_effect(&cache, EffectKind::WritePath));
    let rebuild = bind(PROFILES[6].1, "ldconfig -f /tmp/project/ld.so.conf");
    assert_eq!(rebuild.form_id.as_str(), "configure_cache");
    assert_eq!(values(&rebuild, "config_file"), ["/tmp/project/ld.so.conf"]);
    assert!(has_effect(&rebuild, EffectKind::ReadPath));
    assert!(has_effect(&rebuild, EffectKind::WritePath));

    let alternatives = bind(
        PROFILES[7].1,
        "update-alternatives --force --install /tmp/project/tool tool /tmp/project/tool.real 0",
    );
    assert_eq!(alternatives.form_id.as_str(), "install_link");
    assert_eq!(values(&alternatives, "link_path"), ["/tmp/project/tool"]);
    assert!(has_effect(&alternatives, EffectKind::WritePath));
    assert!(!has_effect(&alternatives, EffectKind::ExecutePayload));

    let logs = bind(
        PROFILES[8].1,
        "varnishncsa -g request -q 'ReqURL ~ \"/probe\"' -F '%{header}i' -w /tmp/project/access.log",
    );
    assert_eq!(logs.form_id.as_str(), "write_selected_logs");
    assert_eq!(values(&logs, "output_file"), ["/tmp/project/access.log"]);
    assert!(has_slot_effect(&logs, EffectKind::WritePath, "output_file"));
    assert!(!has_effect(&logs, EffectKind::NetworkEndpoint));
}

#[test]
fn hashcat_preserves_input_output_and_default_potfile_writes() {
    let explicit = bind(
        PROFILES[9].1,
        "hashcat -m 0 --quiet --potfile-disable -o /tmp/project/cracked --outfile-format=2 --outfile-autohex-disable /tmp/project/hash /tmp/project/words",
    );
    assert_eq!(explicit.form_id.as_str(), "crack_with_output");
    assert_eq!(values(&explicit, "hash_file"), ["/tmp/project/hash"]);
    assert_eq!(values(&explicit, "wordlist"), ["/tmp/project/words"]);
    assert_eq!(values(&explicit, "output_file"), ["/tmp/project/cracked"]);
    assert!(has_effect(&explicit, EffectKind::ReadPath), "{explicit:#?}");
    assert!(has_slot_effect(
        &explicit,
        EffectKind::WritePath,
        "output_file"
    ));

    let default_potfile = bind(
        PROFILES[9].1,
        "hashcat /tmp/project/hash /tmp/project/words",
    );
    assert_eq!(default_potfile.form_id.as_str(), "crack");
    assert!(has_effect(&default_potfile, EffectKind::WritePath));

    let disabled = bind(
        PROFILES[9].1,
        "hashcat --potfile-disable /tmp/project/hash /tmp/project/words",
    );
    assert_eq!(disabled.form_id.as_str(), "crack_without_potfile");
    assert!(!has_effect(&disabled, EffectKind::WritePath));
}
