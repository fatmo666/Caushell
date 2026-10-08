//! Batch 30g group A profile semantics. These strings are parsed as argv; no recipe is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("apport-cli", include_str!("../profiles/apport-cli.yaml")),
    ("asterisk", include_str!("../profiles/asterisk.yaml")),
    ("bconsole", include_str!("../profiles/bconsole.yaml")),
    ("debugfs", include_str!("../profiles/debugfs.yaml")),
    ("ginsh", include_str!("../profiles/ginsh.yaml")),
    ("iftop", include_str!("../profiles/iftop.yaml")),
    ("jtag", include_str!("../profiles/jtag.yaml")),
    ("minicom", include_str!("../profiles/minicom.yaml")),
    ("scanmem", include_str!("../profiles/scanmem.yaml")),
    ("tdbtool", include_str!("../profiles/tdbtool.yaml")),
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

#[test]
fn all_ten_profiles_load_with_provenance_and_limitations() {
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
fn native_escape_surfaces_are_bound_without_parsing_prompt_input_as_argv() {
    for (index, command, expected_form) in [
        (0, "apport-cli -f", "report_with_pager"),
        (1, "asterisk -r", "remote_cli"),
        (2, "bconsole", "interactive_console"),
        (3, "debugfs", "filesystem_debugger"),
        (4, "ginsh", "symbolic_shell"),
        (5, "iftop", "traffic_monitor"),
        (6, "jtag --interactive", "interactive_jtag_shell"),
        (7, "minicom -D /dev/null", "serial_terminal"),
        (8, "scanmem", "process_memory_debugger"),
        (9, "tdbtool", "database_tool"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        let expected_form = if expected_form == "report_with_pager" {
            "file_bug_report_with_pager"
        } else {
            expected_form
        };
        assert_eq!(
            bound.form_id.as_str(),
            expected_form,
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn config_read_and_load_are_explicit_and_distinct_from_console_commands() {
    let bound = bind(PROFILES[2].1, "bconsole -c /opt/shared/bconsole.conf");
    assert_eq!(bound.form_id.as_str(), "console_with_config");
    assert!(has_effect(&bound, EffectKind::ReadPath), "{bound:#?}");
    assert!(has_effect(&bound, EffectKind::LoadConfig), "{bound:#?}");
    assert!(
        has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
        "{bound:#?}"
    );
}

#[test]
fn minicom_startup_script_is_an_opaque_runsafe_payload_reference() {
    let bound = bind(
        PROFILES[7].1,
        "minicom -D /dev/null -S /tmp/project/minicom.run",
    );
    assert_eq!(bound.form_id.as_str(), "serial_terminal_with_script");
    assert!(
        has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
        "{bound:#?}"
    );
    assert!(has_effect(&bound, EffectKind::ExecutePayload), "{bound:#?}");
    assert!(bound.bound_parameters.iter().any(|parameter|
        parameter.name.as_str() == "script_path"
            && parameter.values.iter().any(|value| matches!(value, BoundValue::Argument { text, .. } if text == "/tmp/project/minicom.run"))
    ), "{bound:#?}");
}

#[test]
fn outer_flags_and_ordinary_controls_do_not_become_native_prompt_commands() {
    let asterisk = bind(PROFILES[1].1, "asterisk -V");
    assert_eq!(asterisk.form_id.as_str(), "version");
    assert!(!has_effect(
        &asterisk,
        EffectKind::OpenInteractiveEscapeSurface
    ));

    let jtag = bind(PROFILES[6].1, "jtag --version");
    assert_eq!(jtag.form_id.as_str(), "version");
    assert!(!has_effect(&jtag, EffectKind::OpenInteractiveEscapeSurface));

    let apport = bind(PROFILES[0].1, "apport-cli -u 123");
    assert_eq!(apport.form_id.as_str(), "other_report_mode");
    assert!(!has_effect(
        &apport,
        EffectKind::OpenInteractiveEscapeSurface
    ));

    let debugfs = bind(PROFILES[3].1, "debugfs -R stats /dev/null");
    assert_eq!(debugfs.form_id.as_str(), "direct_native_request");
    assert!(
        has_effect(&debugfs, EffectKind::ExecutePayload),
        "{debugfs:#?}"
    );
    assert!(!has_effect(
        &debugfs,
        EffectKind::OpenInteractiveEscapeSurface
    ));

    let debugfs_file = bind(
        PROFILES[3].1,
        "debugfs -f /tmp/project/debugfs.cmd /dev/null",
    );
    assert_eq!(debugfs_file.form_id.as_str(), "native_command_file");
    assert!(
        has_effect(&debugfs_file, EffectKind::ReadPath),
        "{debugfs_file:#?}"
    );
    assert!(
        has_effect(&debugfs_file, EffectKind::ExecutePayload),
        "{debugfs_file:#?}"
    );

    let minicom = bind(PROFILES[7].1, "minicom -s");
    assert!(has_effect(
        &minicom,
        EffectKind::OpenInteractiveEscapeSurface
    ));
}
