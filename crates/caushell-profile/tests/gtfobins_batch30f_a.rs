//! Batch 30f group A declarations. Inputs are parsed as data and never run.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("batcat", include_str!("../profiles/batcat.yaml")),
    ("pg", include_str!("../profiles/pg.yaml")),
    ("joe", include_str!("../profiles/joe.yaml")),
    ("ispell", include_str!("../profiles/ispell.yaml")),
    ("ncdu", include_str!("../profiles/ncdu.yaml")),
    ("ranger", include_str!("../profiles/ranger.yaml")),
    ("zathura", include_str!("../profiles/zathura.yaml")),
    ("journalctl", include_str!("../profiles/journalctl.yaml")),
    ("fastfetch", include_str!("../profiles/fastfetch.yaml")),
    ("neofetch", include_str!("../profiles/neofetch.yaml")),
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
fn all_profiles_load_with_source_and_limitations() {
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|e| panic!("{name}: {e}"));
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
fn pager_editor_and_tui_profiles_keep_interactions_out_of_argv() {
    for (index, command, name) in [
        (0, "batcat --paging always /opt/shared/input", "batcat"),
        (1, "pg /opt/shared/input", "pg"),
        (2, "joe", "joe"),
        (3, "ispell /etc/hosts", "ispell"),
        (4, "ncdu /tmp/project", "ncdu"),
        (5, "ranger /tmp/project", "ranger"),
        (6, "zathura /opt/shared/input.pdf", "zathura"),
        (7, "journalctl", "journalctl"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(
            bound.form_id.as_str(),
            if name == "journalctl" {
                "display_journal_with_pager"
            } else if name == "batcat" {
                "display_files_with_pager"
            } else if name == "pg" {
                "page_file"
            } else if name == "joe" {
                "interactive_editor"
            } else if name == "ispell" {
                "interactive_spell_check"
            } else if name == "ncdu" {
                "interactive_disk_usage"
            } else if name == "ranger" {
                "interactive_file_manager"
            } else {
                "view_documents"
            },
            "{command}"
        );
        assert!(
            has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}"
        );
    }
}

#[test]
fn system_info_paths_and_configs_have_distinct_semantics() {
    let fast = bind(PROFILES[8].1, "fastfetch --file /opt/shared/logo.txt");
    assert_eq!(fast.form_id.as_str(), "system_info_with_config_and_logo");
    assert!(has_effect(&fast, EffectKind::ReadPath));
    let fast_cfg = bind(PROFILES[8].1, "fastfetch -c /tmp/project/config.jsonc");
    assert_eq!(
        fast_cfg.form_id.as_str(),
        "system_info_with_config_and_logo"
    );
    assert!(
        has_effect(&fast_cfg, EffectKind::ExecutePayload),
        "{fast_cfg:#?}"
    );

    let neo = bind(PROFILES[9].1, "neofetch --ascii /opt/shared/logo.txt");
    assert_eq!(neo.form_id.as_str(), "system_info_with_config_and_logo");
    assert!(has_effect(&neo, EffectKind::ReadPath));
    let neo_cfg = bind(PROFILES[9].1, "neofetch --config /tmp/project/config.sh");
    assert_eq!(neo_cfg.form_id.as_str(), "system_info_with_config_and_logo");
    assert!(has_effect(&neo_cfg, EffectKind::ExecutePayload));
}

#[test]
fn paging_overrides_and_journal_no_pager_are_separate_forms() {
    let bat = bind(PROFILES[0].1, "batcat --paging never /tmp/project/readme");
    assert_eq!(bat.form_id.as_str(), "plain_output");
    assert!(has_effect(&bat, EffectKind::ReadPath));
    assert!(!has_effect(&bat, EffectKind::OpenInteractiveEscapeSurface));

    let journal = bind(
        PROFILES[7].1,
        "journalctl --no-pager --file /tmp/project/events.journal -n 5",
    );
    assert_eq!(journal.form_id.as_str(), "print_journal_without_pager");
    assert!(has_effect(&journal, EffectKind::ReadPath));
    assert!(!has_effect(
        &journal,
        EffectKind::OpenInteractiveEscapeSurface
    ));
}
