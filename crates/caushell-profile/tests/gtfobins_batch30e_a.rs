//! Batch 30e group A profile semantics. Commands are parsed as data only.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("arj", include_str!("../profiles/arj.yaml")),
    ("links", include_str!("../profiles/links.yaml")),
    ("w3m", include_str!("../profiles/w3m.yaml")),
    ("xmore", include_str!("../profiles/xmore.yaml")),
    ("xpad", include_str!("../profiles/xpad.yaml")),
    ("yelp", include_str!("../profiles/yelp.yaml")),
    ("alpine", include_str!("../profiles/alpine.yaml")),
    ("mutt", include_str!("../profiles/mutt.yaml")),
    ("urlget", include_str!("../profiles/urlget.yaml")),
    ("pandoc", include_str!("../profiles/pandoc.yaml")),
];

fn bind(profile_source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(profile_source).unwrap();
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
            other => panic!("unexpected value for {name}: {other:?}"),
        })
        .collect()
}

fn projected_values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| p.projected_values.iter().flatten())
        .map(|v| match &v.resolution {
            SemanticValueResolution::Known(text) => text.clone(),
            other => panic!("unexpected projection for {name}: {other:?}"),
        })
        .collect()
}

fn effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|e| e.kind == kind)
}

#[test]
fn all_profiles_load_with_research_and_limits() {
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
fn archive_and_document_tools_bind_real_input_and_output_roles() {
    let arj = bind(
        PROFILES[0].1,
        "arj a /tmp/project/archive /opt/shared/input.txt",
    );
    assert_eq!(arj.form_id.as_str(), "add_archive_files");
    assert_eq!(values(&arj, "archive_base"), ["/tmp/project/archive"]);
    assert_eq!(values(&arj, "input_paths"), ["/opt/shared/input.txt"]);
    assert!(effect(&arj, EffectKind::ReadPath));
    assert!(effect(&arj, EffectKind::WritePath));

    let pandoc_read = bind(PROFILES[9].1, "pandoc -t plain /opt/shared/input.md");
    assert_eq!(pandoc_read.form_id.as_str(), "convert_input_to_stdout");
    assert_eq!(
        values(&pandoc_read, "input_paths"),
        ["/opt/shared/input.md"]
    );
    assert!(effect(&pandoc_read, EffectKind::ReadPath));
    assert!(!effect(&pandoc_read, EffectKind::WritePath));

    let pandoc_write = bind(PROFILES[9].1, "pandoc -t plain -o /tmp/project/output.txt");
    assert_eq!(pandoc_write.form_id.as_str(), "convert_stdin_to_file");
    assert_eq!(
        values(&pandoc_write, "output_path"),
        ["/tmp/project/output.txt"]
    );
    assert!(effect(&pandoc_write, EffectKind::WritePath));

    let pandoc_both = bind(
        PROFILES[9].1,
        "pandoc -t plain /opt/shared/input.md -o /tmp/project/output.txt",
    );
    assert_eq!(pandoc_both.form_id.as_str(), "convert_input_to_file");
    assert_eq!(
        values(&pandoc_both, "input_paths"),
        ["/opt/shared/input.md"]
    );
    assert_eq!(
        values(&pandoc_both, "output_path"),
        ["/tmp/project/output.txt"]
    );
    assert!(effect(&pandoc_both, EffectKind::ReadPath));
    assert!(effect(&pandoc_both, EffectKind::WritePath));

    let pandoc_stdout = bind(PROFILES[9].1, "pandoc -t plain -o -");
    assert_eq!(pandoc_stdout.form_id.as_str(), "convert_stdin_to_stdout");
    assert!(!effect(&pandoc_stdout, EffectKind::WritePath));
}

#[test]
fn fixed_file_read_forms_preserve_input_path_provenance() {
    for (i, command, form, slot, path) in [
        (
            1,
            "links /opt/shared/secret",
            "display_file_in_tui",
            "input_paths",
            "/opt/shared/secret",
        ),
        (
            2,
            "w3m -dump /opt/shared/secret",
            "dump_file",
            "input_paths",
            "/opt/shared/secret",
        ),
        (
            3,
            "xmore /opt/shared/secret",
            "display_file_in_gui",
            "input_paths",
            "/opt/shared/secret",
        ),
        (
            4,
            "xpad -f /opt/shared/secret",
            "open_file",
            "input_path",
            "/opt/shared/secret",
        ),
        (
            6,
            "alpine -F /opt/shared/secret",
            "read_file_as_message",
            "input_path",
            "/opt/shared/secret",
        ),
        (
            7,
            "mutt -F /opt/shared/config",
            "load_config_file",
            "config_paths",
            "/opt/shared/config",
        ),
        (
            8,
            "urlget - /opt/shared/secret",
            "copy_file_to_stdout",
            "input_path",
            "/opt/shared/secret",
        ),
    ] {
        let bound = bind(PROFILES[i].1, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert_eq!(values(&bound, slot), [path], "{command}");
        assert!(
            effect(&bound, EffectKind::ReadPath),
            "{command}: {bound:#?}"
        );
    }
    let yelp = bind(PROFILES[5].1, "yelp man:/opt/shared/secret");
    assert_eq!(yelp.form_id.as_str(), "display_man_uri");
    assert_eq!(values(&yelp, "document_uri"), ["man:/opt/shared/secret"]);
    assert_eq!(
        projected_values(&yelp, "input_paths"),
        ["/opt/shared/secret"]
    );
    assert!(effect(&yelp, EffectKind::ReadPath));

    let mutt = bind(PROFILES[7].1, "mutt -F /opt/shared/config");
    assert_eq!(mutt.form_id.as_str(), "load_config_file");
    assert_eq!(
        values(&mutt, "config_paths"),
        ["/opt/shared/config"],
        "{mutt:#?}"
    );
    assert!(effect(&mutt, EffectKind::ReadPath));
    assert!(effect(&mutt, EffectKind::ExecutePayload));

    let lua = bind(
        PROFILES[9].1,
        "pandoc -L /opt/shared/filter.lua /tmp/project/in.md",
    );
    assert_eq!(lua.form_id.as_str(), "convert_input_to_stdout");
    assert_eq!(values(&lua, "lua_filter_paths"), ["/opt/shared/filter.lua"]);
    assert!(effect(&lua, EffectKind::ExecutePayload));
}

#[test]
fn option_boundaries_do_not_claim_arbitrary_file_reads_or_write_targets() {
    let arj_print = bind(PROFILES[0].1, "arj p /opt/shared/archive");
    assert_eq!(arj_print.form_id.as_str(), "print_archive_file");
    assert_eq!(values(&arj_print, "archive_base"), ["/opt/shared/archive"]);
    assert!(effect(&arj_print, EffectKind::ReadPath));

    let arj_extract = bind(PROFILES[0].1, "arj e x /tmp/project/");
    assert_eq!(arj_extract.form_id.as_str(), "extract_archive_files");
    assert!(effect(&arj_extract, EffectKind::ReadPath));
    assert!(
        effect(&arj_extract, EffectKind::WritePath),
        "unknown extraction destinations remain represented"
    );

    let w3m_no_dump = bind(PROFILES[2].1, "w3m -dump /opt/shared/page");
    assert_eq!(w3m_no_dump.form_id.as_str(), "dump_file");
    let pandoc_input = bind(PROFILES[9].1, "pandoc /opt/shared/input.md");
    assert!(effect(&pandoc_input, EffectKind::ReadPath));
    assert!(!effect(&pandoc_input, EffectKind::WritePath));
}
