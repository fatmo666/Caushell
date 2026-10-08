//! Batch 30h group C profile contracts. All examples are parsed as CLI argv; no recipe runs.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    (
        "ansible-playbook",
        include_str!("../profiles/ansible-playbook.yaml"),
    ),
    ("bee", include_str!("../profiles/bee.yaml")),
    ("sqlmap", include_str!("../profiles/sqlmap.yaml")),
    ("gcloud", include_str!("../profiles/gcloud.yaml")),
    ("eb", include_str!("../profiles/eb.yaml")),
    ("poetry", include_str!("../profiles/poetry.yaml")),
    ("pipx", include_str!("../profiles/pipx.yaml")),
    ("knife", include_str!("../profiles/knife.yaml")),
    ("volatility", include_str!("../profiles/volatility.yaml")),
    ("forge", include_str!("../profiles/forge.yaml")),
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

fn parameter(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn all_profiles_load_and_publish_source_scope_limits() {
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
fn ansible_playbook_is_executable_yaml_input_not_shell_source() {
    let run = bind(PROFILES[0].1, "ansible-playbook /tmp/project/site.yml");
    assert_eq!(run.form_id.as_str(), "run_playbook");
    assert_eq!(parameter(&run, "playbook_path"), ["/tmp/project/site.yml"]);
    assert!(has_effect(&run, EffectKind::ReadPath), "{run:#?}");
    assert!(has_effect(&run, EffectKind::ExecutePayload), "{run:#?}");
    assert!(!has_effect(&run, EffectKind::DispatchCommand), "{run:#?}");
    assert!(
        !has_effect(&run, EffectKind::OpenInteractiveEscapeSurface),
        "{run:#?}"
    );

    let check = bind(
        PROFILES[0].1,
        "ansible-playbook --syntax-check /tmp/project/site.yml",
    );
    assert_eq!(check.form_id.as_str(), "syntax_check");
    assert!(has_effect(&check, EffectKind::ReadPath), "{check:#?}");
    assert!(
        !has_effect(&check, EffectKind::ExecutePayload),
        "{check:#?}"
    );
}

#[test]
fn inline_foreign_eval_values_remain_opaque_and_separate_from_cli_operands() {
    for (index, command, form, slot, code) in [
        (
            1,
            "bee --root /tmp/project eval 'print(1)'",
            "eval_php",
            "code",
            "print(1)",
        ),
        (
            2,
            "sqlmap -u http://127.0.0.1/item?id=1 --eval 'x=1'",
            "evaluate_python_for_url",
            "evaluation_code",
            "x=1",
        ),
        (
            7,
            "knife exec -E 'puts 1'",
            "exec_eval_ruby",
            "code",
            "puts 1",
        ),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert_eq!(parameter(&bound, slot), [code], "{command}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
    }

    let bee = bind(PROFILES[1].1, "bee --root /tmp/project eval 'print(1)'");
    assert_eq!(parameter(&bee, "framework_root"), ["/tmp/project"]);
    assert_eq!(parameter(&bee, "code"), ["print(1)"]);
    let sqlmap = bind(
        PROFILES[2].1,
        "sqlmap -u http://127.0.0.1/item?id=1 --eval 'x=1'",
    );
    assert_eq!(parameter(&sqlmap, "url"), ["http://127.0.0.1/item?id=1"]);
    assert!(
        has_effect(&sqlmap, EffectKind::NetworkEndpoint),
        "{sqlmap:#?}"
    );
}

#[test]
fn gcloud_and_eb_help_routes_are_possible_pagers_not_fabricated_commands() {
    for (index, command, form) in [
        (3, "gcloud help", "help_search_with_pager"),
        (4, "eb logs", "logs_with_pager"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }
    let gcloud_help = bind(PROFILES[3].1, "gcloud --help");
    assert_eq!(gcloud_help.form_id.as_str(), "information");
    assert!(!has_effect(
        &gcloud_help,
        EffectKind::OpenInteractiveEscapeSurface
    ));
    let eb_help = bind(PROFILES[4].1, "eb --help");
    assert_eq!(eb_help.form_id.as_str(), "information");
    assert!(!has_effect(
        &eb_help,
        EffectKind::OpenInteractiveEscapeSurface
    ));
}

#[test]
fn poetry_run_owns_one_child_command_and_forwards_only_its_arguments() {
    let profile = load_command_profile_from_str(PROFILES[5].1).unwrap();
    let parsed = parse_command(
        "poetry run python /tmp/project/job.py --quiet",
        ShellKind::Bash,
    )
    .unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected).unwrap();
    let bound = bind_invocation(&profile, &projected, &selected);
    assert_eq!(bound.form_id.as_str(), "run_command");
    assert_eq!(parameter(&bound, "run_target"), ["python"]);
    assert_eq!(
        parameter(&bound, "run_args"),
        ["/tmp/project/job.py", "--quiet"]
    );
    assert!(
        has_effect(&bound, EffectKind::DispatchCommand),
        "{bound:#?}"
    );
    assert!(
        !has_effect(&bound, EffectKind::ExecutePayload),
        "{bound:#?}"
    );
}

#[test]
fn pipx_requires_explicit_local_or_package_disambiguation_for_payload_semantics() {
    let local = bind(
        PROFILES[6].1,
        "pipx run --path /tmp/project/script.py --flag",
    );
    assert_eq!(local.form_id.as_str(), "run_local_path");
    assert_eq!(parameter(&local, "script_path"), ["/tmp/project/script.py"]);
    assert!(has_effect(&local, EffectKind::ReadPath), "{local:#?}");
    assert!(has_effect(&local, EffectKind::ExecutePayload), "{local:#?}");
    assert!(
        !has_effect(&local, EffectKind::DispatchCommand),
        "{local:#?}"
    );

    let package = bind(PROFILES[6].1, "pipx run --spec pycowsay pycowsay moo");
    assert_eq!(package.form_id.as_str(), "run_package_spec");
    assert_eq!(parameter(&package, "package_spec"), ["pycowsay"]);
    assert!(
        has_effect(&package, EffectKind::ImportPackage),
        "{package:#?}"
    );
    assert!(
        has_effect(&package, EffectKind::ExecuteImportedPackageLogic),
        "{package:#?}"
    );
    assert!(!has_effect(&package, EffectKind::ReadPath), "{package:#?}");

    let ambiguous = bind(PROFILES[6].1, "pipx run /tmp/project/script.py");
    assert_eq!(ambiguous.form_id.as_str(), "run_ambiguous_app");
    assert!(
        !has_effect(&ambiguous, EffectKind::ReadPath),
        "{ambiguous:#?}"
    );
    assert!(
        has_effect(&ambiguous, EffectKind::ExecutePayload),
        "{ambiguous:#?}"
    );
    assert!(
        !has_effect(&ambiguous, EffectKind::DispatchCommand),
        "{ambiguous:#?}"
    );
}

#[test]
fn knife_script_path_and_inline_ruby_are_distinct_native_inputs() {
    let code = bind(PROFILES[7].1, "knife exec -E 'puts 1'");
    assert_eq!(code.form_id.as_str(), "exec_eval_ruby");
    assert!(has_effect(&code, EffectKind::ExecutePayload), "{code:#?}");
    assert!(!has_effect(&code, EffectKind::ReadPath), "{code:#?}");

    let script = bind(PROFILES[7].1, "knife exec /tmp/project/task.rb");
    assert_eq!(script.form_id.as_str(), "exec_script_file");
    assert_eq!(parameter(&script, "script_path"), ["/tmp/project/task.rb"]);
    assert!(has_effect(&script, EffectKind::ReadPath), "{script:#?}");
    assert!(
        has_effect(&script, EffectKind::ExecutePayload),
        "{script:#?}"
    );
    assert!(
        !has_effect(&script, EffectKind::DispatchCommand),
        "{script:#?}"
    );
}

#[test]
fn volatility_reads_the_memory_image_and_keeps_volshell_opaque() {
    let bound = bind(
        PROFILES[8].1,
        "volatility -f /tmp/project/core-dump volshell",
    );
    assert_eq!(bound.form_id.as_str(), "volshell");
    assert_eq!(
        parameter(&bound, "memory_image"),
        ["/tmp/project/core-dump"]
    );
    assert!(has_effect(&bound, EffectKind::ReadPath), "{bound:#?}");
    assert!(has_effect(&bound, EffectKind::ExecutePayload), "{bound:#?}");
    assert!(
        has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
        "{bound:#?}"
    );
    assert!(
        !has_effect(&bound, EffectKind::DispatchCommand),
        "{bound:#?}"
    );
    assert!(!has_effect(&bound, EffectKind::WritePath), "{bound:#?}");
}

#[test]
fn forge_compiler_selector_is_never_assumed_to_be_a_source_or_path() {
    for value in ["0.8.26", "/tmp/project/compiler"] {
        let command = format!("forge build --use {value}");
        let bound = bind(PROFILES[9].1, &command);
        assert_eq!(
            bound.form_id.as_str(),
            if value.starts_with('/') {
                "build_with_explicit_compiler_path"
            } else {
                "build_with_compiler_selector"
            },
            "{command}: {bound:#?}"
        );
        let slot = if value.starts_with('/') {
            "compiler_path"
        } else {
            "compiler_selector"
        };
        assert_eq!(parameter(&bound, slot), [value]);
        assert_eq!(
            has_effect(&bound, EffectKind::ReadPath),
            value.starts_with('/'),
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn help_and_version_controls_do_not_open_native_escape_surfaces() {
    for (index, command, form) in [
        (3, "gcloud --help", "information"),
        (4, "eb -h", "information"),
        (6, "pipx --help", "information"),
        (7, "knife --help", "information"),
        (8, "volatility --version", "information"),
        (9, "forge --help", "information"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            !has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }
}
