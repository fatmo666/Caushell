//! Batch 30h group A profile bindings. Source examples are data and are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("irb", include_str!("../profiles/irb.yaml")),
    ("pry", include_str!("../profiles/pry.yaml")),
    ("byebug", include_str!("../profiles/byebug.yaml")),
    ("cpan", include_str!("../profiles/cpan.yaml")),
    ("ghc", include_str!("../profiles/ghc.yaml")),
    ("ghci", include_str!("../profiles/ghci.yaml")),
    ("slsh", include_str!("../profiles/slsh.yaml")),
    ("octave", include_str!("../profiles/octave.yaml")),
    ("jshell", include_str!("../profiles/jshell.yaml")),
    ("dotnet", include_str!("../profiles/dotnet.yaml")),
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

fn has_parameter(bound: &BoundInvocation, name: &str, expected: &str) -> bool {
    bound.bound_parameters.iter().any(|parameter| {
        parameter.name.as_str() == name
            && parameter
                .values
                .iter()
                .any(|value| matches!(value, BoundValue::Argument { text, .. } if text == expected))
    })
}

fn rejects_unmodeled_cli(source: &str, command: &str) -> bool {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    select_invocation(&profile, &projected).is_err()
}

#[test]
fn all_profiles_load_with_source_and_opaque_scope_limitations() {
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
    let octave = load_command_profile_from_str(PROFILES[7].1).unwrap();
    assert_eq!(octave.identity.aliases.len(), 1);
    assert_eq!(octave.identity.aliases[0].as_str(), "octave-cli");
    for (name, source) in [PROFILES[4], PROFILES[5], PROFILES[6], PROFILES[8]] {
        let profile = load_command_profile_from_str(source).unwrap();
        assert!(profile.identity.aliases.is_empty(), "{name}");
    }
}

#[test]
fn opaque_repl_entries_are_distinct_from_shell_argv_and_have_no_inferred_paths() {
    for (index, command, name) in [
        (0, "irb", "irb"),
        (1, "pry", "pry"),
        (3, "cpan", "cpan"),
        (5, "ghci", "ghci"),
        (8, "jshell", "jshell"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(
            bound.form_id.as_str(),
            if name == "cpan" {
                "interactive_console"
            } else {
                "interactive_repl"
            },
            "{command}"
        );
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ReadPath),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::WritePath),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn inline_eval_switch_owns_exactly_its_opaque_code_operand() {
    for (index, command, form, parameter, code) in [
        (
            4,
            "ghc -e 'System.Process.callCommand \"/bin/sh\"'",
            "evaluate_expression",
            "expression",
            "System.Process.callCommand \"/bin/sh\"",
        ),
        (
            5,
            "ghci -e '1 + 1'",
            "evaluate_expression",
            "expression",
            "1 + 1",
        ),
        (
            6,
            "slsh -e 'system(\"/bin/sh\")'",
            "evaluate_expression",
            "expression",
            "system(\"/bin/sh\")",
        ),
        (
            7,
            "octave-cli --eval 'system(\"/bin/sh\")'",
            "evaluate_code",
            "code",
            "system(\"/bin/sh\")",
        ),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            has_parameter(&bound, parameter, code),
            "{command}: {bound:#?}"
        );
        assert_eq!(
            bound
                .bound_parameters
                .iter()
                .filter(|p| p.name.as_str() == parameter)
                .count(),
            1,
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ReadPath),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn byebug_target_script_and_debugger_prompt_have_separate_ownership() {
    let bound = bind(
        PROFILES[2].1,
        "byebug --no-stop /tmp/project/target.rb -- benign-arg",
    );
    assert_eq!(bound.form_id.as_str(), "debug_script");
    assert!(
        has_parameter(&bound, "script_path", "/tmp/project/target.rb"),
        "{bound:#?}"
    );
    assert!(
        has_parameter(&bound, "script_args", "benign-arg"),
        "{bound:#?}"
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
}

#[test]
fn irb_script_and_post_dash_dash_arguments_have_distinct_slots() {
    let bound = bind(PROFILES[0].1, "irb /tmp/project/start.rb -- --noscript");
    assert_eq!(bound.form_id.as_str(), "startup_script");
    assert!(
        has_parameter(&bound, "script_path", "/tmp/project/start.rb"),
        "{bound:#?}"
    );
    assert!(
        has_parameter(&bound, "script_args", "--noscript"),
        "{bound:#?}"
    );
    assert_eq!(
        bound
            .bound_parameters
            .iter()
            .filter(|p| p.name.as_str() == "script")
            .count(),
        1
    );
    assert!(has_effect(&bound, EffectKind::ReadPath), "{bound:#?}");
    assert!(has_effect(&bound, EffectKind::ExecutePayload), "{bound:#?}");
    assert!(
        !has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
        "{bound:#?}"
    );
}

#[test]
fn dotnet_fsi_subcommand_is_not_an_alias_and_script_operand_is_not_reused() {
    let repl = bind(PROFILES[9].1, "dotnet fsi");
    assert_eq!(repl.form_id.as_str(), "fsi_interactive");
    assert!(
        has_effect(&repl, EffectKind::OpenInteractiveEscapeSurface),
        "{repl:#?}"
    );
    assert!(!has_effect(&repl, EffectKind::ReadPath), "{repl:#?}");

    let script = bind(
        PROFILES[9].1,
        "dotnet fsi /tmp/project/sample.fsx -- benign-arg",
    );
    assert_eq!(script.form_id.as_str(), "fsi_script");
    assert!(
        has_parameter(&script, "script_path", "/tmp/project/sample.fsx"),
        "{script:#?}"
    );
    assert!(
        has_parameter(&script, "script_args", "benign-arg"),
        "{script:#?}"
    );
    assert!(has_effect(&script, EffectKind::ReadPath), "{script:#?}");
    assert!(
        has_effect(&script, EffectKind::ExecutePayload),
        "{script:#?}"
    );
    assert!(
        !has_effect(&script, EffectKind::OpenInteractiveEscapeSurface),
        "{script:#?}"
    );
}

#[test]
fn octave_cli_alias_and_information_controls_do_not_add_code_semantics() {
    let cli = bind(PROFILES[7].1, "octave-cli --eval 'disp(1 + 1)'");
    assert_eq!(cli.form_id.as_str(), "evaluate_code");
    assert!(has_parameter(&cli, "code", "disp(1 + 1)"), "{cli:#?}");
    for (index, command) in [
        (0, "irb --help"),
        (1, "pry --help"),
        (2, "byebug --help"),
        (3, "cpan -h"),
        (4, "ghc --version"),
        (5, "ghci --help"),
        (6, "slsh -help"),
        (7, "octave --help"),
        (8, "jshell --version"),
        (9, "dotnet --help"),
    ] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(
            bound.form_id.as_str(),
            "information",
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn undocumented_controls_and_cli_shapes_remain_unresolved() {
    for (index, command) in [
        (1, "pry --version"),
        (3, "cpan --unknown-option"),
        (6, "slsh --version"),
    ] {
        assert!(
            rejects_unmodeled_cli(PROFILES[index].1, command),
            "{command}"
        );
    }
}

#[test]
fn help_precedence_prevents_mixed_eval_from_becoming_payload_execution() {
    for (index, command) in [(4, "ghc -e '1 + 1' --help"), (5, "ghci -e '1 + 1' --help")] {
        let bound = bind(PROFILES[index].1, command);
        assert_eq!(
            bound.form_id.as_str(),
            "information",
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
        assert!(
            !has_effect(&bound, EffectKind::OpenInteractiveEscapeSurface),
            "{command}: {bound:#?}"
        );
    }
}
