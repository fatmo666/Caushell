//! Static coverage for GTFOBins batch 30g group C. No language payload is run.
use caushell_parse::parse_command;
use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    collect_dispatch_command_candidates, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("lua", include_str!("../profiles/lua.yaml")),
    ("ruby", include_str!("../profiles/ruby.yaml")),
    ("php", include_str!("../profiles/php.yaml")),
    ("guile", include_str!("../profiles/guile.yaml")),
    ("tclsh", include_str!("../profiles/tclsh.yaml")),
    ("wish", include_str!("../profiles/wish.yaml")),
    ("clisp", include_str!("../profiles/clisp.yaml")),
    ("R", include_str!("../profiles/R.yaml")),
    ("julia", include_str!("../profiles/julia.yaml")),
    ("pwsh", include_str!("../profiles/pwsh.yaml")),
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

fn resolve(command: &str) -> caushell_profile::BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(value) => value.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(value),
            ..
        } => value,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn all_profiles_load_and_native_entry_shapes_resolve() {
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
    for (command, expected) in [
        ("lua -e 'print(1)'", "inline_code"),
        ("lua /tmp/project/script.lua", "script_file"),
        ("lua -", "stdin_marker"),
        ("lua -v -e 'print(1)'", "inline_code"),
        ("ruby -e 'puts 1'", "inline_code"),
        ("ruby -e 'puts 1' -e 'puts 2'", "inline_code"),
        ("ruby -v -e 'puts 1'", "inline_code"),
        ("ruby /tmp/project/script.rb", "script_file"),
        ("php -r 'echo 1;'", "inline_code"),
        ("php /tmp/project/script.php", "script_file"),
        ("php -f /tmp/project/script.php", "script_file_option"),
        (
            "php -S 127.0.0.1:8765 -t /tmp/project/www /tmp/project/router.php",
            "built_in_server",
        ),
        ("guile -c '(display 1)'", "inline_code"),
        ("guile /tmp/project/script.scm", "script_file"),
        ("tclsh /tmp/project/script.tcl", "script_file"),
        ("tclsh", "native_repl"),
        ("wish /tmp/project/ui.tcl", "script_file"),
        ("wish", "native_gui_session"),
        ("clisp -x '(+ 1 2)'", "inline_code"),
        ("clisp /tmp/project/script.lisp", "script_file"),
        ("clisp -", "stdin_marker"),
        ("R -e 'print(1)'", "inline_code"),
        (
            "R -e 'print(1)' --args -f /tmp/project/not_a_script.R",
            "inline_code",
        ),
        ("R -f /tmp/project/script.R", "script_file"),
        ("julia -e 'println(1)'", "inline_code"),
        ("julia /tmp/project/script.jl", "script_file"),
        ("pwsh -Command 'Write-Output 1'", "command_string"),
        ("pwsh -File /tmp/project/script.ps1", "script_file"),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), expected, "{command}: {bound:#?}");
    }
}

#[test]
fn foreign_code_is_opaque_and_never_becomes_shell_dispatch() {
    for command in [
        "lua -e 'os.execute(\"/bin/sh\")'",
        "ruby -e 'exec \"/bin/sh\"'",
        "php -r 'system(\"/bin/sh\");'",
        "guile -c '(system \"/bin/sh\")'",
        "tclsh /tmp/project/script.tcl",
        "wish",
        "clisp -x '(ext:run-shell-command \"/bin/sh\")'",
        "R -e 'system(\"/bin/sh\")'",
        "julia -e 'run(`/bin/sh`)'",
        "pwsh",
    ] {
        let bound = resolve(command);
        assert!(
            collect_dispatch_command_candidates(&bound).is_empty(),
            "{command}: {bound:#?}"
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn explicit_script_paths_and_php_server_document_root_remain_distinct() {
    for (command, expected) in [
        ("lua /tmp/project/script.lua", "script_file"),
        ("ruby /tmp/project/script.rb", "script_file"),
        ("php /tmp/project/script.php", "script_file"),
        ("guile /tmp/project/script.scm", "script_file"),
        ("tclsh /tmp/project/script.tcl", "script_file"),
        ("wish /tmp/project/ui.tcl", "script_file"),
        ("clisp /tmp/project/script.lisp", "script_file"),
        ("R -f /tmp/project/script.R", "script_file"),
        ("julia /tmp/project/script.jl", "script_file"),
        ("pwsh -File /tmp/project/script.ps1", "script_file"),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), expected);
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ReadPath),
            "{command}: {bound:#?}"
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }

    let server = resolve("php -S 127.0.0.1:8765 -t /tmp/project/www /tmp/project/router.php");
    assert_eq!(server.form_id.as_str(), "built_in_server");
    assert!(
        server
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
    assert!(
        server
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint)
    );
    assert!(
        server
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload)
    );
}

#[test]
fn benign_controls_resolve_and_unknown_options_do_not_become_supported_forms() {
    for (command, expected) in [
        ("lua -v", "information"),
        ("ruby --version", "information"),
        ("php -v", "information"),
        ("guile --version", "information"),
        ("clisp --version", "information"),
        ("R --version", "information"),
        ("julia --version", "information"),
        ("pwsh -Version", "information"),
    ] {
        assert_eq!(resolve(command).form_id.as_str(), expected, "{command}");
    }
    for command in [
        "lua -Z",
        "ruby -Z",
        "php -Z",
        "guile -Z",
        "tclsh -Z",
        "wish -Z",
        "clisp -Z",
        "R -Z",
        "julia -Z",
        "pwsh -Bogus",
        "R /tmp/project/positional-is-not-a-script.R",
        "R -e 'print(1)' -f /tmp/project/mutually-exclusive.R",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            !matches!(
                resolve_invocation(
                    &registry(),
                    &parsed.commands[0],
                    InvocationRuntimeContext::new()
                ),
                ResolveInvocationResult::Resolved(_)
            ),
            "unknown option unexpectedly resolved: {command}"
        );
    }
}
