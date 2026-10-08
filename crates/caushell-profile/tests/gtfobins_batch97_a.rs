//! Group A GTFOBins profile bindings. Recipes are modeled as static data and are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 33] = [
    ("autoconf", include_str!("../profiles/autoconf.yaml")),
    ("autoheader", include_str!("../profiles/autoheader.yaml")),
    ("autoreconf", include_str!("../profiles/autoreconf.yaml")),
    ("bundle", include_str!("../profiles/bundle.yaml")),
    ("bundler", include_str!("../profiles/bundler.yaml")),
    ("cabal", include_str!("../profiles/cabal.yaml")),
    ("cobc", include_str!("../profiles/cobc.yaml")),
    ("composer", include_str!("../profiles/composer.yaml")),
    (
        "easy_install",
        include_str!("../profiles/easy_install.yaml"),
    ),
    ("exiftool", include_str!("../profiles/exiftool.yaml")),
    ("gem", include_str!("../profiles/gem.yaml")),
    ("go", include_str!("../profiles/go.yaml")),
    ("java", include_str!("../profiles/java.yaml")),
    ("jjs", include_str!("../profiles/jjs.yaml")),
    ("jrunscript", include_str!("../profiles/jrunscript.yaml")),
    ("latex", include_str!("../profiles/latex.yaml")),
    ("latexmk", include_str!("../profiles/latexmk.yaml")),
    ("lualatex", include_str!("../profiles/lualatex.yaml")),
    ("luatex", include_str!("../profiles/luatex.yaml")),
    ("msfconsole", include_str!("../profiles/msfconsole.yaml")),
    ("pdflatex", include_str!("../profiles/pdflatex.yaml")),
    ("pdftex", include_str!("../profiles/pdftex.yaml")),
    ("puppet", include_str!("../profiles/puppet.yaml")),
    ("rake", include_str!("../profiles/rake.yaml")),
    ("rustc", include_str!("../profiles/rustc.yaml")),
    ("rustdoc", include_str!("../profiles/rustdoc.yaml")),
    ("tex", include_str!("../profiles/tex.yaml")),
    ("vagrant", include_str!("../profiles/vagrant.yaml")),
    ("xelatex", include_str!("../profiles/xelatex.yaml")),
    ("xetex", include_str!("../profiles/xetex.yaml")),
    ("codex", include_str!("../profiles/codex.yaml")),
    ("opencode", include_str!("../profiles/opencode.yaml")),
    ("ffmpeg", include_str!("../profiles/ffmpeg.yaml")),
];

const SOURCE_FORMS: [(&str, &str, &str); 33] = [
    ("autoconf", "autoconf", "configure_tool_callback"),
    ("autoheader", "autoheader", "configure_tool_callback"),
    ("autoreconf", "autoreconf", "configure_tool_callback"),
    ("bundle", "bundle exec /bin/sh", "exec_child"),
    ("bundler", "bundler help", "help_pager"),
    (
        "cabal",
        "cabal exec --project-file=/dev/null -- /bin/sh",
        "exec_child",
    ),
    (
        "cobc",
        "cobc -xFj --frelax-syntax-checks /path/to/temp-file",
        "compile_and_run",
    ),
    ("composer", "composer run-script x", "run_script"),
    ("easy_install", "easy_install .", "install_project"),
    (
        "exiftool",
        "exiftool -filename=/path/to/output-file /path/to/input-file",
        "filename_move",
    ),
    ("gem", "gem open -e '/bin/sh -s' debug", "open_editor"),
    ("go", "go run /path/to/temp-file.go", "run_source_file"),
    ("java", "java Shell", "launch_class"),
    ("jjs", "jjs", "interactive_repl"),
    (
        "jrunscript",
        r###"jrunscript -e 'exec("/bin/sh")'"###,
        "evaluate_javascript",
    ),
    (
        "latex",
        "latex --shell-escape '\\immediate\\write18{/bin/sh}'",
        "shell_escape_source",
    ),
    (
        "latexmk",
        "latexmk -pdf -pdflatex='/bin/sh #' /dev/null",
        "read_tex_input",
    ),
    (
        "lualatex",
        "lualatex -shell-escape '\\directlua{...}\\end'",
        "tex_or_lua_source",
    ),
    (
        "luatex",
        "luatex -shell-escape '\\directlua{...}\\end'",
        "tex_or_lua_source",
    ),
    ("msfconsole", "msfconsole", "interactive_repl"),
    (
        "pdflatex",
        "pdflatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'",
        "shell_escape_source",
    ),
    (
        "pdftex",
        "pdftex --shell-escape '\\write18{/bin/sh}\\end'",
        "shell_escape_source",
    ),
    (
        "puppet",
        "puppet apply -e \"exec { '/bin/sh': }\"",
        "apply_manifest",
    ),
    ("rake", "rake -f /path/to/input-file", "rakefile"),
    ("rustc", "rustc --explain E0001", "explanation_pager"),
    (
        "rustdoc",
        "rustdoc /path/to/input-file",
        "document_source_default_output",
    ),
    (
        "tex",
        "tex --shell-escape '\\immediate\\write18{/bin/sh}'",
        "shell_escape_source",
    ),
    ("vagrant", "vagrant up", "project_up"),
    (
        "xelatex",
        "xelatex --shell-escape '\\immediate\\write18{/bin/sh}'",
        "tex_or_lua_source",
    ),
    (
        "xetex",
        "xetex --shell-escape '\\immediate\\write18{/bin/sh}'",
        "tex_or_lua_source",
    ),
    ("codex", "codex sandbox linux /bin/sh", "sandbox_child"),
    ("opencode", "opencode", "shell_escape_ui"),
    (
        "ffmpeg",
        "ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav",
        "lavfi_ladspa_load",
    ),
];

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected).unwrap();
    bind_invocation(&profile, &projected, &selected)
}

#[test]
fn every_assigned_profile_loads_and_declares_source_and_limit_evidence() {
    assert_eq!(PROFILES.len(), 33);
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(profile.opaque_on_unresolved, "{name}");
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
fn pinned_source_forms_bind_to_the_expected_native_input() {
    for (name, command, expected_form) in SOURCE_FORMS {
        let source = PROFILES.iter().find(|(entry, _)| *entry == name).unwrap().1;
        let bound = bind(source, command);
        assert_eq!(
            bound.form_id.as_str(),
            expected_form,
            "{name}: {command}: {bound:#?}"
        );
        assert!(
            !bound.operation_semantics_unresolved,
            "{name}: {command}: {bound:#?}"
        );
        assert!(!bound.effects.is_empty(), "{name}: {command}");
    }
}

#[test]
fn only_source_demonstrated_child_argv_is_dispatched() {
    for (name, command) in [
        ("bundle", "bundle exec /bin/sh"),
        ("cabal", "cabal exec --project-file=/dev/null -- /bin/sh"),
        (
            "codex",
            "codex sandbox linux /bin/sh -c 'rm /opt/shared/victim'",
        ),
    ] {
        let source = PROFILES.iter().find(|(entry, _)| *entry == name).unwrap().1;
        let bound = bind(source, command);
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::DispatchCommand),
            "{name}: {bound:#?}"
        );
        assert_eq!(
            bound.form_id.as_str(),
            if name == "codex" {
                "sandbox_child"
            } else {
                "exec_child"
            }
        );
        assert!(
            bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "child_command"
                    && p.values.iter().any(
                        |v| matches!(v, BoundValue::Argument { text, .. } if text == "/bin/sh")
                    )),
            "{name}: {bound:#?}"
        );
        if name == "codex" {
            assert!(
                bound
                    .bound_parameters
                    .iter()
                    .any(|p| p.name.as_str() == "child_argv"
                        && p.values.iter().any(
                            |v| matches!(v, BoundValue::Argument { text, .. } if text == "-c")
                        )),
                "{bound:#?}"
            );
            assert!(bound.bound_parameters.iter().any(|p| p.name.as_str() == "child_argv" && p.values.iter().any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "rm /opt/shared/victim"))), "{bound:#?}");
        }
    }
}

#[test]
fn native_code_and_prompt_data_stay_typed_and_unparsed() {
    for (name, command, payload_name) in [
        (
            "jrunscript",
            r###"jrunscript -e 'exec("/bin/sh")'"###,
            "code",
        ),
        (
            "puppet",
            r###"puppet apply -e "exec { '/bin/sh': }""###,
            "manifest",
        ),
        ("rake", "rake -p '...'", "ruby_code"),
    ] {
        let source = PROFILES.iter().find(|(entry, _)| *entry == name).unwrap().1;
        let bound = bind(source, command);
        assert!(
            bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == payload_name
                    && p.values
                        .iter()
                        .any(|v| matches!(v, BoundValue::Argument { .. }))),
            "{name}: {bound:#?}"
        );
        assert!(
            !bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::DispatchCommand),
            "{name}: {bound:#?}"
        );
    }
}

#[test]
fn native_edge_forms_preserve_option_owned_code_and_help_boundaries() {
    let gem = PROFILES.iter().find(|(name, _)| *name == "gem").unwrap().1;
    let default_editor = bind(gem, "gem open debug");
    assert_eq!(default_editor.form_id.as_str(), "open_default_editor");
    assert!(
        default_editor
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    assert!(
        !default_editor
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );
    let install = bind(gem, "gem install --file /tmp/project/installer.rb");
    assert_eq!(
        install.form_id.as_str(),
        "install_ruby_source_file",
        "{install:#?}"
    );
    assert!(install.bound_parameters.iter().any(|p| p.name.as_str() == "ruby_source" && p.values.iter().any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "/tmp/project/installer.rb"))), "{install:#?}");

    let latex = PROFILES
        .iter()
        .find(|(name, _)| *name == "latex")
        .unwrap()
        .1;
    let safe_write18 = bind(
        latex,
        r###"latex --shell-escape '\immediate\write18{echo SAFE}'"###,
    );
    assert_eq!(safe_write18.form_id.as_str(), "shell_escape_source");
    assert!(
        safe_write18
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
    assert!(
        !safe_write18
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );

    let rustc = PROFILES
        .iter()
        .find(|(name, _)| *name == "rustc")
        .unwrap()
        .1;
    let explanation = bind(rustc, "rustc --explain E0001 -o /tmp/project/ignored");
    assert_eq!(
        explanation.form_id.as_str(),
        "explanation_pager",
        "{explanation:#?}"
    );
    assert!(
        !explanation
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath),
        "{explanation:#?}"
    );
    assert!(
        explanation
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "explanation_code"
                && p.values
                    .iter()
                    .any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "E0001"))),
        "{explanation:#?}"
    );
    let parsed_help_output =
        parse_command("rustc --help -o /tmp/project/ignored", ShellKind::Bash).unwrap();
    let projected_help_output = project_invocation(
        &parsed_help_output.commands[0],
        InvocationRuntimeContext::new(),
    );
    let profile = load_command_profile_from_str(rustc).unwrap();
    let selected = select_invocation(&profile, &projected_help_output).unwrap();
    assert_eq!(selected.form.id.as_str(), "show_help");
}

#[test]
fn file_and_conditional_forms_bind_native_operands_without_sample_path_literals() {
    let exiftool = PROFILES
        .iter()
        .find(|(name, _)| *name == "exiftool")
        .unwrap()
        .1;
    let rename = bind(
        exiftool,
        "exiftool -filename=/tmp/project/renamed.jpg /tmp/project/input.jpg",
    );
    assert_eq!(rename.form_id.as_str(), "filename_move", "{rename:#?}");
    assert!(
        rename
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "destination_path"),
        "{rename:#?}"
    );
    assert!(
        rename
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::MovePath),
        "{rename:#?}"
    );
    let query = bind(exiftool, "exiftool /tmp/project/input.jpg");
    assert_eq!(query.form_id.as_str(), "metadata_query", "{query:#?}");
    assert!(
        query
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath),
        "{query:#?}"
    );
    let conditional = bind(exiftool, "exiftool -if 'system(\"/bin/sh\")' /etc/passwd");
    assert_eq!(
        conditional.form_id.as_str(),
        "conditional_perl",
        "{conditional:#?}"
    );
    assert!(
        conditional
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload),
        "{conditional:#?}"
    );

    let latexmk = PROFILES
        .iter()
        .find(|(name, _)| *name == "latexmk")
        .unwrap()
        .1;
    let input = bind(latexmk, "latexmk -dvi /tmp/project/document.tex");
    assert_eq!(input.form_id.as_str(), "read_tex_input", "{input:#?}");
    assert!(
        input.effects.iter().any(|e| e.kind == EffectKind::ReadPath),
        "{input:#?}"
    );

    let opencode = PROFILES
        .iter()
        .find(|(name, _)| *name == "opencode")
        .unwrap()
        .1;
    let query = bind(opencode, "opencode db 'SELECT name FROM project'");
    assert_eq!(query.form_id.as_str(), "database_query", "{query:#?}");
    assert!(query.bound_parameters.iter().any(|p| p.name.as_str() == "sql" && p.values.iter().any(|v| matches!(v, BoundValue::Argument { text, .. } if text == "SELECT name FROM project"))), "{query:#?}");
    assert!(
        query
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload),
        "{query:#?}"
    );
    assert!(
        !query
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::DispatchCommand),
        "{query:#?}"
    );
    let db_ui = bind(opencode, "opencode db");
    assert_eq!(db_ui.form_id.as_str(), "database_ui", "{db_ui:#?}");
    assert!(
        db_ui
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::OpenInteractiveEscapeSurface),
        "{db_ui:#?}"
    );
}
