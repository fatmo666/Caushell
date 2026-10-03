use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                r.bound.residuals.is_empty(),
                "{command}: {:?}",
                r.bound.residuals
            );
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn writes_sources(bound: &BoundInvocation) -> bool {
    bound.effects.iter().any(|e| {
        e.kind == EffectKind::WritePath
            && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "targets")
    })
}

#[test]
fn ordinary_checks_keep_potential_source_writes() {
    for command in [
        "ruff check src/a.py",
        "ruff check --no-fix src/a.py",
        "ruff check --no-fix-only src/a.py",
        "ruff check --config 'fix=true' src/a.py",
        "ruff check --no-fix --fix src/a.py",
        "ruff check --fix --no-fix --no-fix-only src/a.py",
        "ruff check --add-noqa src/a.py",
        "ruff check --diff --add-noqa src/a.py",
        "ruff check --diff --add-ignore src/a.py",
    ] {
        assert!(writes_sources(&resolve(command)), "{command}");
    }
}

#[test]
fn definite_nonwriting_forms_keep_read_but_not_source_write() {
    for command in [
        "ruff check --diff src/a.py",
        "ruff check --fix --diff src/a.py",
        "ruff check --no-fix --no-fix-only src/a.py",
        "ruff check --show-files src/a.py",
        "ruff check --show-files --add-noqa src/a.py",
        "ruff format --check src/a.py",
        "ruff format --diff src/a.py",
    ] {
        let bound = resolve(command);
        assert!(!writes_sources(&bound), "{command}");
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    }
}

#[test]
fn defaults_and_stdin_have_distinct_effects() {
    for command in ["ruff check", "ruff format"] {
        let bound = resolve(command);
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::WritePath
            && matches!(&e.target, EffectTarget::ToolConventionPath(p) if p.path == ".")));
    }
    for command in [
        "ruff check -",
        "ruff check --fix --stdin-filename /etc/a.py src/ignored.py",
        "ruff format --stdin-filename /etc/a.py",
        "ruff format -",
    ] {
        let bound = resolve(command);
        assert!(
            !bound.effects.iter().any(|e| e.kind == EffectKind::WritePath
                && !matches!(e.target, EffectTarget::ConfiguredPath(_))),
            "{command}: {:?}",
            bound.effects
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin)
        );
        assert!(!bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.purpose == Some(PathPurpose::IncidentalCache))));
    }
}

#[test]
fn nocache_and_inspection_suppress_only_cache_effects() {
    for command in [
        "ruff check --no-cache src/a.py",
        "ruff format -n src/a.py",
        "ruff check --show-settings src/a.py",
    ] {
        let bound = resolve(command);
        assert!(!bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.purpose == Some(PathPurpose::IncidentalCache))), "{command}");
    }
    assert!(writes_sources(&resolve("ruff check --no-cache src/a.py")));
}

#[test]
fn modifiers_consume_values_without_treating_them_as_paths() {
    let bound = resolve(
        "ruff --config cfg.toml check src/a.py --select F401 --output-format json --config 'line-length = 99' --cache-dir cache --output-file result.json",
    );
    let targets = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "targets")
        .unwrap();
    assert_eq!(targets.values.len(), 1);
    assert!(matches!(&targets.values[0], BoundValue::Argument {text,..} if text=="src/a.py"));
}

#[test]
fn argfiles_remain_opaque_in_every_argv_position() {
    for command in [
        "ruff check @args.txt",
        "ruff check --diff -- @args.txt",
        "ruff check --select @args.txt src/a.py",
        "ruff check --config @args.txt src/a.py",
        "ruff format --check --stdin-filename @args.txt",
        "ruff check '$LITERAL'",
        "ruff check \"$UNKNOWN\"",
    ] {
        let bound = resolve(command);
        let opaque = bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None);
        assert_eq!(
            opaque,
            command != "ruff check '$LITERAL'",
            "{command}: {:?}",
            bound.effects
        );
        assert!(!bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ExecutePayload | EffectKind::DispatchCommand
        )));
    }
}

#[test]
fn help_and_info_do_not_write() {
    for command in [
        "ruff --help",
        "ruff --version",
        "ruff check --help --cache-dir /etc/cache --output-file /etc/result src/a.py",
        "ruff format --help /etc/a.py",
        "ruff clean --help",
        "ruff rule --all",
        "ruff config cache-dir",
        "ruff linter",
        "ruff version",
        "ruff help check",
    ] {
        let bound = resolve(command);
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath)),
            "{command}: {:?}",
            bound.effects
        );
    }
}

#[test]
fn watch_does_not_inherit_a_stdin_only_exemption() {
    assert!(writes_sources(&resolve(
        "ruff check --watch --stdin-filename ignored.py /etc/a.py"
    )));
    assert!(writes_sources(&resolve("ruff check --add-noqa -")));
}
