//! Profile analysis only; never execute history operations.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> ResolveInvocationArtifactResult {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
    .into_artifact()
}
fn bound(command: &str) -> BoundInvocation {
    match resolve(command) {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            r.bound
        }
        r => panic!("{command}: {r:#?}"),
    }
}

#[test]
fn explicit_write_and_read_modes_keep_real_file_roles() {
    for (command, form, effect) in [
        (
            "history -w /opt/shared/file",
            "write_explicit_file",
            EffectKind::WritePath,
        ),
        (
            "history -a ./file",
            "write_explicit_file",
            EffectKind::WritePath,
        ),
        (
            "history -cw /opt/shared/file",
            "write_explicit_file",
            EffectKind::WritePath,
        ),
        (
            "history -r /opt/shared/file",
            "read_explicit_file",
            EffectKind::ReadPath,
        ),
        (
            "history -n ./file",
            "read_explicit_file",
            EffectKind::ReadPath,
        ),
        (
            "history -cr /opt/shared/file",
            "read_explicit_file",
            EffectKind::ReadPath,
        ),
    ] {
        let b = bound(command);
        assert_eq!(b.form_id.as_str(), form, "{command}");
        assert!(
            b.effects.iter().any(|e| e.kind == effect
                && matches!(&e.target, EffectTarget::Slot(s) if s.as_str()=="filename")),
            "{b:#?}"
        );
        assert!(
            !b.effects.iter().any(|e| e.kind == EffectKind::LoadConfig),
            "{command}"
        );
    }
}

#[test]
fn default_file_uses_shell_variable_not_guessed_path_or_exported_only_value() {
    for command in ["history -a", "history -w", "history -r", "history -n"] {
        let b = bound(command);
        let EffectTarget::ConfiguredPath(t) = &b.effects[0].target else {
            panic!("{b:#?}")
        };
        assert_eq!(t.shell_variable.as_ref().unwrap().name, "HISTFILE");
        assert!(t.shell_variable.as_ref().unwrap().empty_is_unset);
        assert!(t.environment.is_none() && t.default_value.is_none() && t.sources.is_empty());
        assert_eq!(t.missing, ConfiguredPathMissing::Skip);
    }
}

#[test]
fn memory_queries_and_flag_precedence_do_not_invent_file_writes() {
    for command in [
        "history",
        "history 10",
        "history -c",
        "history -d 1",
        "history -d -1",
        "history -d1",
        "history -d 1-3",
        "history -p 'rm /opt/shared/file'",
        "history -s 'rm /opt/shared/file'",
        "history -cw",
        "history -cr",
        "history -sw /opt/shared/file",
        "history -pw /opt/shared/file",
        "history -d 1 -w /opt/shared/file",
        "history -s text -w /opt/shared/file",
        "history --help",
    ] {
        let b = bound(command);
        assert!(b.effects.is_empty(), "{command}: {b:#?}");
    }
}

#[test]
fn only_first_filename_is_used_and_option_parsing_stops_at_operand_or_dash_dash() {
    for (command, first) in [
        ("history -w ./first /opt/shared/ignored", "./first"),
        ("history -w ./first -r", "./first"),
        ("history -w -- -r", "-r"),
    ] {
        let b = bound(command);
        assert_eq!(b.form_id.as_str(), "write_explicit_file");
        let p = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "filename")
            .unwrap();
        assert!(
            matches!(&p.values[0],BoundValue::Argument{text,..} if text==first),
            "{b:#?}"
        );
    }
}

#[test]
fn unknown_options_conflicts_and_missing_offset_remain_unresolved() {
    for command in [
        "history --unknown",
        "history -aw ./file",
        "history -nr ./file",
        "history -d",
    ] {
        match resolve(command) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                assert!(r.bound.operation_semantics_unresolved, "{command}: {r:#?}")
            }
            _ => {}
        }
    }
}
