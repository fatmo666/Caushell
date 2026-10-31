use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationArtifactResult, SessionBindings, load_command_profile_from_str,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::{PathNamespaceEffect, ShellKind};

fn resolve(command: &str, renamed: bool) -> caushell_profile::ResolvedInvocationArtifact {
    let source = include_str!("../profiles/postconf.yaml");
    let source = if renamed {
        source.replace(
            "canonical_name: postconf",
            "canonical_name: alternate_config_editor",
        )
    } else {
        source.into()
    };
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
            .unwrap();
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        )
    else {
        panic!("{command}")
    };
    resolved
}

#[test]
fn config_edits_use_declarative_file_effects_even_for_a_renamed_tool() {
    for command in [
        "alternate_config_editor -e setting=value",
        "alternate_config_editor setting=value",
        "alternate_config_editor -h setting=value",
        "alternate_config_editor -X setting",
        "alternate_config_editor '-#' setting",
        "alternate_config_editor -Me 'svc/inet=inet n - n - - smtpd'",
        "alternate_config_editor -Fe svc/inet/chroot=n",
        "alternate_config_editor -Pe svc/inet/setting=value",
        "alternate_config_editor -MX svc/inet",
    ] {
        let r = resolve(command, true);
        assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath
                    && e.namespace_effect == Some(PathNamespaceEffect::DirectoryTreeWrite)),
            "{command}: {r:#?}"
        );
        assert!(
            r.bound
                .effects
                .iter()
                .all(|e| e.kind != EffectKind::StateOperation
                    && e.kind != EffectKind::DeletePath
                    && e.kind != EffectKind::LoadConfig),
            "{command}"
        );
    }
}

#[test]
fn overrides_and_option_operands_are_not_edit_or_query_operands() {
    for (command, expected) in [
        (
            "postconf -c /workspace/config -e setting=value",
            "/workspace/config",
        ),
        (
            "postconf -c/workspace/config -e setting=value",
            "/workspace/config",
        ),
        ("postconf -c -X -e setting=value", "-X"),
        (
            "postconf -c /outside/config -c /workspace/config -e setting=value",
            "/workspace/config",
        ),
    ] {
        let r = resolve(command, false);
        assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
        let p = r
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "configuration_directory")
            .unwrap();
        assert!(
            matches!(p.values.last().unwrap(), BoundValue::Argument { text, .. } if text == expected),
            "{command}: {p:#?}"
        );
    }
    for command in [
        "postconf -o setting=value -xh other",
        "postconf -C builtin -n",
        "postconf -dh setting",
        "postconf -M",
        "postconf -F svc/inet/chroot",
        "postconf -P svc/inet/setting",
    ] {
        let r = resolve(command, false);
        assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
        assert!(
            r.bound
                .effects
                .iter()
                .all(|e| e.kind != EffectKind::WritePath),
            "{command}"
        );
        assert!(r.bound.effects.iter().filter(|e| e.kind == EffectKind::ReadPath).all(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.relative_to.is_some())), "{command}");
    }
}

#[test]
fn unknown_conflicting_and_late_options_never_get_a_complete_query_contract() {
    for command in [
        "postconf setting -X",
        "postconf setting -e other=value",
        "postconf -c",
        "postconf -o",
        "postconf -e",
        "postconf --help",
        "postconf --version",
        "postconf -n --unknown",
        "postconf -b",
        "postconf -t",
        "postconf -m",
        "postconf -MF",
        "postconf -MP",
        "postconf -FP",
        "postconf -eX setting=value",
    ] {
        let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let registry = ProfileRegistry::built_in().unwrap();
        let r = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        assert!(
            !matches!(&r, ResolveInvocationArtifactResult::Resolved(r) if !r.bound.operation_semantics_unresolved),
            "{command}: {r:#?}"
        );
    }
}
