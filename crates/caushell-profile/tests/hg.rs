//! Mercurial argv/configuration contracts; samples are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}

fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .filter_map(
            |v| match project_semantic_value(&ValueProjection::Identity, v) {
                Some(SemanticValueResolution::Known(text)) => Some(text),
                _ => None,
            },
        )
        .collect()
}
fn effect(b: &BoundInvocation, kind: EffectKind) -> bool {
    b.effects.iter().any(|e| e.kind == kind)
}

#[test]
fn query_forms_are_disjoint_with_and_without_configuration() {
    for (op, form) in [
        ("status", "native_status_alias"),
        ("st", "native_status_alias"),
        ("log", "native_query"),
        ("summary", "native_query"),
        ("sum", "native_query"),
        ("identify", "native_query"),
        ("id", "native_query"),
    ] {
        for command in [
            format!("hg {op}"),
            format!("hg --config ui.color=never {op}"),
            format!("hg {op} --config=ui.color=never"),
        ] {
            let b = resolve(&command);
            assert_eq!(b.form_id.as_str(), form, "{command}");
            assert_eq!(values(&b, "operation"), [op]);
            assert!(!effect(&b, EffectKind::ExecutePayload), "{command}: {b:#?}");
            assert!(!effect(&b, EffectKind::LoadInProcessCode));
        }
    }
}

#[test]
fn active_hooks_use_canonical_commands_and_preserve_native_payloads() {
    for (op, canonical) in [
        ("status", "status"),
        ("st", "status"),
        ("log", "log"),
        ("summary", "summary"),
        ("sum", "summary"),
        ("identify", "identify"),
        ("id", "identify"),
    ] {
        for phase in ["pre", "post", "fail"] {
            for name in ["", ".audit"] {
                let command =
                    format!("hg --config 'hooks.{phase}-{canonical}{name}=touch /opt/out' {op}");
                let b = resolve(&command);
                assert_eq!(
                    values(&b, "hook_definition"),
                    ["touch /opt/out"],
                    "{command}"
                );
                assert!(effect(&b, EffectKind::ExecuteHook), "{command}: {b:#?}");
                assert!(effect(&b, EffectKind::ExecutePayload));
            }
        }
    }
}

#[test]
fn irrelevant_or_disabled_configuration_does_not_forge_execution() {
    for command in [
        "hg --config 'ui.editor=touch /opt/out' log",
        "hg --config 'hooks.pre-status=touch /opt/out' log",
        "hg --config 'hooks.pre-log=touch /opt/out' status",
        "hg --config 'hooks.precommit=touch /opt/out' status",
        "hg --config 'hooks.priority.pre-status=10' status",
        "hg --config hooks.pre-status= status",
        "hg --config 'alias.other=!touch /opt/out' status",
        "hg --config 'alias.log=!touch /opt/out' status",
        "hg --config 'alias.st=!touch /opt/out' status",
        "hg --config 'alias.status=!touch /opt/out' st",
        "hg --config 'alias.id=!touch /opt/out' identify",
        "hg --config 'alias.sum=!touch /opt/out' summary",
        "hg --config extensions.probe=!/opt/probe.py log",
        "hg --config extensions.probe=! log",
        "hg --config extensions.probe:required=yes log",
        "hg --help --config 'hooks.pre-status=touch /opt/out' status",
        "hg --help --config 'alias.status=log' status",
    ] {
        let b = resolve(command);
        for kind in [
            EffectKind::ExecutePayload,
            EffectKind::ExecuteHook,
            EffectKind::LoadInProcessCode,
        ] {
            assert!(!effect(&b, kind), "{command}: {b:#?}");
        }
    }
}

#[test]
fn extensions_load_before_help_and_keep_the_exact_path() {
    for tail in ["log", "status", "--help", "status --help"] {
        for option in [
            "--config 'extensions.probe = /opt/probe.py'",
            "--config=extensions.probe=/opt/probe.py",
        ] {
            let command = format!("hg {option} {tail}");
            let b = resolve(&command);
            assert_eq!(values(&b, "extension_path"), ["/opt/probe.py"], "{command}");
            assert!(effect(&b, EffectKind::LoadInProcessCode));
            assert!(!effect(&b, EffectKind::ExecuteHook));
        }
    }
}

#[test]
fn empty_extension_value_is_module_loading_not_a_local_path() {
    let b = resolve("hg --config extensions.probe= log");
    assert_eq!(values(&b, "extension_module"), ["probe"]);
    assert!(values(&b, "extension_path").is_empty());
    assert!(effect(&b, EffectKind::LoadInProcessCode));
    assert!(effect(&b, EffectKind::ExecutePayload));
}

#[test]
fn aliases_can_override_queries_without_ambiguous_form_selection() {
    for (op, alias) in [
        ("status", "status"),
        ("st", "st"),
        ("log", "log"),
        ("summary", "summary"),
        ("id", "id"),
    ] {
        for payload in ["!touch /opt/out", "update -C"] {
            let command = format!("hg --config 'alias.{alias}={payload}' {op}");
            let b = resolve(&command);
            assert_eq!(values(&b, "shell_alias_definition"), [payload], "{command}");
            assert!(effect(&b, EffectKind::ExecutePayload));
            assert!(!effect(&b, EffectKind::ExecuteHook));
        }
    }
    let b = resolve("hg --config 'alias.x=!touch /opt/out' x");
    assert_eq!(b.form_id.as_str(), "executable_alias");
    assert_eq!(values(&b, "shell_alias_definition"), ["!touch /opt/out"]);
}

#[test]
fn shell_aliases_execute_before_help_and_multi_name_aliases_can_shadow_queries() {
    for command in [
        "hg --config 'alias.status=!touch /opt/out' status --help",
        "hg --help --config 'alias.status=!touch /opt/out' status",
        "hg --help --config 'alias.x=!touch /opt/out' x",
        "hg --config 'alias.other|status=!touch /opt/out' status",
        "hg --config 'alias.^status=!touch /opt/out' status",
    ] {
        let b = resolve(command);
        assert_eq!(
            values(&b, "shell_alias_definition"),
            ["!touch /opt/out"],
            "{command}"
        );
        assert!(effect(&b, EffectKind::ExecutePayload), "{command}: {b:#?}");
    }
}

#[test]
fn repeated_configuration_keeps_all_distinct_execution_sources() {
    let command = "hg --config ui.color=never --config extensions.a=/opt/a.py --config extensions.b=/opt/b.py --config 'hooks.pre-log=touch /opt/out' log";
    let b = resolve(command);
    assert_eq!(values(&b, "extension_path"), ["/opt/a.py", "/opt/b.py"]);
    assert_eq!(values(&b, "hook_definition"), ["touch /opt/out"]);
    assert_eq!(values(&b, "configuration_override").len(), 4);
}

#[test]
fn config_text_and_terminated_data_cannot_become_controls() {
    for command in [
        "hg --config 'ui.editor=--help' status",
        "hg status -- --config extensions.probe=/opt/probe.py",
        "hg status -- --help",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "native_status_alias");
        assert!(!effect(&b, EffectKind::LoadInProcessCode));
        assert!(!effect(&b, EffectKind::ExecutePayload));
    }
    let b = resolve("hg --config 'hooks.pre-log=--help' log");
    assert_eq!(b.form_id.as_str(), "native_query");
    assert_eq!(values(&b, "hook_definition"), ["--help"]);
    assert!(effect(&b, EffectKind::ExecuteHook));
}
