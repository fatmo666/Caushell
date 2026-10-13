use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn known(command: &str) -> ResolvedInvocationArtifact {
    let r = resolve(command);
    assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
    assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
    assert!(r.proven_stream_contract().is_some(), "{command}: {r:#?}");
    r
}
fn values(r: &ResolvedInvocationArtifact, slot: &str) -> Vec<String> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn information_modes_suppress_native_mutations_and_modifier_effects() {
    for command in [
        "mkdir --help /opt/shared/dir",
        "mkdir --version /opt/shared/dir",
        "mkdir -m 700 --help /opt/shared/dir",
        "mkdir --help -m700 /opt/shared/dir",
        "rmdir --help /opt/shared/dir",
        "rmdir -p --version /opt/shared/dir",
        "mkfifo --help /opt/shared/pipe",
        "mkfifo -m600 --version /opt/shared/pipe",
        "mknod --help /opt/shared/node p",
        "mknod --version /opt/shared/node b 8 0",
        "ln --help .env /opt/shared/link",
        "ln -t /opt/shared --version .env",
        "ln --help -t /opt/shared .env",
        "rm --help /opt/shared/file",
        "rm -rv --version /opt/shared/file",
        "truncate --help -r .env /opt/shared/file",
        "truncate -r .env --version /opt/shared/file",
        "chmod --help -R --reference=.env /opt/shared/file",
        "chmod -R --reference=.env --help /opt/shared/file",
    ] {
        let r = known(command);
        assert!(
            r.bound.effects.is_empty(),
            "{command}: {:?}",
            r.bound.effects
        );
        let streams = r.proven_stream_contract().unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert_eq!(
            streams.stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
}

#[test]
fn modifying_tools_do_not_consume_unrelated_payload_stdin() {
    for command in [
        "mkdir cache/dir",
        "rmdir cache/dir",
        "mkfifo cache/pipe",
        "mknod cache/node p",
        "ln public cache/link",
        "rm cache/file",
        "truncate -s 0 cache/file",
        "truncate -r .env cache/file",
        "chmod 600 cache/file",
    ] {
        let r = known(command);
        let streams = r.proven_stream_contract().unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert_eq!(
            streams.stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin),
            "{command}"
        );
    }
    for command in [
        "mkdir -v cache/dir",
        "rmdir -pv cache/dir",
        "ln -sv public cache/link",
        "rm -v cache/file",
        "chmod -v 600 cache/file",
        "chmod -c 600 cache/file",
    ] {
        let streams = known(command).proven_stream_contract().unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert_eq!(
            streams.stdout_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
    }
}

#[test]
fn option_operands_are_not_extra_filesystem_targets() {
    for command in [
        "mkdir -m 700 cache/dir",
        "mkdir --mode=700 cache/dir",
        "mkdir -m700 cache/dir",
        "mkdir cache/dir -m 700",
        "mkdir -m700 -m755 cache/dir",
        "mkdir --context=lab -p cache/dir",
    ] {
        let r = known(command);
        assert_eq!(values(&r, "directory_paths"), ["cache/dir"], "{command}");
    }
    for command in [
        "mkfifo -m600 cache/pipe",
        "mkfifo --mode=600 cache/pipe",
        "mkfifo cache/pipe -m600",
    ] {
        assert_eq!(
            values(&known(command), "output_paths"),
            ["cache/pipe"],
            "{command}"
        );
    }
    assert_eq!(
        values(&known("mknod -m600 cache/pipe p"), "output_path"),
        ["cache/pipe"]
    );
    for command in [
        "mkdir -- --help",
        "rmdir -- --help",
        "mkfifo -- --help",
        "ln -- --help cache/link",
    ] {
        assert!(!known(command).bound.effects.is_empty(), "{command}");
    }
}

#[test]
fn reference_file_supplies_metadata_not_content_bytes() {
    for command in [
        "truncate -r .env cache/file",
        "truncate -r .env -s +2 cache/file",
        "chmod --reference=.env cache/file",
    ] {
        let r = known(command);
        assert_eq!(values(&r, "reference_path"), [".env"], "{command}");
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::TargetPath),
            "{command}"
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath),
            "{command}"
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::ChangeMode)),
            "{command}"
        );
    }
}

#[test]
fn native_deletes_writes_and_recursive_metadata_effects_are_retained() {
    for (command, effect) in [
        ("mkdir -p -m700 cache/dir", EffectKind::WritePath),
        ("rmdir -p cache/dir", EffectKind::DeletePath),
        ("mkfifo -m600 cache/pipe", EffectKind::WritePath),
        ("mknod cache/node p", EffectKind::MetadataMutation),
        ("ln -s public cache/link", EffectKind::WritePath),
        ("ln -t cache public", EffectKind::WritePath),
        ("rm -rf cache/dir", EffectKind::DeletePath),
        ("truncate -s +2 cache/file", EffectKind::WritePath),
        ("chmod -R +x cache/dir", EffectKind::MetadataMutation),
    ] {
        assert!(
            known(command)
                .bound
                .effects
                .iter()
                .any(|e| e.kind == effect),
            "{command}"
        );
    }
    let r = known("rmdir -p cache/dir");
    assert!(r.bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::DerivedPath(p) if p.rule == caushell_types::DerivedPathRule::LexicalAncestors)));
}
