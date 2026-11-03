//! Synthetic argument modeling only; never executes benchmark commands.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| {
        ProfileRegistry::from_profiles(
            [
                include_str!("../profiles/gcc.yaml"),
                include_str!("../profiles/ssh-keygen.yaml"),
            ]
            .into_iter()
            .map(|text| load_command_profile_from_str(text).unwrap())
            .collect(),
        )
        .unwrap()
    });
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn common_symbol_controls_keep_compiler_reads_and_writes() {
    for compiler in ["gcc", "cc", "g++"] {
        let baseline = resolve(&format!("{compiler} -c input.c -o build/output.o"));
        for flag in ["-fcommon", "-fno-common", "-fcommon -fno-common"] {
            let command = format!("{compiler} -c {flag} input.c -o build/output.o");
            let actual = resolve(&command);
            assert!(
                !actual.operation_semantics_unresolved,
                "{command}: {actual:#?}"
            );
            assert_eq!(actual.effects, baseline.effects, "{command}");
            assert!(
                actual
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::WritePath)
            );
        }
    }
}

#[test]
fn common_symbol_flags_do_not_cover_unknown_controls_or_plugins() {
    for flag in ["-fcommon=other", "-fcommon-extra", "-fno-common=other"] {
        let result = resolve(&format!("gcc -fcommon {flag} input.c -o build/output"));
        assert!(result.operation_semantics_unresolved, "{flag}: {result:#?}");
    }
    let plugin = resolve("gcc -fcommon -fplugin=/outside/plugin.so input.c -o build/output");
    assert!(
        plugin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::LoadInProcessCode)
    );
}

#[test]
fn quiet_key_generation_preserves_private_and_public_key_writes() {
    let baseline = resolve("ssh-keygen -t ed25519 -f /outside/key");
    for command in [
        "ssh-keygen -q -t ed25519 -f /outside/key",
        "ssh-keygen -qf /outside/key -t ed25519",
    ] {
        let actual = resolve(command);
        assert!(
            !actual.operation_semantics_unresolved,
            "{command}: {actual:#?}"
        );
        assert_eq!(actual.effects, baseline.effects);
        assert!(
            actual
                .effects
                .iter()
                .filter(|effect| effect.kind == EffectKind::WritePath)
                .count()
                >= 2
        );
    }
}

#[test]
fn quiet_keygen_keeps_provider_loads_and_unknown_options_visible() {
    let provider = resolve("ssh-keygen -q -D /outside/provider.so");
    assert!(
        provider
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::LoadInProcessCode)
    );
    let unknown = resolve("ssh-keygen -q -unknown -f /outside/key");
    assert!(unknown.operation_semantics_unresolved);
    assert!(
        unknown
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
}
