use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn artifact(command: &str) -> ResolveInvocationArtifactResult {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    )
}

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    match artifact(command) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn diagnostic_controls_preserve_compiler_inputs_and_outputs() {
    for tool in ["gcc", "cc", "g++"] {
        for flags in [
            "-Wall -Wextra -pedantic",
            "-Wpedantic -pedantic-errors",
            "-w -Werror -Wfatal-errors",
        ] {
            let command = format!("{tool} {flags} source.c -o build/program");
            let r = resolve(&command);
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            assert_eq!(r.bound.form_id.as_str(), "compile_to_explicit_output");
            assert!(
                r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::ReadPath)
            );
            assert!(
                r.bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::WritePath)
            );
        }
    }
}

#[test]
fn version_is_an_information_query_without_a_fictitious_output() {
    let r = resolve("gcc --version");
    assert_eq!(r.bound.form_id.as_str(), "show_version");
    assert!(!r.bound.operation_semantics_unresolved);
    assert!(r.bound.effects.is_empty(), "{r:#?}");
    assert!(r.proven_stream_contract().is_some());
}

#[test]
fn diagnostic_words_do_not_steal_search_or_output_operands() {
    for command in [
        "gcc -Wall -Wfatal-errors -I include -L lib source.c -o build/program",
        "gcc -I include -L lib source.c -o build/program",
    ] {
        let r = resolve(command);
        assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
        let output = r
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "output_path")
            .unwrap();
        assert!(
            matches!(&output.values[0], BoundValue::Argument { text, .. } if text == "build/program")
        );
    }
}

#[test]
fn diagnostics_and_queries_never_cover_unknown_or_code_loading_controls() {
    for command in [
        "gcc -Wall -Wl,-Map=/outside/map source.c -o build/program",
        "gcc --version --unknown-mode",
    ] {
        if let ResolveInvocationArtifactResult::Resolved(r) = artifact(command) {
            assert!(r.bound.operation_semantics_unresolved, "{command}");
        }
    }
    for command in ["gcc -Wall -fplugin=/outside/plugin.so source.c -o build/program"] {
        let r = resolve(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode),
            "{command}: {r:#?}"
        );
    }
}
