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
        ResolveInvocationArtifactResult::Resolved(r) => r.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn dialects_and_documented_aliases_have_complete_inline_ownership() {
    for standard in [
        "c89",
        "c90",
        "iso9899:1990",
        "iso9899:199409",
        "c99",
        "c9x",
        "iso9899:1999",
        "iso9899:199x",
        "c11",
        "c1x",
        "iso9899:2011",
        "c17",
        "c18",
        "iso9899:2017",
        "iso9899:2018",
        "c2x",
        "gnu89",
        "gnu90",
        "gnu99",
        "gnu9x",
        "gnu11",
        "gnu1x",
        "gnu17",
        "gnu18",
        "gnu2x",
        "c++98",
        "c++03",
        "c++11",
        "c++0x",
        "c++14",
        "c++1y",
        "c++17",
        "c++1z",
        "c++20",
        "c++2a",
        "c++23",
        "c++2b",
        "gnu++98",
        "gnu++03",
        "gnu++11",
        "gnu++0x",
        "gnu++14",
        "gnu++1y",
        "gnu++17",
        "gnu++1z",
        "gnu++20",
        "gnu++2a",
        "gnu++23",
        "gnu++2b",
    ] {
        for tool in ["gcc", "g++", "cc"] {
            for command in [
                format!("{tool} -std={standard} input.c -o build/program"),
                format!("{tool} input.c -std='{standard}' -std={standard} -o build/program"),
            ] {
                let r = resolve(&command);
                assert!(!r.operation_semantics_unresolved, "{command}: {r:#?}");
                let inputs = r
                    .bound_parameters
                    .iter()
                    .find(|p| p.name.as_str() == "input_paths")
                    .unwrap();
                assert_eq!(inputs.values.len(), 1, "{command}");
                assert!(
                    r.effects
                        .iter()
                        .all(|e| matches!(e.kind, EffectKind::ReadPath | EffectKind::WritePath))
                );
            }
        }
    }
    assert!(!resolve("gcc -ansi input.c -o build/program").operation_semantics_unresolved);
}

#[test]
fn unknown_missing_partial_and_similar_options_remain_incomplete() {
    for flags in [
        "-std",
        "-std=",
        "-std c17",
        "-std=unknown",
        "-std=c17,gnu17",
        "-std=c17x",
        "-std=c++26",
        "-std=unknown -std=c17",
        "-std=c17 -std=unknown",
        "-std=\"$UNKNOWN\"",
        "-std=iso9899:$YEAR",
        "-std=c17-fplugin=/outside/p.so",
        "-stdlib=libc++",
        "-std=c17 --unknown",
    ] {
        let command = format!("gcc {flags} input.c -o build/program");
        let r = resolve(&command);
        assert!(r.operation_semantics_unresolved, "{command}: {r:#?}");
        assert!(!r.residuals.is_empty());
    }
}

#[test]
fn invalid_dialects_retain_other_code_loading_effects() {
    for value in ["c17", "unknown", "c17 -std=unknown"] {
        let r = resolve(&format!(
            "gcc -std={value} -fplugin=/outside/p.so input.c -o build/program"
        ));
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode)
        );
    }
}
