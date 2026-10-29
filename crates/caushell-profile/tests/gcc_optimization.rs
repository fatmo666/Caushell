//! Optimization modes describe compiler intent; they do not authorize outputs.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str, bindings: &SessionBindings) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("unexpected argument: {other:#?}"),
        })
        .collect()
}

#[test]
fn documented_modes_are_whole_options_before_and_after_inputs() {
    for tool in ["gcc", "g++", "cc", "c89", "c99"] {
        for mode in [
            "-O", "-O0", "-O1", "-O2", "-O3", "-Os", "-Og", "-Oz", "-Ofast",
        ] {
            for command in [
                format!("{tool} {mode} input.c -o build/program"),
                format!("{tool} input.c {mode} -o build/program"),
                format!("{tool} -std=c17 -g input.c -o build/program {mode}"),
            ] {
                let bound = resolve(&command, &SessionBindings::new());
                assert!(
                    !bound.operation_semantics_unresolved,
                    "{command}: {bound:#?}"
                );
                assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
                assert_eq!(values(&bound, "input_paths"), ["input.c"]);
                assert_eq!(values(&bound, "output_path"), ["build/program"]);
                assert!(
                    bound
                        .effects
                        .iter()
                        .all(|e| matches!(e.kind, EffectKind::ReadPath | EffectKind::WritePath))
                );
            }
        }
    }
}

#[test]
fn bare_optimization_does_not_consume_the_following_argv_word() {
    for command in [
        "gcc -O 2 input.c -o build/program",
        "gcc 2 -O input.c -o build/program",
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(!bound.operation_semantics_unresolved, "{bound:#?}");
        assert_eq!(values(&bound, "input_paths"), ["2", "input.c"]);
    }
    let bound = resolve("gcc -O -o build/program input.c", &SessionBindings::new());
    assert_eq!(values(&bound, "input_paths"), ["input.c"]);
    assert_eq!(values(&bound, "output_path"), ["build/program"]);
}

#[test]
fn repetitions_preserve_each_option_and_unknown_words_stay_incomplete() {
    for flags in [
        "-O -O0 -O1 -O2 -O3",
        "-Ofast -Os -Og -Oz -O2",
        "-O2 -O2 -O0",
    ] {
        let bound = resolve(
            &format!("gcc {flags} input.c -o build/program"),
            &SessionBindings::new(),
        );
        assert!(!bound.operation_semantics_unresolved, "{flags}: {bound:#?}");
    }
    for flags in [
        "-O4",
        "-O02",
        "-O-1",
        "-O+2",
        "-Ounknown",
        "--O2",
        "-O2extra",
        "-O2=3",
        "-O=2",
        "-O2,fplugin=/outside/plugin.so",
        "-O2-Wall",
        "-Ounknown -O2",
        "-O2 -Ounknown",
        "-Ofast-extra -O0",
        "-O2 -fprofile-generate",
        "-O2 -flto",
        "-O2 -fopt-info=/outside/report",
    ] {
        let bound = resolve(
            &format!("gcc {flags} input.c -o build/program"),
            &SessionBindings::new(),
        );
        assert!(bound.operation_semantics_unresolved, "{flags}: {bound:#?}");
        assert!(!bound.residuals.is_empty());
    }
}

#[test]
fn materialized_flags_are_rechecked_and_partial_flags_have_no_certificate() {
    for mode in ["-O2", "-Og", "-Ounknown"] {
        let bound = resolve(
            "gcc \"$MODE\" input.c -o build/program",
            &SessionBindings::new().with_exact_scalar("MODE", mode),
        );
        assert_eq!(
            bound.operation_semantics_unresolved,
            mode == "-Ounknown",
            "{mode}: {bound:#?}"
        );
    }
    let bound = resolve(
        "gcc -O\"$LEVEL\" input.c -o build/program",
        &SessionBindings::new().with_opaque_dynamic("LEVEL", "unobserved level"),
    );
    assert!(bound.operation_semantics_unresolved, "{bound:#?}");
}

#[test]
fn optimization_never_hides_other_declared_effects() {
    for flags in ["-O2", "-Ounknown -O2"] {
        for (control, effect) in [
            ("-fplugin=/outside/plugin.so", EffectKind::LoadInProcessCode),
            ("-specs=/outside/specs", EffectKind::LoadConfig),
        ] {
            let bound = resolve(
                &format!("gcc {flags} {control} input.c -o build/program"),
                &SessionBindings::new(),
            );
            assert!(
                bound.effects.iter().any(|e| e.kind == effect),
                "{control}: {bound:#?}"
            );
        }
    }
}
