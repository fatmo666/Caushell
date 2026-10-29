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
fn debug_levels_and_formats_keep_the_existing_file_effects() {
    for tool in ["gcc", "cc", "g++"] {
        for flag in [
            "-g",
            "-g0",
            "-g1",
            "-g2",
            "-g3",
            "-ggdb",
            "-ggdb0",
            "-ggdb1",
            "-ggdb2",
            "-ggdb3",
            "-gdwarf",
            "-gdwarf-2",
            "-gdwarf-3",
            "-gdwarf-4",
            "-gdwarf-5",
            "-gdwarf32",
            "-gdwarf64",
        ] {
            let command = format!("{tool} {flag} input.c -o build/program");
            let r = resolve(&command);
            assert!(!r.operation_semantics_unresolved, "{command}: {r:#?}");
            assert!(r.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
            assert!(r.effects.iter().any(|e| e.kind == EffectKind::WritePath));
            assert!(
                r.effects
                    .iter()
                    .all(|e| matches!(e.kind, EffectKind::ReadPath | EffectKind::WritePath))
            );
        }
    }
}

#[test]
fn sanitizer_mode_lists_have_native_inline_ownership_and_are_not_paths() {
    for flags in [
        "-fsanitize=address,undefined",
        "-fsanitize=undefined,address,address",
        "-fsanitize=thread",
        "-fsanitize=leak",
        "-fsanitize=hwaddress",
        "-fsanitize=kernel-address,pointer-subtract",
        "-fsanitize=shadow-call-stack",
        "-fsanitize=shift,shift-base,shift-exponent,integer-divide-by-zero",
        "-fsanitize=unreachable,vla-bound,null,return,signed-integer-overflow",
        "-fsanitize=bounds,bounds-strict,alignment,object-size,float-divide-by-zero,float-cast-overflow",
        "-fsanitize=nonnull-attribute,returns-nonnull-attribute,bool,enum,vptr,pointer-overflow,builtin",
        "-fsanitize=kernel-hwaddress,pointer-compare",
        "-fno-sanitize=all",
        "-fsanitize=address -fsanitize=undefined -fno-sanitize=address",
        "-fsanitize='address,undefined' -g3",
        "-g -fno-sanitize=address,undefined",
    ] {
        for command in [
            format!("gcc {flags} input.c -o build/program"),
            format!("gcc input.c {flags} -o build/program"),
        ] {
            let r = resolve(&command);
            assert!(!r.operation_semantics_unresolved, "{command}: {r:#?}");
            assert_eq!(r.form_id.as_str(), "compile_to_explicit_output");
            let inputs = r
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == "input_paths")
                .unwrap();
            assert_eq!(inputs.values.len(), 1, "{command}: {r:#?}");
            assert!(
                matches!(&inputs.values[0], BoundValue::Argument {text, ..} if text == "input.c")
            );
            assert!(
                r.effects
                    .iter()
                    .all(|e| matches!(e.kind, EffectKind::ReadPath | EffectKind::WritePath))
            );
        }
    }
}

#[test]
fn every_unknown_or_partial_mode_keeps_operation_incomplete() {
    for flags in [
        "-fsanitize=all",
        "-fsanitize=unknown",
        "-fsanitize=address,unknown",
        "-fsanitize=unknown -fsanitize=address",
        "-fsanitize=address -fsanitize=unknown -fno-sanitize=all",
        "-fsanitize=",
        "-fsanitize",
        "-fsanitize address",
        "-fsanitize=address,",
        "-fsanitize=address,,undefined",
        "-fsanitize=address,/outside/config",
        "-fsanitize=address-fplugin=/outside/p.so",
        "-fsanitize=\"address,$UNKNOWN\"",
        "-fno-sanitize=\"$UNKNOWN\"",
        "-fno-sanitize=unknown -fno-sanitize=all",
    ] {
        let command = format!("gcc -g {flags} input.c -o build/program");
        let r = resolve(&command);
        assert!(r.operation_semantics_unresolved, "{command}: {r:#?}");
        assert!(!r.residuals.is_empty());
    }
}

#[test]
fn similar_option_prefixes_cannot_hide_extra_outputs_or_controls() {
    for flags in [
        "-g4",
        "-g=3",
        "-ggdb4",
        "-gdwarf-6",
        "-gsplit-dwarf",
        "-ganything",
        "-fsanitize-coverage=trace-pc",
        "-fsanitize-recover=all",
        "-fsanitize-undefined-trap-on-error",
        "-fno-sanitize-recover=all",
    ] {
        let command = format!("gcc -g -fsanitize=address {flags} input.c -o build/program");
        let r = resolve(&command);
        assert!(r.operation_semantics_unresolved, "{command}: {r:#?}");
    }
}

#[test]
fn rejected_sanitizer_values_do_not_discard_code_loads() {
    for flags in [
        "-fsanitize=address",
        "-fsanitize=unknown",
        "-fno-sanitize=all -fsanitize=unknown",
    ] {
        let r = resolve(&format!(
            "gcc -g {flags} -fplugin=/outside/plugin.so input.c -o build/program"
        ));
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode),
            "{r:#?}"
        );
    }
}
