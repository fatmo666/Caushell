use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(source: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound,
        ResolveInvocationArtifactResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{source}: {other:#?}"),
    }
}
fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{other:#?}"),
        })
        .collect()
}

#[test]
fn native_attached_and_separate_operands_keep_their_own_argv() {
    for tool in ["gcc", "cc", "g++"] {
        for flags in [
            "-DRELEASE=1 -UOLD -Iheaders -Llib -xc++ -v",
            "-D RELEASE=1 -U OLD -I headers -L lib -x c++ -v",
        ] {
            for source in [
                format!("{tool} {flags} source.c -o build/tool"),
                format!("{tool} source.c {flags} -obuild/tool"),
            ] {
                let r = resolve(&source);
                assert!(!r.operation_semantics_unresolved, "{source}: {r:#?}");
                assert_eq!(values(&r, "input_paths"), ["source.c"]);
                assert_eq!(values(&r, "output_path"), ["build/tool"]);
                assert_eq!(values(&r, "macro_definitions"), ["RELEASE=1"]);
                assert_eq!(values(&r, "macro_undefinitions"), ["OLD"]);
                assert_eq!(values(&r, "search_paths"), ["headers", "lib"]);
                assert_eq!(values(&r, "language_name"), ["c++"]);
            }
        }
    }
}
#[test]
fn macro_values_do_not_become_options_or_code_load_paths() {
    for source in [
        "gcc '-DMESSAGE=-fplugin=/outside/plugin.so' source.c -o build/tool",
        "gcc -D 'MESSAGE=-o /outside/file' source.c -o build/tool",
        "gcc '-DF(x)=((x)+1)' source.c -o build/tool",
    ] {
        let r = resolve(source);
        assert!(!r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert!(
            !r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode)
        );
        assert_eq!(values(&r, "input_paths"), ["source.c"]);
        assert_eq!(values(&r, "output_path"), ["build/tool"]);
    }
}
#[test]
fn linker_forwarding_owns_only_complete_mode_lists() {
    for flags in [
        "-Wl,-Bstatic -Wl,-Bdynamic",
        "-Wl,--as-needed,--no-as-needed",
        "-Wl,--push-state,-Bstatic,--whole-archive,--no-whole-archive,--pop-state",
        "-Wl,--start-group,--end-group",
    ] {
        let source = format!("gcc source.c {flags} -o build/tool");
        let r = resolve(&source);
        assert!(!r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert_eq!(values(&r, "input_paths"), ["source.c"]);
        assert_eq!(values(&r, "output_path"), ["build/tool"]);
    }
    for flags in [
        "-Wl,",
        "-Wl,-Bstatic,",
        "-Wl,-Bstatic,,--as-needed",
        "-Wl,-Map,/outside/map",
        "-Wl,-T,/outside/script",
        "-Wl,-plugin,/outside/plugin.so",
        "-Wl,@/outside/response",
        "-Wl,\"$UNKNOWN\"",
        "-Wl,-Bstatic,-plugin=/outside/p.so",
        "-Wl,-unknown -Wl,-Bstatic",
        "-Wl -Bstatic",
    ] {
        let source = format!("gcc source.c {flags} -o build/tool");
        assert!(resolve(&source).operation_semantics_unresolved, "{source}");
    }
}
#[test]
fn library_names_remain_selectors_with_unproved_native_search() {
    let r = resolve("gcc source.c -lstdc++ -l m -l:vendor.a -o build/tool");
    assert!(!r.operation_semantics_unresolved, "{r:#?}");
    assert_eq!(values(&r, "library_names"), ["stdc++", "m", ":vendor.a"]);
    assert_eq!(values(&r, "input_paths"), ["source.c"]);
    assert!(r.effects.iter().any(|e| e.kind == EffectKind::LoadConfig
        && matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.sources.is_empty())));
}
#[test]
fn invalid_and_missing_operands_keep_known_effects_and_incompleteness() {
    for flags in [
        "-D",
        "-U",
        "-L",
        "-x",
        "-l",
        "-xunknown",
        "-x c++ -xunknown",
        "-D\"$UNKNOWN\"",
        "-l../outside",
        "-L=lib",
        "'-L$SYSROOT/lib'",
        "-I-",
    ] {
        let source = format!("gcc source.c -o build/tool {flags}");
        let r = resolve(&source);
        assert!(r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert!(r.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
    for flags in ["-DRELEASE -Wl,-Bstatic", "-Wl,-unknown"] {
        let r = resolve(&format!(
            "gcc {flags} -fplugin=/outside/p.so source.c -o build/tool"
        ));
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode)
        );
    }
}
#[test]
fn verbose_alone_is_information_but_does_not_suppress_other_effects() {
    let r = resolve("gcc -v");
    assert_eq!(r.form_id.as_str(), "show_verbose_information");
    assert!(r.effects.is_empty(), "{r:#?}");
    let r = resolve("gcc -v source.c -o build/tool");
    assert!(r.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let r = resolve("gcc -v -fplugin=/outside/p.so");
    assert!(
        r.effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}
