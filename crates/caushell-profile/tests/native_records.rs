use caushell_profile::{NativePathOutputPlan as Plan, *};
use caushell_types::{DirectoryEntryKind as K, ShellKind};

fn plan(args: &[&str]) -> Plan {
    Plan::find(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
}

#[test]
fn native_framing_preserves_newlines_spaces_quotes_and_backslashes() {
    let name = "line\n break'\\.csv";
    let path = format!("./input/{name}");
    for (flag, separator) in [("-print", b'\n'), ("-print0", 0)] {
        let p = plan(&["./input", flag]);
        let mut expected = path.as_bytes().to_vec();
        expected.push(separator);
        assert_eq!(
            p.evaluate(&path, name, name, K::File, 1).unwrap().bytes,
            expected
        );
    }
}

#[test]
fn output_format_is_bytes_not_a_path_domain() {
    let p = plan(&["input", "-printf", r"prefix%%/%P\000%f\n%p\377"]);
    assert_eq!(
        p.evaluate("input/a\nb", "a\nb", "a\nb", K::File, 1)
            .unwrap()
            .bytes,
        b"prefix%/a\nb\0a\nb\ninput/a\nb\xff"
    );
    assert_eq!(
        plan(&["input", "-printf", ""])
            .evaluate("input/a", "a", "a", K::File, 1)
            .unwrap()
            .bytes,
        b""
    );
}

#[test]
fn filters_and_depth_do_not_rewrite_native_spellings() {
    let p = plan(&[
        "-P",
        "./input/",
        "-mindepth",
        "1",
        "-maxdepth",
        "2",
        "-type",
        "f",
        "-iname",
        "*.CSV",
    ]);
    assert_eq!(p.roots, vec!["./input/"]);
    assert!(
        !p.evaluate("./input/", "", "input", K::Directory, 0)
            .unwrap()
            .emitted
    );
    assert!(
        p.evaluate("./input/a.csv", "a.csv", "a.csv", K::File, 1)
            .unwrap()
            .emitted
    );
    assert!(
        !p.evaluate("./input/a.csv", "a.csv", "a.csv", K::Symlink, 1)
            .unwrap()
            .emitted
    );
    assert!(
        p.evaluate("./input/é.csv", "é.csv", "é.csv", K::File, 1)
            .is_err()
    );
    assert!(
        plan(&["input", "-path", "*/sub/*.csv"])
            .evaluate("input/sub/a.csv", "sub/a.csv", "a.csv", K::File, 2)
            .unwrap()
            .emitted
    );
}

#[test]
fn unsupported_actions_controls_patterns_and_partial_formats_have_no_plan() {
    for args in [
        vec!["-L", "input"],
        vec!["input", "-follow"],
        vec!["input", "-name", "a?"],
        vec!["input", "-name", "[a-z]"],
        vec!["input", "-fprint", "out"],
        vec!["input", "-exec", "echo", "{}", ";"],
        vec!["input", "-delete"],
        vec!["input", "-printf", r"%p\c"],
        vec!["input", "-printf", r"%10p\0"],
        vec!["input", "-printf", r"%p\400"],
        vec!["input", "-name"],
        vec!["input", "-true", "-a"],
        vec!["input", "-maxdepth", "33"],
        vec!["input", "("],
        vec!["input", "(", ")"],
        vec!["input", "-true", ")"],
        vec!["input", "-not"],
        vec!["input", "-true", "-or"],
        vec!["input", "-false", ","],
        vec!["input", "-false", "-a", "-exec", "unknown", ";"],
        vec!["input", "-mtime", "-1"],
        vec!["input", "-type", "d", ",", "-true", "-print0"],
    ] {
        assert!(
            Plan::find(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err(),
            "{args:?}"
        );
    }
}

#[test]
fn output_allocation_is_bounded_before_materialization() {
    let p = plan(&["input", "-printf", &"%p".repeat(2048)]);
    assert!(p.evaluate(&"a".repeat(128), "a", "a", K::File, 1).is_err());
}

#[test]
fn native_expression_actions_are_not_flattened_into_a_final_filter() {
    // An action that ran is not undone by a later false test or a negation.
    let p = plan(&["input", "-print0", "-false"]);
    assert_eq!(
        p.evaluate("input/a", "a", "a", K::File, 1).unwrap().bytes,
        b"input/a\0"
    );
    let p = plan(&["input", "!", "-prune"]);
    let result = p.evaluate("input", "", "input", K::Directory, 0).unwrap();
    assert!(result.prune && !result.emitted);
    // An explicit output anywhere suppresses default print globally.
    let p = plan(&["input", "-true", "-o", "-print0"]);
    assert!(!p.evaluate("input/a", "a", "a", K::File, 1).unwrap().emitted);
    let p = plan(&["input", "-prune"]);
    let result = p.evaluate("input", "", "input", K::Directory, 0).unwrap();
    assert!(result.prune && result.emitted);
    assert_eq!(result.bytes, b"input\n");
    let p = plan(&["input", "-printf", r"A%p\0", "-a", "-printf", r"B%p\0"]);
    assert_eq!(
        p.evaluate("input", "", "input", K::Directory, 0)
            .unwrap()
            .bytes,
        b"Ainput\0Binput\0"
    );
}

#[test]
fn find_precedence_negation_and_global_depth_are_preserved() {
    let p = plan(&["input", "-name", "a", "-o", "-name", "b", "-print0"]);
    assert!(!p.evaluate("input/a", "a", "a", K::File, 1).unwrap().emitted);
    assert!(p.evaluate("input/b", "b", "b", K::File, 1).unwrap().emitted);
    let p = plan(&[
        "input", "(", "-name", "a", "-o", "-name", "b", ")", "-a", "!", "-type", "l", "-print0",
    ]);
    assert!(p.evaluate("input/a", "a", "a", K::File, 1).unwrap().emitted);
    assert!(
        !p.evaluate("input/a", "a", "a", K::Symlink, 1)
            .unwrap()
            .emitted
    );
    let p = plan(&[
        "input",
        "-false",
        "-a",
        "-maxdepth",
        "1",
        "-o",
        "-print0",
        "-mindepth",
        "1",
    ]);
    assert_eq!(p.max_depth, Some(1));
    assert!(
        !p.evaluate("input", "", "input", K::Directory, 0)
            .unwrap()
            .emitted
    );
    assert!(p.evaluate("input/a", "a", "a", K::File, 1).unwrap().emitted);
    assert!(Plan::find(&vec!["!".into(); 257]).is_err());
}

fn resolve(registry: &ProfileRegistry, text: &str) -> ResolvedInvocationArtifact {
    let parsed = caushell_parse::parse_command(text, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{other:#?}"),
    }
}

#[test]
fn selected_profile_supplies_adapter_independently_of_symbolic_nul_proof() {
    let registry = ProfileRegistry::built_in().unwrap();
    let line = resolve(&registry, "find ./input -name '*.csv'");
    assert!(line.proven_stdout_records().is_none());
    assert!(line.native_stdout_record_plan().unwrap().is_ok());
    let nul = resolve(&registry, "find ./input -print0");
    assert!(nul.proven_stdout_records().is_some());
    assert!(nul.native_stdout_record_plan().unwrap().is_ok());
    let text = include_str!("../profiles/find.yaml")
        .replace("canonical_name: find", "canonical_name: fixture_walk");
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&text).unwrap()])
            .unwrap();
    assert!(
        resolve(&registry, "fixture_walk ./input -print0")
            .native_stdout_record_plan()
            .unwrap()
            .is_ok()
    );
}

#[test]
fn checker_rejects_unknown_native_grammar() {
    let text = include_str!("../profiles/find.yaml").replace("native: find", "native: arbitrary");
    assert!(load_command_profile_from_str(&text).is_err());
}
