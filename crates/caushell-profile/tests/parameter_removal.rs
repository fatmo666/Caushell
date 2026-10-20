//! Parameter strings are inert. The native oracle only runs fixed Bash printf
//! expressions on argv data, inside the test container; it never uses eval.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

fn scalar(expression: &str, bindings: &SessionBindings) -> Option<String> {
    exact_scalar_shell_parameter_reference_value(expression, bindings)
}
fn args(command: &str, bindings: &SessionBindings) -> MaterializedProjectedInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    materialize_projected_invocation(
        &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new()),
        bindings,
    )
}

#[test]
fn four_operators_match_native_bash_across_literals_globs_and_empty_matches() {
    let values = [
        "",
        "a",
        "ab",
        "abba",
        "abc.txt",
        "./src/a.b.txt",
        "/opt/a/b",
        "a b\nc",
        "abc*",
        "[x]",
        "a\\b",
    ];
    let patterns = [
        "", "a", "*", "?", "a*", "*b", "*/", "/*", ".txt", "*.*", "[ab]", "[!ab]", "[^a]", "[[]",
        "[abc", r"\*", "a?", "*/*",
    ];
    let operators = ["#", "##", "%", "%%"];
    let script = r#"while (( $# >= 2 )); do v=$1; p=$2; shift 2; printf '%s\0' "${v#$p}" "${v##$p}" "${v%$p}" "${v%%$p}"; done"#;
    let mut native = std::process::Command::new("/bin/bash");
    native
        .env("LC_ALL", "C")
        .args(["-c", script, "parameter-oracle"]);
    let mut actual = Vec::new();
    for value in values {
        for pattern in patterns {
            native.args([value, pattern]);
            let b = SessionBindings::new()
                .with_exact_scalar("V", value)
                .with_exact_scalar("P", pattern);
            for operator in operators {
                let expression = format!("${{V{operator}$P}}");
                actual.push(
                    scalar(&expression, &b)
                        .unwrap_or_else(|| panic!("{value:?} {pattern:?} {operator}")),
                );
            }
        }
    }
    let result = native.output().unwrap();
    assert!(result.status.success(), "{:?}", result);
    let mut expected = result.stdout.split(|b| *b == 0).collect::<Vec<_>>();
    assert_eq!(expected.pop(), Some(&b""[..]));
    assert_eq!(actual.len(), expected.len());
    for (i, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual.as_bytes(), expected, "fixture {i}");
    }
}

#[test]
fn pattern_quotes_escapes_and_nested_parameters_are_not_outer_shell_source() {
    let b = SessionBindings::new()
        .with_exact_scalar("V", "abc*.txt")
        .with_exact_scalar("P", "*.txt")
        .with_exact_scalar("SUFFIX", ".txt");
    for (expression, expected) in [
        (r#"${V%"*.txt"}"#, "abc"),
        (r"${V%\*.txt}", "abc"),
        ("${V%$P}", "abc*"),
        (r#"${V%"$P"}"#, "abc"),
        ("${V%${SUFFIX}}", "abc*"),
        ("${V%'.txt'}", "abc*"),
    ] {
        assert_eq!(
            scalar(expression, &b).as_deref(),
            Some(expected),
            "{expression}"
        );
    }
    let b = b.with_exact_scalar("V", "a}b}");
    assert_eq!(scalar(r#"${V%"}"}"#, &b).as_deref(), Some("a}b"));
    assert_eq!(scalar(r"${V%\}}", &b).as_deref(), Some("a}b"));
    assert!(exact_shell_parameter_reference("${V%\"unterminated}").is_none());
}

#[test]
fn known_variables_positionals_and_composite_words_share_the_same_evaluator() {
    let mut b = SessionBindings::new().with_exact_scalar("V", "./src/report.html");
    b.set_shell_program_name(Some(SessionValue::exact_scalar("./zero.html")));
    b.replace_positional_parameters_with_exact_scalars(["./one.html"]);
    for (command, expected) in [
        ("touch -- \"${V%.html}.txt\"", "./src/report.txt"),
        ("touch -- \"${V##*/}\"", "report.html"),
        ("touch -- \"${0%.html}.txt\"", "./zero.txt"),
        ("touch -- \"${1%.html}.txt\"", "./one.txt"),
        ("touch -- \"${V#./}\"", "src/report.html"),
        ("touch -- pre\"${V##*/}\".bak", "prereport.html.bak"),
    ] {
        let a = args(command, &b);
        assert_eq!(
            a.invocation.args.last().unwrap().text,
            expected,
            "{command}: {a:?}"
        );
        assert!(a.invocation.args.last().unwrap().runtime_data, "{command}");
    }
    assert_eq!(
        materialize_shell_assignment_value("${V%.html}.txt", true, "string", &b).as_deref(),
        Some("./src/report.txt")
    );
}

#[test]
fn unknown_and_proven_unset_are_distinct() {
    let mut b = SessionBindings::new();
    assert!(scalar("${V%.txt}", &b).is_none());
    assert!(scalar("${1%.txt}", &b).is_none());
    b.remove("V");
    assert_eq!(scalar("${V%.txt}", &b).as_deref(), Some(""));
    assert_eq!(
        args("touch -- \"${V%.txt}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .text,
        ".bak"
    );
    b.replace_positional_parameters_with_exact_scalars(std::iter::empty::<&str>());
    assert_eq!(scalar("${1%.txt}", &b).as_deref(), Some(""));
    assert_eq!(
        args("touch -- \"${1%.txt}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .text,
        ".bak"
    );
    assert!(scalar("${0%.txt}", &b).is_none());
    b.insert_opaque_dynamic("V", "unknown");
    assert!(scalar("${V%.txt}", &b).is_none());
}

#[test]
fn splitting_raw_quotes_and_producer_origins_are_preserved() {
    let mut b = SessionBindings::new().with_exact_scalar("V", "./a b.txt");
    let a = args("touch -- ${V%.txt}.bak", &b);
    assert!(!a.invocation.args.last().unwrap().runtime_data);
    let a = args("touch -- '${V%.txt}.bak'", &b);
    assert_eq!(a.invocation.args.last().unwrap().text, "${V%.txt}.bak");
    let a = args("touch -- \"${V%.txt}.bak\"", &b);
    assert_eq!(a.invocation.args.last().unwrap().text, "./a b.bak");
    b.insert_runtime_produced("V", "./generated.txt", RuntimeProducedValueKind::Path);
    let a = args("touch -- \"${V%.txt}.bak\"", &b);
    assert!(
        matches!(
            a.arg_resolutions.last(),
            Some(ValueMaterialization::ResolvedRuntimeProduced { .. })
        ),
        "{a:?}"
    );
}

#[test]
fn locale_sensitive_dynamic_extended_and_over_budget_patterns_stay_unknown() {
    let b = SessionBindings::new().with_exact_scalar("V", "abc.txt");
    for expression in [
        "${V%$UNKNOWN}",
        "${V%$(echo txt)}",
        "${V%[a-z]*}",
        "${V%[[:alpha:]]*}",
        "${V%@(txt|html)}",
    ] {
        assert!(scalar(expression, &b).is_none(), "{expression}");
    }
    let b = b.with_exact_scalar("V", "é.txt");
    assert!(scalar("${V#?}", &b).is_none());
    assert_eq!(scalar("${V%.txt}", &b).as_deref(), Some("é"));
    let b = b
        .with_exact_scalar("V", "a".repeat(1200))
        .with_exact_scalar("P", "?".repeat(250));
    assert!(scalar("${V%$P}", &b).is_none());
}

fn paths(roots: &[&str]) -> RuntimeArgumentDomain {
    RuntimeArgumentDomain::PathSet {
        roots: roots.iter().map(|r| r.to_string()).collect(),
        may_escape: false,
    }
}
#[test]
fn bounded_suffix_changes_retain_roots_without_fabricating_a_filename() {
    let mut b = SessionBindings::new();
    b.insert_argument_domain("F", paths(&["./"]));
    let a = args("mv -- \"$F\" \"${F%.html}.txt\"", &b);
    let domain = a
        .invocation
        .args
        .last()
        .unwrap()
        .runtime_argument_domain
        .as_ref()
        .unwrap();
    assert!(
        matches!(domain, RuntimeArgumentDomain::PathSet { roots, may_escape: false } if roots.contains(&"./".into())),
        "{a:?}"
    );
    for command in [
        "touch -- \"${F%.txt}\"",
        "touch -- \"${F%/*}.bak\"",
        "touch -- \"${F%.txt}..\"",
        "touch -- \"${F%.txt}$UNKNOWN\"",
    ] {
        assert!(
            args(command, &b)
                .invocation
                .args
                .last()
                .unwrap()
                .runtime_argument_domain
                .is_none(),
            "{command}"
        );
    }
}

#[test]
fn prefix_domains_and_generated_affixes_are_transformed_only_when_proved() {
    let mut b = SessionBindings::new();
    b.insert_argument_domain("F", paths(&["./src/"]));
    let a = args("touch -- \"${F#./}.bak\"", &b);
    assert!(
        matches!(a.invocation.args.last().unwrap().runtime_argument_domain.as_ref(), Some(RuntimeArgumentDomain::PathTemplate { roots, suffix, .. }) if roots == &["src/"] && suffix == ".bak"),
        "{a:?}"
    );
    assert!(
        args("touch -- \"${F#./src/}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .runtime_argument_domain
            .is_none()
    );
    b.insert_argument_domain(
        "F",
        RuntimeArgumentDomain::GeneratedFileName {
            prefix: "/tmp/tmp.".into(),
            suffix: ".txt".into(),
        },
    );
    let a = args("touch -- \"${F%.txt}.bak\"", &b);
    assert!(
        matches!(a.invocation.args.last().unwrap().runtime_argument_domain.as_ref(), Some(RuntimeArgumentDomain::GeneratedFileName { prefix, suffix }) if prefix == "/tmp/tmp." && suffix == ".bak"),
        "{a:?}"
    );
}

#[test]
fn positional_domains_have_frame_lifetimes_and_do_not_survive_replacement() {
    let mut b = SessionBindings::new();
    b.set_shell_program_name(Some(SessionValue::opaque_dynamic("program")));
    b.replace_positional_parameters([SessionValue::opaque_dynamic("arg")]);
    b.set_positional_argument_domain(0, paths(&["./zero/"]));
    b.set_positional_argument_domain(1, paths(&["./one/"]));
    assert!(
        args("touch -- \"${1%.txt}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .runtime_argument_domain
            .is_some()
    );
    b.replace_positional_parameters_with_exact_scalars(["/opt/new.txt"]);
    assert!(b.positional_argument_domain(1).is_none());
    assert!(b.positional_argument_domain(0).is_some());
    assert_eq!(
        args("touch -- \"${1%.txt}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .text,
        "/opt/new.bak"
    );
    b.forget_positional_parameters();
    assert!(scalar("${1%.txt}", &b).is_none());
    b.enter_child_shell_environment();
    assert!(b.positional_argument_domain(0).is_none());
}

#[test]
fn abstract_proofs_reject_nonstandard_splitting_and_marker_collisions() {
    let mut b = SessionBindings::new();
    b.insert_argument_domain(
        "F",
        RuntimeArgumentDomain::GeneratedFileName {
            prefix: "/tmp/tmp.".into(),
            suffix: ".txt".into(),
        },
    );
    b.insert_exact_scalar("IFS", "t");
    assert!(
        args("touch -- ${F%.txt}.bak", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .runtime_argument_domain
            .is_none()
    );
    assert!(
        args("touch -- \"${F%.txt}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .runtime_argument_domain
            .is_some()
    );
    b.set_shell_program_name(Some(SessionValue::opaque_dynamic("program")));
    b.set_positional_argument_domain(0, paths(&["./"]));
    b.insert_exact_scalar("P", "__CAUSHELL_PARAMETER_DOMAIN__");
    assert!(
        args("touch -- \"$P${0}.bak\"", &b)
            .invocation
            .args
            .last()
            .unwrap()
            .runtime_argument_domain
            .is_none()
    );
}
