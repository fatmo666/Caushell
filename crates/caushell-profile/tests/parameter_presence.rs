use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

fn scalar(expression: &str, b: &SessionBindings) -> Option<String> {
    exact_scalar_shell_parameter_reference_value(expression, b)
}

#[test]
fn missing_observations_and_uncertain_bindings_never_select_a_default() {
    let mut b = SessionBindings::new();
    for parameter in ["V", "0", "1", "10"] {
        for operator in [
            "-fallback",
            ":-fallback",
            "+alternative",
            ":+alternative",
            "/x/y",
            "//x/y",
            "%x",
        ] {
            let expr = format!("${{{parameter}{operator}}}");
            assert_eq!(scalar(&expr, &b), None, "{expr}");
        }
    }
    b.insert_opaque_dynamic("V", "conditional assignment, possibly unset");
    assert_eq!(scalar("${V+alternative}", &b), None);
    assert_eq!(scalar("${V:-fallback}", &b), None);
    b.insert_exact_scalar("V", "old");
    b.mark_variable_presence_unknown("V");
    assert_eq!(scalar("${V+alternative}", &b), None);
    assert_eq!(scalar("${V:-fallback}", &b), None);
}

#[test]
fn symbol_presence_is_not_setness_but_native_scalar_items_are_set() {
    let mut b = SessionBindings::new();
    b.mark_variable_present("V");
    assert_eq!(scalar("${V+alternative}", &b), None);
    assert_eq!(scalar("${V:+alternative}", &b), None);
    assert_eq!(scalar("${V-fallback}", &b), None);
    b.insert_opaque_dynamic("V", "known existing value");
    b.mark_variable_present("V");
    assert_eq!(scalar("${V+alternative}", &b), None);
    b.replace_positional_parameters([SessionValue::opaque_dynamic("native scalar")]);
    assert_eq!(
        scalar("${1+alternative}", &b).as_deref(),
        Some("alternative")
    );
    assert_eq!(scalar("${1:+alternative}", &b), None);
    assert_eq!(scalar("${2+alternative}", &b).as_deref(), Some(""));
}

#[test]
fn empty_alternate_words_are_branch_independent() {
    let mut b = SessionBindings::new();
    for state in 0..3 {
        if state == 1 {
            b.insert_opaque_dynamic("V", "unknown bytes");
            b.mark_variable_present("V");
        }
        if state == 2 {
            b.remove("V");
        }
        assert_eq!(scalar("${V+}", &b).as_deref(), Some(""));
        assert_eq!(scalar("${V:+}", &b).as_deref(), Some(""));
    }
}

#[test]
fn proved_absence_is_distinct_from_empty_or_nonempty_and_matches_bash() {
    let values = [
        None,
        Some(""),
        Some("./x"),
        Some("/opt/x x"),
        Some("$(not-code)*x"),
    ];
    let expressions = [
        "${V-/fallback}",
        "${V:-/fallback}",
        "${V+ALT}",
        "${V:+ALT}",
        "${V/x/y}",
        "${V//x/y}",
    ];
    // Fixed expressions on argv data only; never eval or execute input text.
    let script = r#"while (( $# >= 2 )); do if [[ $1 == set ]]; then V=$2; else unset V; fi; shift 2; printf '%s\0' "${V-/fallback}" "${V:-/fallback}" "${V+ALT}" "${V:+ALT}" "${V/x/y}" "${V//x/y}"; done"#;
    let mut command = std::process::Command::new("/bin/bash");
    command.env_clear().env("LC_ALL", "C").args([
        "--noprofile",
        "--norc",
        "-c",
        script,
        "presence-oracle",
    ]);
    let mut actual = Vec::new();
    for value in values {
        let mut b = SessionBindings::new();
        if let Some(value) = value {
            b.insert_exact_scalar("V", value);
            command.args(["set", value]);
        } else {
            b.remove("V");
            command.args(["unset", ""]);
        }
        for expression in expressions {
            actual.push(scalar(expression, &b).unwrap());
        }
    }
    let native = command.output().unwrap();
    assert!(native.status.success(), "{native:?}");
    let mut expected = native.stdout.split(|c| *c == 0).collect::<Vec<_>>();
    assert_eq!(expected.pop(), Some(&b""[..]));
    assert_eq!(expected.len(), actual.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.as_bytes(), expected);
    }
}

#[test]
fn complete_frames_child_environments_and_invalidation_have_shared_rules() {
    let mut b = SessionBindings::new();
    b.replace_positional_parameters_with_exact_scalars(std::iter::empty::<&str>());
    assert_eq!(scalar("${1:-fallback}", &b).as_deref(), Some("fallback"));
    assert_eq!(scalar("${0:-fallback}", &b), None);
    b.forget_positional_parameters();
    assert_eq!(scalar("${1:-fallback}", &b), None);
    b.reset_child_environment(true);
    assert_eq!(scalar("${V:-fallback}", &b).as_deref(), Some("fallback"));
    b.insert_exact_scalar("V", "./local");
    b.enter_child_shell_environment();
    assert_eq!(scalar("${V:-fallback}", &b).as_deref(), Some("fallback"));
    b.reset_child_environment(false);
    assert_eq!(scalar("${V:-fallback}", &b), None);
    b.insert_inherited_exact_scalar("V", "/opt/value");
    assert_eq!(scalar("${V:-fallback}", &b).as_deref(), Some("/opt/value"));
}

#[test]
fn assignment_and_argv_cannot_turn_unknown_into_literal_default_data() {
    let mut b = SessionBindings::new();
    for expr in ["${V:-./safe}", "${V-./safe}", "${V//x/y}"] {
        assert_eq!(
            materialize_shell_assignment_value(expr, true, "string", &b),
            None
        );
        let parsed = parse_command(&format!("touch -- \"{expr}\""), ShellKind::Bash).unwrap();
        let args = materialize_projected_invocation(
            &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new()),
            &b,
        );
        assert_eq!(args.invocation.args.last().unwrap().text, expr);
        assert!(!args.invocation.args.last().unwrap().runtime_data);
    }
    b.remove("V");
    assert_eq!(
        materialize_shell_assignment_value("${V:-./safe}", true, "string", &b).as_deref(),
        Some("./safe")
    );
}
