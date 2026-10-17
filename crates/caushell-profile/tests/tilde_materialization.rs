//! Static argv materialization, without running any sample command.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::*;

fn args(command: &str, bindings: &SessionBindings) -> MaterializedProjectedInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    materialize_projected_invocation(
        &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new()),
        bindings,
    )
}

fn defaults(home: &str) -> SessionBindings {
    let mut b = SessionBindings::new();
    b.set_default_tilde_home(Some(home));
    b
}

#[test]
fn mixed_quotes_expand_tilde_once_without_fabricating_a_variable() {
    let b = defaults("/home/a b$literal*'\"");
    assert!(b.get("HOME").is_none());
    assert_eq!(b.environment_value("HOME"), EnvironmentValueRef::Unknown);
    for (word, suffix) in [
        (r#"~/Library/"Login Data""#, "/Library/Login Data"),
        ("~/Library/'Login Data'", "/Library/Login Data"),
        ("~/'$literal`*'", "/$literal`*"),
        (r"~/a\ b", "/a b"),
        ("~/a~b", "/a~b"),
    ] {
        let result = args(&format!("cp {word} output"), &b);
        let value = format!("{}{suffix}", b.tilde_home().unwrap());
        assert_eq!(result.invocation.args[0].text, value, "{word}: {result:?}");
        assert_eq!(
            result.arg_resolutions[0],
            ValueMaterialization::ResolvedShellWord { value }
        );
        assert!(result.invocation.args[0].runtime_data);
        let again = materialize_projected_invocation(&result.invocation, &defaults("/wrong"));
        assert_eq!(
            again.invocation.args[0].text,
            result.invocation.args[0].text
        );
    }
    assert!(matches!(
        args("cp \"$HOME\" output", &b).arg_resolutions[0],
        ValueMaterialization::MissingBinding { .. }
    ));
}

#[test]
fn real_home_overrides_defaults_and_preserves_its_origin() {
    let mut b = defaults("/default");
    for home in [
        "/workspace",
        "relative",
        "",
        "--target-directory=/outside",
        "/home/a b*",
    ] {
        b.insert_exact_scalar("HOME", home);
        let result = args("cp ~/\"file name\" output", &b);
        assert_eq!(result.invocation.args[0].text, format!("{home}/file name"));
        assert!(
            matches!(&result.arg_resolutions[0], ValueMaterialization::ResolvedExactScalar { variable_name, origin: BindingOrigin::SessionBinding, .. } if variable_name == "HOME")
        );
    }
    assert_eq!(
        args("cp ~ output", &b.with_exact_scalar("HOME", ""))
            .invocation
            .args[0]
            .text,
        ""
    );
}

#[test]
fn absent_and_unknown_home_are_distinct() {
    let mut b = defaults("/default");
    b.insert_exact_scalar("HOME", "/override");
    b.remove("HOME");
    assert_eq!(b.tilde_home(), Some("/default"));
    b.mark_variable_presence_unknown("HOME");
    assert_eq!(b.tilde_home(), None);
    assert!(matches!(
        args("cp ~/file output", &b).arg_resolutions[0],
        ValueMaterialization::UnsupportedDynamicText { .. }
    ));
    b.insert_exact_scalar("HOME", "bad\0home");
    assert_eq!(b.tilde_home(), None);
    let mut state = ShellStateSnapshot::new("/workspace");
    state.variables.push(ShellVariableSnapshot::new(
        "HOME",
        ShellValueSnapshot::opaque_dynamic("unknown"),
        true,
    ));
    let mut b = SessionBindings::from_summary_and_shell_state(&SessionSummary::new(), &state);
    b.set_default_tilde_home(Some("/default"));
    assert_eq!(b.tilde_home(), None);
}

#[test]
fn child_shell_uses_exported_home_not_unexported_parent_local() {
    let mut b = defaults("/default");
    b.insert_exact_scalar("HOME", "/local");
    let mut child = b.clone();
    child.enter_child_shell_environment();
    assert_eq!(child.tilde_home(), Some("/default"));
    assert!(child.get("HOME").is_none());
    b.export("HOME");
    b.enter_child_shell_environment();
    assert_eq!(b.tilde_home(), Some("/local"));
}

#[test]
fn generated_or_quoted_tildes_do_not_gain_lexical_expansion() {
    let b = defaults("/default")
        .with_exact_scalar("EMPTY", "")
        .with_exact_scalar("VALUE", "~/literal");
    for word in [
        "'~/literal'",
        r#""~/literal""#,
        r"\~/literal",
        "''~/literal",
        "\"$EMPTY\"~/literal",
        "\"$VALUE\"",
    ] {
        let result = args(&format!("cp {word} output"), &b);
        assert!(!result.invocation.args[0].text.starts_with("/default"));
    }
    for word in ["~root/file", "~+/file", "~/$(command)", "~/$UNKNOWN"] {
        let result = args(&format!("cp {word} output"), &b);
        assert!(
            !result.invocation.args[0].runtime_data,
            "{word}: {result:?}"
        );
    }
    let mut original = args("cp input output", &b).invocation;
    original.args[0].text = "~/literal".into();
    original.args[0].runtime_data = true;
    assert_eq!(
        materialize_projected_invocation(&original, &b)
            .invocation
            .args[0]
            .text,
        "~/literal"
    );
}

#[test]
fn lexical_brace_expansion_precedes_tilde_materialization() {
    let b = defaults("/default");
    let result = args("cp ~/{one,two} output", &b);
    assert_eq!(
        result
            .invocation
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect::<Vec<_>>(),
        ["/default/one", "/default/two", "output"]
    );
    assert!(
        result.invocation.args[..2]
            .iter()
            .all(|arg| arg.runtime_data)
    );
    assert!(!result.shell_expansion_unresolved);
}

#[test]
fn glob_prefix_keeps_field_uncertainty_and_uses_the_same_home_fact() {
    for home in ["/home/space name*", "/workspace"] {
        let b = defaults(home);
        let result = args("cp ~/input/* output", &b);
        assert_eq!(
            result.invocation.args[0].lexical_field_prefix.as_deref(),
            Some(home)
        );
        assert!(!result.invocation.args[0].runtime_data);
        assert_eq!(
            argument_structure(&result.invocation.args[0]).fields,
            ArgumentFieldCount::ZeroOrMore
        );
    }
    let b = defaults("/default").with_exact_scalar("HOME", "--target-directory=/outside");
    assert!(
        args("cp ~/input/* output", &b).invocation.args[0]
            .lexical_field_prefix
            .is_none()
    );
}

#[test]
fn request_home_defaults_cannot_overwrite_observed_or_complete_facts() {
    let mut initial = SessionBindings::new();
    initial.set_request_home_facts(Some("/default"));
    assert!(
        matches!(initial.get("HOME").unwrap().value, SessionValue::ExactScalar(v) if v=="/default")
    );
    for knowledge in [
        ShellStateKnowledge::Complete,
        ShellStateKnowledge::ExportedOnly,
    ] {
        let mut state = ShellStateSnapshot::new("/workspace");
        state.observability.variables = knowledge;
        let mut b = SessionBindings::from_summary_and_shell_state(&SessionSummary::new(), &state);
        b.set_request_home_facts(Some("/default"));
        assert!(b.get("HOME").is_none());
        assert_eq!(b.tilde_home(), Some("/default"));
    }
    for value in [
        ShellValueSnapshot::exact_scalar(""),
        ShellValueSnapshot::opaque_dynamic("unknown"),
    ] {
        let mut state = ShellStateSnapshot::new("/workspace");
        state
            .variables
            .push(ShellVariableSnapshot::new("HOME", value.clone(), true));
        let mut b = SessionBindings::from_summary_and_shell_state(&SessionSummary::new(), &state);
        b.set_request_home_facts(Some("/default"));
        let expected = match value {
            ShellValueSnapshot::ExactScalar { .. } => Some(""),
            _ => None,
        };
        assert_eq!(b.tilde_home(), expected);
    }
    for unknown in [false, true] {
        let mut b = SessionBindings::new();
        if unknown {
            b.mark_variable_presence_unknown("HOME");
        } else {
            b.remove("HOME");
        }
        b.set_request_home_facts(Some("/default"));
        assert!(b.get("HOME").is_none());
        assert_eq!(
            b.tilde_home(),
            if unknown { None } else { Some("/default") }
        );
    }
}
