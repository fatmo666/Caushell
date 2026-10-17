//! Static argv modeling. The independent oracle executes only self-authored
//! Bash `set`/`printf` builtins, never benchmark commands or native effects.
use caushell_profile::*;
use caushell_types::ShellKind;

fn materialize(
    command: &str,
    shell: ShellKind,
    bindings: &SessionBindings,
) -> MaterializedProjectedInvocation {
    let parsed = caushell_parse::parse_command(command, shell).unwrap();
    let projection = project_invocation(
        &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(shell),
    );
    let result = materialize_projected_invocation(&projection, bindings);
    for arg in &result.invocation.args {
        assert!(
            projection
                .args
                .iter()
                .any(|original| arg.span == original.span)
        );
    }
    result
}

fn argv(m: &MaterializedProjectedInvocation) -> Vec<String> {
    m.invocation
        .args
        .iter()
        .map(|arg| {
            if arg.runtime_data {
                arg.text.clone()
            } else {
                caushell_parse::decode_static_shell_argument(&arg.text, arg.quoted, &arg.node_kind)
                    .unwrap_or_else(|| arg.text.clone())
            }
        })
        .collect()
}

#[test]
fn real_benchmark_spellings_have_exact_order_and_cardinality() {
    for (command, expected) in [
        (
            "mkdir -p project/{lib/ext,bin,src,doc/{html,info,pdf},demo/stat/a}",
            vec![
                "-p",
                "project/lib/ext",
                "project/bin",
                "project/src",
                "project/doc/html",
                "project/doc/info",
                "project/doc/pdf",
                "project/demo/stat/a",
            ],
        ),
        (
            "mv {,new.}original.filename",
            vec!["original.filename", "new.original.filename"],
        ),
        (
            "touch -a UEDP0{1..5}_20120821.csv",
            vec![
                "-a",
                "UEDP01_20120821.csv",
                "UEDP02_20120821.csv",
                "UEDP03_20120821.csv",
                "UEDP04_20120821.csv",
                "UEDP05_20120821.csv",
            ],
        ),
        ("echo x{1..2}{a,b}", vec!["x1a", "x1b", "x2a", "x2b"]),
        ("echo {,} ''{,}", vec!["", ""]),
        (r#"echo p{a,"b,c",'d e'}"#, vec!["pa", "pb,c", "pd e"]),
        (r"echo {a\,b,c}", vec!["a,b", "c"]),
    ] {
        let result = materialize(command, ShellKind::Bash, &SessionBindings::new());
        assert!(!result.shell_expansion_unresolved, "{command}");
        assert_eq!(argv(&result), expected, "{command}");
    }
}

#[test]
fn expanded_options_and_separators_are_reclassified_before_binding() {
    let r = materialize(
        "find . -{print,delete}",
        ShellKind::Bash,
        &SessionBindings::new(),
    );
    assert_eq!(argv(&r), [".", "-print", "-delete"]);
    assert_eq!(r.invocation.args[2].kind, ProjectedArgKind::Flag);
    let r = materialize(
        "touch {--,-a} file",
        ShellKind::Bash,
        &SessionBindings::new(),
    );
    assert_eq!(argv(&r), ["--", "-a", "file"]);
    assert_eq!(r.invocation.args[0].kind, ProjectedArgKind::DashDash);
    assert_eq!(r.invocation.args[1].kind, ProjectedArgKind::Positional);
}

#[test]
fn literal_and_supplied_data_never_gain_a_second_shell_expansion() {
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("X", "{a,b}");
    let r = materialize(
        r#"echo '{a,b}' "{1..3}" \{x,y\} "$X""#,
        ShellKind::Bash,
        &bindings,
    );
    assert_eq!(argv(&r), ["{a,b}", "{1..3}", "{x,y}", "{a,b}"]);
    let parsed = caushell_parse::parse_command("echo placeholder", ShellKind::Bash).unwrap();
    let mut p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    p.args[0].text = "{a,b}".into();
    p.args[0].runtime_data = true;
    assert_eq!(
        argv(&materialize_projected_invocation(&p, &bindings)),
        ["{a,b}"]
    );
}

#[test]
fn shell_dialect_and_expansion_budget_are_explicit() {
    let r = materialize("echo {a,b}", ShellKind::Sh, &SessionBindings::new());
    assert_eq!(argv(&r), ["{a,b}"]);
    for command in [
        "echo {1..10000}",
        "echo {1..20}{1..20}",
        "echo {1..200} {1..200}",
    ] {
        let r = materialize(command, ShellKind::Bash, &SessionBindings::new());
        assert!(r.shell_expansion_unresolved, "{command}: {r:?}");
        assert!(
            r.invocation.args.iter().any(|arg| arg.text.contains('{')),
            "{command}"
        );
    }
    // The range's earlier lexical expansion must not reinterpret a variable's
    // content as brace syntax, including when both appear in the same argv.
    let r = materialize(
        "echo {a,b}$UNKNOWN",
        ShellKind::Bash,
        &SessionBindings::new(),
    );
    assert_eq!(r.invocation.args.len(), 1);
}

#[test]
fn expansion_failure_retains_operation_uncertainty_even_for_readonly_profiles() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = caushell_parse::parse_command("echo {1..10000}", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!("expected echo profile")
    };
    assert!(r.bound.operation_semantics_unresolved);
}

#[test]
fn pure_builtin_bash_oracle_agrees_on_order_width_quotes_and_tilde() {
    let bindings = SessionBindings::new().with_exact_scalar("HOME", "/oracle/home");
    for word in [
        "{a,b}",
        "{,}",
        "x{,}",
        "''{,}",
        "{1..2}{a,b}",
        "p/{a,b{1,2},}/z",
        "{x{a,b}}",
        r#"p{a,"b,c",'d e'}"#,
        r"{a\,b,c}",
        r"\{a,b\}",
        "'{a,b}'",
        "\"{1..3}\"",
        "{-01..2}",
        "{001..-1}",
        "{+1..3}",
        "{+01..+03}",
        "{+0001..03}",
        "{01..+003}",
        "{-01..+003}",
        "{+001..-01}",
        "{-0..3}",
        "{-00..2}",
        "{3..1..0}",
        "{a..f..2}",
        "{Z..U..-2}",
        "{1..1}",
        "~/{one,two}",
        "{a,}~",
        "{,}~/a",
        "''~/{a,b}",
        "--{help,version}",
    ] {
        let script = format!(
            "set -- {word}; builtin printf '%s\\0' \"$#\"; if (( $# )); then builtin printf '%s\\0' \"$@\"; fi"
        );
        let output = std::process::Command::new("/bin/bash")
            .args(["--noprofile", "--norc", "-c", &script])
            .env_clear()
            .env("HOME", "/oracle/home")
            .output()
            .unwrap();
        assert!(output.status.success(), "{word}: {output:?}");
        let values = output.stdout.split(|b| *b == 0).collect::<Vec<_>>();
        let count: usize = std::str::from_utf8(values[0]).unwrap().parse().unwrap();
        let expected = values[1..1 + count]
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect::<Vec<_>>();
        let result = materialize(&format!("echo {word}"), ShellKind::Bash, &bindings);
        assert!(!result.shell_expansion_unresolved, "{word}");
        assert_eq!(argv(&result), expected, "{word}");
    }
}
