use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{RuntimeArgumentDomain, ShellKind};

fn fields(command: &str, b: &SessionBindings) -> MaterializedProjectedInvocation {
    let p = parse_command(command, ShellKind::Bash).unwrap();
    materialize_projected_invocation(
        &project_invocation(&p.commands[0], InvocationRuntimeContext::new()),
        b,
    )
}
fn argument(text: &str) -> ProjectedArg {
    let p = parse_command(&format!("worker {text}"), ShellKind::Bash).unwrap();
    project_invocation(&p.commands[0], InvocationRuntimeContext::new())
        .args
        .remove(0)
}
fn tail(root: &str) -> ProjectedArg {
    let mut a = argument("placeholder");
    a.text.clear();
    a.quoted = true;
    a.node_kind = "runtime_argument_list".into();
    a.implicit_input_source = Some(caushell_types::ImplicitInputSource::DispatchOutput);
    a.runtime_argument_domain = Some(RuntimeArgumentDomain::PathSet {
        roots: vec![root.into()],
        may_escape: false,
        basename_suffix: None,
        no_adjacent_slashes: false,
    });
    a
}
fn frame(root: &str) -> SessionBindings {
    let mut b = SessionBindings::new();
    b.bind_positional_arguments(&[argument("known"), tail(root)], &[]);
    b
}

#[test]
fn a_typed_tail_proves_each_field_but_not_an_exact_list_or_missing_parameter() {
    let b = frame("./input");
    assert!(!b.positional_parameters_are_complete());
    let a = fields(r#"worker "$@""#, &b);
    assert_eq!(a.invocation.args.len(), 2);
    assert_eq!(a.invocation.args[0].text, "known");
    let shape = argument_structure(&a.invocation.args[1]);
    assert_eq!(shape.fields, ArgumentFieldCount::ZeroOrMore);
    assert!(!shape.may_start_with("-"));
    assert_eq!(
        a.invocation.args[1].implicit_input_source,
        Some(caushell_types::ImplicitInputSource::DispatchOutput)
    );
    assert!(
        argument_structure(&fields(r#"worker "$2""#, &b).invocation.args[0]).may_start_with("-")
    );
}

#[test]
fn joined_unquoted_and_mixed_vectors_do_not_borrow_each_field_bounds() {
    let b = frame("./input");
    for command in [r#"worker "$*""#, "worker $@", r#"worker "prefix$@suffix""#] {
        let a = fields(command, &b);
        assert!(
            a.invocation
                .args
                .iter()
                .all(|a| a.runtime_argument_domain.is_none()),
            "{command}: {a:#?}"
        );
    }
}

#[test]
fn replacement_child_frames_and_branch_joins_invalidate_old_tail_proofs() {
    let mut b = frame("./input");
    b.shift_positional_frame(1);
    assert!(b.has_positional_runtime_tail());
    assert_eq!(fields(r#"worker "$@""#, &b).invocation.args.len(), 1);
    b.shift_positional_frame(1);
    assert!(!b.has_positional_runtime_tail());
    let mut b = frame("./input");
    b.replace_positional_parameters_with_exact_scalars(["-delete"]);
    assert!(!b.has_positional_runtime_tail());
    assert_eq!(
        fields(r#"worker "$@""#, &b).invocation.args[0].text,
        "-delete"
    );
    let mut b = frame("./input");
    b.enter_child_shell_environment();
    assert!(!b.has_positional_runtime_tail());
    let mut b = frame("./input");
    b.join_control_path(
        &frame("/opt/shared"),
        caushell_types::CommandSequenceNo::new(1),
    );
    assert!(!b.has_positional_runtime_tail());
}

#[test]
fn an_unknown_segment_before_a_fixed_suffix_does_not_become_a_final_tail() {
    let mut b = SessionBindings::new();
    b.bind_positional_arguments(&[tail("./input"), argument("-delete")], &[]);
    assert!(!b.has_positional_runtime_tail());
    assert!(!b.positional_parameters_are_complete());
    assert!(
        argument_structure(&fields(r#"worker "$@""#, &b).invocation.args[0]).may_start_with("-")
    );
}

#[test]
fn native_quoted_vectors_preserve_data_fields_across_functions_and_known_shift() {
    // Fixed scripts only; adversarial-looking values are argv data, never eval.
    let values = ["./a b", "", "./$(printf EVALUATED)", "./-delete", "./a\nb"];
    for shell in ["/bin/bash", "/bin/sh"] {
        for script in [
            r#"printf '%s\0' "$@""#,
            r#"f() { printf '%s\0' "$@"; }; f "$@""#,
            r#"shift; printf '%s\0' "$@""#,
        ] {
            let shifted = script.starts_with("shift");
            let mut args = vec!["-c", script, "native-vector"];
            if shifted {
                args.push("ignored");
            }
            args.extend(values);
            let actual = std::process::Command::new(shell)
                .args(args)
                .output()
                .unwrap();
            assert!(actual.status.success(), "{shell} {script}: {actual:?}");
            let expected = values
                .iter()
                .flat_map(|v| v.as_bytes().iter().copied().chain([0]))
                .collect::<Vec<_>>();
            assert_eq!(actual.stdout, expected, "{shell} {script}");
        }
    }
}
