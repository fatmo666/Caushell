//! Shared opt-in string dispatch contract; inputs are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const FIXTURE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: string-fixture}
forms:
  - id: run
    parameters:
      - {name: programs, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: required_many}
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          command_string: {slot: programs, syntax: gnu_wordsplit}
          argv_suffix: [-d]
          stdin_from_tool: true
          unknown_environment_names: [TOOL_FILENAME]
"#;

fn project(yaml: &str, command: &str) -> (BoundInvocation, DispatchCommandProjection) {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()]).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!()
    };
    let projection = collect_dispatch_command_projection(&r.bound);
    (r.bound, projection)
}

#[test]
fn gnu_wordsplit_preserves_actual_argv_source_and_suffix() {
    let (bound, projection) = project(
        FIXTURE,
        r#"string-fixture 'sh -c "printf DATA > /opt/shared/output"'"#,
    );
    assert!(projection.unresolved.is_empty());
    let child = &projection.resolved[0];
    assert_eq!(child.command.text, "sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "printf DATA > /opt/shared/output", "-d"]
    );
    assert!(child.stdin_from_tool);
    assert!(!child.stdin_from_parent);
    assert_eq!(child.unknown_environment_names, ["TOOL_FILENAME"]);
    let BoundValue::Argument {
        span,
        binding_source,
        ..
    } = &bound.bound_parameters[0].values[0]
    else {
        panic!()
    };
    assert!(child.command.span.start_byte >= span.end_byte);
    assert!(child.argv[0].span.end_byte <= child.argv[1].span.start_byte);
    assert_ne!(child.argv[0].span, child.argv[1].span);
    assert_eq!(&child.argv[1].binding_source, binding_source);
    assert!(child.argv.iter().all(|a| a.runtime_data));
}

#[test]
fn shell_mode_defers_parsing_to_existing_shell_payload_engine() {
    let yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell");
    let (_, projection) = project(&yaml, "string-fixture 'printf SAFE; rm /opt/shared/file'");
    let child = &projection.resolved[0];
    assert_eq!(child.command.text, "/bin/sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "printf SAFE; rm /opt/shared/file", "-d"]
    );
}

#[test]
fn each_known_or_unknown_string_gets_a_distinct_dispatch_identity() {
    let (_, p) = project(FIXTURE, "string-fixture 'gzip -9' \"$unknown\" 'xz -T2'");
    assert_eq!(
        p.resolved
            .iter()
            .map(|c| c.dispatch_index)
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(p.unresolved[0].dispatch_index, 1);
    for command in [
        "string-fixture 'gzip $MODE'",
        "string-fixture 'echo \"'",
        "string-fixture ''",
    ] {
        let (_, p) = project(FIXTURE, command);
        assert!(p.resolved.is_empty(), "{command}");
        assert_eq!(p.unresolved.len(), 1, "{command}");
    }
}

#[test]
fn gnu_words_are_runtime_data_not_new_caller_shell_expansions() {
    let (_, p) = project(FIXTURE, r#"string-fixture "printf '\$VAR' ';' 'a b'""#);
    let fact = p.resolved[0].to_command_fact();
    let materialized = materialize_projected_invocation(
        &project_invocation(&fact, InvocationRuntimeContext::new()),
        &SessionBindings::new().with_exact_scalar("VAR", "/opt/shared"),
    );
    assert_eq!(
        materialized
            .invocation
            .args
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["$VAR", ";", "a b", "-d"]
    );
}

#[test]
fn invalid_declarations_fail_at_load_time_and_legacy_sources_are_unchanged() {
    for yaml in [
        FIXTURE.replace("slot: programs", "slot: missing"),
        FIXTURE.replace("gnu_wordsplit", "guess"),
        FIXTURE.replace(
            "syntax: gnu_wordsplit",
            "syntax: gnu_wordsplit, join_arguments: true",
        ),
        FIXTURE.replace(
            "syntax: gnu_wordsplit",
            "syntax: gnu_parallel, join_arguments: true",
        ),
        FIXTURE.replace("slot: programs", "slot: ''"),
        FIXTURE.replace("argv_suffix: [-d]", "argv_prefix: [-d]"),
        FIXTURE.replace("argv_suffix: [-d]", "argv: [programs]"),
        FIXTURE.replace("argv_suffix: [-d]", "command: programs"),
        FIXTURE.replace(
            "stdin_from_tool: true",
            "stdin_from_tool: true\n          stdin_from_parent: true",
        ),
        FIXTURE.replace("[TOOL_FILENAME]", "[A=B]"),
        FIXTURE.replace("[TOOL_FILENAME]", "[TOOL_FILENAME, TOOL_FILENAME]"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
    let legacy = FIXTURE.replace(
        "command_string: {slot: programs, syntax: gnu_wordsplit}",
        "command_whitespace_argv: programs",
    );
    let (_, p) = project(&legacy, r#"string-fixture 'printf "two words"'"#);
    assert_eq!(
        p.resolved[0]
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["\"two", "words\"", "-d"]
    );
}

#[test]
fn joined_shell_program_is_one_dispatch_over_decoded_arguments() {
    let yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell, join_arguments: true");
    let (bound, p) = project(
        &yaml,
        r#"string-fixture printf '%s\n' '"a b"' '; rm /opt/shared/file'"#,
    );
    assert!(p.unresolved.is_empty());
    assert_eq!(p.resolved.len(), 1);
    let child = &p.resolved[0];
    assert_eq!(child.command.text, "/bin/sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "printf %s\\n \"a b\" ; rm /opt/shared/file", "-d"]
    );
    assert_eq!(bound.bound_parameters[0].values.len(), 4);
    assert!(child.argv.iter().all(|a| a.runtime_data));
    assert!(child.argv.iter().all(|a| {
        a.span.start_byte
            > bound.bound_parameters[0]
                .values
                .iter()
                .filter_map(|v| {
                    if let BoundValue::Argument { span, .. } = v {
                        Some(span.end_byte)
                    } else {
                        None
                    }
                })
                .max()
                .unwrap()
    }));
    assert!(child.stdin_from_tool);
    assert_eq!(child.unknown_environment_names, ["TOOL_FILENAME"]);
}

#[test]
fn joined_shell_program_never_dispatches_known_fragments_around_unknown_input() {
    let yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell, join_arguments: true");
    for command in [
        "string-fixture 'printf SAFE' \"$UNKNOWN\" 'rm /opt/file'",
        "string-fixture printf *.txt",
        "string-fixture printf $(cat input)",
    ] {
        let (_, p) = project(&yaml, command);
        assert!(p.resolved.is_empty(), "{command}: {p:?}");
        assert_eq!(p.unresolved.len(), 1, "{command}");
        assert_eq!(p.unresolved[0].dispatch_index, 0);
    }
    let (_, p) = project(&yaml, "string-fixture ''");
    assert_eq!(p.resolved[0].argv[1].text, "");
    let (_, p) = project(&yaml, "string-fixture printf '' SAFE");
    assert_eq!(p.resolved[0].argv[1].text, "printf  SAFE");
}

#[test]
fn joined_program_keeps_one_gap_for_implicit_input_and_nul_bytes() {
    let yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell, join_arguments: true");
    for implicit in [false, true] {
        let (mut bound, _) = project(&yaml, "string-fixture printf SAFE");
        if implicit {
            bound.bound_parameters[0]
                .values
                .push(BoundValue::implicit_input(ImplicitInputSource::StdinData));
        } else {
            let BoundValue::Argument {
                text,
                materialization,
                ..
            } = &mut bound.bound_parameters[0].values[1]
            else {
                panic!()
            };
            *text = "SAFE\0; rm /opt/file".into();
            *materialization = BoundArgumentMaterialization::RuntimeData;
        }
        let p = collect_dispatch_command_projection(&bound);
        assert!(p.resolved.is_empty());
        assert_eq!(p.unresolved.len(), 1);
    }
}

#[test]
fn joined_program_limits_cover_the_entire_region_and_legacy_false_is_unchanged() {
    let yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell, join_arguments: true");
    for command in [
        format!(
            "string-fixture '{}' '{}'",
            "a".repeat(32768),
            "b".repeat(32768)
        ),
        format!("string-fixture {}", vec!["a"; 4097].join(" ")),
    ] {
        let (_, p) = project(&yaml, &command);
        assert!(p.resolved.is_empty());
        assert_eq!(p.unresolved.len(), 1);
    }
    let (_, p) = project(&yaml, &format!("string-fixture '{}'", "a".repeat(65536)));
    assert_eq!(p.resolved.len(), 1);
    let false_yaml = FIXTURE.replace("gnu_wordsplit", "posix_shell, join_arguments: false");
    let (_, p) = project(&false_yaml, "string-fixture 'printf SAFE' 'rm /opt/file'");
    assert_eq!(p.resolved.len(), 2);
    assert_eq!(p.resolved[0].argv[1].text, "printf SAFE");
    assert_eq!(p.resolved[1].argv[1].text, "rm /opt/file");
}
