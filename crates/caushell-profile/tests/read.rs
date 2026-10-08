use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str, bindings: &SessionBindings) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn documented_options_own_their_operands_not_variable_destinations() {
    for (command, names) in [
        ("read target", vec!["target"]),
        ("read first second third", vec!["first", "second", "third"]),
        (r#"read -p "Continue (y/n)?" answer"#, vec!["answer"]),
        ("read -p prompt target", vec!["target"]),
        ("read -pprompt target", vec!["target"]),
        ("read -n 1 c", vec!["c"]),
        ("read -t 10", vec!["REPLY"]),
        ("read -r -d '' f", vec!["f"]),
        (r"read -rd $'\0' f", vec!["f"]),
        (
            r"read -rep $'Please Enter a Message:\n' message",
            vec!["message"],
        ),
        (r#"read -e -p "Do that? [Y,n]" -i Y input"#, vec!["input"]),
        (r#"read -s -p "Password: " password"#, vec!["password"]),
        (
            r#"read -r -n 1 -p "${1:-Continue?} [y/n]: " REPLY"#,
            vec!["REPLY"],
        ),
        (r#"read -n1 -p "Do that? [y,n]" doit"#, vec!["doit"]),
        (
            r"read -rp $'Are you sure (Y/n) : ' -ei $'Y' key",
            vec!["key"],
        ),
        ("read -t5 -n1 -r -p 'Press any key...' key", vec!["key"]),
        ("read -u 4 line", vec!["line"]),
        ("read -u 4 -N \"$char\" -r -s line", vec!["line"]),
        ("read -N \"$BUFSIZE\" buffer", vec!["buffer"]),
        ("read -p --help -d -r target", vec!["target"]),
        ("read '-r' '-p' prompt target", vec!["target"]),
        ("read -p one -p two target", vec!["target"]),
        ("read -n1 -N2 -n3 target", vec!["target"]),
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert!(
            bound.residuals.is_empty(),
            "{command}: {:?}",
            bound.residuals
        );
        let writes = runtime_variable_writes(&bound);
        assert!(!writes.unresolved, "{command}");
        assert_eq!(writes.names, names, "{command}");
        assert!(!bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ExecutePayload | EffectKind::WritePath | EffectKind::DeletePath
        )));
    }
}

#[test]
fn absent_destinations_mean_reply_including_option_only_forms() {
    for command in [
        "read",
        "read -r",
        "read --",
        "read -d ''",
        "read -n1",
        "read -p prompt",
        "read -u4",
        "read -r -u4 --",
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
        assert_eq!(
            runtime_variable_writes(&bound).names,
            ["REPLY"],
            "{command}"
        );
        assert!(bound.effects.iter().any(|e| matches!(&e.target,
            EffectTarget::VariableName(name) if name == "REPLY")));
    }
}

#[test]
fn array_mode_replaces_only_the_declared_array_and_ignores_names() {
    for command in [
        "read -a files",
        "read -ra files",
        "read -d '' -ra files",
        "read -afiles",
        "read -a files ignored REPLY",
        "read -u4 -a files ignored",
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
        assert_eq!(
            runtime_variable_writes(&bound).names,
            ["files"],
            "{command}"
        );
    }
}

#[test]
fn descriptor_reads_do_not_claim_to_consume_stdin() {
    for command in ["read -u4 target", "read -u0", "read -u \"$FD\" -a files"] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert!(bound.bound_implicit_inputs.is_empty());
        assert_eq!(
            bound.stream_contract.as_ref().unwrap().stdin_mode,
            StreamInputMode::Ignored
        );
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin)
        );
        assert!(!runtime_variable_writes(&bound).names.is_empty());
    }
}

#[test]
fn names_after_option_terminator_are_not_reinterpreted_as_flags() {
    let valid = resolve("read -r -- target other", &SessionBindings::new());
    assert!(!valid.operation_semantics_unresolved);
    assert_eq!(runtime_variable_writes(&valid).names, ["target", "other"]);
    for command in ["read -- -p prompt target", "read target -p prompt"] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        let writes = runtime_variable_writes(&bound);
        assert!(writes.unresolved);
        assert!(writes.names.contains(&"target".to_string()));
        assert!(writes.names.contains(&"prompt".to_string()));
    }
}

#[test]
fn materialized_names_use_existing_runtime_destination_checks() {
    let bindings = SessionBindings::new().with_exact_scalar("name", "target");
    let good = resolve("read -p prompt \"$name\"", &bindings);
    assert!(!good.operation_semantics_unresolved);
    assert_eq!(runtime_variable_writes(&good).names, ["target"]);
    for command in [
        "read \"$unknown\"",
        "read 'bad-name'",
        "read 'a[0]'",
        "read -a 'a[0]'",
        "read ''",
    ] {
        assert!(
            resolve(command, &bindings).operation_semantics_unresolved,
            "{command}"
        );
    }
}

#[test]
fn missing_operands_and_unknown_flags_remain_unresolved() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "read -p",
        "read -d",
        "read -n",
        "read -N",
        "read -u",
        "read -t",
        "read -i",
        "read -a",
        "read -Z target",
        "read --version",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        );
        assert!(
            matches!(&result, ResolveInvocationResult::SelectionError { .. })
                || matches!(&result, ResolveInvocationResult::Resolved(r)
                if r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty()),
            "{command}: {result:#?}"
        );
    }
}

#[test]
fn help_has_no_runtime_write() {
    let bound = resolve("read --help", &SessionBindings::new());
    assert_eq!(bound.form_id.as_str(), "show_help");
    assert!(bound.effects.is_empty());
    assert_eq!(
        runtime_variable_writes(&bound),
        RuntimeVariableWrites::default()
    );
}

#[test]
fn known_zero_timeout_only_polls_without_assigning() {
    for command in [
        "read -t0 target",
        "read -t 0",
        "read -t0.0 -a files ignored",
        "read -t .0 -u4 first second",
        "read -t 00.000 target",
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert_eq!(bound.form_id.as_str(), "poll_input", "{command}");
        assert!(bound.residuals.is_empty());
        assert!(bound.effects.is_empty());
        assert!(bound.bound_implicit_inputs.is_empty());
        assert_eq!(
            runtime_variable_writes(&bound),
            RuntimeVariableWrites::default()
        );
    }
    for command in [
        "read -t0 -t1 target",
        "read -t1 -t0 target",
        "read -t \"$timeout\" target",
    ] {
        let bound = resolve(command, &SessionBindings::new());
        assert_eq!(
            runtime_variable_writes(&bound).names,
            ["target"],
            "{command}"
        );
    }
}

#[test]
fn pathname_invocation_is_not_an_owning_shell_variable_write() {
    let bound = resolve("/usr/bin/read target", &SessionBindings::new());
    assert!(bound.operation_semantics_unresolved);
}

#[test]
fn variable_width_operands_cannot_certify_destinations_or_query_forms() {
    for command in [
        "read -p $prompt -t0 target",
        "read -n $count first",
        "read -N$BUFSIZE target",
        "read -p \"$@\" target",
        "read -p prompt* target",
    ] {
        assert!(
            resolve(command, &SessionBindings::new()).operation_semantics_unresolved,
            "{command}"
        );
    }
    for command in ["read -p \"$prompt\" -t0 target", "read -n \"$count\" first"] {
        assert!(
            !resolve(command, &SessionBindings::new()).operation_semantics_unresolved,
            "{command}"
        );
    }
}

#[test]
fn variable_width_validation_is_declared_semantics_not_a_read_name_branch() {
    let original = ProfileRegistry::built_in().unwrap();
    let mut profile = original.lookup("read").profile.unwrap().clone();
    profile.identity.canonical_name = CommandName::new("prompt_input");
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for (command, unresolved) in [
        ("prompt_input -p $prompt -t0 target", true),
        ("prompt_input -p \"$prompt\" -t0 target", false),
    ] {
        let p = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &p.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}");
        };
        assert_eq!(
            r.bound.operation_semantics_unresolved, unresolved,
            "{command}"
        );
    }
}

#[test]
fn fixed_variable_targets_are_generic_and_restricted_to_identifiers() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: prompt_input}
forms:
  - id: input
    selector: {kind: no_arguments}
    effects:
      - kind: bind_variable_from_runtime_input
        target: {kind: variable_name, name: ANSWER}
"#;
    let profile = load_command_profile_from_str(source).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let p = parse_command("prompt_input", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        &registry,
        &p.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!("generic declared variable target");
    };
    assert_eq!(runtime_variable_writes(&r.bound).names, ["ANSWER"]);
    for name in ["", "bad-name", "a[0]", "$target", "$(id)"] {
        let changed = source.replace("name: ANSWER", &format!("name: '{name}'"));
        assert!(matches!(
            load_command_profile_from_str(&changed),
            Err(LoadProfileError::Normalize(
                NormalizeError::InvalidVariableTarget(_)
            ))
        ));
    }
    let changed = source.replace("bind_variable_from_runtime_input", "write_path");
    assert!(matches!(
        load_command_profile_from_str(&changed),
        Err(LoadProfileError::Normalize(
            NormalizeError::InvalidVariableTarget(_)
        ))
    ));
}
